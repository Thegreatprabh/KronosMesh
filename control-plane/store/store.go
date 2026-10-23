// Package store implements the control plane's state store: a
// thread-safe in-memory store that is authoritative for reads, with
// restart persistence. When REDIS_ADDR points at a reachable server,
// every structural write is mirrored there as full state, and at
// startup RecoverFromMirror rebuilds the registry, policy and
// enrollment set from that mirror — so a control-plane restart no
// longer loses the mesh. Without Redis, EnableFilePersistence turns
// on an atomic JSON state file with the same restore semantics.
// With neither, a restart starts empty and previously registered
// nodes are unknown: they must be re-provisioned with an enrollment
// token (or the admin token), because a node identity alone does
// not prove it should be trusted again.
package store

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"net/netip"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"

	"github.com/Thegreatprabh/KronosMesh/control-plane/models"
)

// Store is the state contract the API layer depends on.
type Store interface {
	RegisterNode(req *models.NodeRegisterRequest, now time.Time) (*models.PeerNode, string, error)
	Heartbeat(nodeID string, hb *models.HeartbeatPayload, token string, now time.Time) (*models.PeerNode, error)
	DeleteNode(id string) bool
	KeyExists(publicKey string) bool
	AnyNodeTokenValid(token string) bool
	MintEnrollmentToken() string
	AddEnrollmentHash(hash string)
	EnrollmentValid(token string) bool
	ConsumeEnrollment(token string) bool
	ListNodes() []models.PeerNode
	Topology(now time.Time) models.MeshTopology
	ListAcls() models.AclPolicyResponse
	CreateAcl(rule models.AclRule) (models.AclRule, error)
	DeleteAcl(id string) bool
	ReapStale(now time.Time, offlineAfter time.Duration) int
}

// MemoryStore is the authoritative in-memory implementation.
type MemoryStore struct {
	mu       sync.RWMutex
	byID     map[string]*models.PeerNode
	byKey    map[string]string // public key -> node id
	usedIPs  map[string]bool
	nextIP   uint32 // next candidate pool offset inside 100.64.0.0/10
	poolLast uint32 // last assignable pool offset (test seam for exhaustion)
	acls     []models.AclRule
	aclVer   uint64
	// enrollHashes holds the SHA-256 hashes of outstanding
	// single-use enrollment tokens. Only hashes are kept: the
	// plaintext is shown to the operator exactly once at minting.
	enrollHashes map[string]bool
	// enrollConsumed remembers the hashes of enrollment tokens
	// that have been USED, persistently (state file + mirror).
	// Without it, startup re-seeding of KRONOS_ENROLLMENT_TOKENS
	// would resurrect a consumed token on every restart, quietly
	// breaking the single-use guarantee for env-provisioned
	// tokens. Seeding skips any hash in this set.
	enrollConsumed map[string]bool
	mirror       *redis.Client // optional write-through mirror, may be nil
	// stateFile, when non-empty (and no Redis mirror is in use),
	// is the atomic JSON snapshot path; see persist.go.
	stateFile string
}

// CGNAT pool: the full RFC 6598 100.64.0.0/10 block, expressed as offsets
// from the network address. Offset 0 is the network address and offset 1
// is reserved, so assignment starts at offset 2 (100.64.0.2) and runs to
// offset 0x3FFFFE (100.127.255.254) - about 4.19 million addresses.
const (
	ipPoolBase    = 2          // first assignable offset: 100.64.0.2
	ipPoolLast    = 0x003FFFFE // last assignable offset: 100.127.255.254
	ipPoolNetBase = 0x64400000 // 100.64.0.0 as a uint32
)

// assignableOffset reports whether `ip` (a dotted-quad string)
// falls inside the assignable pool range — i.e. it is not the
// network address (offset 0), the reserved offset 1, or the
// broadcast address (offset 0x3FFFFF). The pool cursor never
// hands those out; a node must not be able to claim them via a
// requested virtual IP either.
func assignableOffset(ip string) bool {
	addr, err := netip.ParseAddr(ip)
	if err != nil || !addr.Is4() {
		return false
	}
	u := addr.As4()
	v := uint32(u[0])<<24 | uint32(u[1])<<16 | uint32(u[2])<<8 | uint32(u[3])
	if v < ipPoolNetBase {
		return false
	}
	off := v - ipPoolNetBase
	return off >= ipPoolBase && off <= ipPoolLast
}

// ErrIPPoolExhausted is returned when every address in the pool is taken.
var ErrIPPoolExhausted = errors.New("virtual IP pool exhausted")

// ErrUnauthorized is returned when a node credential check fails:
// heartbeats and re-registrations must present the bearer token that was
// issued at first registration (or use an admin override).
var ErrUnauthorized = errors.New("unauthorized: invalid or missing node token")

// ErrUnknownNode is returned for operations addressed to a missing node.
var ErrUnknownNode = errors.New("unknown node")

// tokenHashMatches compares a presented token's hash with the
// stored hash in constant time. The compared values are hashes of
// a 256-bit random token, so the practical timing risk was already
// minimal — this keeps credential checks uniformly constant-time.
func tokenHashMatches(presented, storedHash string) bool {
	if storedHash == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(hashToken(presented)), []byte(storedHash)) == 1
}

// AnyNodeTokenValid reports whether the presented bearer token
// belongs to ANY registered node. It gates the read endpoints
// (topology, ACL policy) that daemons legitimately poll with
// their node token — without leaving full mesh reconnaissance
// (names, roles, public keys, live endpoints) open to anyone who
// can reach the port.
func (s *MemoryStore) AnyNodeTokenValid(token string) bool {
	if token == "" {
		return false
	}
	h := hashToken(token)
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, node := range s.byID {
		if node.TokenHash != "" && subtle.ConstantTimeCompare([]byte(h), []byte(node.TokenHash)) == 1 {
			return true
		}
	}
	return false
}

// MintEnrollmentToken creates a fresh single-use enrollment token
// and records its hash. The plaintext is returned exactly once —
// this return value is the only place it ever exists outside the
// operator's hands.
func (s *MemoryStore) MintEnrollmentToken() string {
	tok := newNodeToken()
	s.AddEnrollmentHash(hashToken(tok))
	return tok
}

// AddEnrollmentHash records the SHA-256 hash of an enrollment token
// as valid. Used by MintEnrollmentToken and by startup seeding of
// KRONOS_ENROLLMENT_TOKENS.
func (s *MemoryStore) AddEnrollmentHash(hash string) {
	if hash == "" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.enrollConsumed[hash] {
		// Already used once: single-use means never again,
		// even if the operator's environment still lists it.
		return
	}
	s.enrollHashes[hash] = true
	s.mirrorEnrollment()
	s.persistLocked()
}

// EnrollmentValid reports whether the presented plaintext token is
// an outstanding enrollment token, without consuming it. The
// comparison runs over hashes in constant time per entry.
func (s *MemoryStore) EnrollmentValid(token string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.enrollmentValidLocked(token)
}

// ConsumeEnrollment validates the token and, if valid, burns it:
// enrollment tokens are single-use, so a token that has registered
// one node can never register another. Reports whether the token
// was valid (and is now consumed).
func (s *MemoryStore) ConsumeEnrollment(token string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.enrollmentValidLocked(token) {
		return false
	}
	s.consumeEnrollmentLocked(token)
	return true
}

func (s *MemoryStore) enrollmentValidLocked(token string) bool {
	if token == "" {
		return false
	}
	h := hashToken(token)
	for stored := range s.enrollHashes {
		if subtle.ConstantTimeCompare([]byte(h), []byte(stored)) == 1 {
			return true
		}
	}
	return false
}

// consumeEnrollmentLocked removes the token's hash and propagates
// the removal to the mirror and the state file. Caller holds the
// lock and has already validated the token.
func (s *MemoryStore) consumeEnrollmentLocked(token string) {
	h := hashToken(token)
	delete(s.enrollHashes, h)
	s.enrollConsumed[h] = true
	s.mirrorEnrollment()
	s.persistLocked()
}

func (s *MemoryStore) enrollmentConsumedListLocked() []string {
	out := make([]string, 0, len(s.enrollConsumed))
	for h := range s.enrollConsumed {
		out = append(out, h)
	}
	sort.Strings(out)
	return out
}

func (s *MemoryStore) enrollmentHashListLocked() []string {
	out := make([]string, 0, len(s.enrollHashes))
	for h := range s.enrollHashes {
		out = append(out, h)
	}
	sort.Strings(out)
	return out
}

// mirrorEnrollment writes the outstanding enrollment hash set to
// Redis as a JSON list, so single-use semantics survive a
// control-plane restart exactly like the registry does.
func (s *MemoryStore) mirrorEnrollment() {
	if s.mirror == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := s.mirror.Set(ctx, "kronos:enrollment", mustJSON(s.enrollmentHashListLocked()), 0).Err(); err != nil {
		log.Printf("store: redis enrollment mirror failed: %v", err)
	}
	if err := s.mirror.Set(ctx, "kronos:enrollment_consumed", mustJSON(s.enrollmentConsumedListLocked()), 0).Err(); err != nil {
		log.Printf("store: redis consumed-enrollment mirror failed: %v", err)
	}
}

func hashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// HashToken is the exported form of hashToken, for callers (startup
// seeding of KRONOS_ENROLLMENT_TOKENS) that need to turn a plaintext
// credential into the hash form the store keeps.
func HashToken(token string) string {
	return hashToken(token)
}

func newNodeToken() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		// crypto/rand failure is catastrophic; fall back to concatenated
		// UUIDs rather than issuing an empty credential.
		return uuid.NewString() + uuid.NewString()
	}
	return hex.EncodeToString(b)
}

func formatPoolIP(offset uint32) string {
	v := ipPoolNetBase + offset
	return fmt.Sprintf("%d.%d.%d.%d", (v>>24)&0xFF, (v>>16)&0xFF, (v>>8)&0xFF, v&0xFF)
}

// NewMemoryStore builds an empty store. If redisAddr is non-empty and
// the server answers a ping within the timeout, writes are mirrored.
func NewMemoryStore(redisAddr string) *MemoryStore {
	s := &MemoryStore{
		byID:         make(map[string]*models.PeerNode),
		byKey:        make(map[string]string),
		usedIPs:      make(map[string]bool),
		nextIP:       ipPoolBase,
		poolLast:     ipPoolLast,
		enrollHashes: make(map[string]bool),
		enrollConsumed: make(map[string]bool),
	}
	if redisAddr != "" {
		client := redis.NewClient(&redis.Options{Addr: redisAddr})
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if err := client.Ping(ctx).Err(); err != nil {
			log.Printf("store: redis at %s unreachable (%v); running memory-only", redisAddr, err)
		} else {
			log.Printf("store: redis mirror connected at %s", redisAddr)
			s.mirror = client
		}
	}
	return s
}

// MirrorEnabled reports whether the write-through Redis mirror
// is live (configured AND reachable at construction). Callers
// use it to fall back to state-file persistence when the mirror
// the operator configured is unavailable.
func (s *MemoryStore) MirrorEnabled() bool {
	return s.mirror != nil
}

// allocateIP assigns a virtual IP. A requested address that is still free
// is honored; otherwise the next free address from the pool cursor is
// used. The cursor only ever moves forward, so allocation always
// terminates: when the pool is exhausted it returns ErrIPPoolExhausted.
// (The previous implementation wrapped around a 249-address pool in an
// unbounded loop while the caller held the store mutex, so 250 colliding
// registrations froze the entire control plane.)
func (s *MemoryStore) allocateIP(requested string) (string, error) {
	if requested != "" && !s.usedIPs[requested] && assignableOffset(requested) {
		s.usedIPs[requested] = true
		return requested, nil
	}
	for s.nextIP <= s.poolLast && s.usedIPs[formatPoolIP(s.nextIP)] {
		s.nextIP++
	}
	if s.nextIP > s.poolLast {
		return "", ErrIPPoolExhausted
	}
	ip := formatPoolIP(s.nextIP)
	s.nextIP++
	s.usedIPs[ip] = true
	return ip, nil
}

// RegisterNode inserts a new node or refreshes an existing one (nodes
// are keyed by public key, so re-registration after a restart keeps
// the same node_id). Caller must not hold the lock.
// RegisterNode registers a node or refreshes an existing registration.
// The second return value is a newly issued node token: non-empty only at
// first registration, or when an admin override rotates the credential.
// Re-registration with an existing public key requires the node's token
// (or an admin override); this stops anyone from hijacking a node's
// endpoint or role by replaying its public key.
func (s *MemoryStore) RegisterNode(req *models.NodeRegisterRequest, now time.Time) (*models.PeerNode, string, error) {
	if err := req.Validate(); err != nil {
		return nil, "", err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if id, ok := s.byKey[req.PublicKey]; ok {
		node := s.byID[id]
		if !req.AdminOverride && !tokenHashMatches(req.AuthToken, node.TokenHash) {
			return nil, "", ErrUnauthorized
		}
		node.NodeName = req.NodeName
		node.Endpoint = req.Endpoint
		if req.AdminOverride {
			// Role changes are operator decisions; a node re-registering
			// with its own token cannot promote itself.
			node.Role = req.Role
		}
		node.NATType = req.NATType
		node.EBPFProbePassed = req.EBPFProbePassed
		node.Online = true
		node.LastSeen = now
		issued := ""
		if req.AdminOverride {
			// Admin re-registration rotates the credential (recovery path
			// for a node that lost its token).
			issued = newNodeToken()
			node.TokenHash = hashToken(issued)
		}
		s.mirrorNode(node)
		s.persistLocked()
		copy := *node
		return &copy, issued, nil
	}
	// Enrollment-authorized first registration: re-check the token
	// under the store lock (the handler checked without consuming).
	// Consumption happens only below, once the registration has
	// actually committed — a failure anywhere before that point
	// (including IP exhaustion) leaves the token valid.
	if req.EnrollmentAuthorized && !s.enrollmentValidLocked(req.AuthToken) {
		return nil, "", ErrUnauthorized
	}
	virtualIP, err := s.allocateIP(req.VirtualIP)
	if err != nil {
		return nil, "", err
	}
	issued := newNodeToken()
	node := &models.PeerNode{
		NodeID:          uuid.NewString(),
		NodeName:        req.NodeName,
		PublicKey:       req.PublicKey,
		Fingerprint:     req.Fingerprint,
		VirtualIP:       virtualIP,
		TokenHash:       hashToken(issued),
		Endpoint:        req.Endpoint,
		Role:            req.Role,
		Online:          true,
		NATType:         req.NATType,
		EBPFProbePassed: req.EBPFProbePassed,
		LastSeen:        now,
	}
	s.byID[node.NodeID] = node
	s.byKey[node.PublicKey] = node.NodeID
	if req.EnrollmentAuthorized {
		// The node is committed: burn the single-use token.
		s.consumeEnrollmentLocked(req.AuthToken)
	}
	s.mirrorNode(node)
	s.persistLocked()
	copy := *node
	return &copy, issued, nil
}

// DeleteNode revokes a node's membership: the registry entry, its
// public-key index and its virtual-IP reservation are removed, and
// the mirror copy is deleted. From this moment the node's token is
// worthless (heartbeats fail as unknown node) and its key, if it
// ever comes back, is a brand-new identity that must be provisioned
// again (admin or enrollment token). Reports whether the node
// existed.
func (s *MemoryStore) DeleteNode(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	node, ok := s.byID[id]
	if !ok {
		return false
	}
	delete(s.byID, id)
	delete(s.byKey, node.PublicKey)
	delete(s.usedIPs, node.VirtualIP)
	if s.mirror != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		if err := s.mirror.Del(ctx, "kronos:node:"+id).Err(); err != nil {
			log.Printf("store: redis mirror delete failed for %s: %v", id, err)
		}
	}
	s.persistLocked()
	return true
}

// KeyExists reports whether a public key is already registered.
func (s *MemoryStore) KeyExists(publicKey string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	_, ok := s.byKey[publicKey]
	return ok
}

func (s *MemoryStore) Heartbeat(nodeID string, hb *models.HeartbeatPayload, token string, now time.Time) (*models.PeerNode, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	node, ok := s.byID[nodeID]
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrUnknownNode, nodeID)
	}
	if !tokenHashMatches(token, node.TokenHash) {
		return nil, ErrUnauthorized
	}
	node.TxBytes = hb.TxBytes
	node.RxBytes = hb.RxBytes
	node.AvgLatencyMs = hb.AvgLatencyMs
	node.EstablishedPeers = append([]string(nil), hb.EstablishedPeers...)
	node.Online = true
	node.LastSeen = now
	s.mirrorNode(node)
	copy := *node
	return &copy, nil
}

func (s *MemoryStore) ListNodes() []models.PeerNode {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]models.PeerNode, 0, len(s.byID))
	for _, n := range s.byID {
		out = append(out, *n)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].VirtualIP < out[j].VirtualIP })
	return out
}

// Topology builds the full render model. Links connect every pair of
// online nodes (the mesh is logically fully connected); a link's
// latency is the mean of both endpoints' reported averages, and its
// encrypted flag reflects heartbeat-reported established sessions.
func (s *MemoryStore) Topology(now time.Time) models.MeshTopology {
	nodes := s.ListNodes()
	links := make([]models.TopologyLink, 0)
	for i := 0; i < len(nodes); i++ {
		for j := i + 1; j < len(nodes); j++ {
			a, b := nodes[i], nodes[j]
			if !a.Online || !b.Online {
				continue
			}
			links = append(links, models.TopologyLink{
				A:         a.VirtualIP,
				B:         b.VirtualIP,
				LatencyMs: (a.AvgLatencyMs + b.AvgLatencyMs) / 2,
				// Truthful encryption state: a link is encrypted only
				// when at least one endpoint's latest heartbeat reports
				// an established session with the other. (Previously this
				// was hard-coded true for every pair.)
				Encrypted: reportsEstablished(a, b.PublicKey) || reportsEstablished(b, a.PublicKey),
			})
		}
	}
	if links == nil {
		links = make([]models.TopologyLink, 0)
	}
	if nodes == nil {
		nodes = make([]models.PeerNode, 0)
	}
	return models.MeshTopology{Nodes: nodes, Links: links, GeneratedAt: now}
}

func reportsEstablished(n models.PeerNode, peerKey string) bool {
	for _, k := range n.EstablishedPeers {
		if k == peerKey {
			return true
		}
	}
	return false
}

func (s *MemoryStore) ListAcls() models.AclPolicyResponse {
	s.mu.RLock()
	defer s.mu.RUnlock()
	rules := make([]models.AclRule, len(s.acls))
	copy(rules, s.acls)
	sort.Slice(rules, func(i, j int) bool { return rules[i].Priority < rules[j].Priority })
	return models.AclPolicyResponse{Version: s.aclVer, Rules: rules}
}

func (s *MemoryStore) CreateAcl(rule models.AclRule) (models.AclRule, error) {
	if err := rule.Validate(); err != nil {
		return models.AclRule{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if rule.ID == "" {
		rule.ID = uuid.NewString()
	}
	for _, existing := range s.acls {
		if existing.ID == rule.ID {
			return models.AclRule{}, fmt.Errorf("acl rule id %s already exists", rule.ID)
		}
	}
	s.acls = append(s.acls, rule)
	s.aclVer++
	s.mirrorAcls()
	s.persistLocked()
	return rule, nil
}

func (s *MemoryStore) DeleteAcl(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, existing := range s.acls {
		if existing.ID == id {
			s.acls = append(s.acls[:i], s.acls[i+1:]...)
			s.aclVer++
			s.mirrorAcls()
			s.persistLocked()
			return true
		}
	}
	return false
}

// ReapStale marks nodes offline when their last heartbeat is older
// than offlineAfter. Returns how many nodes transitioned.
func (s *MemoryStore) ReapStale(now time.Time, offlineAfter time.Duration) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	changed := 0
	for _, node := range s.byID {
		if node.Online && now.Sub(node.LastSeen) > offlineAfter {
			node.Online = false
			changed++
			s.mirrorNode(node)
		}
	}
	return changed
}

func (s *MemoryStore) mirrorNode(node *models.PeerNode) {
	if s.mirror == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	key := "kronos:node:" + node.NodeID
	if err := s.mirror.HSet(ctx, key, nodeToHash(node)).Err(); err != nil {
		log.Printf("store: redis mirror write failed for %s: %v", node.NodeID, err)
	}
}

// nodeToHash serializes a node for the Redis mirror. It carries the
// FULL state recovery needs after a restart — identity, role, the
// credential hash (never the token itself) and telemetry. An earlier
// mirror stored only display fields, which made faithful recovery
// impossible: a rebuilt node could not even authenticate heartbeats.
func nodeToHash(node *models.PeerNode) map[string]interface{} {
	return map[string]interface{}{
		"node_name":         node.NodeName,
		"public_key":        node.PublicKey,
		"fingerprint":       node.Fingerprint,
		"virtual_ip":        node.VirtualIP,
		"endpoint":          node.Endpoint,
		"role":              node.Role,
		"nat_type":          node.NATType,
		"ebpf_probe_passed": node.EBPFProbePassed,
		"online":            node.Online,
		"last_seen":         node.LastSeen.Format(time.RFC3339),
		"token_hash":        node.TokenHash,
		"tx_bytes":          node.TxBytes,
		"rx_bytes":          node.RxBytes,
		"avg_latency_ms":    node.AvgLatencyMs,
		"established_peers": mustJSON(node.EstablishedPeers),
	}
}

// nodeFromHash parses a mirrored node back. Missing fields (mirrors
// written by older versions) degrade to zero values; a node without a
// public key or virtual IP is unusable and reported as an error. A
// node recovered without a token hash cannot heartbeat — it must
// re-register with the admin token, which is the honest failure mode.
func nodeFromHash(nodeID string, f map[string]string) (*models.PeerNode, error) {
	if f["public_key"] == "" || f["virtual_ip"] == "" {
		return nil, fmt.Errorf("mirrored node %s lacks a public key or virtual IP", nodeID)
	}
	node := &models.PeerNode{
		NodeID:          nodeID,
		NodeName:        f["node_name"],
		PublicKey:       f["public_key"],
		Fingerprint:     f["fingerprint"],
		VirtualIP:       f["virtual_ip"],
		Endpoint:        f["endpoint"],
		Role:            f["role"],
		NATType:         f["nat_type"],
		EBPFProbePassed: f["ebpf_probe_passed"] == "true",
		Online:          f["online"] == "true",
		TokenHash:       f["token_hash"],
	}
	if ts, err := time.Parse(time.RFC3339, f["last_seen"]); err == nil {
		node.LastSeen = ts
	}
	node.TxBytes, _ = strconv.ParseUint(f["tx_bytes"], 10, 64)
	node.RxBytes, _ = strconv.ParseUint(f["rx_bytes"], 10, 64)
	node.AvgLatencyMs, _ = strconv.ParseFloat(f["avg_latency_ms"], 64)
	if raw := f["established_peers"]; raw != "" && raw != "null" {
		_ = json.Unmarshal([]byte(raw), &node.EstablishedPeers)
	}
	return node, nil
}

// RecoverFromMirror rebuilds the registry, ACL policy and
// outstanding enrollment set from the Redis mirror after a
// control-plane restart. Recovered nodes come back OFFLINE — the
// mirror proves they existed, not that they are alive; a heartbeat
// (authenticated by the recovered token hash) marks them online
// again. Returns the number of nodes and ACL rules recovered.
// With no mirror configured it is a no-op.
func (s *MemoryStore) RecoverFromMirror() (int, int, error) {
	if s.mirror == nil {
		return 0, 0, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	s.mu.Lock()
	defer s.mu.Unlock()
	keys, err := s.mirror.Keys(ctx, "kronos:node:*").Result()
	if err != nil {
		return 0, 0, fmt.Errorf("listing mirrored nodes: %w", err)
	}
	nodes := 0
	for _, key := range keys {
		fields, err := s.mirror.HGetAll(ctx, key).Result()
		if err != nil || len(fields) == 0 {
			continue
		}
		node, err := nodeFromHash(strings.TrimPrefix(key, "kronos:node:"), fields)
		if err != nil {
			log.Printf("store: skipping unrecoverable mirrored node: %v", err)
			continue
		}
		node.Online = false
		s.byID[node.NodeID] = node
		s.byKey[node.PublicKey] = node.NodeID
		s.usedIPs[node.VirtualIP] = true
		nodes++
	}
	if raw, err := s.mirror.Get(ctx, "kronos:enrollment_consumed").Result(); err == nil && raw != "" {
		var consumed []string
		if err := json.Unmarshal([]byte(raw), &consumed); err == nil {
			for _, h := range consumed {
				s.enrollConsumed[h] = true
			}
		}
	}
	if raw, err := s.mirror.Get(ctx, "kronos:enrollment").Result(); err == nil && raw != "" {
		var hashes []string
		if err := json.Unmarshal([]byte(raw), &hashes); err == nil {
			for _, h := range hashes {
				if !s.enrollConsumed[h] {
				s.enrollHashes[h] = true
			}
			}
		} else {
			log.Printf("store: mirrored enrollment set is corrupt and was NOT recovered (outstanding enrollment tokens must be re-minted or re-seeded): %v", err)
		}
	}
	rules := 0
	if raw, err := s.mirror.Get(ctx, "kronos:acls").Result(); err == nil && raw != "" {
		var policy models.AclPolicyResponse
		if err := json.Unmarshal([]byte(raw), &policy); err == nil {
			s.acls = policy.Rules
			s.aclVer = policy.Version
			rules = len(policy.Rules)
		} else {
			// A corrupt ACL blob must not pass silently: the
			// recovered policy stays empty, which the daemons
			// evaluate as default-deny (fail-closed) — safe,
			// but the operator needs to know the policy was
			// lost so they can re-apply it.
			log.Printf("store: mirrored ACL policy is corrupt and was NOT recovered (mesh runs default-deny until it is re-applied): %v", err)
		}
	}
	return nodes, rules, nil
}

func (s *MemoryStore) mirrorAcls() {
	if s.mirror == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	policy := models.AclPolicyResponse{Version: s.aclVer, Rules: s.acls}
	if err := s.mirror.Set(ctx, "kronos:acls", mustJSON(policy), 0).Err(); err != nil {
		log.Printf("store: redis acl mirror failed: %v", err)
	}
}

func mustJSON(v interface{}) string {
	b, err := json.Marshal(v)
	if err != nil {
		return "{}"
	}
	return string(b)
}
