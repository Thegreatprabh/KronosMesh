// Package store implements the control plane's state store: a
// thread-safe in-memory store that is authoritative for reads, with an
// optional Redis write-through mirror. The control plane works fully
// out of the box with no Redis running; when REDIS_ADDR points at a
// reachable server, node and policy writes are mirrored there for
// external tooling and inspection.
package store

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"sort"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"

	"github.com/Thegreatprabh/KronosMesh/control-plane/models"
)

// Store is the state contract the API layer depends on.
type Store interface {
	RegisterNode(req *models.NodeRegisterRequest, now time.Time) (*models.PeerNode, error)
	Heartbeat(nodeID string, hb *models.HeartbeatPayload, now time.Time) (*models.PeerNode, error)
	ListNodes() []models.PeerNode
	Topology(now time.Time) models.MeshTopology
	ListAcls() models.AclPolicyResponse
	CreateAcl(rule models.AclRule) (models.AclRule, error)
	DeleteAcl(id string) bool
	ReapStale(now time.Time, offlineAfter time.Duration) int
}

// MemoryStore is the authoritative in-memory implementation.
type MemoryStore struct {
	mu      sync.RWMutex
	byID    map[string]*models.PeerNode
	byKey   map[string]string // public key -> node id
	usedIPs map[string]bool
	nextIP  uint32 // next candidate host part inside 100.64.0.0/10
	acls    []models.AclRule
	aclVer  uint64
	mirror  *redis.Client // optional write-through mirror, may be nil
}

const ipPoolBase = 2 // first assignable: 100.64.0.2

// NewMemoryStore builds an empty store. If redisAddr is non-empty and
// the server answers a ping within the timeout, writes are mirrored.
func NewMemoryStore(redisAddr string) *MemoryStore {
	s := &MemoryStore{
		byID:    make(map[string]*models.PeerNode),
		byKey:   make(map[string]string),
		usedIPs: make(map[string]bool),
		nextIP:  ipPoolBase,
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

func (s *MemoryStore) allocateIP(requested string) string {
	if requested != "" && !s.usedIPs[requested] {
		s.usedIPs[requested] = true
		return requested
	}
	for {
		candidate := fmt.Sprintf("100.64.0.%d", s.nextIP)
		s.nextIP++
		if s.nextIP > 250 {
			s.nextIP = ipPoolBase
		}
		if !s.usedIPs[candidate] {
			s.usedIPs[candidate] = true
			return candidate
		}
	}
}

// RegisterNode inserts a new node or refreshes an existing one (nodes
// are keyed by public key, so re-registration after a restart keeps
// the same node_id). Caller must not hold the lock.
func (s *MemoryStore) RegisterNode(req *models.NodeRegisterRequest, now time.Time) (*models.PeerNode, error) {
	if err := req.Validate(); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if id, ok := s.byKey[req.PublicKey]; ok {
		node := s.byID[id]
		node.NodeName = req.NodeName
		node.Endpoint = req.Endpoint
		node.Role = req.Role
		node.NATType = req.NATType
		node.EBPFEnabled = req.EBPFEnabled
		node.Online = true
		node.LastSeen = now
		s.mirrorNode(node)
		copy := *node
		return &copy, nil
	}
	node := &models.PeerNode{
		NodeID:      uuid.NewString(),
		NodeName:    req.NodeName,
		PublicKey:   req.PublicKey,
		Fingerprint: req.Fingerprint,
		VirtualIP:   s.allocateIP(req.VirtualIP),
		Endpoint:    req.Endpoint,
		Role:        req.Role,
		Online:      true,
		NATType:     req.NATType,
		EBPFEnabled: req.EBPFEnabled,
		LastSeen:    now,
	}
	s.byID[node.NodeID] = node
	s.byKey[node.PublicKey] = node.NodeID
	s.mirrorNode(node)
	copy := *node
	return &copy, nil
}

func (s *MemoryStore) Heartbeat(nodeID string, hb *models.HeartbeatPayload, now time.Time) (*models.PeerNode, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	node, ok := s.byID[nodeID]
	if !ok {
		return nil, fmt.Errorf("unknown node_id %s", nodeID)
	}
	node.TxBytes = hb.TxBytes
	node.RxBytes = hb.RxBytes
	node.AvgLatencyMs = hb.AvgLatencyMs
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
// latency is the mean of both endpoints' reported averages.
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
				Encrypted: true,
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
	err := s.mirror.HSet(ctx, key,
		"node_name", node.NodeName,
		"public_key", node.PublicKey,
		"virtual_ip", node.VirtualIP,
		"endpoint", node.Endpoint,
		"online", node.Online,
		"last_seen", node.LastSeen.Format(time.RFC3339),
	).Err()
	if err != nil {
		log.Printf("store: redis mirror write failed for %s: %v", node.NodeID, err)
	}
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
