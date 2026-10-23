package store

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"sort"
	"time"

	"github.com/Thegreatprabh/KronosMesh/control-plane/models"
)

// File persistence: when no Redis mirror is configured, the store
// can snapshot its full structural state to a JSON file so a
// control-plane restart recovers the mesh exactly like the Redis
// path does. The snapshot is rewritten atomically (temp file +
// fsync + rename) after every structural mutation — node register
// or delete, ACL create or delete, enrollment add or consume —
// and deliberately NOT on heartbeats, whose telemetry churn would
// rewrite the file several times a second for no recovery benefit
// (recovery only needs the registry: a node's first heartbeat
// after recovery authenticates against the restored token hash).

// snapshotNode is the on-disk form of a registry entry: every field
// nodeFromHash restores for the Redis mirror, in typed form.
type snapshotNode struct {
	NodeID           string    `json:"node_id"`
	NodeName         string    `json:"node_name"`
	PublicKey        string    `json:"public_key"`
	Fingerprint      string    `json:"fingerprint"`
	VirtualIP        string    `json:"virtual_ip"`
	Endpoint         string    `json:"endpoint"`
	Role             string    `json:"role"`
	NATType          string    `json:"nat_type"`
	EBPFProbePassed  bool      `json:"ebpf_probe_passed"`
	LastSeen         time.Time `json:"last_seen"`
	TokenHash        string    `json:"token_hash"`
	TxBytes          uint64    `json:"tx_bytes"`
	RxBytes          uint64    `json:"rx_bytes"`
	AvgLatencyMs     float64   `json:"avg_latency_ms"`
	EstablishedPeers []string  `json:"established_peers,omitempty"`
}

// snapshot is the full persisted state document.
type snapshot struct {
	Nodes            []snapshotNode   `json:"nodes"`
	AclVersion       uint64           `json:"acl_version"`
	AclRules         []models.AclRule `json:"acl_rules"`
	EnrollmentHashes []string         `json:"enrollment_hashes"`
	EnrollmentConsumedHashes []string `json:"enrollment_consumed_hashes,omitempty"`
}

// EnableFilePersistence turns on state-file snapshots at path. It
// is the no-Redis persistence mode; main wires it only when
// REDIS_ADDR is unset, keeping the Redis behaviour untouched.
func (s *MemoryStore) EnableFilePersistence(path string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.stateFile = path
}

// snapshotLocked serializes the structural state. Caller holds the lock.
func (s *MemoryStore) snapshotLocked() ([]byte, error) {
	snap := snapshot{
		AclVersion:       s.aclVer,
		AclRules:         append([]models.AclRule(nil), s.acls...),
		EnrollmentHashes: s.enrollmentHashListLocked(),
		EnrollmentConsumedHashes: s.enrollmentConsumedListLocked(),
	}
	nodes := make([]*models.PeerNode, 0, len(s.byID))
	for _, n := range s.byID {
		nodes = append(nodes, n)
	}
	sort.Slice(nodes, func(i, j int) bool { return nodes[i].VirtualIP < nodes[j].VirtualIP })
	for _, n := range nodes {
		snap.Nodes = append(snap.Nodes, snapshotNode{
			NodeID:           n.NodeID,
			NodeName:         n.NodeName,
			PublicKey:        n.PublicKey,
			Fingerprint:      n.Fingerprint,
			VirtualIP:        n.VirtualIP,
			Endpoint:         n.Endpoint,
			Role:             n.Role,
			NATType:          n.NATType,
			EBPFProbePassed:  n.EBPFProbePassed,
			LastSeen:         n.LastSeen,
			TokenHash:        n.TokenHash,
			TxBytes:          n.TxBytes,
			RxBytes:          n.RxBytes,
			AvgLatencyMs:     n.AvgLatencyMs,
			EstablishedPeers: append([]string(nil), n.EstablishedPeers...),
		})
	}
	if snap.AclRules == nil {
		snap.AclRules = []models.AclRule{}
	}
	if snap.Nodes == nil {
		snap.Nodes = []snapshotNode{}
	}
	return json.Marshal(snap)
}

// persistLocked writes the snapshot atomically. Caller holds the
// lock (mutations already do, and the mirror writes behave the
// same way). Failures are logged, never fatal: persistence must
// not take the registry down with it.
func (s *MemoryStore) persistLocked() {
	if s.stateFile == "" {
		return
	}
	data, err := s.snapshotLocked()
	if err != nil {
		log.Printf("store: state snapshot failed: %v", err)
		return
	}
	tmp := s.stateFile + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		log.Printf("store: writing state file %s failed: %v", tmp, err)
		return
	}
	if f, err := os.Open(tmp); err == nil {
		_ = f.Sync()
		_ = f.Close()
	}
	if err := os.Rename(tmp, s.stateFile); err != nil {
		log.Printf("store: renaming state file %s -> %s failed: %v", tmp, s.stateFile, err)
	}
}

// RestoreFromFile loads the state file written by persistLocked,
// with the same semantics as RecoverFromMirror: nodes come back
// OFFLINE with their credential hashes intact (a heartbeat revives
// them), the ACL policy and its version return, and outstanding
// enrollment hashes are valid again (consumed ones stay consumed).
// A missing file is a clean first boot, not an error. A corrupt
// file returns an error and leaves the store empty — the caller
// logs it loudly and starts empty rather than crashing.
func (s *MemoryStore) RestoreFromFile() (nodes, rules, enroll int, err error) {
	if s.stateFile == "" {
		return 0, 0, 0, fmt.Errorf("file persistence is not enabled")
	}
	data, err := os.ReadFile(s.stateFile)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, 0, 0, nil
		}
		return 0, 0, 0, fmt.Errorf("reading state file: %w", err)
	}
	var snap snapshot
	if err := json.Unmarshal(data, &snap); err != nil {
		return 0, 0, 0, fmt.Errorf("state file %s is corrupt: %w", s.stateFile, err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, sn := range snap.Nodes {
		if sn.PublicKey == "" || sn.VirtualIP == "" || sn.NodeID == "" {
			log.Printf("store: skipping unrecoverable node in state file (id %q lacks key, IP or id)", sn.NodeID)
			continue
		}
		node := &models.PeerNode{
			NodeID:           sn.NodeID,
			NodeName:         sn.NodeName,
			PublicKey:        sn.PublicKey,
			Fingerprint:      sn.Fingerprint,
			VirtualIP:        sn.VirtualIP,
			Endpoint:         sn.Endpoint,
			Role:             sn.Role,
			NATType:          sn.NATType,
			EBPFProbePassed:  sn.EBPFProbePassed,
			Online:           false,
			LastSeen:         sn.LastSeen,
			TokenHash:        sn.TokenHash,
			TxBytes:          sn.TxBytes,
			RxBytes:          sn.RxBytes,
			AvgLatencyMs:     sn.AvgLatencyMs,
			EstablishedPeers: append([]string(nil), sn.EstablishedPeers...),
		}
		s.byID[node.NodeID] = node
		s.byKey[node.PublicKey] = node.NodeID
		s.usedIPs[node.VirtualIP] = true
		nodes++
	}
	s.acls = append([]models.AclRule(nil), snap.AclRules...)
	s.aclVer = snap.AclVersion
	rules = len(s.acls)
	for _, h := range snap.EnrollmentConsumedHashes {
		s.enrollConsumed[h] = true
	}
	for _, h := range snap.EnrollmentHashes {
		if s.enrollConsumed[h] {
			continue
		}
		s.enrollHashes[h] = true
		enroll++
	}
	return nodes, rules, enroll, nil
}
