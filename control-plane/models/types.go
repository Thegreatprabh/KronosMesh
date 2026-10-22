// Package models holds the shared wire contracts for KronosMesh. The
// JSON tags here must match the Rust daemon's serde structs and the
// dashboard's TypeScript interfaces field-for-field (snake_case). The
// fixtures under contracts/ at the repo root pin these shapes in both
// the Rust and Go test suites.
package models

import (
	"encoding/hex"
	"fmt"
	"time"

	"golang.org/x/crypto/blake2b"
)

// Fingerprint returns the BLAKE2b-256 hex digest of a node's X25519
// public key — the same value the Rust daemon computes with the blake2
// crate (cross-checked against shared reference vectors in the tests).
func Fingerprint(publicKey []byte) string {
	sum := blake2b.Sum256(publicKey)
	return hex.EncodeToString(sum[:])
}

// PeerNode is one mesh member as known by the control plane.
type PeerNode struct {
	NodeID       string    `json:"node_id"`
	NodeName     string    `json:"node_name"`
	PublicKey    string    `json:"public_key"`
	Fingerprint  string    `json:"fingerprint"`
	VirtualIP    string    `json:"virtual_ip"`
	Endpoint     string    `json:"endpoint"`
	Role         string    `json:"role"`
	Online       bool      `json:"online"`
	NATType      string    `json:"nat_type"`
	EBPFEnabled  bool      `json:"ebpf_enabled"`
	LastSeen     time.Time `json:"last_seen"`
	TxBytes      uint64    `json:"tx_bytes"`
	RxBytes      uint64    `json:"rx_bytes"`
	AvgLatencyMs float64   `json:"avg_latency_ms"`
}

// NodeRegisterRequest is sent by a daemon when it joins the mesh.
type NodeRegisterRequest struct {
	NodeName    string `json:"node_name"`
	PublicKey   string `json:"public_key"`
	Fingerprint string `json:"fingerprint"`
	VirtualIP   string `json:"virtual_ip"`
	Endpoint    string `json:"endpoint"`
	Role        string `json:"role"`
	NATType     string `json:"nat_type"`
	EBPFEnabled bool   `json:"ebpf_enabled"`
	Version     string `json:"version"`
}

// Validate checks structural requirements and that the fingerprint
// actually belongs to the presented public key (a node cannot claim
// another node's identity fingerprint at registration time).
func (r *NodeRegisterRequest) Validate() error {
	if r.NodeName == "" {
		return fmt.Errorf("node_name is required")
	}
	keyBytes, err := hex.DecodeString(r.PublicKey)
	if err != nil || len(keyBytes) != 32 {
		return fmt.Errorf("public_key must be 64 hex characters (32 bytes)")
	}
	if Fingerprint(keyBytes) != r.Fingerprint {
		return fmt.Errorf("fingerprint does not match public_key")
	}
	if r.VirtualIP == "" {
		return fmt.Errorf("virtual_ip is required")
	}
	if r.Endpoint == "" {
		return fmt.Errorf("endpoint is required")
	}
	if r.Role == "" {
		return fmt.Errorf("role is required")
	}
	return nil
}

// NodeRegisterResponse tells the daemon its assigned identity and the
// current peer list.
type NodeRegisterResponse struct {
	NodeID            string     `json:"node_id"`
	AssignedVirtualIP string     `json:"assigned_virtual_ip"`
	Peers             []PeerNode `json:"peers"`
}

// HeartbeatPayload is the daemon's periodic telemetry report.
type HeartbeatPayload struct {
	NodeID         string  `json:"node_id"`
	TxBytes        uint64  `json:"tx_bytes"`
	RxBytes        uint64  `json:"rx_bytes"`
	PacketsTx      uint64  `json:"packets_tx"`
	PacketsRx      uint64  `json:"packets_rx"`
	PeersConnected uint32  `json:"peers_connected"`
	AvgLatencyMs   float64 `json:"avg_latency_ms"`
	UptimeSecs     uint64  `json:"uptime_secs"`
}

// HeartbeatResponse acknowledges the heartbeat and returns the fresh
// peer list so daemons can converge their peer tables.
type HeartbeatResponse struct {
	Acknowledged bool       `json:"acknowledged"`
	Peers        []PeerNode `json:"peers"`
}

// AclRule is one zero-trust policy rule: a source role may (or may not)
// reach a destination service on a port. Port 0 is the wildcard ("any
// port"); dest_service "*" matches any service. The Rust data plane
// enforces mesh-data rules (service "*" or "mesh-data", port 0) in the
// tunnel itself.
type AclRule struct {
	ID          string `json:"id"`
	SourceRole  string `json:"source_role"`
	DestService string `json:"dest_service"`
	Port        uint16 `json:"port"`
	Action      string `json:"action"` // ALLOW | DENY
	Priority    int32  `json:"priority"`
}

// Validate checks the rule's shape.
func (r *AclRule) Validate() error {
	if r.SourceRole == "" {
		return fmt.Errorf("source_role is required")
	}
	if r.DestService == "" {
		return fmt.Errorf("dest_service is required")
	}
	if r.Action != "ALLOW" && r.Action != "DENY" {
		return fmt.Errorf("action must be ALLOW or DENY")
	}
	return nil
}

// AclPolicyResponse is the full policy with its version counter.
type AclPolicyResponse struct {
	Version uint64    `json:"version"`
	Rules   []AclRule `json:"rules"`
}

// TopologyLink is one encrypted adjacency in the mesh graph. A and B
// are virtual IPs so the dashboard can render without a lookup.
type TopologyLink struct {
	A         string  `json:"a"`
	B         string  `json:"b"`
	LatencyMs float64 `json:"latency_ms"`
	Encrypted bool    `json:"encrypted"`
}

// MeshTopology is the dashboard's render model.
type MeshTopology struct {
	Nodes       []PeerNode     `json:"nodes"`
	Links       []TopologyLink `json:"links"`
	GeneratedAt time.Time      `json:"generated_at"`
}
