package store

import (
	"errors"
	"testing"
	"time"

	"github.com/Thegreatprabh/KronosMesh/control-plane/models"
)

func testRequest(name, keyHex string) *models.NodeRegisterRequest {
	keyBytes := make([]byte, 32)
	for i := range keyBytes {
		keyBytes[i] = byte(len(name) + i)
	}
	return &models.NodeRegisterRequest{
		NodeName:    name,
		PublicKey:   keyHex,
		Fingerprint: models.Fingerprint(keyBytes),
		VirtualIP:   "100.64.0.10",
		Endpoint:    "203.0.113.10:51820",
		Role:        "node",
		NATType:     "nat",
		Version:     "1.0.0",
	}
}

func hexOf(b []byte) string {
	const digits = "0123456789abcdef"
	out := make([]byte, 0, len(b)*2)
	for _, v := range b {
		out = append(out, digits[v>>4], digits[v&0xf])
	}
	return string(out)
}

func keyFor(name string) (string, []byte) {
	keyBytes := make([]byte, 32)
	for i := range keyBytes {
		keyBytes[i] = byte(len(name)*7 + i)
	}
	return hexOf(keyBytes), keyBytes
}

func TestRegisterAssignsAndDeduplicates(t *testing.T) {
	s := NewMemoryStore("")
	now := time.Now().UTC()
	keyA, bytesA := keyFor("alpha")
	reqA := testRequest("alpha", keyA)
	reqA.Fingerprint = models.Fingerprint(bytesA)
	nodeA, err := s.RegisterNode(reqA, now)
	if err != nil {
		t.Fatal(err)
	}
	if nodeA.VirtualIP != "100.64.0.10" {
		t.Fatalf("requested free IP not honored: %s", nodeA.VirtualIP)
	}
	// Same public key re-registering keeps the node ID (restart case).
	again, err := s.RegisterNode(reqA, now)
	if err != nil {
		t.Fatal(err)
	}
	if again.NodeID != nodeA.NodeID {
		t.Fatal("re-registration must keep the node id")
	}
	// A second node asking for the same IP gets a different one.
	keyB, bytesB := keyFor("beta-node")
	reqB := testRequest("beta", keyB)
	reqB.Fingerprint = models.Fingerprint(bytesB)
	nodeB, err := s.RegisterNode(reqB, now)
	if err != nil {
		t.Fatal(err)
	}
	if nodeB.VirtualIP == nodeA.VirtualIP {
		t.Fatal("IP collision between two nodes")
	}
	if got := len(s.ListNodes()); got != 2 {
		t.Fatalf("expected 2 nodes, got %d", got)
	}
}

func TestHeartbeatAndReaper(t *testing.T) {
	s := NewMemoryStore("")
	now := time.Now().UTC()
	key, keyBytes := keyFor("gamma")
	req := testRequest("gamma", key)
	req.Fingerprint = models.Fingerprint(keyBytes)
	node, err := s.RegisterNode(req, now)
	if err != nil {
		t.Fatal(err)
	}
	hb := &models.HeartbeatPayload{NodeID: node.NodeID, TxBytes: 100, RxBytes: 200, AvgLatencyMs: 5}
	updated, err := s.Heartbeat(node.NodeID, hb, now.Add(5*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if updated.TxBytes != 100 || updated.RxBytes != 200 {
		t.Fatal("heartbeat telemetry not stored")
	}
	// No heartbeat for 60s with a 45s threshold -> reaped offline.
	if n := s.ReapStale(now.Add(60*time.Second), 45*time.Second); n != 1 {
		t.Fatalf("expected 1 reaped node, got %d", n)
	}
	nodes := s.ListNodes()
	if nodes[0].Online {
		t.Fatal("stale node still online after reap")
	}
	topo := s.Topology(now)
	if len(topo.Links) != 0 {
		t.Fatal("offline nodes must not appear in links")
	}
}

func TestAclLifecycleBumpsVersion(t *testing.T) {
	s := NewMemoryStore("")
	if v := s.ListAcls().Version; v != 0 {
		t.Fatalf("fresh policy version = %d, want 0", v)
	}
	rule, err := s.CreateAcl(models.AclRule{
		SourceRole: "admin", DestService: "ssh", Port: 22, Action: "ALLOW", Priority: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	if rule.ID == "" {
		t.Fatal("created rule must get an id")
	}
	if v := s.ListAcls().Version; v != 1 {
		t.Fatalf("version after create = %d, want 1", v)
	}
	if !s.DeleteAcl(rule.ID) {
		t.Fatal("delete of existing rule failed")
	}
	if v := s.ListAcls().Version; v != 2 {
		t.Fatalf("version after delete = %d, want 2", v)
	}
	if s.DeleteAcl("does-not-exist") {
		t.Fatal("delete of missing rule must return false")
	}
}

// TestAllocatorExhaustionReturnsError proves pool exhaustion surfaces an
// error instead of hanging: all requests ask for the same virtual IP, so
// after the first registration every node falls back to the pool cursor.
// With a two-address pool the fourth registration must fail fast. (The old
// allocator looped forever here while holding the store mutex.)
func TestAllocatorExhaustionReturnsError(t *testing.T) {
	s := NewMemoryStore("")
	s.poolLast = ipPoolBase + 1 // auto-assign range: exactly 2 addresses
	now := time.Now().UTC()

	register := func(name string) (*models.PeerNode, error) {
		key, keyBytes := keyFor(name)
		req := testRequest(name, key)
		req.Fingerprint = models.Fingerprint(keyBytes)
		req.VirtualIP = "100.64.0.10" // same request for every node
		return s.RegisterNode(req, now)
	}

	first, err := register("n1")
	if err != nil {
		t.Fatalf("first register: %v", err)
	}
	if first.VirtualIP != "100.64.0.10" {
		t.Fatalf("first node should keep its requested IP, got %s", first.VirtualIP)
	}
	second, err := register("n22")
	if err != nil {
		t.Fatalf("second register: %v", err)
	}
	if second.VirtualIP != "100.64.0.2" {
		t.Fatalf("second node should get first pool IP, got %s", second.VirtualIP)
	}
	third, err := register("n333")
	if err != nil {
		t.Fatalf("third register: %v", err)
	}
	if third.VirtualIP != "100.64.0.3" {
		t.Fatalf("third node should get second pool IP, got %s", third.VirtualIP)
	}
	if _, err := register("n4444"); !errors.Is(err, ErrIPPoolExhausted) {
		t.Fatalf("fourth register should fail with ErrIPPoolExhausted, got %v", err)
	}
}
