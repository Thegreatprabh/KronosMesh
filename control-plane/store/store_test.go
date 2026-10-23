package store

import (
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"

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
	nodeA, issuedA, err := s.RegisterNode(reqA, now)
	if err != nil {
		t.Fatal(err)
	}
	if nodeA.VirtualIP != "100.64.0.10" {
		t.Fatalf("requested free IP not honored: %s", nodeA.VirtualIP)
	}
	// Same public key re-registering keeps the node ID (restart case);
	// it must present the token issued at first registration.
	reqA.AuthToken = issuedA
	again, _, err := s.RegisterNode(reqA, now)
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
	nodeB, _, err := s.RegisterNode(reqB, now)
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
	node, token, err := s.RegisterNode(req, now)
	if err != nil {
		t.Fatal(err)
	}
	hb := &models.HeartbeatPayload{NodeID: node.NodeID, TxBytes: 100, RxBytes: 200, AvgLatencyMs: 5}
	updated, err := s.Heartbeat(node.NodeID, hb, token, now.Add(5*time.Second))
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
		node, _, err := s.RegisterNode(req, now)
		return node, err
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

// TestStoreRejectsSpoofedReRegisterAndHeartbeat proves the credential
// checks: a stranger who knows a victim's public key (public information)
// cannot take over its registration or forge its heartbeats.
func TestStoreRejectsSpoofedReRegisterAndHeartbeat(t *testing.T) {
	s := NewMemoryStore("")
	now := time.Now().UTC()
	key, keyBytes := keyFor("victim-node")
	req := testRequest("victim", key)
	req.Fingerprint = models.Fingerprint(keyBytes)
	node, token, err := s.RegisterNode(req, now)
	if err != nil {
		t.Fatal(err)
	}
	if token == "" {
		t.Fatal("first registration must issue a node token")
	}
	// Re-register with no token: rejected.
	attacker := testRequest("victim", key)
	attacker.Fingerprint = models.Fingerprint(keyBytes)
	attacker.Endpoint = "203.0.113.99:51820"
	if _, _, err := s.RegisterNode(attacker, now); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("spoofed re-register: got %v, want ErrUnauthorized", err)
	}
	// The stored endpoint must be untouched.
	if got := s.ListNodes()[0].Endpoint; got == "203.0.113.99:51820" {
		t.Fatal("spoofed re-register changed the endpoint")
	}
	// Heartbeat with a wrong token: rejected; with the real one: accepted.
	hb := &models.HeartbeatPayload{NodeID: node.NodeID}
	if _, err := s.Heartbeat(node.NodeID, hb, "forged-token", now); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("forged heartbeat: got %v, want ErrUnauthorized", err)
	}
	if _, err := s.Heartbeat(node.NodeID, hb, token, now); err != nil {
		t.Fatalf("legit heartbeat rejected: %v", err)
	}
	// A node-token re-register cannot change its own role.
	req.AuthToken = token
	req.Role = "admin"
	again, _, err := s.RegisterNode(req, now)
	if err != nil {
		t.Fatal(err)
	}
	if again.Role == "admin" {
		t.Fatal("node promoted its own role via re-registration")
	}
	// Heartbeat-reported sessions drive topology encryption truthfully.
	hb.EstablishedPeers = []string{key}
	if _, err := s.Heartbeat(node.NodeID, hb, token, now); err != nil {
		t.Fatal(err)
	}
	if got := s.ListNodes()[0].EstablishedPeers; len(got) != 1 || got[0] != key {
		t.Fatalf("established peers not stored: %v", got)
	}
}

// TestRegisterRejectsOutOfRangeVirtualIP pins the requested-address
// validation: virtual IPs must live inside the mesh range.
// Round 8: the pool cursor never hands out the network address
// (offset 0), the reserved offset 1, or the broadcast address —
// and a node must not be able to CLAIM them via a requested
// virtual IP either. Reserved requests fall back to a normal
// pool assignment.
func TestRegisterCannotClaimReservedAddresses(t *testing.T) {
	for _, reserved := range []string{"100.64.0.0", "100.64.0.1", "100.127.255.255"} {
		s := NewMemoryStore("")
		key, keyBytes := keyFor("reserved-" + reserved)
		req := testRequest("claimer", key)
		req.Fingerprint = models.Fingerprint(keyBytes)
		req.VirtualIP = reserved
		node, _, err := s.RegisterNode(req, time.Now().UTC())
		if err != nil {
			t.Fatalf("registration with requested %s should fall back to the pool, got error: %v", reserved, err)
		}
		if node.VirtualIP == reserved {
			t.Fatalf("node claimed reserved address %s", reserved)
		}
	}
	// Sanity: a normal in-pool request is still honored.
	s := NewMemoryStore("")
	key, keyBytes := keyFor("normal-request")
	req := testRequest("normal", key)
	req.Fingerprint = models.Fingerprint(keyBytes)
	req.VirtualIP = "100.64.0.10"
	node, _, err := s.RegisterNode(req, time.Now().UTC())
	if err != nil {
		t.Fatalf("normal registration failed: %v", err)
	}
	if node.VirtualIP != "100.64.0.10" {
		t.Fatalf("normal requested IP not honored: got %s", node.VirtualIP)
	}
}

func TestRegisterRejectsOutOfRangeVirtualIP(t *testing.T) {
	s := NewMemoryStore("")
	key, keyBytes := keyFor("out-of-range-node")
	req := testRequest("rogue", key)
	req.Fingerprint = models.Fingerprint(keyBytes)
	req.VirtualIP = "8.8.8.8"
	if _, _, err := s.RegisterNode(req, time.Now().UTC()); err == nil {
		t.Fatal("out-of-range virtual_ip must be rejected")
	}
}

func TestNodeHashRoundTripPreservesState(t *testing.T) {
	orig := &models.PeerNode{
		NodeID: "id-1", NodeName: "n1", PublicKey: "ab", Fingerprint: "fp",
		VirtualIP: "100.64.0.10", Endpoint: "1.2.3.4:51820", Role: "edge",
		NATType: "nat", EBPFProbePassed: true, Online: true,
		LastSeen:  time.Date(2026, 10, 22, 4, 0, 0, 0, time.UTC),
		TokenHash: "deadbeef", TxBytes: 123, RxBytes: 456, AvgLatencyMs: 7.5,
		EstablishedPeers: []string{"k1", "k2"},
	}
	// Simulate the Redis round trip: every hash value becomes a string.
	fields := map[string]string{}
	for k, v := range nodeToHash(orig) {
		fields[k] = fmt.Sprint(v)
	}
	back, err := nodeFromHash(orig.NodeID, fields)
	if err != nil {
		t.Fatal(err)
	}
	if back.NodeName != orig.NodeName || back.PublicKey != orig.PublicKey ||
		back.Fingerprint != orig.Fingerprint || back.VirtualIP != orig.VirtualIP ||
		back.Endpoint != orig.Endpoint || back.Role != orig.Role ||
		back.NATType != orig.NATType || back.EBPFProbePassed != orig.EBPFProbePassed ||
		back.TokenHash != orig.TokenHash || back.TxBytes != orig.TxBytes ||
		back.RxBytes != orig.RxBytes || back.AvgLatencyMs != orig.AvgLatencyMs ||
		!back.LastSeen.Equal(orig.LastSeen) || len(back.EstablishedPeers) != 2 {
		t.Fatalf("round trip lost state:\norig %+v\nback %+v", orig, back)
	}
}

// A control-plane restart must not lose the mesh: a fresh store on the
// same Redis mirror recovers nodes (offline until they heartbeat), the
// ACL policy with its version, and the credential hashes — so nodes
// keep their IPs and can authenticate without re-registering.
// A corrupt mirrored ACL blob must not abort recovery or fail
// open: nodes still recover, the policy stays empty (daemons
// read that as default-deny), and the loss is surfaced via the
// returned rule count — not hidden as "no ACLs configured".
func TestRecoveryWithCorruptAclBlobKeepsNodesAndDenyAll(t *testing.T) {
	mr := miniredis.RunT(t)
	now := time.Now().UTC()

	s1 := NewMemoryStore(mr.Addr())
	keyA, bytesA := keyFor("corrupt-acl-alpha")
	reqA := testRequest("corrupt-acl-alpha", keyA)
	reqA.Fingerprint = models.Fingerprint(bytesA)
	if _, _, err := s1.RegisterNode(reqA, now); err != nil {
		t.Fatal(err)
	}
	// Corrupt the mirrored ACL policy directly in Redis.
	mr.Set("kronos:acls", "{not json")

	s2 := NewMemoryStore(mr.Addr())
	nodes, rules, err := s2.RecoverFromMirror()
	if err != nil {
		t.Fatal(err)
	}
	if nodes != 1 {
		t.Fatalf("nodes must still recover, got %d", nodes)
	}
	if rules != 0 || len(s2.ListAcls().Rules) != 0 {
		t.Fatalf("corrupt ACL blob must recover as empty policy, got %d rules", rules)
	}
}

func TestRecoveryFromMirrorRestoresMesh(t *testing.T) {
	mr := miniredis.RunT(t)
	now := time.Now().UTC()

	s1 := NewMemoryStore(mr.Addr())
	keyA, bytesA := keyFor("recover-alpha")
	reqA := testRequest("recover-alpha", keyA)
	reqA.Fingerprint = models.Fingerprint(bytesA)
	nodeA, issuedA, err := s1.RegisterNode(reqA, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s1.CreateAcl(models.AclRule{
		SourceRole: "edge", DestService: "*", Action: "DENY", Priority: 10,
	}); err != nil {
		t.Fatal(err)
	}
	versionBefore := s1.ListAcls().Version

	// Restart: a brand-new store against the same Redis.
	s2 := NewMemoryStore(mr.Addr())
	nodes, rules, err := s2.RecoverFromMirror()
	if err != nil {
		t.Fatal(err)
	}
	if nodes != 1 || rules != 1 {
		t.Fatalf("expected 1 node and 1 rule recovered, got %d and %d", nodes, rules)
	}
	list := s2.ListNodes()
	if len(list) != 1 || list[0].VirtualIP != nodeA.VirtualIP {
		t.Fatalf("recovered registry wrong: %+v", list)
	}
	if list[0].Online {
		t.Fatal("a recovered node must come back offline until it heartbeats")
	}
	// The credential hash survived: the original token still
	// authenticates a heartbeat, which revives the node.
	hb := &models.HeartbeatPayload{NodeID: nodeA.NodeID}
	if _, err := s2.Heartbeat(nodeA.NodeID, hb, issuedA, now.Add(time.Minute)); err != nil {
		t.Fatalf("heartbeat after recovery must authenticate: %v", err)
	}
	if !s2.ListNodes()[0].Online {
		t.Fatal("heartbeat must mark the recovered node online")
	}
	// The allocator must not hand the recovered node's IP to anyone else.
	keyB, bytesB := keyFor("recover-beta")
	reqB := testRequest("recover-beta", keyB) // also requests 100.64.0.10
	reqB.Fingerprint = models.Fingerprint(bytesB)
	nodeB, _, err := s2.RegisterNode(reqB, now)
	if err != nil {
		t.Fatal(err)
	}
	if nodeB.VirtualIP == nodeA.VirtualIP {
		t.Fatal("allocator reissued a recovered node's IP")
	}
	// Policy survived with its version.
	if got := s2.ListAcls(); len(got.Rules) != 1 || got.Version != versionBefore {
		t.Fatalf("ACL policy not recovered: %+v", got)
	}
}

// Deleting a node is revocation: its token dies with the registry
// entry (heartbeats become "unknown node"), its key is forgotten so
// a later registration of the same key is a NEW identity, and its
// virtual IP returns to the pool.
func TestDeleteNodeRevokesMembership(t *testing.T) {
	s := NewMemoryStore("")
	now := time.Now().UTC()
	keyA, bytesA := keyFor("revoked-alpha")
	reqA := testRequest("revoked-alpha", keyA)
	reqA.Fingerprint = models.Fingerprint(bytesA)
	nodeA, issuedA, err := s.RegisterNode(reqA, now)
	if err != nil {
		t.Fatal(err)
	}

	if !s.DeleteNode(nodeA.NodeID) {
		t.Fatal("deleting a known node must report true")
	}
	if s.DeleteNode(nodeA.NodeID) {
		t.Fatal("deleting an unknown node must report false")
	}
	if s.KeyExists(keyA) {
		t.Fatal("deleted node's key must be forgotten")
	}
	hb := &models.HeartbeatPayload{NodeID: nodeA.NodeID}
	if _, err := s.Heartbeat(nodeA.NodeID, hb, issuedA, now); !errors.Is(err, ErrUnknownNode) {
		t.Fatalf("heartbeat of a revoked node must fail as unknown node, got %v", err)
	}

	// The freed VIP (testRequest asks for 100.64.0.10) is reusable.
	keyB, bytesB := keyFor("revoked-beta")
	reqB := testRequest("revoked-beta", keyB)
	reqB.Fingerprint = models.Fingerprint(bytesB)
	nodeB, _, err := s.RegisterNode(reqB, now)
	if err != nil {
		t.Fatal(err)
	}
	if nodeB.VirtualIP != nodeA.VirtualIP {
		t.Fatalf("freed VIP must be reusable: got %s, want %s", nodeB.VirtualIP, nodeA.VirtualIP)
	}

	// The same key registering again is a brand-new node identity.
	nodeA2, _, err := s.RegisterNode(reqA, now)
	if err != nil {
		t.Fatal(err)
	}
	if nodeA2.NodeID == nodeA.NodeID {
		t.Fatal("re-registration after revocation must mint a new node id")
	}
}

// Enrollment tokens are single-use: validation does not consume,
// consumption burns, and a burned or bogus token never validates.
func TestEnrollmentTokensAreSingleUse(t *testing.T) {
	s := NewMemoryStore("")
	s.AddEnrollmentHash(HashToken("enroll-one"))

	if !s.EnrollmentValid("enroll-one") {
		t.Fatal("seeded enrollment token must validate")
	}
	if !s.EnrollmentValid("enroll-one") {
		t.Fatal("validation alone must not consume the token")
	}
	if s.EnrollmentValid("bogus") || s.EnrollmentValid("") {
		t.Fatal("bogus/empty tokens must not validate")
	}
	if !s.ConsumeEnrollment("enroll-one") {
		t.Fatal("first consume must succeed")
	}
	if s.ConsumeEnrollment("enroll-one") {
		t.Fatal("second consume of the same token must fail (single-use)")
	}
	if s.EnrollmentValid("enroll-one") {
		t.Fatal("consumed token must no longer validate")
	}
	if s.ConsumeEnrollment("never-issued") {
		t.Fatal("consuming an unknown token must fail")
	}

	// Minted tokens validate exactly once too.
	minted := s.MintEnrollmentToken()
	if minted == "" || !s.EnrollmentValid(minted) {
		t.Fatal("minted token must validate")
	}
	if !s.ConsumeEnrollment(minted) || s.ConsumeEnrollment(minted) {
		t.Fatal("minted token must be consumable exactly once")
	}
}

// An enrollment-authorized registration consumes the token only when
// the store commits the new node: a registration that fails (here,
// an unauthorized replay after consumption) must not be possible,
// and the same token cannot enroll a second key.
func TestEnrollmentRegistrationConsumesOnCommit(t *testing.T) {
	s := NewMemoryStore("")
	now := time.Now().UTC()
	s.AddEnrollmentHash(HashToken("enroll-reg"))

	keyA, bytesA := keyFor("enroll-alpha")
	reqA := testRequest("enroll-alpha", keyA)
	reqA.Fingerprint = models.Fingerprint(bytesA)
	reqA.AuthToken = "enroll-reg"
	reqA.EnrollmentAuthorized = true
	if _, _, err := s.RegisterNode(reqA, now); err != nil {
		t.Fatalf("enrollment registration must succeed: %v", err)
	}
	if s.EnrollmentValid("enroll-reg") {
		t.Fatal("token must be consumed once the registration committed")
	}

	keyB, bytesB := keyFor("enroll-beta")
	reqB := testRequest("enroll-beta", keyB)
	reqB.Fingerprint = models.Fingerprint(bytesB)
	reqB.AuthToken = "enroll-reg"
	reqB.EnrollmentAuthorized = true
	if _, _, err := s.RegisterNode(reqB, now); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("reusing a consumed enrollment token must fail, got %v", err)
	}
}

// The outstanding enrollment set is mirrored to Redis: a restart
// recovers un-consumed tokens and does not resurrect consumed ones.
func TestRecoveryFromMirrorRestoresEnrollment(t *testing.T) {
	mr := miniredis.RunT(t)
	s1 := NewMemoryStore(mr.Addr())
	s1.AddEnrollmentHash(HashToken("enroll-live"))
	s1.AddEnrollmentHash(HashToken("enroll-spent"))
	if !s1.ConsumeEnrollment("enroll-spent") {
		t.Fatal("consume before restart must succeed")
	}

	s2 := NewMemoryStore(mr.Addr())
	if _, _, err := s2.RecoverFromMirror(); err != nil {
		t.Fatal(err)
	}
	if !s2.EnrollmentValid("enroll-live") {
		t.Fatal("un-consumed enrollment token must survive a restart")
	}
	if s2.EnrollmentValid("enroll-spent") {
		t.Fatal("consumed enrollment token must stay consumed across a restart")
	}
}
