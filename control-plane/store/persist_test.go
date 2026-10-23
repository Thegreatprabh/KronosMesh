package store

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Thegreatprabh/KronosMesh/control-plane/models"
)

// Restart recovery without Redis: a fresh store pointed at the same
// state file restores the registry (nodes OFFLINE, credential hashes
// intact — a heartbeat with the ORIGINAL node token revives the
// node), the ACL policy with its version, and the outstanding
// enrollment set with consumed tokens staying consumed.
func TestFilePersistenceRestartRecovery(t *testing.T) {
	path := filepath.Join(t.TempDir(), "kronos-state.json")
	now := time.Now().UTC()

	a := NewMemoryStore("")
	a.EnableFilePersistence(path)
	keyA, bytesA := keyFor("persist-alpha")
	reqA := testRequest("persist-alpha", keyA)
	reqA.Fingerprint = models.Fingerprint(bytesA)
	nodeA, issuedA, err := a.RegisterNode(reqA, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.CreateAcl(models.AclRule{
		SourceRole: "edge", DestService: "postgres", Port: 5432, Action: "ALLOW", Priority: 5,
	}); err != nil {
		t.Fatal(err)
	}
	versionBefore := a.ListAcls().Version
	a.AddEnrollmentHash(HashToken("persist-enroll"))
	a.AddEnrollmentHash(HashToken("persist-spent"))
	if !a.ConsumeEnrollment("persist-spent") {
		t.Fatal("consume before restart must succeed")
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("state file must exist after structural mutations: %v", err)
	}

	// Restart: a brand-new store on the same file.
	b := NewMemoryStore("")
	b.EnableFilePersistence(path)
	nodes, rules, enroll, err := b.RestoreFromFile()
	if err != nil {
		t.Fatal(err)
	}
	if nodes != 1 || rules != 1 || enroll != 1 {
		t.Fatalf("expected 1 node, 1 rule, 1 enrollment hash restored, got %d/%d/%d", nodes, rules, enroll)
	}
	list := b.ListNodes()
	if len(list) != 1 || list[0].NodeID != nodeA.NodeID || list[0].VirtualIP != nodeA.VirtualIP {
		t.Fatalf("restored registry wrong: %+v", list)
	}
	if list[0].Online {
		t.Fatal("a restored node must come back offline until it heartbeats")
	}
	hb := &models.HeartbeatPayload{NodeID: nodeA.NodeID}
	if _, err := b.Heartbeat(nodeA.NodeID, hb, issuedA, now.Add(time.Minute)); err != nil {
		t.Fatalf("heartbeat with the original node token must revive the node: %v", err)
	}
	if !b.ListNodes()[0].Online {
		t.Fatal("node must be online after its post-recovery heartbeat")
	}
	if got := b.ListAcls(); len(got.Rules) != 1 || got.Version != versionBefore {
		t.Fatalf("ACL policy not restored with its version: %+v", got)
	}
	// The outstanding enrollment token is consumable exactly once;
	// the one burned before the restart stays burned.
	if !b.ConsumeEnrollment("persist-enroll") {
		t.Fatal("restored enrollment token must be consumable")
	}
	if b.ConsumeEnrollment("persist-enroll") {
		t.Fatal("restored enrollment token must still be single-use")
	}
	if b.EnrollmentValid("persist-spent") {
		t.Fatal("a token consumed before the restart must not be resurrected")
	}

	// Revocation persists too: after B deletes the node, a third
	// store on the same file must not bring it back.
	if !b.DeleteNode(nodeA.NodeID) {
		t.Fatal("delete on the restored store must succeed")
	}
	c := NewMemoryStore("")
	c.EnableFilePersistence(path)
	nodes, _, _, err = c.RestoreFromFile()
	if err != nil {
		t.Fatal(err)
	}
	if nodes != 0 || c.KeyExists(keyA) {
		t.Fatal("a revoked node must not reappear after another restart")
	}
	if _, err := c.Heartbeat(nodeA.NodeID, hb, issuedA, now); !errors.Is(err, ErrUnknownNode) {
		t.Fatalf("revoked node heartbeat must stay unknown after restart, got %v", err)
	}
}

// A missing state file is a clean first boot; a corrupt one is an
// error the caller logs while starting empty — never a crash and
// never a half-restored registry.
func TestRestoreFromFileMissingAndCorrupt(t *testing.T) {
	dir := t.TempDir()

	s := NewMemoryStore("")
	s.EnableFilePersistence(filepath.Join(dir, "absent.json"))
	nodes, rules, enroll, err := s.RestoreFromFile()
	if err != nil {
		t.Fatalf("missing state file must not be an error: %v", err)
	}
	if nodes != 0 || rules != 0 || enroll != 0 {
		t.Fatalf("missing state file must restore nothing, got %d/%d/%d", nodes, rules, enroll)
	}

	bad := filepath.Join(dir, "corrupt.json")
	if err := os.WriteFile(bad, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	s2 := NewMemoryStore("")
	s2.EnableFilePersistence(bad)
	if _, _, _, err := s2.RestoreFromFile(); err == nil {
		t.Fatal("corrupt state file must return an error")
	}
	if len(s2.ListNodes()) != 0 {
		t.Fatal("corrupt state file must leave the store empty")
	}
}

// A consumed enrollment token must stay consumed across a
// restart AND across startup re-seeding: single-use is the whole
// point. Regression test for the resurrection flaw where main.go
// re-seeded KRONOS_ENROLLMENT_TOKENS on every boot.
func TestConsumedEnrollmentStaysConsumedAcrossRestartAndReseed(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")

	a := NewMemoryStore("")
	a.EnableFilePersistence(path)
	tok := a.MintEnrollmentToken()
	if !a.ConsumeEnrollment(tok) {
		t.Fatal("first consume must succeed")
	}
	// Same-process reseed attempt (what main.go does at boot).
	a.AddEnrollmentHash(HashToken(tok))
	if a.EnrollmentValid(tok) {
		t.Fatal("consumed token resurrected by re-seeding in the same process")
	}
	// Restart: fresh store, restore, reseed again.
	b := NewMemoryStore("")
	b.EnableFilePersistence(path)
	if _, _, _, err := b.RestoreFromFile(); err != nil {
		t.Fatalf("restore: %v", err)
	}
	b.AddEnrollmentHash(HashToken(tok))
	if b.EnrollmentValid(tok) {
		t.Fatal("consumed token resurrected after restart + reseed")
	}
	if b.ConsumeEnrollment(tok) {
		t.Fatal("consumed token must never validate again")
	}
	// A DIFFERENT token still seeds and works (denylist is precise).
	fresh := "fresh-token-never-used"
	b.AddEnrollmentHash(HashToken(fresh))
	if !b.EnrollmentValid(fresh) {
		t.Fatal("unrelated token must seed normally")
	}
}
