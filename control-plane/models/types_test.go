package models

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

// The fingerprint must match the Rust daemon's blake2 crate output for
// the same key bytes. Vectors computed with Python hashlib.blake2b
// (digest_size=32) and asserted in the Rust test suite as well.
func TestFingerprintMatchesRustReferenceVectors(t *testing.T) {
	zeros := make([]byte, 32)
	if got := Fingerprint(zeros); got != "89eb0d6a8a691dae2cd15ed0369931ce0a949ecafa5c3f93f8121833646e15c3" {
		t.Fatalf("zeros vector mismatch: %s", got)
	}
	seq := make([]byte, 32)
	for i := range seq {
		seq[i] = byte(i)
	}
	if got := Fingerprint(seq); got != "cb2f5160fc1f7e05a55ef49d340b48da2e5a78099d53393351cd579dd42503d6" {
		t.Fatalf("range vector mismatch: %s", got)
	}
}

func fixtureMap(t *testing.T, name string) map[string]interface{} {
	t.Helper()
	path := filepath.Join("..", "..", "contracts", name)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading fixture %s: %v", name, err)
	}
	var m map[string]interface{}
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("fixture %s is not valid JSON: %v", name, err)
	}
	return m
}

func roundTripMap(t *testing.T, v interface{}) map[string]interface{} {
	t.Helper()
	data, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var m map[string]interface{}
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	return m
}

func assertSameShape(t *testing.T, name string, got, want map[string]interface{}) {
	t.Helper()
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("%s shape drift:\n got: %v\nwant: %v", name, got, want)
	}
}

func TestRegisterRequestMatchesFixture(t *testing.T) {
	want := fixtureMap(t, "node_register_request.json")
	var req NodeRegisterRequest
	data, _ := json.Marshal(want)
	if err := json.Unmarshal(data, &req); err != nil {
		t.Fatal(err)
	}
	assertSameShape(t, "node_register_request", roundTripMap(t, req), want)
}

func TestHeartbeatMatchesFixture(t *testing.T) {
	want := fixtureMap(t, "heartbeat_payload.json")
	var hb HeartbeatPayload
	data, _ := json.Marshal(want)
	if err := json.Unmarshal(data, &hb); err != nil {
		t.Fatal(err)
	}
	assertSameShape(t, "heartbeat_payload", roundTripMap(t, hb), want)
}

func TestAclPolicyMatchesFixture(t *testing.T) {
	want := fixtureMap(t, "acl_policy_response.json")
	var pol AclPolicyResponse
	data, _ := json.Marshal(want)
	if err := json.Unmarshal(data, &pol); err != nil {
		t.Fatal(err)
	}
	assertSameShape(t, "acl_policy_response", roundTripMap(t, pol), want)
}

func TestTopologyNodeMatchesFixture(t *testing.T) {
	want := fixtureMap(t, "mesh_topology.json")
	nodes, ok := want["nodes"].([]interface{})
	if !ok || len(nodes) != 1 {
		t.Fatal("fixture topology must contain exactly one node")
	}
	nodeMap, _ := nodes[0].(map[string]interface{})
	var node PeerNode
	data, _ := json.Marshal(nodeMap)
	if err := json.Unmarshal(data, &node); err != nil {
		t.Fatal(err)
	}
	assertSameShape(t, "mesh_topology.nodes[0]", roundTripMap(t, node), nodeMap)
	links, _ := want["links"].([]interface{})
	linkMap, _ := links[0].(map[string]interface{})
	var link TopologyLink
	ldata, _ := json.Marshal(linkMap)
	if err := json.Unmarshal(ldata, &link); err != nil {
		t.Fatal(err)
	}
	assertSameShape(t, "mesh_topology.links[0]", roundTripMap(t, link), linkMap)
}

func TestRegisterValidationRejectsForgedFingerprint(t *testing.T) {
	req := &NodeRegisterRequest{
		NodeName:    "n1",
		PublicKey:   "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
		Fingerprint: "deadbeef",
		VirtualIP:   "100.64.0.10",
		Endpoint:    "203.0.113.10:51820",
		Role:        "node",
	}
	if err := req.Validate(); err == nil {
		t.Fatal("expected validation failure for forged fingerprint")
	}
}

func TestAclValidation(t *testing.T) {
	bad := AclRule{SourceRole: "admin", DestService: "ssh", Port: 22, Action: "MAYBE"}
	if err := bad.Validate(); err == nil {
		t.Fatal("expected invalid action to fail validation")
	}
	good := AclRule{SourceRole: "admin", DestService: "ssh", Port: 22, Action: "ALLOW"}
	if err := good.Validate(); err != nil {
		t.Fatalf("valid rule rejected: %v", err)
	}
}
