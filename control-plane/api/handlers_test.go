package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/Thegreatprabh/KronosMesh/control-plane/models"
	"github.com/Thegreatprabh/KronosMesh/control-plane/store"
)

func setupRouter() *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	st := store.NewMemoryStore("")
	RegisterRoutes(r, &Handlers{Store: st})
	return r
}

func doJSON(t *testing.T, r *gin.Engine, method, path string, body interface{}) (*httptest.ResponseRecorder, []byte) {
	t.Helper()
	return doJSONToken(t, r, method, path, body, "")
}

func doJSONToken(t *testing.T, r *gin.Engine, method, path string, body interface{}, token string) (*httptest.ResponseRecorder, []byte) {
	t.Helper()
	var buf bytes.Buffer
	if body != nil {
		if err := json.NewEncoder(&buf).Encode(body); err != nil {
			t.Fatal(err)
		}
	}
	req := httptest.NewRequest(method, path, &buf)
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w, w.Body.Bytes()
}

func TestRegisterHeartbeatTopologyFlow(t *testing.T) {
	r := setupRouter()
	keyBytes := make([]byte, 32)
	for i := range keyBytes {
		keyBytes[i] = byte(42 + i)
	}
	const digits = "0123456789abcdef"
	keyHex := ""
	for _, v := range keyBytes {
		keyHex += string([]byte{digits[v>>4], digits[v&0xf]})
	}
	regBody := map[string]interface{}{
		"node_name": "edge-01", "public_key": keyHex,
		"fingerprint": models.Fingerprint(keyBytes),
		"virtual_ip":  "100.64.0.10", "endpoint": "198.51.100.5:51820",
		"role": "node", "nat_type": "nat", "ebpf_probe_passed": false, "version": "1.0.0",
	}
	w, body := doJSON(t, r, http.MethodPost, "/api/v1/nodes/register", regBody)
	if w.Code != http.StatusOK {
		t.Fatalf("register status %d: %s", w.Code, body)
	}
	var regResp models.NodeRegisterResponse
	if err := json.Unmarshal(body, &regResp); err != nil {
		t.Fatal(err)
	}
	if regResp.NodeID == "" || regResp.AssignedVirtualIP != "100.64.0.10" {
		t.Fatalf("bad register response: %+v", regResp)
	}

	if regResp.NodeToken == "" {
		t.Fatal("first registration must return a node token")
	}
	hbBody := map[string]interface{}{
		"node_id": regResp.NodeID, "tx_bytes": 10, "rx_bytes": 20,
		"packets_tx": 1, "packets_rx": 2, "peers_connected": 0,
		"avg_latency_ms": 3.5, "uptime_secs": 60,
	}
	// Heartbeat without the node token must be rejected...
	w, body = doJSON(t, r, http.MethodPost, "/api/v1/nodes/"+regResp.NodeID+"/heartbeat", hbBody)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated heartbeat status %d, want 401: %s", w.Code, body)
	}
	// ...and with it, accepted.
	w, body = doJSONToken(t, r, http.MethodPost, "/api/v1/nodes/"+regResp.NodeID+"/heartbeat", hbBody, regResp.NodeToken)
	if w.Code != http.StatusOK {
		t.Fatalf("heartbeat status %d: %s", w.Code, body)
	}

	w, body = doJSON(t, r, http.MethodGet, "/api/v1/topology", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("topology status %d", w.Code)
	}
	var topo models.MeshTopology
	if err := json.Unmarshal(body, &topo); err != nil {
		t.Fatal(err)
	}
	if len(topo.Nodes) != 1 || !topo.Nodes[0].Online {
		t.Fatalf("topology wrong: %+v", topo)
	}

	// Heartbeat for an unknown node must 404 (body id matches path id,
	// so the request reaches the store lookup).
	unknownHb := map[string]interface{}{
		"node_id": "nope", "tx_bytes": 0, "rx_bytes": 0,
		"packets_tx": 0, "packets_rx": 0, "peers_connected": 0,
		"avg_latency_ms": 0, "uptime_secs": 1,
	}
	w, _ = doJSON(t, r, http.MethodPost, "/api/v1/nodes/nope/heartbeat", unknownHb)
	if w.Code != http.StatusNotFound {
		t.Fatalf("unknown node heartbeat status %d, want 404", w.Code)
	}
}

func TestAclEndpoints(t *testing.T) {
	r := setupRouter()
	rule := map[string]interface{}{
		"id": "", "source_role": "admin", "dest_service": "ssh",
		"port": 22, "action": "ALLOW", "priority": 1,
	}
	w, body := doJSON(t, r, http.MethodPost, "/api/v1/acls", rule)
	if w.Code != http.StatusCreated {
		t.Fatalf("create acl status %d: %s", w.Code, body)
	}
	var created models.AclRule
	if err := json.Unmarshal(body, &created); err != nil {
		t.Fatal(err)
	}
	w, body = doJSON(t, r, http.MethodGet, "/api/v1/acls", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("list acl status %d", w.Code)
	}
	var policy models.AclPolicyResponse
	if err := json.Unmarshal(body, &policy); err != nil {
		t.Fatal(err)
	}
	if policy.Version != 1 || len(policy.Rules) != 1 {
		t.Fatalf("policy wrong: %+v", policy)
	}
	w, _ = doJSON(t, r, http.MethodDelete, "/api/v1/acls/"+created.ID, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("delete acl status %d", w.Code)
	}
	// Invalid action is rejected.
	bad := map[string]interface{}{
		"source_role": "x", "dest_service": "y", "port": 1, "action": "SOMETIMES", "priority": 1,
	}
	w, _ = doJSON(t, r, http.MethodPost, "/api/v1/acls", bad)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("bad action status %d, want 400", w.Code)
	}
	_ = time.Now // keep time import if unused in future edits
}

// TestReadEndpointsRequireCredential pins the read gate:
// with an admin token configured, topology and the ACL policy
// (full mesh reconnaissance data) require the admin token or a
// registered node's token; in the open posture (no admin token)
// they stay readable.
func TestReadEndpointsRequireCredential(t *testing.T) {
	r := setupAdminRouter()
	keyBytes := make([]byte, 32)
	for i := range keyBytes {
		keyBytes[i] = byte(11 + i)
	}
	const digits = "0123456789abcdef"
	keyHex := ""
	for _, v := range keyBytes {
		keyHex += string([]byte{digits[v>>4], digits[v&0xf]})
	}
	regBody := map[string]interface{}{
		"node_name": "reader-01", "public_key": keyHex,
		"fingerprint": models.Fingerprint(keyBytes),
		"virtual_ip":  "100.64.0.12", "endpoint": "198.51.100.7:51820",
		"role": "node", "nat_type": "nat", "ebpf_probe_passed": false, "version": "1.0.0",
	}
	w, body := doJSONToken(t, r, http.MethodPost, "/api/v1/nodes/register", regBody, "test-admin-token")
	if w.Code != http.StatusOK {
		t.Fatalf("register with admin: status %d: %s", w.Code, body)
	}
	var regResp models.NodeRegisterResponse
	if err := json.Unmarshal(body, &regResp); err != nil {
		t.Fatal(err)
	}
	nodeToken := regResp.NodeToken
	if nodeToken == "" {
		t.Fatal("registration must issue a node token")
	}
	for _, path := range []string{"/api/v1/topology", "/api/v1/acls"} {
		if w, _ := doJSON(t, r, http.MethodGet, path, nil); w.Code != http.StatusUnauthorized {
			t.Fatalf("GET %s without credential: status %d, want 401", path, w.Code)
		}
		if w, _ := doJSONToken(t, r, http.MethodGet, path, nil, "bogus-token"); w.Code != http.StatusUnauthorized {
			t.Fatalf("GET %s with bogus token: status %d, want 401", path, w.Code)
		}
		if w, _ := doJSONToken(t, r, http.MethodGet, path, nil, nodeToken); w.Code != http.StatusOK {
			t.Fatalf("GET %s with node token: status %d, want 200", path, w.Code)
		}
		if w, _ := doJSONToken(t, r, http.MethodGet, path, nil, "test-admin-token"); w.Code != http.StatusOK {
			t.Fatalf("GET %s with admin token: status %d, want 200", path, w.Code)
		}
	}
	// Open posture: no admin token configured — reads stay open.
	open := setupRouter()
	if w, _ := doJSON(t, open, http.MethodGet, "/api/v1/topology", nil); w.Code != http.StatusOK {
		t.Fatalf("open posture topology: status %d, want 200", w.Code)
	}
}

func setupAdminRouter() *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	st := store.NewMemoryStore("")
	RegisterRoutes(r, &Handlers{Store: st, AdminToken: "test-admin-token"})
	return r
}

// TestAdminTokenEnforcement covers operator-provisioned mode: new nodes
// and ACL changes require the admin token; node tokens guard the rest.
func TestAdminTokenEnforcement(t *testing.T) {
	r := setupAdminRouter()
	keyBytes := make([]byte, 32)
	for i := range keyBytes {
		keyBytes[i] = byte(7 + i)
	}
	const digits = "0123456789abcdef"
	keyHex := ""
	for _, v := range keyBytes {
		keyHex += string([]byte{digits[v>>4], digits[v&0xf]})
	}
	regBody := map[string]interface{}{
		"node_name": "edge-02", "public_key": keyHex,
		"fingerprint": models.Fingerprint(keyBytes),
		"virtual_ip":  "100.64.0.11", "endpoint": "198.51.100.6:51820",
		"role": "node", "nat_type": "nat", "ebpf_probe_passed": false, "version": "1.0.0",
	}
	// New node without admin token: 401.
	w, body := doJSON(t, r, http.MethodPost, "/api/v1/nodes/register", regBody)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("register without admin: status %d, want 401: %s", w.Code, body)
	}
	// With admin token: 200 and a node token is issued.
	w, body = doJSONToken(t, r, http.MethodPost, "/api/v1/nodes/register", regBody, "test-admin-token")
	if w.Code != http.StatusOK {
		t.Fatalf("register with admin: status %d: %s", w.Code, body)
	}
	var regResp models.NodeRegisterResponse
	if err := json.Unmarshal(body, &regResp); err != nil {
		t.Fatal(err)
	}
	// Re-register with a forged token: 403.
	w, _ = doJSONToken(t, r, http.MethodPost, "/api/v1/nodes/register", regBody, "forged")
	if w.Code != http.StatusForbidden {
		t.Fatalf("re-register with forged token: status %d, want 403", w.Code)
	}
	// ACL create without admin: 401; with admin: 201.
	rule := map[string]interface{}{
		"id": "", "source_role": "admin", "dest_service": "ssh",
		"port": 22, "action": "ALLOW", "priority": 1,
	}
	w, _ = doJSON(t, r, http.MethodPost, "/api/v1/acls", rule)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("ACL create without admin: status %d, want 401", w.Code)
	}
	w, body = doJSONToken(t, r, http.MethodPost, "/api/v1/acls", rule, "test-admin-token")
	if w.Code != http.StatusCreated {
		t.Fatalf("ACL create with admin: status %d: %s", w.Code, body)
	}
}

func regBodyFor(seed byte, name, vip string) map[string]interface{} {
	keyBytes := make([]byte, 32)
	for i := range keyBytes {
		keyBytes[i] = seed + byte(i)
	}
	const digits = "0123456789abcdef"
	keyHex := ""
	for _, v := range keyBytes {
		keyHex += string([]byte{digits[v>>4], digits[v&0xf]})
	}
	return map[string]interface{}{
		"node_name": name, "public_key": keyHex,
		"fingerprint": models.Fingerprint(keyBytes),
		"virtual_ip":  vip, "endpoint": "198.51.100.9:51820",
		"role": "node", "nat_type": "nat", "ebpf_probe_passed": false, "version": "1.0.0",
	}
}

// TestRevocationFlow pins DELETE /api/v1/nodes/:id: admin-only,
// 404 for unknown ids, and after revocation the node's token is
// dead and its key is treated as brand-new (admin required again).
func TestRevocationFlow(t *testing.T) {
	r := setupAdminRouter()
	regBody := regBodyFor(21, "revoke-me", "100.64.0.21")
	w, body := doJSONToken(t, r, http.MethodPost, "/api/v1/nodes/register", regBody, "test-admin-token")
	if w.Code != http.StatusOK {
		t.Fatalf("register with admin: status %d: %s", w.Code, body)
	}
	var regResp models.NodeRegisterResponse
	if err := json.Unmarshal(body, &regResp); err != nil {
		t.Fatal(err)
	}

	// Revocation without the admin token: 401.
	if w, _ := doJSON(t, r, http.MethodDelete, "/api/v1/nodes/"+regResp.NodeID, nil); w.Code != http.StatusUnauthorized {
		t.Fatalf("delete without admin: status %d, want 401", w.Code)
	}
	// Unknown id with admin: 404.
	if w, _ := doJSONToken(t, r, http.MethodDelete, "/api/v1/nodes/does-not-exist", nil, "test-admin-token"); w.Code != http.StatusNotFound {
		t.Fatalf("delete unknown node: status %d, want 404", w.Code)
	}
	// Revoke with admin: 200 {"deleted": id}.
	w, body = doJSONToken(t, r, http.MethodDelete, "/api/v1/nodes/"+regResp.NodeID, nil, "test-admin-token")
	if w.Code != http.StatusOK {
		t.Fatalf("delete with admin: status %d: %s", w.Code, body)
	}
	var delResp map[string]string
	if err := json.Unmarshal(body, &delResp); err != nil || delResp["deleted"] != regResp.NodeID {
		t.Fatalf("delete response wrong: %s", body)
	}
	// The old node token no longer authenticates anything.
	hbBody := map[string]interface{}{"node_id": regResp.NodeID}
	if w, _ := doJSONToken(t, r, http.MethodPost, "/api/v1/nodes/"+regResp.NodeID+"/heartbeat", hbBody, regResp.NodeToken); w.Code != http.StatusNotFound {
		t.Fatalf("heartbeat of revoked node: status %d, want 404", w.Code)
	}
	// The same key is brand-new now: registering it without admin
	// is refused, with admin it succeeds under a fresh node id.
	if w, _ := doJSON(t, r, http.MethodPost, "/api/v1/nodes/register", regBody); w.Code != http.StatusUnauthorized {
		t.Fatalf("re-register revoked key without admin: status %d, want 401", w.Code)
	}
	w, body = doJSONToken(t, r, http.MethodPost, "/api/v1/nodes/register", regBody, "test-admin-token")
	if w.Code != http.StatusOK {
		t.Fatalf("re-register revoked key with admin: status %d: %s", w.Code, body)
	}
	var regResp2 models.NodeRegisterResponse
	if err := json.Unmarshal(body, &regResp2); err != nil {
		t.Fatal(err)
	}
	if regResp2.NodeID == regResp.NodeID {
		t.Fatal("re-registration after revocation must mint a new node id")
	}
}

// TestEnrollmentTokenRegistration pins the single-use enrollment
// flow: minting is admin-only, a token registers exactly one new
// node, reuse and bogus tokens are refused, a failed registration
// does not burn the token, and the admin path is unaffected.
func TestEnrollmentTokenRegistration(t *testing.T) {
	r := setupAdminRouter()

	if w, _ := doJSON(t, r, http.MethodPost, "/api/v1/enrollment-tokens", nil); w.Code != http.StatusUnauthorized {
		t.Fatalf("mint without admin: status %d, want 401", w.Code)
	}
	w, body := doJSONToken(t, r, http.MethodPost, "/api/v1/enrollment-tokens", nil, "test-admin-token")
	if w.Code != http.StatusCreated {
		t.Fatalf("mint with admin: status %d: %s", w.Code, body)
	}
	var mint map[string]string
	if err := json.Unmarshal(body, &mint); err != nil || mint["token"] == "" {
		t.Fatalf("mint response wrong: %s", body)
	}
	enrollToken := mint["token"]

	// First new key with the enrollment token: 200.
	regA := regBodyFor(31, "enrolled-a", "100.64.0.31")
	w, body = doJSONToken(t, r, http.MethodPost, "/api/v1/nodes/register", regA, enrollToken)
	if w.Code != http.StatusOK {
		t.Fatalf("register with enrollment token: status %d: %s", w.Code, body)
	}
	// Same token, another new key: 401 (consumed).
	regB := regBodyFor(32, "enrolled-b", "100.64.0.32")
	if w, _ := doJSONToken(t, r, http.MethodPost, "/api/v1/nodes/register", regB, enrollToken); w.Code != http.StatusUnauthorized {
		t.Fatalf("reuse of consumed enrollment token: status %d, want 401", w.Code)
	}
	// Bogus token: 401.
	if w, _ := doJSONToken(t, r, http.MethodPost, "/api/v1/nodes/register", regB, "bogus-token"); w.Code != http.StatusUnauthorized {
		t.Fatalf("register with bogus token: status %d, want 401", w.Code)
	}

	// A failed registration must not burn the token: mint a second
	// token, fail validation with it (fingerprint mismatch → 400),
	// then register the same key correctly with the same token.
	w, body = doJSONToken(t, r, http.MethodPost, "/api/v1/enrollment-tokens", nil, "test-admin-token")
	if w.Code != http.StatusCreated {
		t.Fatalf("second mint: status %d: %s", w.Code, body)
	}
	if err := json.Unmarshal(body, &mint); err != nil {
		t.Fatal(err)
	}
	token2 := mint["token"]
	regC := regBodyFor(33, "enrolled-c", "100.64.0.33")
	badC := regBodyFor(33, "enrolled-c", "100.64.0.33")
	badC["fingerprint"] = "deadbeef"
	if w, _ := doJSONToken(t, r, http.MethodPost, "/api/v1/nodes/register", badC, token2); w.Code != http.StatusBadRequest {
		t.Fatalf("invalid registration with enrollment token: status %d, want 400", w.Code)
	}
	w, body = doJSONToken(t, r, http.MethodPost, "/api/v1/nodes/register", regC, token2)
	if w.Code != http.StatusOK {
		t.Fatalf("register after failed attempt must still accept the token: status %d: %s", w.Code, body)
	}

	// The admin path is unaffected.
	regD := regBodyFor(34, "enrolled-d", "100.64.0.34")
	if w, _ := doJSONToken(t, r, http.MethodPost, "/api/v1/nodes/register", regD, "test-admin-token"); w.Code != http.StatusOK {
		t.Fatalf("register with admin token: status %d, want 200", w.Code)
	}
}
