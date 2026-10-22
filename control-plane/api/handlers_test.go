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
