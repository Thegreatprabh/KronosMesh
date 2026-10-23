package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
)

func envGetter(vars map[string]string) func(string) string {
	return func(k string) string { return vars[k] }
}

func TestResolveAdminModeFailsClosedWithoutToken(t *testing.T) {
	_, _, err := resolveAdminMode(envGetter(map[string]string{}))
	if err == nil {
		t.Fatal("missing admin token must fail startup (fail-closed)")
	}
}

func TestResolveAdminModeDevOptInAllowsOpenPosture(t *testing.T) {
	token, devOpen, err := resolveAdminMode(envGetter(map[string]string{
		"KRONOS_DEV_OPEN_ADMIN": "1",
	}))
	if err != nil {
		t.Fatalf("explicit dev opt-in must start: %v", err)
	}
	if token != "" || !devOpen {
		t.Fatalf("expected empty token with devOpen=true, got token=%q devOpen=%v", token, devOpen)
	}
}

func TestResolveAdminModeRejectsShortToken(t *testing.T) {
	_, _, err := resolveAdminMode(envGetter(map[string]string{
		"KRONOS_ADMIN_TOKEN": "short",
	}))
	if err == nil {
		t.Fatal("a short admin token must fail startup outside dev mode")
	}
}

func TestResolveAdminModeAcceptsStrongToken(t *testing.T) {
	token, devOpen, err := resolveAdminMode(envGetter(map[string]string{
		"KRONOS_ADMIN_TOKEN": "a-strong-operator-token",
	}))
	if err != nil {
		t.Fatalf("strong token must start: %v", err)
	}
	if token != "a-strong-operator-token" || devOpen {
		t.Fatalf("unexpected result token=%q devOpen=%v", token, devOpen)
	}
}

func TestResolveTLSModeNotRequiredByDefault(t *testing.T) {
	cert, key, err := resolveTLSMode(envGetter(map[string]string{}))
	if err != nil {
		t.Fatalf("plaintext must remain available by default (local use): %v", err)
	}
	if cert != "" || key != "" {
		t.Fatalf("expected no cert pair, got %q/%q", cert, key)
	}
}

func TestResolveTLSModeRequiredWithoutCertsFailsClosed(t *testing.T) {
	_, _, err := resolveTLSMode(envGetter(map[string]string{
		"KRONOS_REQUIRE_TLS": "1",
	}))
	if err == nil {
		t.Fatal("KRONOS_REQUIRE_TLS=1 without certificates must fail startup")
	}
}

func TestResolveTLSModeHalfPairIsAnError(t *testing.T) {
	_, _, err := resolveTLSMode(envGetter(map[string]string{
		"KRONOS_TLS_CERT": "/tmp/cert.pem",
	}))
	if err == nil {
		t.Fatal("a cert without its key must fail startup")
	}
}

func TestResolveTLSModeRequiredWithCertsStarts(t *testing.T) {
	cert, key, err := resolveTLSMode(envGetter(map[string]string{
		"KRONOS_REQUIRE_TLS": "1",
		"KRONOS_TLS_CERT":    "/tmp/cert.pem",
		"KRONOS_TLS_KEY":     "/tmp/key.pem",
	}))
	if err != nil {
		t.Fatalf("required TLS with a cert pair must start: %v", err)
	}
	if cert != "/tmp/cert.pem" || key != "/tmp/key.pem" {
		t.Fatalf("unexpected pair %q/%q", cert, key)
	}
}

func TestParseEnrollmentTokens(t *testing.T) {
	got := parseEnrollmentTokens(" alpha ,beta-token,,  gamma  ,")
	want := []string{"alpha", "beta-token", "gamma"}
	if len(got) != len(want) {
		t.Fatalf("parseEnrollmentTokens = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("parseEnrollmentTokens = %v, want %v", got, want)
		}
	}
	if got := parseEnrollmentTokens(""); len(got) != 0 {
		t.Fatalf("empty env must seed nothing, got %v", got)
	}
	if got := parseEnrollmentTokens(" , ,"); len(got) != 0 {
		t.Fatalf("blank entries must be dropped, got %v", got)
	}
}

// --- Round 8.5: failed-auth throttle ---------------------------------------

func TestAuthThrottleBlocksAfterLimitAndRecovers(t *testing.T) {
	th := newAuthThrottle()
	base := time.Date(2026, 10, 23, 0, 0, 0, 0, time.UTC)
	now := base
	th.now = func() time.Time { return now }
	for i := 0; i < authFailLimit-1; i++ {
		th.recordFailure("203.0.113.7")
		if th.blocked("203.0.113.7") {
			t.Fatalf("blocked early after %d failures", i+1)
		}
	}
	th.recordFailure("203.0.113.7")
	if !th.blocked("203.0.113.7") {
		t.Fatal("must be blocked at the failure limit")
	}
	if th.blocked("203.0.113.8") {
		t.Fatal("a different source must not be blocked")
	}
	now = base.Add(authBlockFor + time.Second)
	if th.blocked("203.0.113.7") {
		t.Fatal("block must expire after the cooldown")
	}
}

func TestAuthThrottleWindowSlides(t *testing.T) {
	th := newAuthThrottle()
	base := time.Date(2026, 10, 23, 0, 0, 0, 0, time.UTC)
	now := base
	th.now = func() time.Time { return now }
	// Half the limit now, half after the window has slid past:
	// the old failures no longer count.
	for i := 0; i < authFailLimit/2; i++ {
		th.recordFailure("198.51.100.3")
	}
	now = base.Add(authFailWindow + time.Second)
	for i := 0; i < authFailLimit/2; i++ {
		th.recordFailure("198.51.100.3")
	}
	if th.blocked("198.51.100.3") {
		t.Fatal("failures older than the window must not count toward the limit")
	}
}

func TestAuthThrottleMiddlewareCountsOnlyFailures(t *testing.T) {
	gin.SetMode(gin.TestMode)
	th := newAuthThrottle()
	base := time.Date(2026, 10, 23, 0, 0, 0, 0, time.UTC)
	th.now = func() time.Time { return base }
	r := gin.New()
	r.Use(authThrottleMiddleware(th))
	r.GET("/api/v1/health", func(c *gin.Context) { c.Status(http.StatusOK) })
	r.GET("/api/v1/topology", func(c *gin.Context) {
		if c.GetHeader("Authorization") == "Bearer good" {
			c.Status(http.StatusOK)
			return
		}
		c.Status(http.StatusUnauthorized)
	})
	do := func(path, auth string) int {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.RemoteAddr = "203.0.113.9:4444"
		if auth != "" {
			req.Header.Set("Authorization", auth)
		}
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		return w.Code
	}
	// Health is exempt: hammering it with no credential counts nothing.
	for i := 0; i < authFailLimit+5; i++ {
		if code := do("/api/v1/health", ""); code != http.StatusOK {
			t.Fatalf("health: got %d", code)
		}
	}
	// Successful auths never count.
	for i := 0; i < authFailLimit+5; i++ {
		if code := do("/api/v1/topology", "Bearer good"); code != http.StatusOK {
			t.Fatalf("good auth: got %d", code)
		}
	}
	// Failures accumulate to a 429 with Retry-After.
	for i := 0; i < authFailLimit; i++ {
		if code := do("/api/v1/topology", "Bearer bad"); code != http.StatusUnauthorized {
			t.Fatalf("bad auth %d: got %d", i, code)
		}
	}
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/topology", nil)
	req.RemoteAddr = "203.0.113.9:4444"
	req.Header.Set("Authorization", "Bearer good")
	r.ServeHTTP(w, req)
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("blocked source must get 429 even with a good token, got %d", w.Code)
	}
	if w.Header().Get("Retry-After") == "" {
		t.Fatal("429 must carry Retry-After")
	}
}
