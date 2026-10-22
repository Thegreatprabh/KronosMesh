package main

import "testing"

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
