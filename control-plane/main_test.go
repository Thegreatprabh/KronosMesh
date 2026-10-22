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
