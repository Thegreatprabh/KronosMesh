// KronosMesh control plane: node registry, heartbeat/telemetry intake,
// mesh topology, and zero-trust ACL policy distribution.
//
// Environment:
//
//	PORT       listen port (default 8080)
//	REDIS_ADDR optional Redis address for the write-through mirror
//	           (e.g. "redis:6379"); the plane works without it.
//	KRONOS_STATE_FILE
//	           registry snapshot path used when REDIS_ADDR is NOT
//	           set (default "kronos-state.json" in the working
//	           directory). Structural changes (node register/delete,
//	           ACL changes, enrollment tokens) are persisted there
//	           atomically and restored at startup, so a restart
//	           without Redis no longer loses the mesh.
//	KRONOS_ENROLLMENT_TOKENS
//	           comma-separated plaintext single-use enrollment
//	           tokens to pre-seed at startup (hashed before storage;
//	           only the count is logged). Each lets one new node
//	           register without the admin token and is consumed by
//	           that registration.
//	KRONOS_ADMIN_TOKEN
//	           operator token gating ACL changes and first-time node
//	           registrations. REQUIRED (minimum 16 characters): the
//	           plane refuses to start without one, because an unset
//	           token would leave operator endpoints open to anyone who
//	           can reach the port. KRONOS_DEV_OPEN_ADMIN=1 explicitly
//	           selects the unauthenticated posture for local
//	           development only.
//	KRONOS_TLS_CERT / KRONOS_TLS_KEY
//	           optional PEM paths; when both are set the plane serves
//	           HTTPS instead of HTTP (point daemons at an https:// URL).
//	KRONOS_REQUIRE_TLS
//	           when "1", a certificate pair is mandatory: the plane
//	           refuses to start without one, so a production deploy
//	           cannot silently serve bearer tokens over plaintext
//	           because two variables were forgotten. (Terminating TLS
//	           at a trusted reverse proxy is the supported alternative;
//	           keep this port reachable only from that proxy.)
//	KRONOS_CORS_ORIGINS
//	           comma-separated browser origins allowed to call the API
//	           (default: localhost dashboard origins).
package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/Thegreatprabh/KronosMesh/control-plane/api"
	"github.com/Thegreatprabh/KronosMesh/control-plane/store"
)

const offlineAfter = 45 * time.Second
const reapEvery = 15 * time.Second

// corsMiddleware allows credentialed cross-origin calls only from an
// explicit allowlist (KRONOS_CORS_ORIGINS, comma-separated). The previous
// wildcard policy let any website the operator browsed issue requests
// against a localhost control plane. Defaults cover the local dashboard
// dev server (Vite :5173) and the composed dashboard (:8081).
func corsMiddleware() gin.HandlerFunc {
	allowed := map[string]bool{}
	for _, o := range strings.Split(os.Getenv("KRONOS_CORS_ORIGINS"), ",") {
		if o = strings.TrimSpace(o); o != "" {
			allowed[o] = true
		}
	}
	if len(allowed) == 0 {
		for _, o := range []string{
			"http://localhost:5173", "http://localhost:8081",
			"http://127.0.0.1:5173", "http://127.0.0.1:8081",
		} {
			allowed[o] = true
		}
	}
	return func(c *gin.Context) {
		if origin := c.GetHeader("Origin"); origin != "" && allowed[origin] {
			c.Header("Access-Control-Allow-Origin", origin)
			c.Header("Vary", "Origin")
			c.Header("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS")
			c.Header("Access-Control-Allow-Headers", "Content-Type, Authorization")
		}
		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(204)
			return
		}
		c.Next()
	}
}

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	redisAddr := os.Getenv("REDIS_ADDR")
	st := store.NewMemoryStore(redisAddr)
	if redisAddr == "" {
		// No Redis: persist the registry to a state file instead,
		// with the same restore semantics as the mirror. A corrupt
		// file is logged loudly and the plane starts empty (nodes
		// re-provision) — it never crashes on bad state.
		stateFile := os.Getenv("KRONOS_STATE_FILE")
		if stateFile == "" {
			stateFile = "kronos-state.json"
		}
		st.EnableFilePersistence(stateFile)
		if n, a, e, err := st.RestoreFromFile(); err != nil {
			log.Printf("store: state file %s could not be restored (%v); starting with EMPTY state — previously registered nodes must re-provision", stateFile, err)
		} else if n > 0 || a > 0 || e > 0 {
			log.Printf("store: restored %d node(s), %d ACL rule(s) and %d enrollment token(s) from state file %s", n, a, e, stateFile)
		}
	} else if n, a, err := st.RecoverFromMirror(); err != nil {
		// Restart recovery: when a Redis mirror exists, rebuild the
		// registry and ACL policy from it instead of starting empty.
		log.Printf("store: mirror recovery failed (%v); starting with empty state", err)
	} else if n > 0 || a > 0 {
		log.Printf("store: recovered %d node(s) and %d ACL rule(s) from the Redis mirror", n, a)
	}

	// Pre-seed single-use enrollment tokens from the environment.
	// Only the count is logged — the values are credentials.
	if seeded := parseEnrollmentTokens(os.Getenv("KRONOS_ENROLLMENT_TOKENS")); len(seeded) > 0 {
		for _, tok := range seeded {
			st.AddEnrollmentHash(store.HashToken(tok))
		}
		log.Printf("store: seeded %d enrollment token(s) from KRONOS_ENROLLMENT_TOKENS", len(seeded))
	}

	// Stale-node reaper: nodes that stop heartbeating are marked
	// offline so the topology and dashboards stay truthful.
	go func() {
		ticker := time.NewTicker(reapEvery)
		defer ticker.Stop()
		for now := range ticker.C {
			if n := st.ReapStale(now.UTC(), offlineAfter); n > 0 {
				log.Printf("reaper: marked %d node(s) offline", n)
			}
		}
	}()

	adminToken, devOpen, err := resolveAdminMode(os.Getenv)
	if err != nil {
		log.Fatalf("kronos control plane: %v", err)
	}
	if devOpen {
		log.Printf("WARNING: KRONOS_DEV_OPEN_ADMIN=1 - operator authentication is DISABLED (local development only). ACL changes and new-node registration are unauthenticated; node tokens are still enforced for heartbeats and re-registration.")
	}
	// Ship in release mode by default: Gin's debug mode prints
	// its route table and development warnings an operator did
	// not ask for. An explicit GIN_MODE still wins.
	if os.Getenv("GIN_MODE") == "" {
		gin.SetMode(gin.ReleaseMode)
	}
	router := gin.Default()
	router.Use(corsMiddleware())
	router.Use(bodyLimitMiddleware())
	api.RegisterRoutes(router, &api.Handlers{Store: st, AdminToken: adminToken})

	// Explicit server timeouts: the default http.Server has none, so a
	// slow-loris client could hold connections open forever.
	srv := &http.Server{
		Addr:              ":" + port,
		Handler:           router,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	certFile, keyFile, err := resolveTLSMode(os.Getenv)
	if err != nil {
		log.Fatalf("kronos control plane: %v", err)
	}
	if certFile != "" && keyFile != "" {
		log.Printf("kronos control plane listening on :%s (TLS)", port)
		if err := srv.ListenAndServeTLS(certFile, keyFile); err != nil {
			log.Fatalf("server failed: %v", err)
		}
		return
	}
	log.Printf("WARNING: serving plaintext HTTP on :%s - node and operator bearer tokens cross the wire unencrypted. Keep this port on a trusted network only, or set KRONOS_TLS_CERT/KRONOS_TLS_KEY (KRONOS_REQUIRE_TLS=1 makes TLS mandatory)", port)
	log.Printf("kronos control plane listening on :%s", port)
	if err := srv.ListenAndServe(); err != nil {
		log.Fatalf("server failed: %v", err)
	}
}

// parseEnrollmentTokens splits the KRONOS_ENROLLMENT_TOKENS value
// into individual tokens, dropping blanks and whitespace.
func parseEnrollmentTokens(raw string) []string {
	var out []string
	for _, part := range strings.Split(raw, ",") {
		if part = strings.TrimSpace(part); part != "" {
			out = append(out, part)
		}
	}
	return out
}

// minAdminTokenLen is the shortest operator token accepted outside
// the explicit development opt-in.
const minAdminTokenLen = 16

// resolveAdminMode decides the operator-auth posture at startup.
// Fail-closed by default: without a KRONOS_ADMIN_TOKEN of at least
// minAdminTokenLen characters the plane refuses to start — an unset
// token previously just logged a warning and left ACL changes and
// new-node registration open to anyone who could reach the port.
// KRONOS_DEV_OPEN_ADMIN=1 is the explicit, greppable opt-in to that
// open posture for local development.
func resolveAdminMode(getenv func(string) string) (token string, devOpen bool, err error) {
	token = getenv("KRONOS_ADMIN_TOKEN")
	devOpen = getenv("KRONOS_DEV_OPEN_ADMIN") == "1"
	if token == "" {
		if devOpen {
			return "", true, nil
		}
		return "", false, fmt.Errorf("KRONOS_ADMIN_TOKEN is not set: operator endpoints (ACL changes, new-node registration) would be unauthenticated. Set a token of at least %d characters, or set KRONOS_DEV_OPEN_ADMIN=1 for local development only", minAdminTokenLen)
	}
	if len(token) < minAdminTokenLen && !devOpen {
		return "", false, fmt.Errorf("KRONOS_ADMIN_TOKEN is too short (%d characters): use at least %d, or set KRONOS_DEV_OPEN_ADMIN=1 for local development only", len(token), minAdminTokenLen)
	}
	return token, devOpen, nil
}

// resolveTLSMode decides the transport posture. KRONOS_REQUIRE_TLS=1
// makes TLS mandatory — the plane refuses to start without a
// certificate pair — so production cannot silently fall back to
// plaintext bearer tokens. A half-configured pair is always an error.
func resolveTLSMode(getenv func(string) string) (certFile, keyFile string, err error) {
	certFile, keyFile = getenv("KRONOS_TLS_CERT"), getenv("KRONOS_TLS_KEY")
	if (certFile == "") != (keyFile == "") {
		return "", "", fmt.Errorf("KRONOS_TLS_CERT and KRONOS_TLS_KEY must be set together (only one was provided)")
	}
	if getenv("KRONOS_REQUIRE_TLS") == "1" && certFile == "" {
		return "", "", fmt.Errorf("KRONOS_REQUIRE_TLS=1 but KRONOS_TLS_CERT/KRONOS_TLS_KEY are not set: refusing to serve operator endpoints and bearer tokens over plaintext HTTP. Provide a certificate pair, or terminate TLS at a trusted reverse proxy and keep this port reachable only from that proxy")
	}
	return certFile, keyFile, nil
}

// bodyLimitMiddleware caps request bodies (registrations, heartbeats and
// ACL rules are all small JSON documents) so a client cannot stream an
// unbounded body at the plane.
func bodyLimitMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		if c.Request.Body != nil {
			c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, 64<<10)
		}
		c.Next()
	}
}
