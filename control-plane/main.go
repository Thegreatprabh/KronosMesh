// KronosMesh control plane: node registry, heartbeat/telemetry intake,
// mesh topology, and zero-trust ACL policy distribution.
//
// Environment:
//
//	PORT       listen port (default 8080)
//	REDIS_ADDR optional Redis address for the write-through mirror
//	           (e.g. "redis:6379"); the plane works without it.
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
	st := store.NewMemoryStore(os.Getenv("REDIS_ADDR"))
	// Restart recovery: when a Redis mirror exists, rebuild the
	// registry and ACL policy from it instead of starting empty.
	if n, a, err := st.RecoverFromMirror(); err != nil {
		log.Printf("store: mirror recovery failed (%v); starting with empty state", err)
	} else if n > 0 || a > 0 {
		log.Printf("store: recovered %d node(s) and %d ACL rule(s) from the Redis mirror", n, a)
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
	certFile, keyFile := os.Getenv("KRONOS_TLS_CERT"), os.Getenv("KRONOS_TLS_KEY")
	if certFile != "" && keyFile != "" {
		log.Printf("kronos control plane listening on :%s (TLS)", port)
		if err := srv.ListenAndServeTLS(certFile, keyFile); err != nil {
			log.Fatalf("server failed: %v", err)
		}
		return
	}
	log.Printf("kronos control plane listening on :%s", port)
	if err := srv.ListenAndServe(); err != nil {
		log.Fatalf("server failed: %v", err)
	}
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
