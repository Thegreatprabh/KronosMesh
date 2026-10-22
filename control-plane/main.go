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
//	           registrations; strongly recommended outside local dev.
//	KRONOS_TLS_CERT / KRONOS_TLS_KEY
//	           optional PEM paths; when both are set the plane serves
//	           HTTPS instead of HTTP (point daemons at an https:// URL).
//	KRONOS_CORS_ORIGINS
//	           comma-separated browser origins allowed to call the API
//	           (default: localhost dashboard origins).
package main

import (
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

	adminToken := os.Getenv("KRONOS_ADMIN_TOKEN")
	if adminToken == "" {
		log.Printf("WARNING: KRONOS_ADMIN_TOKEN is not set - ACL changes and new-node registration are unauthenticated (development mode). Node tokens are still enforced for heartbeats and re-registration.")
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
