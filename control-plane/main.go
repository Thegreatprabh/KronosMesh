// KronosMesh control plane: node registry, heartbeat/telemetry intake,
// mesh topology, and zero-trust ACL policy distribution.
//
// Environment:
//
//	PORT       listen port (default 8080)
//	REDIS_ADDR optional Redis address for the write-through mirror
//	           (e.g. "redis:6379"); the plane works without it.
package main

import (
	"log"
	"os"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/Thegreatprabh/KronosMesh/control-plane/api"
	"github.com/Thegreatprabh/KronosMesh/control-plane/store"
)

const offlineAfter = 45 * time.Second
const reapEvery = 15 * time.Second

func corsMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("Access-Control-Allow-Origin", "*")
		c.Header("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS")
		c.Header("Access-Control-Allow-Headers", "Content-Type, Authorization")
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

	router := gin.Default()
	router.Use(corsMiddleware())
	api.RegisterRoutes(router, &api.Handlers{Store: st})

	log.Printf("kronos control plane listening on :%s", port)
	if err := router.Run(":" + port); err != nil {
		log.Fatalf("server failed: %v", err)
	}
}
