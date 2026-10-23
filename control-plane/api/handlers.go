// Package api exposes the control plane's REST endpoints via Gin.
package api

import (
	"crypto/subtle"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/Thegreatprabh/KronosMesh/control-plane/models"
	"github.com/Thegreatprabh/KronosMesh/control-plane/store"
)

// Handlers bundles the store dependency for the route handlers.
type Handlers struct {
	Store store.Store
	Now   func() time.Time
	// AdminToken, when non-empty, gates ACL mutations and first-time
	// node registrations (operator-provisioned mode). Set it from the
	// KRONOS_ADMIN_TOKEN environment variable. When empty the plane runs
	// in open development mode (node tokens are still enforced).
	AdminToken string
}

// bearerToken extracts the token from an Authorization: Bearer header.
func bearerToken(c *gin.Context) string {
	h := c.GetHeader("Authorization")
	if strings.HasPrefix(h, "Bearer ") {
		return strings.TrimPrefix(h, "Bearer ")
	}
	return ""
}

// isAdmin reports whether the request carries the admin token.
func (h *Handlers) isAdmin(c *gin.Context) bool {
	if h.AdminToken == "" {
		return false
	}
	tok := bearerToken(c)
	return subtle.ConstantTimeCompare([]byte(tok), []byte(h.AdminToken)) == 1
}

// requireAdmin gates a handler behind the admin token when one is
// configured. It returns false (after writing 401) when access is denied.
func (h *Handlers) requireAdmin(c *gin.Context) bool {
	if h.AdminToken == "" || h.isAdmin(c) {
		return true
	}
	c.JSON(http.StatusUnauthorized, gin.H{"error": "admin token required"})
	return false
}

func (h *Handlers) now() time.Time {
	if h.Now != nil {
		return h.Now()
	}
	return time.Now().UTC()
}

// RegisterRoutes wires every endpoint onto the router.
func RegisterRoutes(r *gin.Engine, h *Handlers) {
	v1 := r.Group("/api/v1")
	v1.GET("/health", h.Health)
	v1.POST("/nodes/register", h.RegisterNode)
	v1.POST("/nodes/:id/heartbeat", h.Heartbeat)
	v1.DELETE("/nodes/:id", h.DeleteNode)
	v1.POST("/enrollment-tokens", h.CreateEnrollmentToken)
	v1.GET("/topology", h.GetTopology)
	v1.GET("/acls", h.ListAcls)
	v1.POST("/acls", h.CreateAcl)
	v1.DELETE("/acls/:id", h.DeleteAcl)
}

// Health reports liveness for orchestrators and the dashboard.
func (h *Handlers) Health(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"status":  "ok",
		"service": "kronos-control-plane",
		"time":    h.now().Format(time.RFC3339),
	})
}

// requireReader gates the read endpoints that disclose the
// mesh (topology, ACL policy) behind ANY valid credential — the
// admin token, or a registered node's bearer token (which is
// what daemons poll with). When no admin token is configured
// the plane is in its explicit open posture and reads stay
// open, mirroring requireAdmin.
func (h *Handlers) requireReader(c *gin.Context) bool {
	if h.AdminToken == "" || h.isAdmin(c) || h.Store.AnyNodeTokenValid(bearerToken(c)) {
		return true
	}
	c.JSON(http.StatusUnauthorized, gin.H{"error": "admin or node token required"})
	return false
}

// RegisterNode handles POST /api/v1/nodes/register.
func (h *Handlers) RegisterNode(c *gin.Context) {
	var req models.NodeRegisterRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid JSON body: " + err.Error()})
		return
	}
	admin := h.isAdmin(c)
	bearer := bearerToken(c)
	enroll := false
	if h.AdminToken != "" && !admin && !h.Store.KeyExists(req.PublicKey) {
		// Operator-provisioned mode: a brand-new public key may only
		// be registered by the admin, or with a single-use enrollment
		// token. The token is only CHECKED here — the store consumes
		// it at the point the registration commits, so a failed
		// registration leaves it valid. Existing nodes re-register
		// with the node token they were issued.
		enroll = h.Store.EnrollmentValid(bearer)
		if !enroll {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "admin token or enrollment token required to register a new node"})
			return
		}
	}
	req.AdminOverride = admin
	req.EnrollmentAuthorized = enroll
	if !admin {
		req.AuthToken = bearer
	}
	node, issued, err := h.Store.RegisterNode(&req, h.now())
	if err != nil {
		if errors.Is(err, store.ErrUnauthorized) {
			c.JSON(http.StatusForbidden, gin.H{"error": "invalid node token for this public key"})
			return
		}
		if errors.Is(err, store.ErrIPPoolExhausted) {
			c.JSON(http.StatusServiceUnavailable, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, models.NodeRegisterResponse{
		NodeID:            node.NodeID,
		AssignedVirtualIP: node.VirtualIP,
		Peers:             h.Store.ListNodes(),
		NodeToken:         issued,
	})
}

// DeleteNode handles DELETE /api/v1/nodes/:id — operator revocation
// of a node's membership. Admin-only. The node's token stops working
// immediately and its virtual IP returns to the pool.
func (h *Handlers) DeleteNode(c *gin.Context) {
	if !h.requireAdmin(c) {
		return
	}
	id := c.Param("id")
	if !h.Store.DeleteNode(id) {
		c.JSON(http.StatusNotFound, gin.H{"error": "node not found"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"deleted": id})
}

// CreateEnrollmentToken handles POST /api/v1/enrollment-tokens.
// Admin-only. It mints a single-use enrollment token: the plaintext
// is returned in this response and never stored or shown again
// (the store keeps only its SHA-256 hash). Hand it to one new node
// as its registration credential; it is consumed when that node's
// registration commits.
func (h *Handlers) CreateEnrollmentToken(c *gin.Context) {
	if !h.requireAdmin(c) {
		return
	}
	c.JSON(http.StatusCreated, gin.H{"token": h.Store.MintEnrollmentToken()})
}

// Heartbeat handles POST /api/v1/nodes/:id/heartbeat.
func (h *Handlers) Heartbeat(c *gin.Context) {
	var hb models.HeartbeatPayload
	if err := c.ShouldBindJSON(&hb); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid JSON body: " + err.Error()})
		return
	}
	nodeID := c.Param("id")
	if hb.NodeID != "" && hb.NodeID != nodeID {
		c.JSON(http.StatusBadRequest, gin.H{"error": "node_id in body does not match path"})
		return
	}
	if _, err := h.Store.Heartbeat(nodeID, &hb, bearerToken(c), h.now()); err != nil {
		if errors.Is(err, store.ErrUnauthorized) {
			c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, models.HeartbeatResponse{
		Acknowledged: true,
		Peers:        h.Store.ListNodes(),
	})
}

// GetTopology handles GET /api/v1/topology.
func (h *Handlers) GetTopology(c *gin.Context) {
	if !h.requireReader(c) {
		return
	}
	c.JSON(http.StatusOK, h.Store.Topology(h.now()))
}

// ListAcls handles GET /api/v1/acls.
func (h *Handlers) ListAcls(c *gin.Context) {
	if !h.requireReader(c) {
		return
	}
	c.JSON(http.StatusOK, h.Store.ListAcls())
}

// CreateAcl handles POST /api/v1/acls.
func (h *Handlers) CreateAcl(c *gin.Context) {
	if !h.requireAdmin(c) {
		return
	}
	var rule models.AclRule
	if err := c.ShouldBindJSON(&rule); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid JSON body: " + err.Error()})
		return
	}
	created, err := h.Store.CreateAcl(rule)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusCreated, created)
}

// DeleteAcl handles DELETE /api/v1/acls/:id.
func (h *Handlers) DeleteAcl(c *gin.Context) {
	if !h.requireAdmin(c) {
		return
	}
	if !h.Store.DeleteAcl(c.Param("id")) {
		c.JSON(http.StatusNotFound, gin.H{"error": "acl rule not found"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"deleted": true})
}
