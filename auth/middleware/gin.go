package middleware

import (
	"errors"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/yonatannnn/go-jwt-manager/auth/core"
	"github.com/yonatannnn/go-jwt-manager/auth/extractors"
	"github.com/yonatannnn/go-jwt-manager/auth/utils"
)

// GinAuthMiddleware returns a Gin middleware for JWT authentication
func GinAuthMiddleware(manager *core.JWTManager) gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "missing or invalid Authorization header"})
			c.Abort()
			return
		}

		tokenStr := strings.TrimPrefix(authHeader, "Bearer ")
		claims, err := manager.Verify(tokenStr)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid token: " + err.Error()})
			c.Abort()
			return
		}

		// Add claims to Gin context
		c.Set(utils.JWTClaimsKey, claims)
		c.Next()
	}
}

// GetGinClaims extracts claims from Gin context
func GetGinClaims(c *gin.Context) (map[string]interface{}, error) {
	claims, exists := c.Get(utils.JWTClaimsKey)
	if !exists {
		return nil, errors.New("no claims in context")
	}
	casted, ok := claims.(map[string]interface{})
	if !ok {
		return nil, errors.New("invalid claims format")
	}
	return casted, nil
}

// GinRequireRole returns a Gin middleware for role-based access control
func GinRequireRole(allowedRoles ...string) gin.HandlerFunc {
	return func(c *gin.Context) {
		claims, err := GetGinClaims(c)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized: " + err.Error()})
			c.Abort()
			return
		}

		if !extractors.HasAnyRole(claims, allowedRoles...) {
			c.JSON(http.StatusForbidden, gin.H{"error": "forbidden: insufficient role"})
			c.Abort()
			return
		}

		c.Next()
	}
}

// GinRequireABAC returns a Gin middleware for attribute-based access control
func GinRequireABAC(ruleFunc func(map[string]interface{}) bool) gin.HandlerFunc {
	return func(c *gin.Context) {
		claims, err := GetGinClaims(c)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized: " + err.Error()})
			c.Abort()
			return
		}

		if !ruleFunc(claims) {
			c.JSON(http.StatusForbidden, gin.H{"error": "forbidden: ABAC rule failed"})
			c.Abort()
			return
		}

		c.Next()
	}
}

// GinRequirePermission returns a Gin middleware for permission-based access control
func GinRequirePermission(requiredPermission string) gin.HandlerFunc {
	return func(c *gin.Context) {
		claims, err := GetGinClaims(c)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized: " + err.Error()})
			c.Abort()
			return
		}

		if !extractors.HasPermission(claims, requiredPermission) {
			c.JSON(http.StatusForbidden, gin.H{"error": "forbidden: insufficient permissions"})
			c.Abort()
			return
		}

		c.Next()
	}
}

// GinRequireAdmin returns a Gin middleware for admin-only access
func GinRequireAdmin() gin.HandlerFunc {
	return GinRequireRole(utils.RoleAdmin)
}

// GinRequireModerator returns a Gin middleware for moderator or admin access
func GinRequireModerator() gin.HandlerFunc {
	return GinRequireRole(utils.RoleModerator, utils.RoleAdmin)
}

// GinRequireSensitiveAccess returns a Gin middleware for sensitive data access
func GinRequireSensitiveAccess() gin.HandlerFunc {
	return GinRequirePermission(utils.PermissionReadSensitive)
}
