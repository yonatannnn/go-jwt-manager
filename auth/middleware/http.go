package middleware

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/yonatannnn/go-jwt-manager/auth/core"
	"github.com/yonatannnn/go-jwt-manager/auth/extractors"
	"github.com/yonatannnn/go-jwt-manager/auth/utils"
)

// 👤 Key type to avoid collisions in context
type contextKey string

const userClaimsKey contextKey = "userClaims"

// AuthMiddleware returns a middleware that:
// - Extracts the token from Authorization header
// - Verifies it
// - Stores claims in the request context
func AuthMiddleware(manager *core.JWTManager) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			authHeader := r.Header.Get("Authorization")
			if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
				http.Error(w, "missing or invalid Authorization header", http.StatusUnauthorized)
				return
			}

			tokenStr := strings.TrimPrefix(authHeader, "Bearer ")
			claims, err := manager.Verify(tokenStr)
			if err != nil {
				http.Error(w, "invalid token: "+err.Error(), http.StatusUnauthorized)
				return
			}

			// Add claims to context
			ctx := context.WithValue(r.Context(), userClaimsKey, claims)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// Helper to extract user claims from context
func GetUserClaims(r *http.Request) (map[string]interface{}, error) {
	claims := r.Context().Value(userClaimsKey)
	if claims == nil {
		return nil, errors.New("no claims in context")
	}
	casted, ok := claims.(map[string]interface{})
	if !ok {
		return nil, errors.New("invalid claims format")
	}
	return casted, nil
}

// 🔐 RequireRole middleware: allow only users with specific roles
func RequireRole(allowedRoles ...string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			claims, err := GetUserClaims(r)
			if err != nil {
				http.Error(w, "unauthorized: "+err.Error(), http.StatusUnauthorized)
				return
			}

			if !extractors.HasAnyRole(claims, allowedRoles...) {
				http.Error(w, "forbidden: insufficient role", http.StatusForbidden)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// 🧠 RequireABAC middleware: pass a function to evaluate access rules
func RequireABAC(ruleFunc func(map[string]interface{}) bool) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			claims, err := GetUserClaims(r)
			if err != nil {
				http.Error(w, "unauthorized: "+err.Error(), http.StatusUnauthorized)
				return
			}

			if !ruleFunc(claims) {
				http.Error(w, "forbidden: ABAC rule failed", http.StatusForbidden)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// RequirePermission middleware for permission-based access control
func RequirePermission(requiredPermission string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			claims, err := GetUserClaims(r)
			if err != nil {
				http.Error(w, "unauthorized: "+err.Error(), http.StatusUnauthorized)
				return
			}

			if !extractors.HasPermission(claims, requiredPermission) {
				http.Error(w, "forbidden: insufficient permissions", http.StatusForbidden)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// RequireAdmin middleware for admin-only access
func RequireAdmin() func(http.Handler) http.Handler {
	return RequireRole(utils.RoleAdmin)
}

// RequireModerator middleware for moderator or admin access
func RequireModerator() func(http.Handler) http.Handler {
	return RequireRole(utils.RoleModerator, utils.RoleAdmin)
}

// RequireSensitiveAccess middleware for sensitive data access
func RequireSensitiveAccess() func(http.Handler) http.Handler {
	return RequirePermission(utils.PermissionReadSensitive)
}
