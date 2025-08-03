package auth

// Core JWT functionality
import (
	"github.com/yonatannnn/go-jwt-manager/auth/core"
	"github.com/yonatannnn/go-jwt-manager/auth/extractors"
	"github.com/yonatannnn/go-jwt-manager/auth/middleware"
)

// Re-export core types for convenience
type (
	JWTManager     = core.JWTManager
	RefreshManager = core.RefreshManager
	TokenManager   = core.TokenManager
	TokenConfig    = core.TokenConfig
	Claims         = core.Claims
)

// Re-export core constructors
var (
	NewJWTManager                = core.NewJWTManager
	NewJWTManagerWithDuration    = core.NewJWTManagerWithDuration
	NewRefreshManager            = core.NewRefreshManager
	NewRefreshManagerWithDefault = core.NewRefreshManagerWithDefault
	NewTokenConfig               = core.NewTokenConfig
)

// Re-export data extraction functions
var (
	// Basic extraction
	ExtractString               = extractors.ExtractString
	ExtractStringOrDefault      = extractors.ExtractStringOrDefault
	ExtractInt                  = extractors.ExtractInt
	ExtractIntOrDefault         = extractors.ExtractIntOrDefault
	ExtractFloat                = extractors.ExtractFloat
	ExtractFloatOrDefault       = extractors.ExtractFloatOrDefault
	ExtractBool                 = extractors.ExtractBool
	ExtractBoolOrDefault        = extractors.ExtractBoolOrDefault
	ExtractStringSlice          = extractors.ExtractStringSlice
	ExtractStringSliceOrDefault = extractors.ExtractStringSliceOrDefault
	ExtractMap                  = extractors.ExtractMap
	ExtractMapOrDefault         = extractors.ExtractMapOrDefault

	// Common JWT claims
	GetUserID      = extractors.GetUserID
	GetEmail       = extractors.GetEmail
	GetRoles       = extractors.GetRoles
	GetPermissions = extractors.GetPermissions
	GetSubject     = extractors.GetSubject
	GetIssuer      = extractors.GetIssuer
	GetAudience    = extractors.GetAudience

	// Role and permission validation
	HasRole           = extractors.HasRole
	HasAnyRole        = extractors.HasAnyRole
	HasAllRoles       = extractors.HasAllRoles
	HasPermission     = extractors.HasPermission
	HasAnyPermission  = extractors.HasAnyPermission
	HasAllPermissions = extractors.HasAllPermissions
	IsAdmin           = extractors.IsAdmin
	IsUser            = extractors.IsUser
	IsModerator       = extractors.IsModerator
	CanReadSensitive  = extractors.CanReadSensitive
	CanWriteData      = extractors.CanWriteData
	HasAdminAccess    = extractors.HasAdminAccess
)

// Re-export HTTP middleware
var (
	AuthMiddleware         = middleware.AuthMiddleware
	GetUserClaims          = middleware.GetUserClaims
	RequireRole            = middleware.RequireRole
	RequireABAC            = middleware.RequireABAC
	RequirePermission      = middleware.RequirePermission
	RequireAdmin           = middleware.RequireAdmin
	RequireModerator       = middleware.RequireModerator
	RequireSensitiveAccess = middleware.RequireSensitiveAccess
)

// Re-export Gin middleware
var (
	GinAuthMiddleware         = middleware.GinAuthMiddleware
	GetGinClaims              = middleware.GetGinClaims
	GinRequireRole            = middleware.GinRequireRole
	GinRequireABAC            = middleware.GinRequireABAC
	GinRequirePermission      = middleware.GinRequirePermission
	GinRequireAdmin           = middleware.GinRequireAdmin
	GinRequireModerator       = middleware.GinRequireModerator
	GinRequireSensitiveAccess = middleware.GinRequireSensitiveAccess
)
