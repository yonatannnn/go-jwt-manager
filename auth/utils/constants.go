package utils

import "time"

// Default token duration
const DefaultTokenDuration = 15 * time.Minute

// Default refresh token duration (7 days)
const DefaultRefreshTokenDuration = 7 * 24 * time.Hour

// Common JWT claim keys
const (
	ClaimUserID      = "user_id"
	ClaimEmail       = "email"
	ClaimRoles       = "roles"
	ClaimPermissions = "permissions"
	ClaimSubject     = "sub"
	ClaimIssuer      = "iss"
	ClaimAudience    = "aud"
	ClaimExpiration  = "exp"
	ClaimIssuedAt    = "iat"
	ClaimType        = "type"
)

// Token types
const (
	TokenTypeAccess  = "access"
	TokenTypeRefresh = "refresh"
	TokenTypeService = "service"
)

// Common roles
const (
	RoleAdmin     = "admin"
	RoleUser      = "user"
	RoleModerator = "moderator"
)

// Common permissions
const (
	PermissionReadSensitive = "read:sensitive"
	PermissionWriteData     = "write:data"
	PermissionAdminAll      = "admin:all"
)

// Context keys
const (
	UserClaimsKey = "userClaims"
	JWTClaimsKey  = "jwt_claims"
)
