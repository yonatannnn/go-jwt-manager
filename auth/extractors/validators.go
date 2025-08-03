package extractors

import (
	"github.com/yonatannnn/go-jwt-manager/auth/utils"
)

// HasRole checks if the user has a specific role
func HasRole(claims map[string]interface{}, role string) bool {
	roles, err := GetRoles(claims)
	if err != nil {
		return false
	}
	for _, r := range roles {
		if r == role {
			return true
		}
	}
	return false
}

// HasAnyRole checks if the user has any of the specified roles
func HasAnyRole(claims map[string]interface{}, roles ...string) bool {
	for _, role := range roles {
		if HasRole(claims, role) {
			return true
		}
	}
	return false
}

// HasAllRoles checks if the user has all of the specified roles
func HasAllRoles(claims map[string]interface{}, roles ...string) bool {
	for _, role := range roles {
		if !HasRole(claims, role) {
			return false
		}
	}
	return true
}

// HasPermission checks if the user has a specific permission
func HasPermission(claims map[string]interface{}, permission string) bool {
	permissions, err := GetPermissions(claims)
	if err != nil {
		return false
	}
	for _, p := range permissions {
		if p == permission {
			return true
		}
	}
	return false
}

// HasAnyPermission checks if the user has any of the specified permissions
func HasAnyPermission(claims map[string]interface{}, permissions ...string) bool {
	for _, permission := range permissions {
		if HasPermission(claims, permission) {
			return true
		}
	}
	return false
}

// HasAllPermissions checks if the user has all of the specified permissions
func HasAllPermissions(claims map[string]interface{}, permissions ...string) bool {
	for _, permission := range permissions {
		if !HasPermission(claims, permission) {
			return false
		}
	}
	return true
}

// IsAdmin checks if the user has admin role
func IsAdmin(claims map[string]interface{}) bool {
	return HasRole(claims, utils.RoleAdmin)
}

// IsUser checks if the user has user role
func IsUser(claims map[string]interface{}) bool {
	return HasRole(claims, utils.RoleUser)
}

// IsModerator checks if the user has moderator role
func IsModerator(claims map[string]interface{}) bool {
	return HasRole(claims, utils.RoleModerator)
}

// CanReadSensitive checks if the user has read:sensitive permission
func CanReadSensitive(claims map[string]interface{}) bool {
	return HasPermission(claims, utils.PermissionReadSensitive)
}

// CanWriteData checks if the user has write:data permission
func CanWriteData(claims map[string]interface{}) bool {
	return HasPermission(claims, utils.PermissionWriteData)
}

// HasAdminAccess checks if the user has admin:all permission
func HasAdminAccess(claims map[string]interface{}) bool {
	return HasPermission(claims, utils.PermissionAdminAll)
}
