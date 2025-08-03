package extractors

import (
	"fmt"

	"github.com/yonatannnn/go-jwt-manager/auth/utils"
)

// ExtractString safely extracts a string value from claims
func ExtractString(claims map[string]interface{}, key string) (string, error) {
	if value, ok := claims[key]; ok {
		if str, ok := value.(string); ok {
			return str, nil
		}
		return "", fmt.Errorf("claim '%s' is not a string", key)
	}
	return "", fmt.Errorf("claim '%s' not found", key)
}

// ExtractStringOrDefault safely extracts a string value from claims with a default
func ExtractStringOrDefault(claims map[string]interface{}, key, defaultValue string) string {
	if value, ok := claims[key]; ok {
		if str, ok := value.(string); ok {
			return str
		}
	}
	return defaultValue
}

// ExtractInt safely extracts an int value from claims
func ExtractInt(claims map[string]interface{}, key string) (int, error) {
	if value, ok := claims[key]; ok {
		switch v := value.(type) {
		case int:
			return v, nil
		case float64:
			return int(v), nil
		case int64:
			return int(v), nil
		default:
			return 0, fmt.Errorf("claim '%s' is not a number", key)
		}
	}
	return 0, fmt.Errorf("claim '%s' not found", key)
}

// ExtractIntOrDefault safely extracts an int value from claims with a default
func ExtractIntOrDefault(claims map[string]interface{}, key string, defaultValue int) int {
	if value, ok := claims[key]; ok {
		switch v := value.(type) {
		case int:
			return v
		case float64:
			return int(v)
		case int64:
			return int(v)
		}
	}
	return defaultValue
}

// ExtractFloat safely extracts a float value from claims
func ExtractFloat(claims map[string]interface{}, key string) (float64, error) {
	if value, ok := claims[key]; ok {
		switch v := value.(type) {
		case float64:
			return v, nil
		case int:
			return float64(v), nil
		case int64:
			return float64(v), nil
		default:
			return 0, fmt.Errorf("claim '%s' is not a number", key)
		}
	}
	return 0, fmt.Errorf("claim '%s' not found", key)
}

// ExtractFloatOrDefault safely extracts a float value from claims with a default
func ExtractFloatOrDefault(claims map[string]interface{}, key string, defaultValue float64) float64 {
	if value, ok := claims[key]; ok {
		switch v := value.(type) {
		case float64:
			return v
		case int:
			return float64(v)
		case int64:
			return float64(v)
		}
	}
	return defaultValue
}

// ExtractBool safely extracts a boolean value from claims
func ExtractBool(claims map[string]interface{}, key string) (bool, error) {
	if value, ok := claims[key]; ok {
		if b, ok := value.(bool); ok {
			return b, nil
		}
		return false, fmt.Errorf("claim '%s' is not a boolean", key)
	}
	return false, fmt.Errorf("claim '%s' not found", key)
}

// ExtractBoolOrDefault safely extracts a boolean value from claims with a default
func ExtractBoolOrDefault(claims map[string]interface{}, key string, defaultValue bool) bool {
	if value, ok := claims[key]; ok {
		if b, ok := value.(bool); ok {
			return b
		}
	}
	return defaultValue
}

// ExtractStringSlice safely extracts a string slice from claims
func ExtractStringSlice(claims map[string]interface{}, key string) ([]string, error) {
	if value, ok := claims[key]; ok {
		if slice, ok := value.([]interface{}); ok {
			result := make([]string, len(slice))
			for i, item := range slice {
				if str, ok := item.(string); ok {
					result[i] = str
				} else {
					return nil, fmt.Errorf("claim '%s' contains non-string elements", key)
				}
			}
			return result, nil
		}
		return nil, fmt.Errorf("claim '%s' is not a slice", key)
	}
	return nil, fmt.Errorf("claim '%s' not found", key)
}

// ExtractStringSliceOrDefault safely extracts a string slice from claims with a default
func ExtractStringSliceOrDefault(claims map[string]interface{}, key string, defaultValue []string) []string {
	if value, ok := claims[key]; ok {
		if slice, ok := value.([]interface{}); ok {
			result := make([]string, len(slice))
			for i, item := range slice {
				if str, ok := item.(string); ok {
					result[i] = str
				} else {
					return defaultValue
				}
			}
			return result
		}
	}
	return defaultValue
}

// ExtractMap safely extracts a map from claims
func ExtractMap(claims map[string]interface{}, key string) (map[string]interface{}, error) {
	if value, ok := claims[key]; ok {
		if m, ok := value.(map[string]interface{}); ok {
			return m, nil
		}
		return nil, fmt.Errorf("claim '%s' is not a map", key)
	}
	return nil, fmt.Errorf("claim '%s' not found", key)
}

// ExtractMapOrDefault safely extracts a map from claims with a default
func ExtractMapOrDefault(claims map[string]interface{}, key string, defaultValue map[string]interface{}) map[string]interface{} {
	if value, ok := claims[key]; ok {
		if m, ok := value.(map[string]interface{}); ok {
			return m
		}
	}
	return defaultValue
}

// GetUserID safely extracts user_id from claims
func GetUserID(claims map[string]interface{}) (string, error) {
	return ExtractString(claims, utils.ClaimUserID)
}

// GetEmail safely extracts email from claims
func GetEmail(claims map[string]interface{}) (string, error) {
	return ExtractString(claims, utils.ClaimEmail)
}

// GetRoles safely extracts roles from claims
func GetRoles(claims map[string]interface{}) ([]string, error) {
	return ExtractStringSlice(claims, utils.ClaimRoles)
}

// GetPermissions safely extracts permissions from claims
func GetPermissions(claims map[string]interface{}) ([]string, error) {
	return ExtractStringSlice(claims, utils.ClaimPermissions)
}

// GetSubject safely extracts sub (subject) from claims
func GetSubject(claims map[string]interface{}) (string, error) {
	return ExtractString(claims, utils.ClaimSubject)
}

// GetIssuer safely extracts iss (issuer) from claims
func GetIssuer(claims map[string]interface{}) (string, error) {
	return ExtractString(claims, utils.ClaimIssuer)
}

// GetAudience safely extracts aud (audience) from claims
func GetAudience(claims map[string]interface{}) (string, error) {
	return ExtractString(claims, utils.ClaimAudience)
}
