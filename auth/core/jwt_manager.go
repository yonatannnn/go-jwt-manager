package core

import (
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/yonatannnn/go-jwt-manager/auth/utils"
)

// JWTManager handles JWT token generation and verification
type JWTManager struct {
	config *TokenConfig
}

// NewJWTManager creates a new JWT manager with default 15-minute token expiration
func NewJWTManager(secretKey string) *JWTManager {
	return &JWTManager{
		config: NewTokenConfig(secretKey, utils.DefaultTokenDuration),
	}
}

// NewJWTManagerWithDuration creates a new JWT manager with custom duration
func NewJWTManagerWithDuration(secretKey string, duration time.Duration) *JWTManager {
	return &JWTManager{
		config: NewTokenConfig(secretKey, duration),
	}
}

// Generate creates a JWT token from a user-defined map of attributes
func (m *JWTManager) Generate(attributes map[string]interface{}, customDuration ...time.Duration) (string, error) {
	// Allow override of the default duration
	duration := m.config.TokenDuration
	if len(customDuration) > 0 {
		duration = customDuration[0]
	}

	claims := jwt.MapClaims{}

	// Copy all user-defined attributes into claims
	for k, v := range attributes {
		claims[k] = v
	}

	// Add standard claims
	now := time.Now()
	claims[utils.ClaimIssuedAt] = now.Unix()

	// Only add expiration if duration is not zero
	if duration > 0 {
		claims[utils.ClaimExpiration] = now.Add(duration).Unix()
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(m.config.SecretKey))
}

// GenerateForUser is a convenience method for common user authentication scenarios
func (m *JWTManager) GenerateForUser(userID string, email string, roles []string, customDuration ...time.Duration) (string, error) {
	attributes := map[string]interface{}{
		utils.ClaimUserID:  userID,
		utils.ClaimEmail:   email,
		utils.ClaimRoles:   roles,
		utils.ClaimSubject: userID,
		utils.ClaimIssuer:  "auth-service",
		utils.ClaimType:    utils.TokenTypeAccess,
	}
	return m.Generate(attributes, customDuration...)
}

// GenerateForService is a convenience method for service-to-service authentication
func (m *JWTManager) GenerateForService(serviceID string, permissions []string, customDuration ...time.Duration) (string, error) {
	attributes := map[string]interface{}{
		"service_id":           serviceID,
		utils.ClaimPermissions: permissions,
		utils.ClaimSubject:     serviceID,
		utils.ClaimIssuer:      "auth-service",
		utils.ClaimType:        utils.TokenTypeService,
	}
	return m.Generate(attributes, customDuration...)
}

// Verify decodes and verifies a JWT token, returning its claims
func (m *JWTManager) Verify(tokenStr string) (map[string]interface{}, error) {
	token, err := jwt.Parse(tokenStr, func(token *jwt.Token) (interface{}, error) {
		// Validate signing method
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(m.config.SecretKey), nil
	})

	if err != nil {
		return nil, fmt.Errorf("token parsing error: %w", err)
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid {
		return nil, errors.New("invalid token claims")
	}

	// Optional: check token expiration manually
	if exp, ok := claims[utils.ClaimExpiration].(float64); ok {
		if time.Now().Unix() > int64(exp) {
			return nil, errors.New("token expired")
		}
	}

	return claims, nil
}

// IsExpired checks if a token is expired without full verification
func (m *JWTManager) IsExpired(tokenStr string) (bool, error) {
	token, err := jwt.Parse(tokenStr, func(token *jwt.Token) (interface{}, error) {
		return []byte(m.config.SecretKey), nil
	})

	if err != nil {
		return false, err
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return false, errors.New("invalid claims")
	}

	if exp, ok := claims[utils.ClaimExpiration].(float64); ok {
		return time.Now().Unix() > int64(exp), nil
	}

	return false, nil
}

// GetExpirationTime returns the expiration time of a token
func (m *JWTManager) GetExpirationTime(tokenStr string) (*time.Time, error) {
	token, err := jwt.Parse(tokenStr, func(token *jwt.Token) (interface{}, error) {
		return []byte(m.config.SecretKey), nil
	})

	if err != nil {
		return nil, err
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, errors.New("invalid claims")
	}

	if exp, ok := claims[utils.ClaimExpiration].(float64); ok {
		expTime := time.Unix(int64(exp), 0)
		return &expTime, nil
	}

	return nil, errors.New("no expiration time found")
}

// GetConfig returns the token configuration
func (m *JWTManager) GetConfig() *TokenConfig {
	return m.config
}
