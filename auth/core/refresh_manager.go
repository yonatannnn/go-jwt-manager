package core

import (
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/yonatannnn/go-jwt-manager/auth/utils"
)

// RefreshManager handles refresh token generation and verification
type RefreshManager struct {
	config *TokenConfig
}

// NewRefreshManager creates a new refresh token manager
func NewRefreshManager(secretKey string, duration time.Duration) *RefreshManager {
	return &RefreshManager{
		config: NewTokenConfig(secretKey, duration),
	}
}

// NewRefreshManagerWithDefault creates a new refresh token manager with default duration
func NewRefreshManagerWithDefault(secretKey string) *RefreshManager {
	return &RefreshManager{
		config: NewTokenConfig(secretKey, utils.DefaultRefreshTokenDuration),
	}
}

// Generate creates a refresh token with a session_id or user_id
func (r *RefreshManager) Generate(attributes map[string]interface{}, customDuration ...time.Duration) (string, error) {
	duration := r.config.TokenDuration
	if len(customDuration) > 0 {
		duration = customDuration[0]
	}

	claims := jwt.MapClaims{}

	// Copy user-defined attributes to claims
	for k, v := range attributes {
		claims[k] = v
	}

	now := time.Now()
	claims[utils.ClaimType] = utils.TokenTypeRefresh
	claims[utils.ClaimIssuedAt] = now.Unix()
	claims[utils.ClaimExpiration] = now.Add(duration).Unix()

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(r.config.SecretKey))
}

// Verify parses and validates a refresh token
func (r *RefreshManager) Verify(tokenStr string) (map[string]interface{}, error) {
	token, err := jwt.Parse(tokenStr, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(r.config.SecretKey), nil
	})

	if err != nil {
		return nil, fmt.Errorf("token parsing error: %w", err)
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid {
		return nil, errors.New("invalid token")
	}

	if claims[utils.ClaimType] != utils.TokenTypeRefresh {
		return nil, errors.New("not a refresh token")
	}

	// Optional: check expiration
	if exp, ok := claims[utils.ClaimExpiration].(float64); ok {
		if time.Now().Unix() > int64(exp) {
			return nil, errors.New("refresh token expired")
		}
	}

	return claims, nil
}

// GetConfig returns the refresh token configuration
func (r *RefreshManager) GetConfig() *TokenConfig {
	return r.config
}
