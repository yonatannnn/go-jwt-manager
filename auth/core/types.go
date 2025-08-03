package core

import "time"

// TokenManager defines the interface for JWT token operations
type TokenManager interface {
	Generate(attributes map[string]interface{}, customDuration ...time.Duration) (string, error)
	Verify(tokenStr string) (map[string]interface{}, error)
	IsExpired(tokenStr string) (bool, error)
	GetExpirationTime(tokenStr string) (*time.Time, error)
}

// Claims represents JWT claims as a map
type Claims map[string]interface{}

// TokenConfig holds configuration for token generation
type TokenConfig struct {
	SecretKey     string
	TokenDuration time.Duration
}

// NewTokenConfig creates a new token configuration
func NewTokenConfig(secretKey string, duration time.Duration) *TokenConfig {
	return &TokenConfig{
		SecretKey:     secretKey,
		TokenDuration: duration,
	}
}
