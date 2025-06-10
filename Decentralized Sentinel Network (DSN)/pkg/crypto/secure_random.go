package crypto

import (
	"crypto/rand"
	"encoding/base32"
	"fmt"
)

// SecureIDGenerator provides cryptographically secure ID generation
type SecureIDGenerator struct {
	prefix string
	length int
}

// NewSecureIDGenerator creates a new secure ID generator
func NewSecureIDGenerator(prefix string, length int) *SecureIDGenerator {
	if length < 8 {
		length = 16 // Minimum secure length
	}
	return &SecureIDGenerator{
		prefix: prefix,
		length: length,
	}
}

// GenerateID creates a cryptographically secure random ID
func (g *SecureIDGenerator) GenerateID() (string, error) {
	// Generate cryptographically secure random bytes
	randomBytes := make([]byte, g.length)
	if _, err := rand.Read(randomBytes); err != nil {
		return "", fmt.Errorf("failed to generate secure random bytes: %w", err)
	}
	
	// Encode as base32 for readability (no padding for cleaner IDs)
	encoded := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(randomBytes)
	
	// Truncate to desired length and add prefix
	if len(encoded) > g.length {
		encoded = encoded[:g.length]
	}
	
	return fmt.Sprintf("%s-%s", g.prefix, encoded), nil
}

// GenerateSentinelID creates a secure Sentinel ID
func GenerateSentinelID() (string, error) {
	generator := NewSecureIDGenerator("sentinel", 16)
	return generator.GenerateID()
}

// GenerateAPIKey creates a secure API key
func GenerateAPIKey() (string, error) {
	generator := NewSecureIDGenerator("dsn", 32)
	return generator.GenerateID()
}

// GenerateSessionToken creates a secure session token
func GenerateSessionToken() (string, error) {
	generator := NewSecureIDGenerator("sess", 24)
	return generator.GenerateID()
}
