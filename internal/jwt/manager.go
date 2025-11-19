package jwt

import (
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Manager issues and verifies HS256 JWTs for the proxy cookie.
type Manager struct {
	key []byte
	ttl time.Duration
}

// NewManager constructs a Manager with shared secret key.
func NewManager(signingKey string, ttl time.Duration) (*Manager, error) {
	if signingKey == "" {
		return nil, errors.New("signing key is required")
	}
	if ttl <= 0 {
		ttl = time.Hour
	}
	return &Manager{
		key: []byte(signingKey),
		ttl: ttl,
	}, nil
}

// TokenPayload describes the JWT payload.
type TokenPayload struct {
	Subject string
	Email   string
	Roles   []string
}

// Mint creates a signed JWT and returns the serialized token and expiry.
func (m *Manager) Mint(payload TokenPayload) (string, time.Time, error) {
	now := time.Now()
	exp := now.Add(m.ttl)
	claims := jwt.MapClaims{
		"sub":   payload.Subject,
		"email": payload.Email,
		"roles": payload.Roles,
		"iat":   now.Unix(),
		"exp":   exp.Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := token.SignedString(m.key)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("sign jwt: %w", err)
	}
	return signed, exp, nil
}

// Verify validates a serialized JWT and returns the claims.
func (m *Manager) Verify(tokenString string) (jwt.MapClaims, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (any, error) {
		if token.Method != jwt.SigningMethodHS256 {
			return nil, fmt.Errorf("unexpected signing method: %s", token.Header["alg"])
		}
		return m.key, nil
	})
	if err != nil {
		return nil, err
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid {
		return nil, errors.New("invalid token claims")
	}
	return claims, nil
}
