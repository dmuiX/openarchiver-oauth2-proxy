package config

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// Config defines the runtime configuration of the proxy.
type Config struct {
	Addr          string
	ClientID      string
	ClientSecret  string
	RedirectURL   string
	ProviderURL   string
	TargetURL     string
	JWTSigningKey string
	JWTExpiry     time.Duration
	CookieDomain  string
	CookieSecure  bool
	ClaimMapping  ClaimMapping
	RoleValueMap  map[string]string
}

// ClaimMapping allows configuring how OIDC claims map into the JWT payload.
type ClaimMapping struct {
	Subject string
	Email   string
	Roles   string
}

// Load reads configuration values from the environment.
func Load() (Config, error) {
	cfg := Config{
		Addr:          getEnv("PROXY_LISTEN_ADDR", ":8080"),
		ClientID:      os.Getenv("OIDC_CLIENT_ID"),
		ClientSecret:  os.Getenv("OIDC_CLIENT_SECRET"),
		RedirectURL:   os.Getenv("OIDC_REDIRECT_URL"),
		ProviderURL:   os.Getenv("OIDC_PROVIDER_URL"),
		TargetURL:     os.Getenv("TARGET_ENDPOINT_URL"),
		JWTSigningKey: os.Getenv("JWT_SIGNING_KEY"),
		JWTExpiry:     getDuration("JWT_TTL", time.Hour),
		CookieDomain:  os.Getenv("COOKIE_DOMAIN"),
		CookieSecure:  parseBool(getEnv("COOKIE_SECURE", "true")),
		ClaimMapping: ClaimMapping{
			Subject: getEnv("CLAIM_SUBJECT", "sub"),
			Email:   getEnv("CLAIM_EMAIL", "email"),
			Roles:   getEnv("CLAIM_ROLES", "roles"),
		},
		RoleValueMap: parseRoleMap(os.Getenv("ROLE_VALUE_MAP")),
	}

	if err := cfg.validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func (c Config) validate() error {
	var missing []string
	if c.ClientID == "" {
		missing = append(missing, "OIDC_CLIENT_ID")
	}
	if c.ClientSecret == "" {
		missing = append(missing, "OIDC_CLIENT_SECRET")
	}
	if c.RedirectURL == "" {
		missing = append(missing, "OIDC_REDIRECT_URL")
	}
	if c.ProviderURL == "" {
		missing = append(missing, "OIDC_PROVIDER_URL")
	}
	if c.TargetURL == "" {
		missing = append(missing, "TARGET_ENDPOINT_URL")
	}
	if c.JWTSigningKey == "" {
		missing = append(missing, "JWT_SIGNING_KEY")
	}
	if len(missing) > 0 {
		return fmt.Errorf("missing required configuration: %s", strings.Join(missing, ", "))
	}
	if c.JWTExpiry <= 0 {
		return errors.New("JWT_TTL must be greater than zero")
	}
	return nil
}

func getEnv(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}

func parseBool(val string) bool {
	b, err := strconv.ParseBool(val)
	if err != nil {
		return false
	}
	return b
}

func getDuration(key string, fallback time.Duration) time.Duration {
	raw := os.Getenv(key)
	if raw == "" {
		return fallback
	}
	d, err := time.ParseDuration(raw)
	if err != nil {
		return fallback
	}
	return d
}

func parseRoleMap(raw string) map[string]string {
	result := map[string]string{}
	if raw == "" {
		return result
	}
	pairs := strings.Split(raw, ",")
	for _, pair := range pairs {
		pair = strings.TrimSpace(pair)
		if pair == "" {
			continue
		}
		parts := strings.SplitN(pair, ":", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.TrimSpace(parts[0])
		val := strings.TrimSpace(parts[1])
		if key == "" || val == "" {
			continue
		}
		result[key] = val
	}
	return result
}
