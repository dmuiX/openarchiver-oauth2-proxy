package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"

	"github.com/tomfrenzel/openarchiver-oauth2-proxy/internal/config"
)

const (
	codeChallengeMethod = "S256"
	defaultStateTTL     = 10 * time.Minute
	httpTimeout         = 15 * time.Second
)

// Service wraps OIDC/OAuth2 logic, including PKCE handling.
type Service struct {
	oauth2Config *oauth2.Config
	verifier     *oidc.IDTokenVerifier
	stateStore   *stateStore
	claimsMap    config.ClaimMapping
	roleMap      map[string]string
	provider     *oidc.Provider
	httpClient   *http.Client
}

// UserClaims represents the normalized payload extracted from the ID token.
type UserClaims struct {
	Subject string
	Email   string
	Roles   []string
	Raw     map[string]any
}

// NewService creates a Service from config.
func NewService(ctx context.Context, cfg config.Config) (*Service, error) {
	httpClient := newHTTPClient()
	ctx = context.WithValue(ctx, oauth2.HTTPClient, httpClient)

	provider, err := oidc.NewProvider(ctx, cfg.ProviderURL)
	if err != nil {
		return nil, fmt.Errorf("create OIDC provider: %w", err)
	}

	verifier := provider.Verifier(&oidc.Config{ClientID: cfg.ClientID})

	oauth2Config := &oauth2.Config{
		ClientID:     cfg.ClientID,
		ClientSecret: cfg.ClientSecret,
		Endpoint:     provider.Endpoint(),
		RedirectURL:  cfg.RedirectURL,
		Scopes:       []string{oidc.ScopeOpenID, "profile", "email"},
	}

	store := newStateStore(defaultStateTTL)

	return &Service{
		oauth2Config: oauth2Config,
		verifier:     verifier,
		stateStore:   store,
		claimsMap:    cfg.ClaimMapping,
		roleMap:      cfg.RoleValueMap,
		provider:     provider,
		httpClient:   httpClient,
	}, nil
}

// BeginAuth constructs the authorization URL and stores PKCE metadata.
func (s *Service) BeginAuth(ctx context.Context, returnTo string) (string, error) {
	state, err := randomString(32)
	if err != nil {
		return "", err
	}
	codeVerifier, err := randomString(64)
	if err != nil {
		return "", err
	}
	codeChallenge := pkceChallenge(codeVerifier)

	s.stateStore.save(state, AuthSession{
		CodeVerifier: codeVerifier,
		ReturnTo:     sanitizeReturnTo(returnTo),
		CreatedAt:    time.Now(),
	})

	authURL := s.oauth2Config.AuthCodeURL(
		state,
		oauth2.SetAuthURLParam("code_challenge", codeChallenge),
		oauth2.SetAuthURLParam("code_challenge_method", codeChallengeMethod),
	)

	return authURL, nil
}

// CompleteAuth exchanges the auth code for tokens and returns mapped claims.
func (s *Service) CompleteAuth(ctx context.Context, state, code string) (UserClaims, string, error) {
	session, ok := s.stateStore.pop(state)
	if !ok {
		return UserClaims{}, "", errors.New("invalid or expired state parameter")
	}
	if code == "" {
		return UserClaims{}, "", errors.New("code is required")
	}

	token, err := s.oauth2Config.Exchange(ctx, code, oauth2.SetAuthURLParam("code_verifier", session.CodeVerifier))
	if err != nil {
		return UserClaims{}, "", fmt.Errorf("exchange auth code: %w", err)
	}

	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		return UserClaims{}, "", errors.New("id_token not found in OAuth2 token response")
	}

	idToken, err := s.verifier.Verify(ctx, rawIDToken)
	if err != nil {
		return UserClaims{}, "", fmt.Errorf("verify id_token: %w", err)
	}

	claims := map[string]any{}
	if err := idToken.Claims(&claims); err != nil {
		return UserClaims{}, "", fmt.Errorf("parse id_token claims: %w", err)
	}

	userClaims := UserClaims{
		Subject: extractStringClaim(claims, s.claimsMap.Subject),
		Email:   extractStringClaim(claims, s.claimsMap.Email),
		Roles:   applyRoleMap(extractStringSliceClaim(claims, s.claimsMap.Roles), s.roleMap),
		Raw:     claims,
	}

	if userClaims.Subject == "" {
		return UserClaims{}, "", errors.New("subject claim could not be resolved")
	}
	if userClaims.Email == "" {
		return UserClaims{}, "", errors.New("email claim could not be resolved")
	}

	return userClaims, session.ReturnTo, nil
}

func randomString(length int) (string, error) {
	buf := make([]byte, length)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("generate random string: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

func pkceChallenge(verifier string) string {
	hash := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(hash[:])
}

func sanitizeReturnTo(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" || strings.HasPrefix(raw, "//") {
		return "/"
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.IsAbs() || parsed.Host != "" || strings.Contains(parsed.Path, "//") {
		return "/"
	}
	if parsed.Path == "" {
		parsed.Path = "/"
	}
	return parsed.String()
}

func extractStringClaim(claims map[string]any, path string) string {
	value := traverseClaims(claims, path)
	if str, ok := value.(string); ok {
		return str
	}
	return ""
}

func extractStringSliceClaim(claims map[string]any, path string) []string {
	value := traverseClaims(claims, path)
	switch v := value.(type) {
	case []any:
		result := make([]string, 0, len(v))
		for _, item := range v {
			if str, ok := item.(string); ok {
				result = append(result, str)
			}
		}
		return result
	case []string:
		return v
	case string:
		return []string{v}
	default:
		return nil
	}
}

func applyRoleMap(roles []string, mapping map[string]string) []string {
	if len(roles) == 0 || len(mapping) == 0 {
		return roles
	}
	mapped := make([]string, 0, len(roles))
	for _, role := range roles {
		if newVal, ok := mapping[role]; ok {
			mapped = append(mapped, newVal)
			continue
		}
		mapped = append(mapped, role)
	}
	return mapped
}

func newHTTPClient() *http.Client {
	return &http.Client{
		Timeout: httpTimeout,
	}
}

func traverseClaims(claims map[string]any, path string) any {
	if path == "" {
		return nil
	}
	current := any(claims)
	for _, segment := range strings.Split(path, ".") {
		m, ok := current.(map[string]any)
		if !ok {
			return nil
		}
		current, ok = m[segment]
		if !ok {
			return nil
		}
	}
	return current
}
