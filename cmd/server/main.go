package main

import (
	"context"
	"log"
	"net/http"
	"net/url"
	"time"

	"github.com/tomfrenzel/openarchiver-oauth2-proxy/internal/auth"
	"github.com/tomfrenzel/openarchiver-oauth2-proxy/internal/config"
	"github.com/tomfrenzel/openarchiver-oauth2-proxy/internal/jwt"
	"github.com/tomfrenzel/openarchiver-oauth2-proxy/internal/proxy"
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("load config: %v", err)
	}

	ctx := context.Background()
	authService, err := auth.NewService(ctx, cfg)
	if err != nil {
		log.Fatalf("create auth service: %v", err)
	}

	jwtManager, err := jwt.NewManager(cfg.JWTSigningKey, cfg.JWTExpiry)
	if err != nil {
		log.Fatalf("init jwt manager: %v", err)
	}

	targetURL, err := url.Parse(cfg.TargetURL)
	if err != nil {
		log.Fatalf("parse target url: %v", err)
	}

	proxyHandler := proxy.New(targetURL, jwtManager)
	srv := &server{
		cfg:         cfg,
		authService: authService,
		jwtManager:  jwtManager,
		proxy:       proxyHandler,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/auth/login", srv.loginHandler)
	mux.HandleFunc("/auth/callback", srv.callbackHandler)
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	})
	mux.Handle("/", proxyHandler)

	httpServer := &http.Server{
		Addr:         cfg.Addr,
		Handler:      mux,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	log.Printf("OIDC proxy listening on %s, forwarding to %s", cfg.Addr, cfg.TargetURL)
	if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("server error: %v", err)
	}
}

type server struct {
	cfg         config.Config
	authService *auth.Service
	jwtManager  *jwt.Manager
	proxy       http.Handler
}

func (s *server) loginHandler(w http.ResponseWriter, r *http.Request) {
	returnTo := r.URL.Query().Get("return_to")
	authURL, err := s.authService.BeginAuth(r.Context(), returnTo)
	if err != nil {
		http.Error(w, "failed to start authentication", http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, authURL, http.StatusFound)
}

func (s *server) callbackHandler(w http.ResponseWriter, r *http.Request) {
	state := r.URL.Query().Get("state")
	code := r.URL.Query().Get("code")

	userClaims, returnTo, err := s.authService.CompleteAuth(r.Context(), state, code)
	if err != nil {
		http.Error(w, "authentication failed: "+err.Error(), http.StatusUnauthorized)
		return
	}

	token, exp, err := s.jwtManager.Mint(jwt.TokenPayload{
		Subject: userClaims.Subject,
		Email:   userClaims.Email,
		Roles:   defaultRoles(userClaims.Roles),
	})
	if err != nil {
		http.Error(w, "could not create session", http.StatusInternalServerError)
		return
	}

	setAccessCookie(w, s.cfg, token, exp)
	http.Redirect(w, r, returnTo, http.StatusFound)
}

func setAccessCookie(w http.ResponseWriter, cfg config.Config, token string, exp time.Time) {
	cookie := &http.Cookie{
		Name:     "accessToken",
		Value:    token,
		Expires:  exp,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   cfg.CookieSecure,
	}
	if cfg.CookieDomain != "" {
		cookie.Domain = cfg.CookieDomain
	}
	http.SetCookie(w, cookie)
}

func defaultRoles(roles []string) []string {
	if len(roles) == 0 {
		return []string{"Super Admin"}
	}
	return roles
}
