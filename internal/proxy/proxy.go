package proxy

import (
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"

	"github.com/tomfrenzel/openarchiver-oauth2-proxy/internal/jwt"
)

const (
	cookieName = "accessToken"
	loginPath  = "/auth/login"
)

// Handler enforces the JWT cookie and proxies traffic to the target endpoint.
type Handler struct {
	target *url.URL
	proxy  *httputil.ReverseProxy
	jwt    *jwt.Manager
}

// New builds a proxy handler for the provided target URL.
func New(target *url.URL, jwtManager *jwt.Manager) *Handler {
	reverseProxy := httputil.NewSingleHostReverseProxy(target)
	reverseProxy.Director = func(req *http.Request) {
		req.URL.Scheme = target.Scheme
		req.URL.Host = target.Host
		req.URL.Path = singleJoin(target.Path, req.URL.Path)
		req.Host = target.Host
		if req.Header.Get("X-Forwarded-Host") == "" {
			req.Header.Set("X-Forwarded-Host", req.Host)
		}
		if req.Header.Get("X-Forwarded-Proto") == "" {
			req.Header.Set("X-Forwarded-Proto", req.URL.Scheme)
		}
	}

	return &Handler{
		target: target,
		proxy:  reverseProxy,
		jwt:    jwtManager,
	}
}

// ServeHTTP validates the access cookie and forwards traffic to the target.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie(cookieName)
	if err != nil || cookie.Value == "" {
		redirectToLogin(w, r)
		return
	}

	_, err = h.jwt.Verify(cookie.Value)
	if err != nil {
		clearCookie(w)
		redirectToLogin(w, r)
		return
	}

	propagateCookie(r, cookie.Value)

	h.proxy.ServeHTTP(w, r)
}

func propagateCookie(r *http.Request, accessToken string) {
	cookieHeader := r.Header.Get("Cookie")
	newCookie := cookieName + "=" + accessToken
	if cookieHeader == "" {
		r.Header.Set("Cookie", newCookie)
		return
	}
	if !strings.Contains(cookieHeader, cookieName+"=") {
		r.Header.Set("Cookie", cookieHeader+"; "+newCookie)
	}
}

func redirectToLogin(w http.ResponseWriter, r *http.Request) {
	returnTo := url.QueryEscape(r.URL.RequestURI())
	http.Redirect(w, r, loginPath+"?return_to="+returnTo, http.StatusFound)
}

func clearCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     cookieName,
		Value:    "",
		MaxAge:   -1,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
}

func singleJoin(a, b string) string {
	aslash := strings.HasSuffix(a, "/")
	bslash := strings.HasPrefix(b, "/")
	switch {
	case aslash && bslash:
		return a + b[1:]
	case !aslash && !bslash:
		return a + "/" + b
	default:
		return a + b
	}
}
