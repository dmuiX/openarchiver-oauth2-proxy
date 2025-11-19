# OpenArchiver OAuth2 Proxy

This service exists purely to add OpenID Connect / OAuth2 authentication to
**OpenArchiver**. It performs the entire browser flow against your Identity
Provider, creates the exact same `accessToken` cookie/JWT that OpenArchiver
would issue after a manual login, and forwards traffic to your OpenArchiver
deployment.

To keep the JWT byte-for-byte compatible you **must** provide the same HS256
signing key that OpenArchiver uses (`JWT_SIGNING_KEY`). The proxy writes the
cookie and the downstream OpenArchiver instance accepts it as if the user had
logged in directly.

Because the `sub` claim must match the OpenArchiver user ID, you need to obtain
each user’s ID from a legitimate OpenArchiver session (inspect the original
cookie/JWT) and make sure your Identity Provider exposes that identifier either
as the user’s subject or in a dedicated claim that you map via the config.

## How it works

1. User accesses the proxy (e.g. `https://openarchiver.example.com`).
2. The proxy starts the Authorization Code + PKCE flow against your configured
   OIDC/OAuth2 provider.
3. When the callback arrives, the proxy extracts the configured claims
   (`sub`, `email`, `roles`), mints a JWT using OpenArchiver’s signing key, and
   writes the `accessToken` cookie.
4. Every subsequent request is proxied to the actual OpenArchiver instance with
   all original headers plus the trusted cookie.

## Configuration

| Variable | Purpose |
| --- | --- |
| `PROXY_LISTEN_ADDR` | Listener address (default `:8080`). |
| `TARGET_ENDPOINT_URL` | URL of your existing OpenArchiver deployment (required). |
| `JWT_SIGNING_KEY` | The HS256 key from OpenArchiver’s config (required). |
| `JWT_TTL` | Lifetime of the minted cookie (Go duration, default `1h`). |
| `COOKIE_DOMAIN` | Domain attribute for the cookie. |
| `COOKIE_SECURE` | `true` / `false` to control the Secure flag (default `true`). |
| `OIDC_CLIENT_ID` | Client ID registered in your IdP (required). |
| `OIDC_CLIENT_SECRET` | Client secret (required). |
| `OIDC_REDIRECT_URL` | Callback URL exposed by this proxy (required). |
| `OIDC_PROVIDER_URL` | Issuer URL of your IdP (required). |
| `CLAIM_SUBJECT` | Claim path that yields the OpenArchiver user ID (default `sub`). |
| `CLAIM_EMAIL` | Claim path for the user’s email (default `email`). |
| `CLAIM_ROLES` | Claim path for roles (default `roles`). |
| `ROLE_VALUE_MAP` | Optional mapping of IdP role names to OpenArchiver role names. e.g. `admin:Super Admin,viewer:Reader` |

Claim paths support dot-notation (e.g. `realm_access.roles`). If your IdP
stores the OpenArchiver user ID in a custom claim, set `CLAIM_SUBJECT` to that
path, or configure the IdP to emit the ID as the subject.

## Running the Proxy

```bash
export OIDC_CLIENT_ID=...
export OIDC_CLIENT_SECRET=...
export COOKIE_DOMAIN=openarchiver.example.com
export OIDC_REDIRECT_URL=https://openarchiver.example.com/auth/callback
export OIDC_PROVIDER_URL=https://auth.example.com/
export TARGET_ENDPOINT_URL=http://your-openarchiver-host/
export JWT_SIGNING_KEY=<same key as OpenArchiver>
go run ./cmd/server
```

Open `https://openarchiver.example.com` and complete the login flow. After authentication
the browser receives the OpenArchiver-compatible `accessToken` cookie and all
traffic is proxied to `TARGET_ENDPOINT_URL`.