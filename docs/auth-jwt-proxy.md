# Proxy-Forwarded JWT Auth

KubePosture's UI can be gated by a reverse-proxy that authenticates users
upstream and forwards a signed JWT in a request header. The Django
middleware verifies the JWT against the proxy's JWKS endpoint and
auto-creates the matching `User` in the `viewer` group on first login —
no manual user provisioning, no shared password.

Same pattern as Grafana's `GF_AUTH_JWT` integration. Compatible with
Pomerium, oauth2-proxy (JWT mode), Cloudflare Access, Authelia (jwt
mode), and Traefik forward-auth with an OIDC plugin.

## How it works

1. Proxy authenticates the user against an IdP (Google, Okta, …).
2. Proxy mints a short-lived JWT signed with its own key, places it in a
   request header (e.g. `X-Pomerium-Jwt-Assertion`), and forwards the
   request to KubePosture.
3. `ProxyJWTAuthMiddleware` reads the header, fetches the proxy's JWKS
   (cached), verifies signature + `aud` + `exp`.
4. On first verification for an email, a Django `User` is created with
   an unusable password and added to the `viewer` group.
5. `login()` mints a session — subsequent requests skip the JWT path.

Bypass paths (always unauth or bearer-token auth):
`/api/v1/ingest/`, `/api/v1/imports/`, `/api/v1/cluster-metadata/`,
`/healthz`, `/readyz`, `/metrics`.

Verification failures fall through silently — `/accounts/login/`
password auth stays available as a break-glass path for the initial
superuser.

## Settings

| Env var | Default | Purpose |
| --- | --- | --- |
| `JWT_AUTH_ENABLED` | `false` | Master switch. |
| `JWT_AUTH_HEADER` | `X-Pomerium-Jwt-Assertion` | Header carrying the JWT. `Bearer …` framing is also accepted. |
| `JWT_AUTH_JWKS_URL` | — | URL of the proxy's JWKS. |
| `JWT_AUTH_AUDIENCE` | — | Expected `aud` claim. For Pomerium: the route's `from` hostname. |
| `JWT_AUTH_ISSUER` | — | Optional `iss` claim check. |
| `JWT_AUTH_JWKS_CACHE_TTL` | `3600` | JWKS cache lifetime in seconds. |

## Pomerium preset

Add the route in your gitops repo (the chart does not ship a Pomerium
Ingress — values stay external):

```yaml
# Pomerium route — pass_identity_headers forwards X-Pomerium-Jwt-Assertion.
from: https://kubeposture.someorg.xyz
to: http://kubeposture-web.kubeposture.svc.cluster.local:8000
policy:
  - allow:
      and:
        - authenticated_user: {}
pass_identity_headers: true
```

KubePosture chart values:

```yaml
app:
  env:
    JWT_AUTH_ENABLED: "true"
    JWT_AUTH_HEADER: "X-Pomerium-Jwt-Assertion"
    JWT_AUTH_JWKS_URL: "https://authenticate.pomerium.someorg.xyz/.well-known/pomerium/jwks.json"
    JWT_AUTH_AUDIENCE: "kubeposture.someorg.xyz"
    JWT_AUTH_ISSUER: "authenticate.pomerium.someorg.xyz"
```

## Other proxies

| Proxy | `JWT_AUTH_HEADER` | `JWT_AUTH_JWKS_URL` |
| --- | --- | --- |
| oauth2-proxy (JWT mode) | `X-Forwarded-Access-Token` | Your IdP's JWKS (`<issuer>/.well-known/jwks.json`). |
| Cloudflare Access | `Cf-Access-Jwt-Assertion` | `https://<team>.cloudflareaccess.com/cdn-cgi/access/certs` |
| Authelia (jwt mode) | `Authorization` (Bearer) | Authelia's `/jwks.json`. |

`JWT_AUTH_AUDIENCE` is always the public hostname users hit.

## Day-2 ops

**Promote a user.** New users land in `viewer`. To grant
`SecEngineer` or `admin`: `/admin/` → Users → pick the user → add to
the group. Promotions stick across logins (the middleware never
downgrades existing group memberships).

**Revoke a user.** Set `is_active=False` in `/admin/`. The proxy will
still let them through, but Django will reject the request. (Removing
their access at the IdP/proxy layer is cleaner — handle there too.)

**Sign out.** Django's `/accounts/logout/` clears the local session but
the proxy will silently sign the user back in on the next request.
True logout means hitting the proxy's sign-out URL
(`/.pomerium/sign_out` for Pomerium).

## Trust model

The JWT is signature-verified against the proxy's published JWKS, so
header spoofing by a pod-direct request can't bypass auth — same
guarantee Grafana's JWT mode gives. The proxy must be reachable on the
network path the JWKS URL resolves to (typically in-cluster DNS or a
public HTTPS endpoint).
