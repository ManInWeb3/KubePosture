"""Proxy-forwarded JWT auth middleware.

Generic header-JWT auth for reverse-proxy front-ends that authenticate
users upstream and forward a signed JWT (Pomerium, oauth2-proxy in JWT
mode, Cloudflare Access, Authelia jwt mode, Traefik forward-auth + OIDC).

When ``JWT_AUTH_ENABLED`` is true, requests carrying a valid JWT in
``JWT_AUTH_HEADER`` are verified against ``JWT_AUTH_JWKS_URL`` and the
matching Django ``User`` is auto-created (in the ``viewer`` group on
first login). A session is started so subsequent requests skip the
verification cost.

Importer paths (``/api/v1/ingest/``, ``/api/v1/imports/``,
``/api/v1/cluster-metadata/``) and probes (``/healthz``, ``/readyz``,
``/metrics``) bypass this middleware unconditionally.

Verification failures fall through silently so ``/accounts/login/``
password auth remains available as a break-glass path.
"""
from __future__ import annotations

import logging
import threading
import time

import jwt
from django.conf import settings
from django.contrib.auth import login
from django.contrib.auth.models import Group, User
from jwt import PyJWKClient, PyJWKClientError

logger = logging.getLogger(__name__)


# Importer + probe paths that must never go through JWT auth.
BYPASS_PREFIXES: tuple[str, ...] = (
    "/api/v1/ingest/",
    "/api/v1/imports/",
    "/api/v1/cluster-metadata/",
    "/healthz",
    "/readyz",
    "/metrics",
)


class _JWKSCache:
    """Per-URL JWKS cache. PyJWKClient handles fetch + parse; we
    just bound its lifetime so key rotation eventually propagates."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        # url -> (created_at, PyJWKClient)
        self._entries: dict[str, tuple[float, PyJWKClient]] = {}

    def get(self, url: str, ttl: int) -> PyJWKClient:
        now = time.monotonic()
        with self._lock:
            entry = self._entries.get(url)
            if entry is not None and (now - entry[0]) < ttl:
                return entry[1]
            client = PyJWKClient(url, cache_keys=True)
            self._entries[url] = (now, client)
            return client

    def invalidate(self, url: str) -> None:
        with self._lock:
            self._entries.pop(url, None)


_jwks_cache = _JWKSCache()


class ProxyJWTAuthMiddleware:
    """Verify proxy-forwarded JWTs and start a Django session."""

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if not getattr(settings, "JWT_AUTH_ENABLED", False):
            return self.get_response(request)

        if request.path.startswith(BYPASS_PREFIXES):
            return self.get_response(request)

        if request.user.is_authenticated:
            return self.get_response(request)

        token = self._extract_token(request)
        if not token:
            return self.get_response(request)

        claims = self._verify(token)
        if claims is None:
            return self.get_response(request)

        try:
            user = _get_or_create_user(claims)
        except Exception:
            logger.exception("jwt_auth: user provisioning failed")
            return self.get_response(request)

        login(request, user)
        return self.get_response(request)

    # ── helpers ──

    @staticmethod
    def _extract_token(request) -> str | None:
        header_name: str = settings.JWT_AUTH_HEADER
        # Django stringifies HTTP headers as HTTP_<UPPER_UNDERSCORE>.
        meta_key = "HTTP_" + header_name.upper().replace("-", "_")
        raw = request.META.get(meta_key)
        if not raw:
            return None
        # Support both bare JWT and "Bearer <jwt>" framing (Authelia uses Bearer).
        if raw.lower().startswith("bearer "):
            return raw.split(None, 1)[1].strip() or None
        return raw.strip() or None

    def _verify(self, token: str) -> dict | None:
        jwks_url: str = settings.JWT_AUTH_JWKS_URL
        audience: str = settings.JWT_AUTH_AUDIENCE
        if not jwks_url or not audience:
            logger.warning("jwt_auth: JWT_AUTH_JWKS_URL/AUDIENCE not configured")
            return None

        ttl: int = settings.JWT_AUTH_JWKS_CACHE_TTL
        issuer: str = settings.JWT_AUTH_ISSUER or None

        for attempt in (1, 2):
            client = _jwks_cache.get(jwks_url, ttl)
            try:
                signing_key = client.get_signing_key_from_jwt(token)
                claims = jwt.decode(
                    token,
                    signing_key.key,
                    algorithms=["ES256", "RS256", "ES384", "RS384", "ES512", "RS512"],
                    audience=audience,
                    issuer=issuer,
                    options={"require": ["exp", "iat", "sub"]},
                )
                return claims
            except jwt.InvalidSignatureError:
                # Key may have rotated — invalidate cache and retry once.
                _jwks_cache.invalidate(jwks_url)
                if attempt == 2:
                    logger.warning("jwt_auth: signature invalid after JWKS refresh")
                    return None
            except (jwt.PyJWTError, PyJWKClientError) as exc:
                logger.warning("jwt_auth: verification failed: %s", exc)
                return None
        return None


def _get_or_create_user(claims: dict) -> User:
    email = (claims.get("email") or claims.get("sub") or "").lower().strip()
    if not email:
        raise ValueError("JWT has no email/sub claim")

    # Match by email (case-insensitive) so a pre-existing user created
    # via `createsuperuser` with a different username (e.g. "admin")
    # but the same real email is adopted, not duplicated. Pomerium-
    # provisioned users default to username=email; the email field is
    # the stable identity either way.
    user = User.objects.filter(email__iexact=email).first()
    if user is not None:
        return user

    name = (claims.get("name") or "").strip()
    first, _, last = name.partition(" ")
    user = User.objects.create(
        username=email,
        email=email,
        first_name=first[:30],
        last_name=last[:30],
        is_active=True,
    )
    user.set_unusable_password()
    user.save(update_fields=["password"])
    viewer = Group.objects.filter(name="viewer").first()
    if viewer is not None:
        user.groups.add(viewer)
    return user
