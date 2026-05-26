"""Tests for the proxy-forwarded JWT auth middleware."""
from __future__ import annotations

import time

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import ec
from django.contrib.auth.models import Group, User
from django.core.management import call_command
from django.test import override_settings

from core.middleware import jwt_auth


# ── Test keypair + fake JWKS client ─────────────────────────────


@pytest.fixture
def keypair():
    priv = ec.generate_private_key(ec.SECP256R1())
    return priv, priv.public_key()


class _FakeKey:
    def __init__(self, key):
        self.key = key


class _FakeJWKClient:
    def __init__(self, pub):
        self._pub = pub

    def get_signing_key_from_jwt(self, token):  # noqa: ARG002
        return _FakeKey(self._pub)


@pytest.fixture
def fake_jwks(keypair, monkeypatch):
    _, pub = keypair
    client = _FakeJWKClient(pub)

    def fake_get(url, ttl):  # noqa: ARG001
        return client

    monkeypatch.setattr(jwt_auth._jwks_cache, "get", fake_get)
    monkeypatch.setattr(jwt_auth._jwks_cache, "invalidate", lambda url: None)
    return client


@pytest.fixture
def groups(db):
    call_command("setup_rbac")
    return {g.name: g for g in Group.objects.filter(name__in=["viewer", "SecEngineer", "admin"])}


@pytest.fixture
def jwt_settings():
    overrides = dict(
        JWT_AUTH_ENABLED=True,
        JWT_AUTH_HEADER="X-Pomerium-Jwt-Assertion",
        JWT_AUTH_JWKS_URL="https://example.test/jwks.json",
        JWT_AUTH_AUDIENCE="kubeposture.test",
        JWT_AUTH_ISSUER="",
        JWT_AUTH_JWKS_CACHE_TTL=3600,
    )
    with override_settings(**overrides):
        yield overrides


def _make_jwt(priv, *, email="alice@example.test", name="Alice Example",
              aud="kubeposture.test", iss=None, exp_offset=600, sub=None):
    now = int(time.time())
    payload = {
        "sub": sub or email,
        "email": email,
        "name": name,
        "aud": aud,
        "iat": now,
        "exp": now + exp_offset,
    }
    if iss:
        payload["iss"] = iss
    return jwt.encode(payload, priv, algorithm="ES256")


# ── 1) Missing header → falls through to LoginRequiredMixin ───────


def test_missing_header_redirects_to_login(client, db, jwt_settings):
    response = client.get("/workloads/")
    assert response.status_code == 302
    assert "/accounts/login/" in response["Location"]


# ── 2) Valid JWT, new user → created in viewer ───────────────────


def test_valid_jwt_creates_viewer_user(client, db, groups, fake_jwks, keypair, jwt_settings):
    priv, _ = keypair
    token = _make_jwt(priv, email="newuser@example.test", name="New User")
    response = client.get("/workloads/", HTTP_X_POMERIUM_JWT_ASSERTION=token)
    assert response.status_code == 200
    user = User.objects.get(username="newuser@example.test")
    assert user.email == "newuser@example.test"
    assert user.first_name == "New"
    assert user.last_name == "User"
    assert not user.has_usable_password()
    assert list(user.groups.values_list("name", flat=True)) == ["viewer"]
    # Session cookie was set.
    assert "sessionid" in response.cookies


# ── 3) Valid JWT, existing user → no new user row ────────────────


def test_valid_jwt_reuses_existing_user(client, db, groups, fake_jwks, keypair, jwt_settings):
    priv, _ = keypair
    User.objects.create_user(username="alice@example.test", email="alice@example.test")
    before = User.objects.count()
    token = _make_jwt(priv, email="alice@example.test")
    response = client.get("/workloads/", HTTP_X_POMERIUM_JWT_ASSERTION=token)
    assert response.status_code == 200
    assert User.objects.count() == before


# ── 3b) Existing user matched by email (different username) ──────


def test_existing_user_matched_by_email_not_username(client, db, groups, fake_jwks, keypair, jwt_settings):
    """A pre-existing user (e.g. `createsuperuser` with username=admin,
    email=boss@example.test) must be adopted on first Pomerium login,
    not duplicated."""
    priv, _ = keypair
    admin = User.objects.create_user(username="admin", email="Boss@Example.Test", password="x")
    admin.groups.add(groups["admin"])
    before = User.objects.count()
    token = _make_jwt(priv, email="boss@example.test")  # different casing
    response = client.get("/workloads/", HTTP_X_POMERIUM_JWT_ASSERTION=token)
    assert response.status_code == 200
    assert User.objects.count() == before
    admin.refresh_from_db()
    # Existing admin role preserved; no second user row.
    assert set(admin.groups.values_list("name", flat=True)) == {"admin"}


# ── 4) Existing admin user stays admin (no downgrade) ────────────


def test_existing_admin_not_downgraded(client, db, groups, fake_jwks, keypair, jwt_settings):
    priv, _ = keypair
    user = User.objects.create_user(username="boss@example.test", email="boss@example.test")
    user.groups.add(groups["admin"])
    token = _make_jwt(priv, email="boss@example.test")
    client.get("/workloads/", HTTP_X_POMERIUM_JWT_ASSERTION=token)
    user.refresh_from_db()
    assert set(user.groups.values_list("name", flat=True)) == {"admin"}


# ── 5) Expired JWT → no login ────────────────────────────────────


def test_expired_jwt_falls_through(client, db, groups, fake_jwks, keypair, jwt_settings):
    priv, _ = keypair
    token = _make_jwt(priv, exp_offset=-60)
    response = client.get("/workloads/", HTTP_X_POMERIUM_JWT_ASSERTION=token)
    assert response.status_code == 302
    assert "/accounts/login/" in response["Location"]
    assert not User.objects.filter(username="alice@example.test").exists()


# ── 6) Bad signature → no login (and JWKS refresh attempted) ─────


def test_bad_signature_falls_through(client, db, groups, fake_jwks, jwt_settings):
    # Sign with a *different* key — fake JWKS still serves the original pub key.
    other_priv = ec.generate_private_key(ec.SECP256R1())
    token = _make_jwt(other_priv)
    response = client.get("/workloads/", HTTP_X_POMERIUM_JWT_ASSERTION=token)
    assert response.status_code == 302
    assert not User.objects.filter(username="alice@example.test").exists()


# ── 7) Wrong audience → no login ─────────────────────────────────


def test_wrong_audience_falls_through(client, db, groups, fake_jwks, keypair, jwt_settings):
    priv, _ = keypair
    token = _make_jwt(priv, aud="some-other-app")
    response = client.get("/workloads/", HTTP_X_POMERIUM_JWT_ASSERTION=token)
    assert response.status_code == 302
    assert not User.objects.filter(username="alice@example.test").exists()


# ── 8) Bypass paths: middleware does not touch request.user ──────


@pytest.mark.parametrize("path", ["/api/v1/ingest/", "/api/v1/imports/start/", "/healthz", "/metrics"])
def test_bypass_paths_skip_jwt(client, db, fake_jwks, keypair, jwt_settings, path):
    priv, _ = keypair
    token = _make_jwt(priv, email="bypass@example.test")
    client.get(path, HTTP_X_POMERIUM_JWT_ASSERTION=token)
    # The JWT user must NOT have been auto-created.
    assert not User.objects.filter(username="bypass@example.test").exists()


# ── 9) JWT_AUTH_ENABLED=False → middleware is a no-op ────────────


def test_disabled_is_noop(client, db, groups, fake_jwks, keypair):
    priv, _ = keypair
    token = _make_jwt(priv, email="ignored@example.test")
    with override_settings(JWT_AUTH_ENABLED=False):
        response = client.get("/workloads/", HTTP_X_POMERIUM_JWT_ASSERTION=token)
    assert response.status_code == 302  # LoginRequiredMixin redirect
    assert not User.objects.filter(username="ignored@example.test").exists()


# ── 10) Already-authenticated session → JWT path skipped ─────────


def test_existing_session_preserved(client, db, groups, fake_jwks, keypair, jwt_settings):
    priv, _ = keypair
    admin = User.objects.create_user(username="root", password="x")
    admin.groups.add(groups["admin"])
    client.force_login(admin)
    # JWT for a *different* user is present, but the existing session must win.
    token = _make_jwt(priv, email="other@example.test")
    response = client.get("/workloads/", HTTP_X_POMERIUM_JWT_ASSERTION=token)
    assert response.status_code == 200
    # The JWT user was never created (middleware short-circuited).
    assert not User.objects.filter(username="other@example.test").exists()


# ── 11) Custom JWT_AUTH_HEADER (proves generalization) ───────────


def test_custom_header_works(client, db, groups, fake_jwks, keypair):
    priv, _ = keypair
    token = _make_jwt(priv, email="cf@example.test")
    with override_settings(
        JWT_AUTH_ENABLED=True,
        JWT_AUTH_HEADER="Cf-Access-Jwt-Assertion",
        JWT_AUTH_JWKS_URL="https://example.test/jwks.json",
        JWT_AUTH_AUDIENCE="kubeposture.test",
        JWT_AUTH_ISSUER="",
        JWT_AUTH_JWKS_CACHE_TTL=3600,
    ):
        response = client.get("/workloads/", HTTP_CF_ACCESS_JWT_ASSERTION=token)
    assert response.status_code == 200
    assert User.objects.filter(username="cf@example.test").exists()


# ── 12) Bearer-framed token is accepted (Authelia jwt mode) ──────


def test_bearer_framed_token(client, db, groups, fake_jwks, keypair, jwt_settings):
    priv, _ = keypair
    token = _make_jwt(priv, email="authelia@example.test")
    response = client.get(
        "/workloads/",
        HTTP_X_POMERIUM_JWT_ASSERTION=f"Bearer {token}",
    )
    assert response.status_code == 200
    assert User.objects.filter(username="authelia@example.test").exists()
