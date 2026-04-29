"""Bearer-token auth for the importer.

Per dev_docs/02-architecture.md *Importer authentication*: a named
`IngestToken` carries a hashed bearer secret. The importer sends
`Authorization: Bearer <plain>`. Tokens are NOT bound to a cluster —
cluster identity comes from the payload's `cluster` field and is
auto-registered on first observation (CLAUDE.md D2).

Authentication contract:
  - Header: `Authorization: Bearer <token>`
  - On match: `request.user = AnonymousUser`, `request.auth =
    IngestToken` (the token row, NOT a cluster).
  - Mismatched / missing payload cluster → 400 (`require_cluster`).
"""
from __future__ import annotations

import hashlib
import secrets

from rest_framework import authentication, exceptions
from rest_framework.permissions import BasePermission

from core.models import Cluster, IngestToken


def hash_token(plain: str) -> str:
    return hashlib.sha256(plain.encode("utf-8")).hexdigest()


def generate_token() -> tuple[str, str]:
    """Returns (plain, hashed). Plain is shown once; hash is persisted."""
    plain = secrets.token_urlsafe(32)
    return plain, hash_token(plain)


class IngestBearerAuthentication(authentication.BaseAuthentication):
    keyword = "Bearer"

    def authenticate(self, request):
        header = authentication.get_authorization_header(request).decode("latin-1")
        if not header:
            return None
        parts = header.split()
        if len(parts) != 2 or parts[0] != self.keyword:
            return None
        plain = parts[1]
        token_row = (
            IngestToken.objects
            .filter(token_hash=hash_token(plain), revoked_at__isnull=True)
            .first()
        )
        if not token_row:
            raise exceptions.AuthenticationFailed("Invalid bearer token")
        # Mark used; coarse, no per-request lock contention concerns yet.
        from django.utils import timezone
        IngestToken.objects.filter(id=token_row.id).update(
            last_used_at=timezone.now(),
        )
        # request.user stays anonymous; request.auth carries the IngestToken.
        from django.contrib.auth.models import AnonymousUser
        return AnonymousUser(), token_row

    def authenticate_header(self, request):
        return self.keyword


class IsIngestAuthenticated(BasePermission):
    """Allow only requests that authenticated via IngestBearerAuthentication."""

    def has_permission(self, request, view):
        return isinstance(request.auth, IngestToken)


def require_cluster(request, payload_cluster_name: str) -> Cluster:
    """Resolve the cluster the request is targeting.

    Tokens are not bound to clusters; the cluster identity comes
    entirely from the payload. Auto-registers the Cluster row if
    missing (CLAUDE.md D2 "Auto-registration"). Raises if the
    payload didn't supply a cluster name.
    """
    if not isinstance(request.auth, IngestToken):
        raise exceptions.NotAuthenticated()
    name = (payload_cluster_name or "").strip()
    if not name:
        raise exceptions.ValidationError(
            "payload field 'cluster' is required"
        )
    cluster, _ = Cluster.objects.get_or_create(name=name)
    return cluster
