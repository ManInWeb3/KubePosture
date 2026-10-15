"""Ingest-token admin pages: create → one-shot reveal, regenerate
invalidates the old secret immediately, revoked rows can't be rotated,
delete is unconditional."""
from __future__ import annotations

import pytest
from django.contrib.auth.models import Group, User
from django.urls import reverse
from django.utils import timezone

from core.api.auth import generate_token, hash_token
from core.models import Cluster, IngestToken


@pytest.fixture
def admin(client, db):
    g, _ = Group.objects.get_or_create(name="admin")
    u = User.objects.create_user(username="adm", password="x")
    u.groups.add(g)
    client.force_login(u)
    Cluster.objects.create(name="zz", environment="dev")
    return u


def _api_ok(client, plain) -> bool:
    resp = client.get("/api/v1/imports/pending/?cluster=zz", HTTP_AUTHORIZATION=f"Bearer {plain}")
    return resp.status_code == 200


def _revealed(client) -> dict[int, str]:
    rows = client.get(reverse("token-list")).context["tokens"]
    return {r["obj"].pk: r["new_key"] for r in rows if r["new_key"]}


def test_create_reveals_the_secret_exactly_once_and_it_authenticates(client, admin):
    resp = client.post(reverse("token-create"), {"name": "tok-a", "description": "ci"})
    assert resp.status_code == 302
    tok = IngestToken.objects.get(name="tok-a")

    first = _revealed(client)
    assert set(first) == {tok.pk}
    assert hash_token(first[tok.pk]) == tok.token_hash
    assert _api_ok(client, first[tok.pk])
    assert _revealed(client) == {}, "the plain value is popped from the session on first render"


@pytest.mark.parametrize("payload", [{"name": ""}, {"name": "dup"}], ids=["blank", "duplicate"])
def test_create_rejects_blank_and_duplicate_names(client, admin, payload):
    IngestToken.objects.create(name="dup", token_hash=generate_token()[1])
    before = IngestToken.objects.count()
    resp = client.post(reverse("token-create"), payload, follow=True)
    assert IngestToken.objects.count() == before
    assert "already exists" in resp.content.decode() or "required" in resp.content.decode()


def test_regenerate_invalidates_the_old_secret_immediately(client, admin):
    old_plain, hashed = generate_token()
    tok = IngestToken.objects.create(name="tok-b", token_hash=hashed, last_used_at=timezone.now())
    assert _api_ok(client, old_plain)

    assert client.post(reverse("token-regenerate", args=[tok.pk])).status_code == 302

    assert not _api_ok(client, old_plain)
    tok.refresh_from_db()
    assert tok.token_hash != hashed and tok.last_used_at is None
    new_plain = _revealed(client)[tok.pk]
    assert hash_token(new_plain) == tok.token_hash and _api_ok(client, new_plain)


def test_revoked_token_cannot_be_regenerated_but_can_be_deleted(client, admin):
    tok = IngestToken.objects.create(name="tok-c", token_hash=generate_token()[1],
                                     revoked_at=timezone.now())
    assert client.post(reverse("token-regenerate", args=[tok.pk])).status_code == 404
    assert client.post(reverse("token-delete", args=[tok.pk])).status_code == 302
    assert not IngestToken.objects.filter(pk=tok.pk).exists()
