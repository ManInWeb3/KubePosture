"""Tests for the pull-pattern on-demand reimport API.

  GET  /api/v1/imports/pending/?cluster=<name>
  POST /api/v1/imports/pending/clear/   {cluster, satisfied_at}

The endpoints back the per-minute trigger CronJob: an admin clicks
"Re-import" in the UI, which sets `Cluster.reimport_requested_at`;
the trigger polls /pending/ and runs a full import + clears the flag
when it sees a request.
"""
from __future__ import annotations

from datetime import timedelta

import pytest
from django.utils import timezone

from core.api.auth import generate_token
from core.constants import ImportMarkState
from core.models import Cluster, ImportMark, IngestToken


@pytest.fixture
def token(db) -> str:
    plain, hashed = generate_token()
    IngestToken.objects.create(name="test", token_hash=hashed)
    return plain


@pytest.fixture
def cluster(db):
    return Cluster.objects.create(name="c-pending", environment="dev")


def _auth(token: str) -> dict:
    return {"HTTP_AUTHORIZATION": f"Bearer {token}"}


# ── GET /imports/pending/ ─────────────────────────────────────────


def test_pending_false_when_no_request(client, token, cluster):
    resp = client.get(
        "/api/v1/imports/pending/?cluster=c-pending", **_auth(token)
    )
    assert resp.status_code == 200, resp.content
    data = resp.json()
    assert data["pending"] is False
    assert data["requested_at"] is None
    assert data["in_flight"] is False


def test_pending_true_when_admin_flagged(client, token, cluster):
    cluster.reimport_requested_at = timezone.now()
    cluster.save(update_fields=["reimport_requested_at"])

    resp = client.get(
        "/api/v1/imports/pending/?cluster=c-pending", **_auth(token)
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["pending"] is True
    assert data["requested_at"] is not None
    assert data["in_flight"] is False


def test_unknown_cluster_returns_idempotent_negative(client, token):
    resp = client.get(
        "/api/v1/imports/pending/?cluster=does-not-exist", **_auth(token)
    )
    assert resp.status_code == 200
    data = resp.json()
    # No row, no auto-create on GET. The trigger sees "nothing to do".
    assert data == {
        "cluster": "does-not-exist",
        "pending": False,
        "requested_at": None,
        "in_flight": False,
    }
    assert not Cluster.objects.filter(name="does-not-exist").exists()


def test_in_flight_detected_from_recent_open_mark(client, token, cluster):
    ImportMark.objects.create(
        cluster=cluster,
        kind="inventory",
        import_id="imp-recent",
        state=ImportMarkState.OPEN.value,
        started_at=timezone.now() - timedelta(minutes=5),
    )
    resp = client.get(
        "/api/v1/imports/pending/?cluster=c-pending", **_auth(token)
    )
    assert resp.json()["in_flight"] is True


def test_in_flight_ignores_stuck_mark_past_horizon(client, token, cluster):
    """A draining mark older than 30min is treated as abandoned."""
    ImportMark.objects.create(
        cluster=cluster,
        kind="inventory",
        import_id="imp-stuck",
        state=ImportMarkState.DRAINING.value,
        started_at=timezone.now() - timedelta(minutes=45),
    )
    resp = client.get(
        "/api/v1/imports/pending/?cluster=c-pending", **_auth(token)
    )
    assert resp.json()["in_flight"] is False


def test_in_flight_ignores_reaped_mark(client, token, cluster):
    ImportMark.objects.create(
        cluster=cluster,
        kind="inventory",
        import_id="imp-done",
        state=ImportMarkState.REAPED.value,
        started_at=timezone.now() - timedelta(minutes=2),
    )
    resp = client.get(
        "/api/v1/imports/pending/?cluster=c-pending", **_auth(token)
    )
    assert resp.json()["in_flight"] is False


def test_get_requires_cluster_param(client, token):
    resp = client.get("/api/v1/imports/pending/", **_auth(token))
    assert resp.status_code == 400


def test_get_requires_bearer_token(client, cluster):
    resp = client.get("/api/v1/imports/pending/?cluster=c-pending")
    assert resp.status_code in (401, 403)


# ── POST /imports/pending/clear/ ──────────────────────────────────


def test_clear_succeeds_when_satisfied_at_matches(client, token, cluster):
    requested_at = timezone.now()
    cluster.reimport_requested_at = requested_at
    cluster.save(update_fields=["reimport_requested_at"])

    resp = client.post(
        "/api/v1/imports/pending/clear/",
        data={
            "cluster": "c-pending",
            "satisfied_at": requested_at.isoformat(),
        },
        content_type="application/json",
        **_auth(token),
    )
    assert resp.status_code == 200, resp.content
    assert resp.json()["cleared"] is True

    cluster.refresh_from_db()
    assert cluster.reimport_requested_at is None


def test_clear_skipped_when_request_is_newer_than_satisfied(
    client, token, cluster,
):
    """Mid-import re-click race: a click at T=70s arrives while the
    import that started at T=60s is still running. The trigger calls
    clear with satisfied_at=T=10s (the request it observed). Server
    refuses to clear because the stored request (T=70s) is newer.
    """
    older_request = timezone.now() - timedelta(seconds=120)
    cluster.reimport_requested_at = timezone.now()  # newer click during import
    cluster.save(update_fields=["reimport_requested_at"])

    resp = client.post(
        "/api/v1/imports/pending/clear/",
        data={
            "cluster": "c-pending",
            "satisfied_at": older_request.isoformat(),
        },
        content_type="application/json",
        **_auth(token),
    )
    assert resp.status_code == 200
    assert resp.json()["cleared"] is False

    cluster.refresh_from_db()
    assert cluster.reimport_requested_at is not None


def test_clear_idempotent_when_no_request(client, token, cluster):
    resp = client.post(
        "/api/v1/imports/pending/clear/",
        data={
            "cluster": "c-pending",
            "satisfied_at": timezone.now().isoformat(),
        },
        content_type="application/json",
        **_auth(token),
    )
    assert resp.status_code == 200
    assert resp.json()["cleared"] is False


def test_clear_validates_satisfied_at_format(client, token, cluster):
    resp = client.post(
        "/api/v1/imports/pending/clear/",
        data={"cluster": "c-pending", "satisfied_at": "not-a-date"},
        content_type="application/json",
        **_auth(token),
    )
    assert resp.status_code == 400


def test_clear_requires_satisfied_at(client, token, cluster):
    resp = client.post(
        "/api/v1/imports/pending/clear/",
        data={"cluster": "c-pending"},
        content_type="application/json",
        **_auth(token),
    )
    assert resp.status_code == 400
