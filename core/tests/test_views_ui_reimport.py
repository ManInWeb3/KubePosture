"""Tests for the cluster-detail "Re-import" HTMX action."""
from __future__ import annotations

import pytest
from django.contrib.auth.models import Group, User
from django.urls import reverse

from core.models import Cluster


@pytest.fixture
def admin_user(db):
    user = User.objects.create_user(username="admin1", password="x")
    admin_group, _ = Group.objects.get_or_create(name="admin")
    user.groups.add(admin_group)
    return user


@pytest.fixture
def viewer_user(db):
    user = User.objects.create_user(username="viewer1", password="x")
    viewer_group, _ = Group.objects.get_or_create(name="viewer")
    user.groups.add(viewer_group)
    return user


@pytest.fixture
def cluster(db):
    return Cluster.objects.create(name="c-reimport", environment="dev")


def _login(client, user):
    client.force_login(user)
    return client


def test_admin_post_sets_reimport_request(client, admin_user, cluster):
    _login(client, admin_user)
    resp = client.post(reverse("cluster-reimport", args=[cluster.pk]))
    assert resp.status_code == 200, resp.content

    cluster.refresh_from_db()
    assert cluster.reimport_requested_at is not None
    assert cluster.reimport_requested_by_id == admin_user.id


def test_viewer_post_forbidden(client, viewer_user, cluster):
    _login(client, viewer_user)
    resp = client.post(reverse("cluster-reimport", args=[cluster.pk]))
    assert resp.status_code == 403

    cluster.refresh_from_db()
    assert cluster.reimport_requested_at is None


def test_anonymous_post_redirects_to_login(client, cluster):
    resp = client.post(reverse("cluster-reimport", args=[cluster.pk]))
    # LoginRequiredMixin -> 302 to login URL.
    assert resp.status_code == 302


def test_partial_response_renders_pending_state(client, admin_user, cluster):
    _login(client, admin_user)
    resp = client.post(reverse("cluster-reimport", args=[cluster.pk]))
    assert resp.status_code == 200
    body = resp.content.decode()
    # After the click, the partial swaps in the "requested" label and
    # hides the button form.
    assert "Re-import requested" in body
    assert "hx-post" not in body  # button form is gone


def test_partial_renders_button_when_no_pending_request(
    client, admin_user, cluster,
):
    """The cluster-detail page (full GET) should render the button
    partial in its 'no request' state. Smoke-checked via the cluster
    detail view since the partial isn't reachable on its own (POST-only).
    """
    _login(client, admin_user)
    resp = client.get(reverse("cluster-detail", args=[cluster.pk]))
    assert resp.status_code == 200
    body = resp.content.decode()
    assert "queue a fresh import" in body  # button-only helper text
    assert "Re-import requested" not in body
