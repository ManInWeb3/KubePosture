"""Access pages (`/access/users/...`) — the group-`admin` role must not be
able to escalate past itself or lock itself out, and the cluster
metadata form must reject values the priority tree doesn't know."""
from __future__ import annotations

import pytest
from django.contrib.auth.models import Group, User
from django.urls import reverse

from core.constants import Environment
from core.models import Cluster, Snapshot


@pytest.fixture(autouse=True)
def _role_groups(db):
    for name in ("viewer", "SecEngineer", "admin"):
        Group.objects.get_or_create(name=name)


@pytest.fixture
def admin_user(db):
    u = User.objects.create_user(username="group-admin", password="x")
    u.groups.add(Group.objects.get(name="admin"))
    return u


@pytest.fixture
def superuser(db):
    return User.objects.create_superuser(username="root", password="x")


@pytest.fixture
def viewer(db):
    viewer_group, _ = Group.objects.get_or_create(name="viewer")
    u = User.objects.create_user(username="viewer-1", password="x")
    u.groups.add(viewer_group)
    return u


def _edit_payload(**overrides):
    return {"first_name": "", "last_name": "", "email": "", "is_active": "on",
            "role": "viewer", **overrides}


def test_group_admin_cannot_edit_a_superuser(client, admin_user, superuser):
    client.force_login(admin_user)
    resp = client.post(
        reverse("user-edit", args=[superuser.pk]),
        _edit_payload(new_password="owned", role="admin"),
    )
    assert resp.status_code == 403
    superuser.refresh_from_db()
    assert superuser.check_password("x"), "the superuser's password must be untouched"


def test_superuser_can_edit_a_superuser(client, superuser):
    other = User.objects.create_superuser(username="root2", password="x")
    client.force_login(superuser)
    resp = client.post(reverse("user-edit", args=[other.pk]), _edit_payload(new_password="new"))
    assert resp.status_code == 302
    other.refresh_from_db()
    assert other.check_password("new")


def test_admin_cannot_demote_or_deactivate_themselves_via_edit(client, admin_user):
    client.force_login(admin_user)
    resp = client.post(
        reverse("user-edit", args=[admin_user.pk]),
        _edit_payload(role="viewer", email="me@example.com"),  # is_active omitted → off
    )
    assert resp.status_code == 302
    admin_user.refresh_from_db()
    assert admin_user.is_active is True
    assert set(admin_user.groups.values_list("name", flat=True)) == {"admin"}
    assert admin_user.email == "me@example.com", "profile fields still save"


def test_admin_changing_own_password_stays_logged_in(client, admin_user):
    client.force_login(admin_user)
    client.post(reverse("user-edit", args=[admin_user.pk]), _edit_payload(role="admin", new_password="new"))
    assert client.get(reverse("user-list")).status_code == 200, "session hash was rotated"


def test_admin_can_still_edit_a_regular_user(client, admin_user, viewer):
    client.force_login(admin_user)
    resp = client.post(
        reverse("user-edit", args=[viewer.pk]),
        _edit_payload(role="SecEngineer", new_password="rotated"),
    )
    assert resp.status_code == 302
    viewer.refresh_from_db()
    assert viewer.check_password("rotated")
    assert set(viewer.groups.values_list("name", flat=True)) == {"SecEngineer"}


# ── cluster metadata form ────────────────────────────────────────


@pytest.fixture
def cluster(db):
    return Cluster.objects.create(name="c-meta", environment=Environment.DEV.value)


def test_cluster_environment_must_be_a_known_value(client, admin_user, cluster):
    client.force_login(admin_user)
    resp = client.post(reverse("cluster-detail", args=[cluster.pk]), {"environment": "foo"})
    assert resp.status_code == 302
    cluster.refresh_from_db()
    assert cluster.environment == Environment.DEV.value
    assert cluster.environment_is_manual is False


def test_cluster_environment_edit_is_snapshot_bracketed(client, admin_user, cluster):
    client.force_login(admin_user)
    resp = client.post(reverse("cluster-detail", args=[cluster.pk]), {"environment": "prod"})
    assert resp.status_code == 302
    cluster.refresh_from_db()
    assert cluster.environment == Environment.PROD.value and cluster.environment_is_manual
    assert Snapshot.objects.filter(cluster=cluster, scope_kind="cluster").count() == 2, (
        "pre + post rows, like the admin path"
    )
