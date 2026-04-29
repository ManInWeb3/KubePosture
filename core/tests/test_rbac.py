"""RBAC tests for session-auth + group-based role checks.

Covers:
  - Anonymous user redirected to LOGIN_URL
  - Each role only passes its own check + lower
  - Hierarchy: admin > operator > viewer
  - Superuser bypasses all role checks
  - setup_rbac management command is idempotent
"""
from __future__ import annotations

import pytest
from django.contrib.auth.models import Group, User
from django.core.management import call_command
from django.http import HttpResponse
from django.urls import reverse

from core.api.permissions import IsAdmin, IsOperator, IsViewer, _has_role, require_role


# ── Fixtures ──────────────────────────────────────────────────────


@pytest.fixture
def groups(db):
    """Seed the three RBAC groups via the real mgmt command."""
    call_command("setup_rbac")
    return {g.name: g for g in Group.objects.filter(name__in=["viewer", "operator", "admin"])}


def _make_user(username: str, role: str | None = None, *, superuser: bool = False, groups=None) -> User:
    user = User.objects.create_user(username=username, password="x")
    if superuser:
        user.is_superuser = True
        user.is_staff = True
        user.save()
    if role is not None and groups is not None:
        user.groups.add(groups[role])
    return user


# ── _has_role helper ──────────────────────────────────────────────


def test_anonymous_user_has_no_role(db):
    from django.contrib.auth.models import AnonymousUser
    assert _has_role(AnonymousUser(), "viewer") is False
    assert _has_role(None, "viewer") is False


def test_viewer_passes_viewer_check(db, groups):
    user = _make_user("u1", role="viewer", groups=groups)
    assert _has_role(user, "viewer") is True
    assert _has_role(user, "operator") is False
    assert _has_role(user, "admin") is False


def test_operator_inherits_viewer(db, groups):
    user = _make_user("u2", role="operator", groups=groups)
    assert _has_role(user, "viewer") is True
    assert _has_role(user, "operator") is True
    assert _has_role(user, "admin") is False


def test_admin_inherits_operator_and_viewer(db, groups):
    user = _make_user("u3", role="admin", groups=groups)
    assert _has_role(user, "viewer") is True
    assert _has_role(user, "operator") is True
    assert _has_role(user, "admin") is True


def test_superuser_passes_every_role_check(db):
    user = _make_user("root", superuser=True)
    assert _has_role(user, "viewer") is True
    assert _has_role(user, "operator") is True
    assert _has_role(user, "admin") is True


def test_unknown_role_raises(db, groups):
    user = _make_user("u4", role="viewer", groups=groups)
    with pytest.raises(ValueError, match="unknown role"):
        _has_role(user, "nonsense")


# ── @require_role decorator ───────────────────────────────────────


@require_role("operator")
def _operator_view(request):
    return HttpResponse("ok")


def test_require_role_redirects_anonymous(client, db):
    response = client.get("/__test_operator_view__/")
    # No URL is registered for that test path, but the auth/login redirect
    # behavior of @login_required is what we want to verify directly.
    # We exercise via direct call.
    from django.test import RequestFactory
    rf = RequestFactory()
    request = rf.get("/x/")
    from django.contrib.auth.models import AnonymousUser
    request.user = AnonymousUser()
    response = _operator_view(request)
    # @login_required returns 302 redirect to LOGIN_URL for anon users
    assert response.status_code == 302
    assert "/accounts/login/" in response["Location"]


def test_require_role_403_for_insufficient_role(db, groups):
    from django.test import RequestFactory
    from django.core.exceptions import PermissionDenied

    rf = RequestFactory()
    request = rf.get("/x/")
    request.user = _make_user("v", role="viewer", groups=groups)
    with pytest.raises(PermissionDenied):
        _operator_view(request)


def test_require_role_passes_for_sufficient_role(db, groups):
    from django.test import RequestFactory

    rf = RequestFactory()
    for role in ("operator", "admin"):
        request = rf.get("/x/")
        request.user = _make_user(f"u_{role}", role=role, groups=groups)
        response = _operator_view(request)
        assert response.status_code == 200
        assert response.content == b"ok"


# ── DRF IsViewer/IsOperator/IsAdmin permission classes ────────────


def test_is_viewer_grants_for_all_roles(db, groups):
    from django.test import RequestFactory
    perm = IsViewer()
    rf = RequestFactory()
    for role in ("viewer", "operator", "admin"):
        request = rf.get("/x/")
        request.user = _make_user(f"isv_{role}", role=role, groups=groups)
        assert perm.has_permission(request, view=None) is True


def test_is_admin_grants_only_for_admin(db, groups):
    from django.test import RequestFactory
    perm = IsAdmin()
    rf = RequestFactory()
    for role in ("viewer", "operator"):
        request = rf.get("/x/")
        request.user = _make_user(f"isa_{role}", role=role, groups=groups)
        assert perm.has_permission(request, view=None) is False
    request = rf.get("/x/")
    request.user = _make_user("isa_admin", role="admin", groups=groups)
    assert perm.has_permission(request, view=None) is True


def test_is_operator_denies_viewer(db, groups):
    from django.test import RequestFactory
    perm = IsOperator()
    rf = RequestFactory()
    request = rf.get("/x/")
    request.user = _make_user("iso_v", role="viewer", groups=groups)
    assert perm.has_permission(request, view=None) is False


# ── setup_rbac management command ─────────────────────────────────


def test_setup_rbac_creates_three_groups(db):
    Group.objects.filter(name__in=["viewer", "operator", "admin"]).delete()
    call_command("setup_rbac")
    names = set(Group.objects.values_list("name", flat=True))
    assert {"viewer", "operator", "admin"}.issubset(names)


def test_setup_rbac_is_idempotent(db):
    call_command("setup_rbac")
    call_command("setup_rbac")  # second run must not fail
    names = list(Group.objects.filter(name__in=["viewer", "operator", "admin"]).values_list("name", flat=True))
    assert sorted(names) == ["admin", "operator", "viewer"]


# ── Login flow (smoke) ────────────────────────────────────────────


def test_login_url_renders(client, db):
    response = client.get(reverse("login"))
    assert response.status_code == 200
    # Tabler-styled login template should reference the form
    assert b"login" in response.content.lower() or b"username" in response.content.lower()


def test_login_redirects_to_inventory_on_success(client, db, groups):
    user = _make_user("login_test", role="admin", groups=groups)
    response = client.post(reverse("login"), {"username": "login_test", "password": "x"})
    assert response.status_code == 302
    assert response["Location"] == "/"
