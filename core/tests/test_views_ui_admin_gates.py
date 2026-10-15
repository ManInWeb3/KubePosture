"""Every admin-gated UI view must send a viewer to 403 and an anonymous
request to the login page — and do nothing while refusing. One
parametrised sweep over the admin routes in core/urls_ui.py so a new
admin view can't ship without the gate."""
from __future__ import annotations

import pytest
from django.contrib.auth.models import Group, User
from django.urls import reverse

from core.api.auth import generate_token
from core.constants import Environment
from core.models import Cluster, IngestToken, Namespace


@pytest.fixture
def world(db):
    for name in ("viewer", "SecEngineer", "admin"):
        Group.objects.get_or_create(name=name)
    c = Cluster.objects.create(name="gated", environment=Environment.DEV.value)
    ns = Namespace.objects.create(cluster=c, name="ns", internet_exposed=False)
    _plain, hashed = generate_token()
    tok = IngestToken.objects.create(name="tok", token_hash=hashed)
    other = User.objects.create_user(username="other", password="x")
    viewer = User.objects.create_user(username="viewer", password="x")
    viewer.groups.add(Group.objects.get(name="viewer"))
    return {"cluster": c, "ns": ns, "token": tok, "other": other, "viewer": viewer}


# (url name, kwargs builder, method, POST payload)
ADMIN_ROUTES = [
    ("cluster-detail", lambda w: {"pk": w["cluster"].pk}, "post", {"environment": "prod"}),
    ("cluster-reimport", lambda w: {"pk": w["cluster"].pk}, "post", {}),
    ("cluster-delete", lambda w: {"pk": w["cluster"].pk}, "post", {"confirm_name": "gated"}),
    ("namespace-toggle", lambda w: {"cluster_pk": w["cluster"].pk, "ns_pk": w["ns"].pk}, "post",
     {"field": "internet_exposed"}),
    ("namespace-reset-auto", lambda w: {"cluster_pk": w["cluster"].pk, "ns_pk": w["ns"].pk}, "post", {}),
    ("user-list", lambda w: {}, "get", {}),
    ("user-create", lambda w: {}, "get", {}),
    ("user-create", lambda w: {}, "post", {"username": "new", "password": "x", "role": "viewer"}),
    ("user-edit", lambda w: {"pk": w["other"].pk}, "get", {}),
    ("user-edit", lambda w: {"pk": w["other"].pk}, "post", {"role": "admin", "is_active": "on"}),
    ("user-toggle-active", lambda w: {"pk": w["other"].pk}, "post", {}),
    ("token-list", lambda w: {}, "get", {}),
    ("token-create", lambda w: {}, "post", {"name": "new-tok"}),
    ("token-regenerate", lambda w: {"pk": w["token"].pk}, "post", {}),
    ("token-delete", lambda w: {"pk": w["token"].pk}, "post", {}),
]
_IDS = [f"{name}:{method}" for name, _, method, _ in ADMIN_ROUTES]


def _snapshot(w) -> tuple:
    w["cluster"].refresh_from_db(); w["ns"].refresh_from_db(); w["other"].refresh_from_db()
    return (
        w["cluster"].environment, w["cluster"].reimport_requested_at, Cluster.objects.count(),
        w["ns"].internet_exposed, w["ns"].exposure_is_manual,
        w["other"].is_active, set(w["other"].groups.values_list("name", flat=True)), User.objects.count(),
        IngestToken.objects.get(pk=w["token"].pk).token_hash, IngestToken.objects.count(),
    )


@pytest.mark.parametrize(("name", "kwargs", "method", "payload"), ADMIN_ROUTES, ids=_IDS)
def test_viewer_gets_403_and_nothing_changes(client, world, name, kwargs, method, payload):
    client.force_login(world["viewer"])
    before = _snapshot(world)
    resp = getattr(client, method)(reverse(name, kwargs=kwargs(world)), payload)
    assert resp.status_code == 403
    assert _snapshot(world) == before


@pytest.mark.parametrize(("name", "kwargs", "method", "payload"), ADMIN_ROUTES, ids=_IDS)
def test_anonymous_is_redirected_to_login_and_nothing_changes(client, world, name, kwargs, method, payload):
    before = _snapshot(world)
    resp = getattr(client, method)(reverse(name, kwargs=kwargs(world)), payload)
    assert resp.status_code == 302 and resp["Location"].startswith("/accounts/login/")
    assert _snapshot(world) == before
