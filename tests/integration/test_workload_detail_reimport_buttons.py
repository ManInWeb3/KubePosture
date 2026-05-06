"""Tests for the per-cluster Re-import buttons on the workload detail page.

A workload may run in several clusters; the import (and so the
`Re-import` request) is per-cluster, so the workload detail page renders
one row per cluster in scope, each with its own *Imports* timestamp and
its own button. Pending state for cluster A must NOT spill into cluster
B's row.
"""
from __future__ import annotations

from datetime import timedelta

import pytest
from django.contrib.auth.models import Group, User
from django.urls import reverse
from django.utils import timezone

from core.models import (
    Cluster,
    Image,
    Namespace,
    Workload,
    WorkloadImageObservation,
)


# ── Fixtures ──────────────────────────────────────────────────────


@pytest.fixture
def admin_user(db):
    u = User.objects.create_user(username="admin1", password="x")
    g, _ = Group.objects.get_or_create(name="admin")
    u.groups.add(g)
    return u


@pytest.fixture
def viewer_user(db):
    u = User.objects.create_user(username="viewer1", password="x")
    g, _ = Group.objects.get_or_create(name="viewer")
    u.groups.add(g)
    return u


def _cluster(name, env="prod"):
    c = Cluster.objects.create(
        name=name, environment=env, provider="aws", region="eu-west-1",
    )
    c.last_complete_inventory_at = timezone.now()
    c.save()
    return c


def _ns(cluster, name):
    return Namespace.objects.create(cluster=cluster, name=name)


def _workload(cluster, ns, kind, name):
    return Workload.objects.create(
        cluster=cluster,
        namespace=ns,
        kind=kind,
        name=name,
        deployed=True,
        last_inventory_at=cluster.last_complete_inventory_at,
    )


def _observe(workload, image, container="app"):
    obs = WorkloadImageObservation.objects.create(
        workload=workload, image=image, container_name=container,
        currently_deployed=True,
    )
    WorkloadImageObservation.objects.filter(pk=obs.pk).update(
        last_seen_at=workload.cluster.last_complete_inventory_at + timedelta(seconds=1),
    )
    return obs


@pytest.fixture
def shared_image(db):
    return Image.objects.create(
        digest="sha256:" + "a" * 64,
        ref="registry/api:v1",
        repository="api",
    )


@pytest.fixture
def single_cluster_scene(db, shared_image):
    """One cluster, one workload."""
    c = _cluster("cluster-a", env="prod")
    ns = _ns(c, "payments")
    w = _workload(c, ns, "Deployment", "api")
    _observe(w, shared_image)
    return {"cluster": c, "workload": w}


@pytest.fixture
def multi_cluster_scene(db, shared_image):
    """Same (kind, name) deployed to 3 clusters across 3 namespaces."""
    ca = _cluster("cluster-a", env="prod")
    cb = _cluster("cluster-b", env="staging")
    cc = _cluster("cluster-c", env="dev")

    ns_a = _ns(ca, "payments")
    ns_b = _ns(cb, "payments")
    ns_c = _ns(cc, "payments")

    w_a = _workload(ca, ns_a, "Deployment", "api")
    w_b = _workload(cb, ns_b, "Deployment", "api")
    w_c = _workload(cc, ns_c, "Deployment", "api")

    _observe(w_a, shared_image)
    _observe(w_b, shared_image)
    _observe(w_c, shared_image)

    return {
        "cluster_a": ca, "cluster_b": cb, "cluster_c": cc,
        "w_a": w_a, "w_b": w_b, "w_c": w_c,
    }


def _get_detail(client, kind="Deployment", name="api", **params):
    url = reverse("workloads-detail", kwargs={"kind": kind, "name": name})
    return client.get(url, params)


# ── Tests ─────────────────────────────────────────────────────────


def test_single_cluster_renders_one_button(client, admin_user, single_cluster_scene):
    client.force_login(admin_user)
    cluster = single_cluster_scene["cluster"]

    resp = _get_detail(client)
    assert resp.status_code == 200, resp.content
    body = resp.content.decode()

    assert body.count(f'id="reimport-{cluster.pk}"') == 1
    assert body.count("queue a fresh import") == 1
    # Form action points at the right cluster's re-import URL.
    assert reverse("cluster-reimport", args=[cluster.pk]) in body
    # CSRF token must be present — without it, the POST is rejected and
    # the button silently does nothing in the browser. Regression guard
    # against re-introducing `{% include … only %}` which would strip
    # the parent context's csrf_token.
    assert "csrfmiddlewaretoken" in body


def test_multi_cluster_renders_button_per_cluster(
    client, admin_user, multi_cluster_scene,
):
    client.force_login(admin_user)
    s = multi_cluster_scene

    resp = _get_detail(client)
    assert resp.status_code == 200
    body = resp.content.decode()

    # One wrapper per cluster.
    for c in (s["cluster_a"], s["cluster_b"], s["cluster_c"]):
        assert f'id="reimport-{c.pk}"' in body, (
            f"missing wrapper for {c.name}"
        )
        assert reverse("cluster-reimport", args=[c.pk]) in body
    # Three button-state rows, no pending badges.
    assert body.count("queue a fresh import") == 3
    assert "Re-import requested" not in body


def test_viewer_sees_no_buttons_only_timestamps(
    client, viewer_user, multi_cluster_scene,
):
    client.force_login(viewer_user)
    s = multi_cluster_scene

    resp = _get_detail(client)
    assert resp.status_code == 200
    body = resp.content.decode()

    # Per-cluster code blocks still render so the viewer sees scope.
    assert s["cluster_a"].name in body
    assert s["cluster_b"].name in body
    assert s["cluster_c"].name in body
    # But no buttons / forms / wrappers — the partial's button branch is
    # gated on `is_admin` and the wrapper id only renders when a button
    # or pending badge is shown. With no admin and no pending request,
    # the partial's outer div still renders empty (whitespace only) but
    # never shows the action affordances.
    assert "queue a fresh import" not in body
    assert "Re-import requested" not in body
    assert "hx-post" not in body


def test_pending_state_renders_per_cluster_independently(
    client, admin_user, multi_cluster_scene,
):
    """Cluster A has a pending re-import request; cluster B does not.
    The per-cluster loop must show A's badge AND B's clickable button
    on the same page — no aggregation across rows.
    """
    client.force_login(admin_user)
    s = multi_cluster_scene
    s["cluster_a"].reimport_requested_at = timezone.now()
    s["cluster_a"].save(update_fields=["reimport_requested_at"])

    resp = _get_detail(client)
    body = resp.content.decode()

    # A's badge present, B and C still show buttons.
    assert "Re-import requested" in body
    assert body.count("queue a fresh import") == 2
    # The badge is inside A's wrapper, not B's.
    a_block_start = body.index(f'id="reimport-{s["cluster_a"].pk}"')
    a_block_end = body.index("</div>", a_block_start)
    assert "Re-import requested" in body[a_block_start:a_block_end]


def test_cluster_filter_narrows_clusters_in_scope(
    client, admin_user, multi_cluster_scene,
):
    """`?cluster=cluster-a` narrows scope to one cluster; only A's row
    + button render.
    """
    client.force_login(admin_user)
    s = multi_cluster_scene

    url = reverse("workloads-detail", kwargs={"kind": "Deployment", "name": "api"})
    resp = client.get(f"{url}?cluster={s['cluster_a'].name}")
    assert resp.status_code == 200
    body = resp.content.decode()

    assert f'id="reimport-{s["cluster_a"].pk}"' in body
    assert f'id="reimport-{s["cluster_b"].pk}"' not in body
    assert f'id="reimport-{s["cluster_c"].pk}"' not in body
    assert body.count("queue a fresh import") == 1
