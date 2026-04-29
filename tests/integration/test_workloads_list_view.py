"""Integration tests for the Workloads landing + Workload detail.

The Workloads list at `/workloads/` is the primary landing per
[Architecture/dev_docs/08-ui.md §1](Architecture/dev_docs/08-ui.md#L100).
Fixture scene: two clusters (prod + staging), three workloads (one
shared `(kind, name)` across clusters, one extra), four findings —
one with an active per-finding ACCEPT overlay that the default
predicate must hide.
"""
from __future__ import annotations

from datetime import timedelta

import pytest
from django.contrib.auth.models import User
from django.urls import reverse
from django.utils import timezone

from core.constants import FindingActionScope, FindingActionType
from core.models import (
    Cluster,
    Finding,
    FindingAction,
    Image,
    Namespace,
    Workload,
    WorkloadImageObservation,
    WorkloadSignal,
)


# ── Fixtures ─────────────────────────────────────────────────────


@pytest.fixture
def viewer(db):
    return User.objects.create_user(username="viewer", password="x")


@pytest.fixture
def authed(client, viewer):
    client.force_login(viewer)
    return client


def _cluster(name, env="prod"):
    c = Cluster.objects.create(
        name=name, environment=env, provider="aws", region="eu-west-1",
    )
    c.last_complete_inventory_at = timezone.now()
    c.save()
    return c


@pytest.fixture
def cluster_a(db):
    return _cluster("cluster-a", env="prod")


@pytest.fixture
def cluster_b(db):
    return _cluster("cluster-b", env="staging")


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


def _observe(workload, image, container="app", init_container=False):
    obs = WorkloadImageObservation.objects.create(
        workload=workload, image=image, container_name=container,
        init_container=init_container, currently_deployed=True,
    )
    WorkloadImageObservation.objects.filter(pk=obs.pk).update(
        last_seen_at=workload.cluster.last_complete_inventory_at + timedelta(seconds=1),
    )
    return obs


@pytest.fixture
def scene(db, cluster_a, cluster_b):
    """Two clusters, three workloads, one shared image, four findings
    (one muted)."""
    ns_a = _ns(cluster_a, "payments")
    ns_b = _ns(cluster_b, "payments")
    w_api_a = _workload(cluster_a, ns_a, "Deployment", "api")
    w_api_b = _workload(cluster_b, ns_b, "Deployment", "api")
    w_other = _workload(cluster_a, ns_a, "Deployment", "worker")

    img_shared = Image.objects.create(
        digest="sha256:" + "a" * 64,
        ref="registry/api:v1",
        repository="api",
    )
    img_other = Image.objects.create(
        digest="sha256:" + "b" * 64,
        ref="registry/worker:v1",
        repository="worker",
    )

    _observe(w_api_a, img_shared, container="app")
    _observe(w_api_b, img_shared, container="app")
    _observe(w_other, img_other, container="batch")

    # Critical → IMMEDIATE on shared image, cluster-a workload
    Finding.objects.create(
        cluster=cluster_a, workload=w_api_a, image=img_shared,
        source="trivy", category="vulnerability", vuln_id="CVE-2025-0001",
        title="critical bug", severity="critical",
        effective_priority="immediate", kev_listed=True,
        epss_score=0.92, hash_code="hi",
    )
    # High → OUT_OF_CYCLE on shared image, cluster-b workload
    Finding.objects.create(
        cluster=cluster_b, workload=w_api_b, image=img_shared,
        source="trivy", category="vulnerability", vuln_id="CVE-2025-0002",
        title="high bug", severity="high",
        effective_priority="out_of_cycle", epss_score=0.4,
        hash_code="ho",
    )
    # Medium → SCHEDULED on other image
    Finding.objects.create(
        cluster=cluster_a, workload=w_other, image=img_other,
        source="trivy", category="vulnerability", vuln_id="CVE-2025-0003",
        title="medium bug", severity="medium",
        effective_priority="scheduled", hash_code="hs",
    )
    # Muted (Accept) finding on shared image — must be hidden by default
    muted = Finding.objects.create(
        cluster=cluster_a, workload=w_api_a, image=img_shared,
        source="trivy", category="vulnerability", vuln_id="CVE-2025-0004",
        title="accepted bug", severity="high",
        effective_priority="out_of_cycle", hash_code="hm",
    )
    FindingAction.objects.create(
        action_type=FindingActionType.ACCEPT,
        scope_kind=FindingActionScope.PER_FINDING,
        finding=muted,
        reason="risk accepted",
        expires_at=timezone.now() + timedelta(days=30),
    )

    # Active signal on cluster-a's api workload
    WorkloadSignal.objects.create(
        workload=w_api_a,
        signal_id="kp:has-nodeport-service",
        currently_active=True,
    )

    return {
        "cluster_a": cluster_a,
        "cluster_b": cluster_b,
        "w_api_a": w_api_a,
        "w_api_b": w_api_b,
        "w_other": w_other,
        "img_shared": img_shared,
        "img_other": img_other,
        "muted": muted,
    }


# ── Root redirect + auth ─────────────────────────────────────────


def test_root_redirects_to_workloads(client, db):
    response = client.get("/")
    assert response.status_code == 302
    assert response["Location"].rstrip("/") == "/workloads"


def test_workloads_anonymous_redirected_to_login(client, db):
    response = client.get("/workloads/")
    assert response.status_code == 302
    assert "/accounts/login/" in response["Location"]


# ── Workloads landing ────────────────────────────────────────────


def test_workloads_list_renders_rows(authed, scene):
    response = authed.get("/workloads/")
    assert response.status_code == 200
    rows = response.context["rows"]
    keys = {(r["cluster"], r["kind"], r["name"]) for r in rows}
    assert keys == {
        ("cluster-a", "Deployment", "api"),
        ("cluster-b", "Deployment", "api"),
        ("cluster-a", "Deployment", "worker"),
    }


def test_workloads_priority_counts_match(authed, scene):
    response = authed.get("/workloads/")
    rows = response.context["rows"]
    by_key = {(r["cluster"], r["name"]): r for r in rows}
    api_a = by_key[("cluster-a", "api")]
    api_b = by_key[("cluster-b", "api")]
    worker = by_key[("cluster-a", "worker")]
    # Muted CVE-0004 must be hidden by default predicate
    assert api_a["n_immediate"] == 1
    assert api_a["n_out_of_cycle"] == 0
    assert api_b["n_immediate"] == 0
    assert api_b["n_out_of_cycle"] == 1
    assert worker["n_scheduled"] == 1


def test_default_sort_floats_immediate_to_top(authed, scene):
    response = authed.get("/workloads/")
    rows = response.context["rows"]
    # cluster-a api carries the only IMMEDIATE finding
    assert rows[0]["cluster"] == "cluster-a"
    assert rows[0]["name"] == "api"


def test_include_muted_reveals_accepted(authed, scene):
    response = authed.get("/workloads/?include_muted=true")
    rows = response.context["rows"]
    api_a = next(r for r in rows if r["cluster"] == "cluster-a" and r["name"] == "api")
    # Now the muted Out-of-Cycle finding is also counted
    assert api_a["n_out_of_cycle"] == 1


def test_cluster_filter(authed, scene):
    response = authed.get("/workloads/?cluster=cluster-b")
    rows = response.context["rows"]
    assert all(r["cluster"] == "cluster-b" for r in rows)
    assert {r["name"] for r in rows} == {"api"}


def test_namespace_filter(authed, scene):
    response = authed.get("/workloads/?namespace=payments")
    rows = response.context["rows"]
    assert {r["namespace"] for r in rows} == {"payments"}


def test_name_substring_filter(authed, scene):
    response = authed.get("/workloads/?name=work")
    rows = response.context["rows"]
    assert {r["name"] for r in rows} == {"worker"}


def test_has_immediate_filter(authed, scene):
    response = authed.get("/workloads/?has_immediate=true")
    rows = response.context["rows"]
    assert {(r["cluster"], r["name"]) for r in rows} == {
        ("cluster-a", "api"),
    }


def test_namespace_selector_dedupes_across_clusters(authed, scene):
    response = authed.get("/workloads/")
    names = response.context["namespace_names"]
    # Both clusters have a "payments" namespace — the selector lists it once.
    assert names.count("payments") == 1


def test_namespace_selector_scopes_to_selected_cluster(authed, scene, cluster_b):
    # An empty namespace (no workloads) on cluster-b must NOT leak into
    # the selector when filtering to cluster-a.
    Namespace.objects.create(cluster=cluster_b, name="cluster-b-only")
    response = authed.get("/workloads/?cluster=cluster-a")
    names = response.context["namespace_names"]
    assert "cluster-b-only" not in names
    assert "payments" in names


def test_namespace_selector_excludes_undeployed_only_namespaces(authed, scene):
    # A namespace that exists but whose workloads are all undeployed
    # must not appear — selector reflects "deployed now".
    ghost_ns = Namespace.objects.create(cluster=scene["cluster_a"], name="ghost")
    Workload.objects.create(
        cluster=scene["cluster_a"], namespace=ghost_ns,
        kind="Deployment", name="phantom", deployed=False,
    )
    response = authed.get("/workloads/")
    names = response.context["namespace_names"]
    assert "ghost" not in names


def test_namespace_selector_excludes_empty_namespaces(authed, scene):
    Namespace.objects.create(cluster=scene["cluster_a"], name="vacant")
    response = authed.get("/workloads/")
    names = response.context["namespace_names"]
    assert "vacant" not in names


def test_deployed_only_default_excludes_undeployed(authed, scene):
    scene["w_other"].deployed = False
    scene["w_other"].save(update_fields=["deployed"])
    response = authed.get("/workloads/")
    rows = response.context["rows"]
    keys = {(r["cluster"], r["name"]) for r in rows}
    assert ("cluster-a", "worker") not in keys


def test_deployed_only_off_includes_undeployed(authed, scene):
    scene["w_other"].deployed = False
    scene["w_other"].save(update_fields=["deployed"])
    response = authed.get("/workloads/?deployed_only=false")
    rows = response.context["rows"]
    keys = {(r["cluster"], r["name"]) for r in rows}
    assert ("cluster-a", "worker") in keys


def test_sort_by_n_scheduled_desc(authed, scene):
    response = authed.get("/workloads/?sort=n_scheduled&dir=desc")
    rows = response.context["rows"]
    # worker has the only SCHEDULED finding
    assert rows[0]["name"] == "worker"


def test_htmx_returns_rows_partial_only(authed, scene):
    response = authed.get(
        "/workloads/",
        HTTP_HX_REQUEST="true",
        HTTP_HX_TARGET="workload-rows",
    )
    body = response.content.decode()
    assert "<html" not in body.lower()
    assert "Deployment" in body  # at least one row's kind cell


# ── Workload detail (regression) ─────────────────────────────────


def test_workload_detail_renders(authed, scene):
    url = reverse("workloads-detail", kwargs={"kind": "Deployment", "name": "api"})
    response = authed.get(url)
    assert response.status_code == 200
    body = response.content.decode()
    assert "cluster-a" in body
    assert "cluster-b" in body
    assert "kp:has-nodeport-service" in body


def test_workload_detail_cluster_narrows(authed, scene):
    url = reverse("workloads-detail", kwargs={"kind": "Deployment", "name": "api"})
    response = authed.get(url + "?cluster=cluster-a")
    assert response.status_code == 200
    rows = response.context["image_rows"]
    assert all(r["cluster"].name == "cluster-a" for r in rows)


def test_workload_detail_404_for_unknown(authed, scene):
    url = reverse("workloads-detail", kwargs={"kind": "Deployment", "name": "ghost"})
    assert authed.get(url).status_code == 404


def test_workload_detail_404_for_invalid_kind(authed, scene):
    assert authed.get("/workloads/NotAKind/api/").status_code == 404


def test_workload_detail_excludes_muted_finding(authed, scene):
    url = reverse("workloads-detail", kwargs={"kind": "Deployment", "name": "api"})
    response = authed.get(url)
    findings = response.context["findings"]
    vuln_ids = {f.vuln_id for f in findings}
    assert "CVE-2025-0004" not in vuln_ids
    assert "CVE-2025-0001" in vuln_ids


# ── Per-image findings panel ─────────────────────────────────────


def test_default_active_row_is_top_urgency(authed, scene):
    url = reverse("workloads-detail", kwargs={"kind": "Deployment", "name": "api"})
    response = authed.get(url)
    active = response.context["active_row"]
    # cluster-a/api carries the only IMMEDIATE finding → top of the
    # urgency-sorted Images table → default selection.
    assert active is not None
    assert active["cluster"].name == "cluster-a"
    assert active["image"].digest == scene["img_shared"].digest


def test_image_query_param_selects_that_row(authed, scene):
    url = reverse("workloads-detail", kwargs={"kind": "Deployment", "name": "worker"})
    digest = scene["img_other"].digest
    response = authed.get(f"{url}?image={digest}")
    active = response.context["active_row"]
    assert active["image"].digest == digest
    assert active["cluster"].name == "cluster-a"


def test_findings_panel_scoped_to_selected_image(authed, scene):
    # Worker workload uses img_other (CVE-2025-0003 only). Selecting
    # that image must NOT leak api-workload findings into the panel.
    url = reverse(
        "workloads-detail", kwargs={"kind": "Deployment", "name": "worker"},
    )
    response = authed.get(f"{url}?image={scene['img_other'].digest}")
    findings = response.context["findings"]
    vuln_ids = {f.vuln_id for f in findings}
    assert vuln_ids == {"CVE-2025-0003"}


def test_htmx_returns_findings_panel_partial_only(authed, scene):
    url = reverse("workloads-detail", kwargs={"kind": "Deployment", "name": "api"})
    response = authed.get(
        url,
        HTTP_HX_REQUEST="true",
        HTTP_HX_TARGET="findings-panel",
    )
    body = response.content.decode()
    assert "<html" not in body.lower()
    assert 'id="findings-panel"' in body
    # Page chrome / Images card must NOT be in the partial.
    assert "Click a row to view its findings" not in body


def test_findings_panel_muted_finding_hidden_by_default(authed, scene):
    # img_shared on cluster-a carries CVE-2025-0001 (visible) and a
    # muted CVE-2025-0004. The panel must hide the muted one.
    url = reverse("workloads-detail", kwargs={"kind": "Deployment", "name": "api"})
    response = authed.get(f"{url}?cluster=cluster-a&image={scene['img_shared'].digest}")
    findings = response.context["findings"]
    vuln_ids = {f.vuln_id for f in findings}
    assert "CVE-2025-0001" in vuln_ids
    assert "CVE-2025-0004" not in vuln_ids


def test_active_row_falls_back_when_image_param_unknown(authed, scene):
    # An ?image= digest that doesn't match any row in scope should
    # fall back to the default top-urgency row, not 404 or render
    # an empty panel.
    url = reverse("workloads-detail", kwargs={"kind": "Deployment", "name": "api"})
    response = authed.get(f"{url}?image=sha256:{'f' * 64}")
    active = response.context["active_row"]
    assert active is not None
    assert active["image"].digest == scene["img_shared"].digest
