"""Tests for `core.services.components`.

Locks the contract:
- list_components groups by purl with image/workload/cluster counts.
- active() filter excludes components whose images aren't deployed.
- search_by_purls JOINs through observations and returns one row per
  (cluster, workload, purl).
- component_detail returns the affected-images breakdown and the
  other-versions list.
"""
from __future__ import annotations

import pytest

from core.constants import Environment
from core.models import (
    Cluster,
    Image,
    Namespace,
    SbomComponent,
    Workload,
    WorkloadImageObservation,
)
from core.services.components import (
    component_detail,
    list_components,
    search_by_purls,
)


# ── Fixtures ────────────────────────────────────────────────────


def _cluster(name: str) -> Cluster:
    return Cluster.objects.create(name=name, environment=Environment.PROD.value)


def _ns(c: Cluster, name: str = "payments") -> Namespace:
    return Namespace.objects.create(cluster=c, name=name)


def _workload(c: Cluster, ns: Namespace, name: str) -> Workload:
    return Workload.objects.create(
        cluster=c, namespace=ns, kind="Deployment", name=name, deployed=True,
    )


def _image(digest: str, ref: str = "") -> Image:
    return Image.objects.create(digest=digest, ref=ref or f"img:{digest[:8]}")


def _observation(workload: Workload, image: Image, *, deployed: bool, container: str = "app"):
    return WorkloadImageObservation.objects.create(
        workload=workload, image=image, container_name=container,
        currently_deployed=deployed,
    )


def _component(image: Image, purl: str, *, name: str | None = None, version: str = "1.0", ecosystem: str = "npm"):
    return SbomComponent.objects.create(
        image=image, purl=purl,
        name=name or purl.split("/")[-1].split("@")[0],
        version=version, ecosystem=ecosystem,
    )


# ── list_components ──────────────────────────────────────────────


@pytest.mark.django_db
def test_list_components_groups_by_purl_with_counts():
    c = _cluster("c1")
    ns = _ns(c)
    w1 = _workload(c, ns, "api")
    w2 = _workload(c, ns, "worker")

    img1 = _image("sha256:" + "a" * 64)
    img2 = _image("sha256:" + "b" * 64)
    _observation(w1, img1, deployed=True)
    _observation(w2, img2, deployed=True)

    # Same purl in two different images → two SbomComponent rows,
    # but one display row with image_count=2.
    _component(img1, "pkg:npm/lodash@4.17.21")
    _component(img2, "pkg:npm/lodash@4.17.21")
    _component(img1, "pkg:npm/express@4.18.0")

    rows = list(list_components())
    by_purl = {r["purl"]: r for r in rows}
    assert by_purl["pkg:npm/lodash@4.17.21"]["image_count"] == 2
    assert by_purl["pkg:npm/lodash@4.17.21"]["workload_count"] == 2
    assert by_purl["pkg:npm/lodash@4.17.21"]["cluster_count"] == 1
    assert by_purl["pkg:npm/express@4.18.0"]["image_count"] == 1
    assert by_purl["pkg:npm/express@4.18.0"]["workload_count"] == 1


@pytest.mark.django_db
def test_list_components_excludes_undeployed_by_default():
    c = _cluster("c1")
    ns = _ns(c)
    w_active = _workload(c, ns, "active")
    w_inactive = _workload(c, ns, "inactive")

    img_active = _image("sha256:" + "a" * 64)
    img_inactive = _image("sha256:" + "b" * 64)
    _observation(w_active, img_active, deployed=True)
    _observation(w_inactive, img_inactive, deployed=False)

    _component(img_active, "pkg:npm/deployed-pkg@1.0")
    _component(img_inactive, "pkg:npm/orphan-pkg@1.0")

    purls = {r["purl"] for r in list_components()}
    assert "pkg:npm/deployed-pkg@1.0" in purls
    assert "pkg:npm/orphan-pkg@1.0" not in purls

    # include_inactive=True surfaces both.
    purls_all = {r["purl"] for r in list_components(include_inactive=True)}
    assert "pkg:npm/orphan-pkg@1.0" in purls_all


@pytest.mark.django_db
def test_list_components_cluster_filter_scopes_both_selection_and_counts():
    c1 = _cluster("c1")
    c2 = _cluster("c2")
    ns1 = _ns(c1, "ns1")
    ns2 = _ns(c2, "ns2")
    w1 = _workload(c1, ns1, "api1")
    w2 = _workload(c2, ns2, "api2")

    img = _image("sha256:" + "a" * 64)
    _observation(w1, img, deployed=True)
    _observation(w2, img, deployed=True)
    _component(img, "pkg:npm/shared@1.0")

    # Global: 2 workloads / 2 clusters.
    global_rows = list(list_components())
    assert global_rows[0]["workload_count"] == 2
    assert global_rows[0]["cluster_count"] == 2

    # Scoped to c1: 1 workload / 1 cluster.
    c1_rows = list(list_components(cluster=c1))
    assert c1_rows[0]["workload_count"] == 1
    assert c1_rows[0]["cluster_count"] == 1


@pytest.mark.django_db
def test_list_components_filters_by_name_substring_and_ecosystem():
    c = _cluster("c1")
    ns = _ns(c)
    w = _workload(c, ns, "api")
    img = _image("sha256:" + "a" * 64)
    _observation(w, img, deployed=True)

    _component(img, "pkg:npm/lodash@4.17.21", name="lodash", ecosystem="npm")
    _component(img, "pkg:pypi/requests@2.28.0", name="requests", ecosystem="pypi")
    _component(img, "pkg:npm/express@4.18.0", name="express", ecosystem="npm")

    names = {r["name"] for r in list_components(name_contains="lod")}
    assert names == {"lodash"}


@pytest.mark.django_db
def test_list_components_image_digest_scopes_to_one_image_incl_undeployed():
    """The `X components` link from an image detail page passes the image
    digest. It must scope to that image's SBOM only — and surface it even
    when the image isn't currently deployed (the SBOM count on the detail
    page counts all components regardless of deployment).
    """
    c = _cluster("c1")
    ns = _ns(c)
    w = _workload(c, ns, "api")

    img_target = _image("sha256:" + "a" * 64)
    img_other = _image("sha256:" + "b" * 64)
    # Target image is NOT deployed; other image is.
    _observation(w, img_other, deployed=True)

    _component(img_target, "pkg:npm/in-target@1.0")
    _component(img_other, "pkg:npm/in-other@1.0")

    purls = {r["purl"] for r in list_components(image_digest=img_target.digest)}
    assert purls == {"pkg:npm/in-target@1.0"}


@pytest.mark.django_db
def test_search_matches_name_at_version_and_full_purl():
    """Regression: the search bar must match against name + purl + version,
    not name only — otherwise pasting a purl returns zero results.
    """
    c = _cluster("c1")
    ns = _ns(c)
    w = _workload(c, ns, "api")
    img = _image("sha256:" + "a" * 64)
    _observation(w, img, deployed=True)
    _component(img, "pkg:npm/lodash@4.17.21", name="lodash", version="4.17.21", ecosystem="npm")
    _component(img, "pkg:npm/express@4.18.0", name="express", version="4.18.0", ecosystem="npm")

    # name-only
    assert {r["name"] for r in list_components(name_contains="lodash")} == {"lodash"}
    # name@version
    assert {r["name"] for r in list_components(name_contains="lodash@4.17.21")} == {"lodash"}
    # full purl
    assert {r["name"] for r in list_components(name_contains="pkg:npm/lodash@4.17.21")} == {"lodash"}
    # bare version
    assert {r["name"] for r in list_components(name_contains="4.17.21")} == {"lodash"}
    # encoded purl (%40 round-trip)
    assert {r["name"] for r in list_components(name_contains="lodash%404.17.21")} == {"lodash"}

    npms = {r["name"] for r in list_components(ecosystem="npm")}
    assert npms == {"lodash", "express"}


# ── search_by_purls ──────────────────────────────────────────────


@pytest.mark.django_db
def test_search_by_purls_returns_matched_workloads():
    c = _cluster("c1")
    ns = _ns(c)
    w = _workload(c, ns, "api")
    img = _image("sha256:" + "a" * 64, ref="registry/payments/api:v1")
    _observation(w, img, deployed=True, container="app")
    _component(img, "pkg:npm/lodash@4.17.21")
    _component(img, "pkg:npm/express@4.18.0")

    matches = search_by_purls(purls=["pkg:npm/lodash@4.17.21"])
    assert len(matches) == 1
    m = matches[0]
    assert m["cluster"] == "c1"
    assert m["workload_name"] == "api"
    assert m["container_name"] == "app"
    assert m["purl"] == "pkg:npm/lodash@4.17.21"


@pytest.mark.django_db
def test_search_by_purls_prefix_match():
    c = _cluster("c1")
    ns = _ns(c)
    w = _workload(c, ns, "api")
    img = _image("sha256:" + "a" * 64)
    _observation(w, img, deployed=True)
    _component(img, "pkg:npm/lodash@4.17.21")
    _component(img, "pkg:npm/lodash@4.17.20")
    _component(img, "pkg:npm/express@4.18.0")

    matches = search_by_purls(purl_prefixes=["pkg:npm/lodash"])
    assert len(matches) == 2
    assert all(m["purl"].startswith("pkg:npm/lodash") for m in matches)


@pytest.mark.django_db
def test_search_by_purls_excludes_undeployed_by_default():
    c = _cluster("c1")
    ns = _ns(c)
    w = _workload(c, ns, "api")
    img = _image("sha256:" + "a" * 64)
    _observation(w, img, deployed=False)
    _component(img, "pkg:npm/lodash@4.17.21")

    assert search_by_purls(purls=["pkg:npm/lodash@4.17.21"]) == []
    assert search_by_purls(purls=["pkg:npm/lodash@4.17.21"], include_inactive=True) != []


# ── component_detail ─────────────────────────────────────────────


@pytest.mark.django_db
def test_component_detail_returns_image_and_workload_breakdown():
    c = _cluster("c1")
    ns = _ns(c)
    w1 = _workload(c, ns, "api")
    w2 = _workload(c, ns, "worker")
    img = _image("sha256:" + "a" * 64, ref="registry/api:v1")
    _observation(w1, img, deployed=True, container="app")
    _observation(w2, img, deployed=True, container="main")
    _component(img, "pkg:npm/lodash@4.17.21", version="4.17.21")

    d = component_detail("pkg:npm/lodash@4.17.21")
    assert d is not None
    assert d["name"] == "lodash"
    assert d["version"] == "4.17.21"
    assert len(d["images"]) == 1
    workloads = d["images"][0]["workloads"]
    assert {w["workload"].name for w in workloads} == {"api", "worker"}


@pytest.mark.django_db
def test_component_detail_lists_other_versions_of_same_name():
    c = _cluster("c1")
    ns = _ns(c)
    w = _workload(c, ns, "api")
    img1 = _image("sha256:" + "a" * 64)
    img2 = _image("sha256:" + "b" * 64)
    _observation(w, img1, deployed=True)
    _observation(w, img2, deployed=True)
    _component(img1, "pkg:npm/lodash@4.17.21", name="lodash", version="4.17.21")
    _component(img2, "pkg:npm/lodash@4.17.20", name="lodash", version="4.17.20")

    d = component_detail("pkg:npm/lodash@4.17.21")
    other_purls = {v["purl"] for v in d["other_versions"]}
    assert other_purls == {"pkg:npm/lodash@4.17.20"}


@pytest.mark.django_db
def test_component_detail_returns_none_for_unknown_purl():
    assert component_detail("pkg:npm/nope@1.0.0") is None
