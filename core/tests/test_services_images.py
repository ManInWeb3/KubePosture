"""Tests for `core.services.images.list_images` + `get_image_detail`.

Backs the `/images/` page. Verifies the blast-radius impact ranking,
the quick-win `impact_per_cve` sort, the currently-deployed filter,
and the namespace filter semantics (image set narrows, band counts
stay fleet-wide).
"""
from __future__ import annotations

from datetime import timedelta

import pytest
from django.utils import timezone

from core.constants import Environment, PriorityBand
from core.models import (
    Cluster,
    Finding,
    Image,
    Namespace,
    SbomComponent,
    Workload,
    WorkloadImageObservation,
)
from core.services.images import (
    IMPACT_WEIGHTS,
    get_image_detail,
    is_valid_digest,
    list_images,
)


# ── Fixtures ─────────────────────────────────────────────────────


@pytest.fixture
def cluster(db):
    c = Cluster.objects.create(name="c-img", environment=Environment.PROD.value)
    c.last_complete_inventory_at = timezone.now()
    c.save()
    return c


@pytest.fixture
def cluster_b(db):
    c = Cluster.objects.create(name="c-img-b", environment=Environment.STAGING.value)
    c.last_complete_inventory_at = timezone.now()
    c.save()
    return c


def _ns(cluster, name):
    return Namespace.objects.create(cluster=cluster, name=name)


def _workload(cluster, ns, name, kind="Deployment"):
    return Workload.objects.create(
        cluster=cluster, namespace=ns, kind=kind, name=name,
        deployed=True, last_inventory_at=cluster.last_complete_inventory_at,
    )


def _image(letter):
    return Image.objects.create(
        digest=f"sha256:{letter * 64}",
        ref=f"registry/{letter}:v1",
        registry="registry",
        repository=letter,
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


def _finding(cluster, workload, image, priority, vuln_id):
    return Finding.objects.create(
        cluster=cluster, workload=workload, image=image,
        source="trivy", category="vulnerability", vuln_id=vuln_id,
        title=f"bug {vuln_id}", severity="high",
        effective_priority=priority, hash_code=f"h-{vuln_id}",
    )


# ── Impact ranking ───────────────────────────────────────────────


def test_impact_ranks_one_immediate_above_pile_of_scheduled(cluster):
    """1 IMMEDIATE × 12 workloads (= 12 000) outranks 10 SCHEDULED ×
    1 workload (= 100). Powers-of-10 weighting guarantees the urgency
    tree's verdict survives aggregation."""
    ns = _ns(cluster, "n")

    # Image A: 12 workloads, 1 IMMEDIATE CVE per workload.
    img_a = _image("a")
    for i in range(12):
        w = _workload(cluster, ns, f"wa-{i}")
        _observe(w, img_a)
        _finding(cluster, w, img_a, PriorityBand.IMMEDIATE.value, f"CVE-A-{i}")

    # Image B: 1 workload, 10 SCHEDULED CVEs.
    img_b = _image("b")
    w_b = _workload(cluster, ns, "wb")
    _observe(w_b, img_b)
    for i in range(10):
        _finding(cluster, w_b, img_b, PriorityBand.SCHEDULED.value, f"CVE-B-{i}")

    rows = list_images()
    by_digest = {r["digest"]: r for r in rows}

    a = by_digest[img_a.digest]
    b = by_digest[img_b.digest]

    # 12 workloads × (12 IMMEDIATE × 1000) = 12 * 12_000 = 144_000
    assert a["impact"] == 12 * (12 * IMPACT_WEIGHTS[PriorityBand.IMMEDIATE.value])
    # 1 workload × (10 SCHEDULED × 10) = 100
    assert b["impact"] == 1 * (10 * IMPACT_WEIGHTS[PriorityBand.SCHEDULED.value])
    assert a["impact"] > b["impact"]

    # Default sort is impact desc → image A first.
    assert rows[0]["digest"] == img_a.digest


def test_impact_per_cve_quick_win_sort(cluster):
    """1 CVE × 50 workloads (impact 1000×50=50000, per_cve=50000) outranks
    50 CVEs × 1 workload (impact 50×1000=50000, per_cve=1000) on the
    quick-win sort, even when total impact is identical."""
    ns = _ns(cluster, "n")

    img_a = _image("a")
    for i in range(50):
        w = _workload(cluster, ns, f"wa-{i}")
        _observe(w, img_a)
    # Single CVE, attached to the first workload (it's per-Finding).
    first_wa = Workload.objects.filter(name="wa-0").first()
    _finding(cluster, first_wa, img_a, PriorityBand.IMMEDIATE.value, "CVE-A-0")

    img_b = _image("b")
    w_b = _workload(cluster, ns, "wb")
    _observe(w_b, img_b)
    for i in range(50):
        _finding(cluster, w_b, img_b, PriorityBand.IMMEDIATE.value, f"CVE-B-{i}")

    rows = list_images(sort="impact_per_cve", sort_dir="desc")
    # Image A has impact/cve = (50 * 1 * 1000) / 1 = 50_000
    # Image B has impact/cve = (1 * 50 * 1000) / 50 = 1_000
    assert rows[0]["digest"] == img_a.digest
    assert rows[0]["impact_per_cve"] > rows[1]["impact_per_cve"]


# ── currently_deployed filter ────────────────────────────────────


def test_currently_deployed_filter_default_excludes_undeployed(cluster):
    """Image observed only with currently_deployed=False must not appear
    in the default listing."""
    ns = _ns(cluster, "n")
    w = _workload(cluster, ns, "w")

    img_live = _image("a")
    _observe(w, img_live)

    img_stale = _image("b")
    obs = WorkloadImageObservation.objects.create(
        workload=w, image=img_stale, container_name="legacy",
        currently_deployed=False,
    )
    WorkloadImageObservation.objects.filter(pk=obs.pk).update(
        last_seen_at=cluster.last_complete_inventory_at - timedelta(days=2),
    )

    rows = list_images()
    digests = {r["digest"] for r in rows}
    assert img_live.digest in digests
    assert img_stale.digest not in digests


def test_currently_deployed_off_surfaces_historical_images(cluster):
    ns = _ns(cluster, "n")
    w = _workload(cluster, ns, "w")
    img_stale = _image("b")
    obs = WorkloadImageObservation.objects.create(
        workload=w, image=img_stale, container_name="legacy",
        currently_deployed=False,
    )
    WorkloadImageObservation.objects.filter(pk=obs.pk).update(
        last_seen_at=cluster.last_complete_inventory_at - timedelta(days=2),
    )

    rows = list_images(currently_deployed_only=False)
    digests = {r["digest"] for r in rows}
    assert img_stale.digest in digests


# ── Namespace filter semantics ───────────────────────────────────


def test_namespace_filter_narrows_image_set_not_counts(cluster):
    """An image deployed in both ns-a and ns-b: filtering to ns-a still
    counts every CVE on the image. Workload count narrows to ns-a, but
    band counts stay fleet-wide."""
    ns_a = _ns(cluster, "ns-a")
    ns_b = _ns(cluster, "ns-b")

    w_a = _workload(cluster, ns_a, "wa")
    w_b = _workload(cluster, ns_b, "wb")

    img = _image("a")
    _observe(w_a, img)
    _observe(w_b, img)

    _finding(cluster, w_a, img, PriorityBand.IMMEDIATE.value, "CVE-1")
    _finding(cluster, w_b, img, PriorityBand.IMMEDIATE.value, "CVE-2")

    rows = list_images(namespace="ns-a")
    assert len(rows) == 1
    row = rows[0]
    assert row["workload_count"] == 1
    # Band count covers BOTH findings — the image is the unit, not the workload.
    assert row["n_immediate"] == 2


# ── Cluster filter ───────────────────────────────────────────────


def test_cluster_filter_scopes_image_set(cluster, cluster_b):
    """Image only deployed in cluster_b must not appear when filtered
    to cluster."""
    ns_a = _ns(cluster, "n")
    ns_b = _ns(cluster_b, "n")
    img_a = _image("a")
    img_b = _image("b")
    _observe(_workload(cluster, ns_a, "wa"), img_a)
    _observe(_workload(cluster_b, ns_b, "wb"), img_b)

    rows = list_images(cluster="c-img")
    digests = {r["digest"] for r in rows}
    assert img_a.digest in digests
    assert img_b.digest not in digests


def test_repository_filter_substring(cluster):
    ns = _ns(cluster, "n")
    w = _workload(cluster, ns, "w")
    img_api = Image.objects.create(
        digest="sha256:" + "1" * 64, ref="reg/api:v1",
        registry="reg", repository="api",
    )
    img_db = Image.objects.create(
        digest="sha256:" + "2" * 64, ref="reg/db:v1",
        registry="reg", repository="db",
    )
    _observe(w, img_api)
    _observe(_workload(cluster, ns, "w2"), img_db)

    rows = list_images(repository_contains="ap")
    digests = {r["digest"] for r in rows}
    assert img_api.digest in digests
    assert img_db.digest not in digests


# ── get_image_detail ─────────────────────────────────────────────


def test_get_image_detail_returns_workloads_and_findings(cluster):
    ns = _ns(cluster, "n")
    w = _workload(cluster, ns, "w")
    img = _image("a")
    _observe(w, img)
    _finding(cluster, w, img, PriorityBand.IMMEDIATE.value, "CVE-1")

    SbomComponent.objects.create(
        image=img, purl="pkg:npm/x@1", name="x", version="1", ecosystem="npm",
    )

    detail = get_image_detail(img.digest)
    assert detail is not None
    assert detail["image"].pk == img.pk
    assert len(detail["workload_rows"]) == 1
    assert detail["workload_rows"][0]["workload"].pk == w.pk
    assert detail["sbom_count"] == 1
    vuln_ids = {f.vuln_id for f in detail["findings_qs"]}
    assert vuln_ids == {"CVE-1"}


def test_get_image_detail_unknown_returns_none(db):
    assert get_image_detail("sha256:" + "0" * 64) is None


# ── Digest validation ────────────────────────────────────────────


def test_is_valid_digest():
    assert is_valid_digest("sha256:" + "a" * 64)
    assert is_valid_digest("sha256:" + "f" * 64)
    assert not is_valid_digest("")
    assert not is_valid_digest("sha256:")
    assert not is_valid_digest("sha256:abc")  # too short
    assert not is_valid_digest("md5:" + "a" * 32)
    assert not is_valid_digest("sha256:" + "Z" * 64)  # non-hex
    assert not is_valid_digest("../etc/passwd")
