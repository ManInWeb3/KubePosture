"""Tests for `core.services.pruning` — one block per target."""
from __future__ import annotations

from datetime import timedelta

import pytest
from django.utils import timezone

from core.constants import (
    Category,
    Environment,
    ImportMarkState,
    IngestQueueStatus,
    PriorityBand,
    Severity,
    Source,
)
from core.models import (
    Cluster,
    Finding,
    Image,
    ImportMark,
    IngestQueue,
    Namespace,
    SbomComponent,
    ScanInconsistency,
    Workload,
    WorkloadImageObservation,
)
from core.services.pruning import (
    prune_import_marks,
    prune_ingest_queue,
    prune_scan_inconsistencies,
    prune_stale_findings,
    prune_stale_sbom_components,
)


# ── helpers ─────────────────────────────────────────────────────


def _bump(obj, **fields):
    """Bypass auto_now and friends by going through .update()."""
    type(obj).objects.filter(pk=obj.pk).update(**fields)
    obj.refresh_from_db()
    return obj


def _ago(days: int):
    return timezone.now() - timedelta(days=days)


# ── IngestQueue ────────────────────────────────────────────────


@pytest.mark.django_db
def test_prune_ingest_queue_keeps_recent_done_items():
    fresh = IngestQueue.objects.create(
        cluster_name="c", kind="inventory", import_id="i1", raw_json={},
        status=IngestQueueStatus.DONE.value,
    )
    _bump(fresh, processed_at=_ago(5))

    stale = IngestQueue.objects.create(
        cluster_name="c", kind="inventory", import_id="i2", raw_json={},
        status=IngestQueueStatus.DONE.value,
    )
    _bump(stale, processed_at=_ago(30))

    result = prune_ingest_queue(days=14)
    assert result.scanned == 1
    assert result.deleted == 1
    assert IngestQueue.objects.filter(pk=fresh.pk).exists()
    assert not IngestQueue.objects.filter(pk=stale.pk).exists()


@pytest.mark.django_db
def test_prune_ingest_queue_skips_pending_and_processing():
    """Active rows must never be pruned even if they're old."""
    pending = IngestQueue.objects.create(
        cluster_name="c", kind="inventory", import_id="i1", raw_json={},
        status=IngestQueueStatus.PENDING.value,
    )
    _bump(pending, processed_at=_ago(60))   # shouldn't happen but defensive

    processing = IngestQueue.objects.create(
        cluster_name="c", kind="inventory", import_id="i2", raw_json={},
        status=IngestQueueStatus.PROCESSING.value,
    )
    _bump(processing, processed_at=_ago(60))

    result = prune_ingest_queue(days=14)
    assert result.scanned == 0
    assert IngestQueue.objects.filter(pk__in=[pending.pk, processing.pk]).count() == 2


@pytest.mark.django_db
def test_prune_ingest_queue_handles_failed_items():
    failed_old = IngestQueue.objects.create(
        cluster_name="c", kind="inventory", import_id="i", raw_json={},
        status=IngestQueueStatus.FAILED.value,
    )
    _bump(failed_old, processed_at=_ago(30))
    result = prune_ingest_queue(days=14)
    assert result.deleted == 1


@pytest.mark.django_db
def test_prune_ingest_queue_dry_run_no_delete():
    stale = IngestQueue.objects.create(
        cluster_name="c", kind="inventory", import_id="i", raw_json={},
        status=IngestQueueStatus.DONE.value,
    )
    _bump(stale, processed_at=_ago(30))

    result = prune_ingest_queue(days=14, dry_run=True)
    assert result.scanned == 1
    assert result.deleted == 0
    assert IngestQueue.objects.filter(pk=stale.pk).exists()


# ── ImportMark ──────────────────────────────────────────────────


@pytest.mark.django_db
def test_prune_import_marks_keeps_open_and_draining_marks():
    c = Cluster.objects.create(name="c1", environment=Environment.PROD.value)
    now = timezone.now()
    open_mark = ImportMark.objects.create(
        cluster=c, kind="inventory", import_id="x",
        state=ImportMarkState.OPEN.value, started_at=now,
    )
    _bump(open_mark, completed_at=_ago(200))   # should be ignored — wrong state

    draining = ImportMark.objects.create(
        cluster=c, kind="inventory", import_id="y",
        state=ImportMarkState.DRAINING.value, started_at=now,
    )
    _bump(draining, completed_at=_ago(200))

    reaped_old = ImportMark.objects.create(
        cluster=c, kind="inventory", import_id="z",
        state=ImportMarkState.REAPED.value, started_at=now,
    )
    _bump(reaped_old, completed_at=_ago(120))

    reaped_recent = ImportMark.objects.create(
        cluster=c, kind="inventory", import_id="w",
        state=ImportMarkState.REAPED.value, started_at=now,
    )
    _bump(reaped_recent, completed_at=_ago(30))

    result = prune_import_marks(days=90)
    assert result.scanned == 1
    assert result.deleted == 1
    surviving = set(ImportMark.objects.values_list("pk", flat=True))
    assert surviving == {open_mark.pk, draining.pk, reaped_recent.pk}


# ── ScanInconsistency ──────────────────────────────────────────


@pytest.mark.django_db
def test_prune_scan_inconsistencies_filters_on_last_observed():
    c = Cluster.objects.create(name="c1", environment=Environment.PROD.value)
    fresh = ScanInconsistency.objects.create(
        cluster=c, kind="VulnerabilityReport", image_digest="sha256:a" * 8,
    )
    _bump(fresh, last_observed_at=_ago(5))

    stale = ScanInconsistency.objects.create(
        cluster=c, kind="SbomReport", image_digest="sha256:b" * 8,
    )
    _bump(stale, last_observed_at=_ago(60))

    result = prune_scan_inconsistencies(days=30)
    assert result.deleted == 1
    assert ScanInconsistency.objects.filter(pk=fresh.pk).exists()
    assert not ScanInconsistency.objects.filter(pk=stale.pk).exists()


# ── Finding ─────────────────────────────────────────────────────


@pytest.mark.django_db
def test_prune_stale_findings_protects_deployed_workloads():
    """Even very old findings on currently-deployed workloads survive."""
    c = Cluster.objects.create(name="c1", environment=Environment.PROD.value)
    ns = Namespace.objects.create(cluster=c, name="default")
    deployed = Workload.objects.create(
        cluster=c, namespace=ns, kind="Deployment", name="active", deployed=True,
    )
    f = Finding.objects.create(
        cluster=c, workload=deployed,
        source=Source.TRIVY.value, category=Category.VULNERABILITY.value,
        vuln_id="CVE-1", title="x", severity=Severity.HIGH.value,
        effective_priority=PriorityBand.SCHEDULED.value, hash_code="h",
    )
    _bump(f, last_seen=_ago(365))

    result = prune_stale_findings(days=180)
    assert result.scanned == 0
    assert Finding.objects.filter(pk=f.pk).exists()


@pytest.mark.django_db
def test_prune_stale_findings_removes_old_undeployed_findings():
    c = Cluster.objects.create(name="c1", environment=Environment.PROD.value)
    ns = Namespace.objects.create(cluster=c, name="default")
    undeployed = Workload.objects.create(
        cluster=c, namespace=ns, kind="Deployment", name="zombie", deployed=False,
    )
    old = Finding.objects.create(
        cluster=c, workload=undeployed,
        source=Source.TRIVY.value, category=Category.VULNERABILITY.value,
        vuln_id="CVE-1", title="x", severity=Severity.HIGH.value,
        effective_priority=PriorityBand.SCHEDULED.value, hash_code="h",
    )
    _bump(old, last_seen=_ago(365))

    recent = Finding.objects.create(
        cluster=c, workload=undeployed,
        source=Source.TRIVY.value, category=Category.VULNERABILITY.value,
        vuln_id="CVE-2", title="y", severity=Severity.HIGH.value,
        effective_priority=PriorityBand.SCHEDULED.value, hash_code="h2",
    )
    _bump(recent, last_seen=_ago(30))   # well within window

    result = prune_stale_findings(days=180)
    assert result.deleted == 1
    assert Finding.objects.filter(pk=recent.pk).exists()
    assert not Finding.objects.filter(pk=old.pk).exists()


@pytest.mark.django_db
def test_prune_stale_findings_handles_cluster_scoped_with_null_workload():
    """Cluster-scoped findings (workload IS NULL) prune purely on age."""
    c = Cluster.objects.create(name="c1", environment=Environment.PROD.value)
    old = Finding.objects.create(
        cluster=c, workload=None,
        source=Source.TRIVY.value, category=Category.RBAC.value,
        vuln_id="AVD-1", title="cluster-scoped", severity=Severity.HIGH.value,
        effective_priority=PriorityBand.SCHEDULED.value, hash_code="hcs",
    )
    _bump(old, last_seen=_ago(365))

    result = prune_stale_findings(days=180)
    assert result.deleted == 1


# ── SbomComponent ──────────────────────────────────────────────


@pytest.mark.django_db
def test_prune_stale_sbom_components_protects_currently_deployed_images():
    """A component on an image observed as currently_deployed=True
    survives even if the Image row's last_seen_at is old.
    """
    c = Cluster.objects.create(name="c1", environment=Environment.PROD.value)
    ns = Namespace.objects.create(cluster=c, name="default")
    w = Workload.objects.create(
        cluster=c, namespace=ns, kind="Deployment", name="api", deployed=True,
    )
    img = Image.objects.create(digest="sha256:" + "a" * 64, ref="r:1")
    _bump(img, last_seen_at=_ago(365))
    WorkloadImageObservation.objects.create(
        workload=w, image=img, container_name="main", currently_deployed=True,
    )
    comp = SbomComponent.objects.create(
        image=img, purl="pkg:npm/x@1.0", name="x", version="1.0", ecosystem="npm",
    )

    result = prune_stale_sbom_components(days=90)
    assert result.scanned == 0
    assert SbomComponent.objects.filter(pk=comp.pk).exists()


@pytest.mark.django_db
def test_prune_stale_sbom_components_deletes_orphaned_components():
    """Old + no currently-deployed observation → pruned."""
    img = Image.objects.create(digest="sha256:" + "a" * 64, ref="r:1")
    _bump(img, last_seen_at=_ago(180))
    comp = SbomComponent.objects.create(
        image=img, purl="pkg:npm/orphan@1.0",
        name="orphan", version="1.0", ecosystem="npm",
    )

    result = prune_stale_sbom_components(days=90)
    assert result.deleted == 1
    assert not SbomComponent.objects.filter(pk=comp.pk).exists()
    # Image row itself MUST survive — append-only contract.
    assert Image.objects.filter(pk=img.pk).exists()


@pytest.mark.django_db
def test_prune_stale_sbom_components_with_only_undeployed_observation_is_pruned():
    """Image has an observation but `currently_deployed=False`. Old
    enough → component pruned, image survives.
    """
    c = Cluster.objects.create(name="c1", environment=Environment.PROD.value)
    ns = Namespace.objects.create(cluster=c, name="default")
    w = Workload.objects.create(
        cluster=c, namespace=ns, kind="Deployment", name="old", deployed=False,
    )
    img = Image.objects.create(digest="sha256:" + "b" * 64, ref="r:2")
    _bump(img, last_seen_at=_ago(180))
    WorkloadImageObservation.objects.create(
        workload=w, image=img, container_name="main", currently_deployed=False,
    )
    SbomComponent.objects.create(
        image=img, purl="pkg:npm/y@1.0", name="y", version="1.0", ecosystem="npm",
    )

    result = prune_stale_sbom_components(days=90)
    assert result.deleted == 1
    assert Image.objects.filter(pk=img.pk).exists()


# ── Common: dry-run ─────────────────────────────────────────────


@pytest.mark.django_db
def test_dry_run_is_side_effect_free_across_all_targets():
    """Smoke-style: seed a row for each target, dry-run reports counts,
    nothing deleted.
    """
    c = Cluster.objects.create(name="c1", environment=Environment.PROD.value)

    q = IngestQueue.objects.create(
        cluster_name="c", kind="inventory", import_id="i", raw_json={},
        status=IngestQueueStatus.DONE.value,
    )
    _bump(q, processed_at=_ago(30))

    m = ImportMark.objects.create(
        cluster=c, kind="inventory", import_id="iz",
        state=ImportMarkState.REAPED.value, started_at=timezone.now(),
    )
    _bump(m, completed_at=_ago(120))

    si = ScanInconsistency.objects.create(
        cluster=c, kind="A", image_digest="sha256:z" * 8,
    )
    _bump(si, last_observed_at=_ago(60))

    img = Image.objects.create(digest="sha256:" + "c" * 64, ref="orphan:1")
    _bump(img, last_seen_at=_ago(180))
    SbomComponent.objects.create(
        image=img, purl="pkg:npm/o@1.0", name="o", version="1.0", ecosystem="npm",
    )

    results = [
        prune_ingest_queue(dry_run=True),
        prune_import_marks(dry_run=True),
        prune_scan_inconsistencies(dry_run=True),
        prune_stale_findings(dry_run=True),
        prune_stale_sbom_components(dry_run=True),
    ]
    for r in results:
        assert r.deleted == 0, f"{r.target} touched rows in dry-run"

    # All seeded rows still present.
    assert IngestQueue.objects.filter(pk=q.pk).exists()
    assert ImportMark.objects.filter(pk=m.pk).exists()
    assert ScanInconsistency.objects.filter(pk=si.pk).exists()
    assert SbomComponent.objects.filter(image=img).exists()


@pytest.mark.django_db
def test_second_run_is_idempotent():
    """After a successful prune, a second run reports scanned=0."""
    fresh = IngestQueue.objects.create(
        cluster_name="c", kind="inventory", import_id="i", raw_json={},
        status=IngestQueueStatus.DONE.value,
    )
    _bump(fresh, processed_at=_ago(30))

    prune_ingest_queue(days=14)
    second = prune_ingest_queue(days=14)
    assert second.scanned == 0
    assert second.deleted == 0
