"""Unit tests for `core.services.pruning.prune_stale_findings`.

Two independent reasons a Finding becomes eligible: the workload is
undeployed (or cluster-scoped), OR the finding's own image is no longer
the (workload, image) pair's currently-deployed one — the "redeployed
onto a fixed image, workload itself still healthy" case. Both still
require `last_seen` to be older than the retention window first.
"""
from __future__ import annotations

from datetime import timedelta

import pytest
from django.utils import timezone

from core.constants import Category, IngestQueueStatus, Severity, Source
from core.models import (
    Cluster,
    Finding,
    Image,
    Namespace,
    Workload,
    WorkloadImageObservation,
)
from core.services.pruning import prune_stale_findings


def _bump(obj, **fields):
    type(obj).objects.filter(pk=obj.pk).update(**fields)
    obj.refresh_from_db()
    return obj


@pytest.fixture
def cluster(db):
    return Cluster.objects.create(name="c-prune-findings")


@pytest.fixture
def workload(cluster):
    ns = Namespace.objects.create(cluster=cluster, name="ns")
    return Workload.objects.create(
        cluster=cluster, namespace=ns, kind="Deployment", name="api", deployed=True,
    )


def _finding(cluster, workload, image, *, last_seen) -> Finding:
    f = Finding.objects.create(
        cluster=cluster,
        workload=workload,
        image=image,
        source=Source.TRIVY.value,
        category=Category.VULNERABILITY.value,
        vuln_id="CVE-2024-1",
        title="test finding",
        severity=Severity.HIGH.value,
        hash_code=f"hash-{workload.id if workload else 0}-{image.id if image else 0}",
        first_seen=last_seen,
        last_seen=last_seen,
    )
    return f


@pytest.mark.django_db
def test_finding_on_still_deployed_workload_but_stale_image_is_pruned(cluster, workload):
    """Workload stays deployed=True (redeployed onto a new image), but
    the OLD image this finding is bound to is no longer the currently
    deployed one for this workload — eligible once past the retention
    window, regardless of the workload's own deployed status."""
    old_image = Image.objects.create(digest="sha256:" + "a" * 64, ref="x:old")
    finding = _finding(
        cluster, workload, old_image,
        last_seen=timezone.now() - timedelta(days=200),
    )
    # No WorkloadImageObservation with currently_deployed=True for
    # (workload, old_image) — the redeploy already moved on.

    result = prune_stale_findings(days=180)

    assert result.deleted == 1
    assert not Finding.objects.filter(pk=finding.pk).exists()


@pytest.mark.django_db
def test_finding_on_still_deployed_and_still_current_image_is_protected(cluster, workload):
    """Same workload, same image, and that (workload, image) pair IS
    still currently deployed — must never be pruned regardless of age,
    since the observation itself would keep bumping last_seen in
    production; simulate the protected case directly."""
    image = Image.objects.create(digest="sha256:" + "b" * 64, ref="x:current")
    WorkloadImageObservation.objects.create(
        workload=workload, image=image, container_name="app",
        currently_deployed=True,
    )
    finding = _finding(
        cluster, workload, image,
        last_seen=timezone.now() - timedelta(days=200),
    )

    result = prune_stale_findings(days=180)

    assert result.deleted == 0
    assert Finding.objects.filter(pk=finding.pk).exists()


@pytest.mark.django_db
def test_stale_image_finding_within_grace_window_is_not_pruned_yet(cluster, workload):
    """The image was swapped out, but last_seen is still within the
    retention window — a fast rollout shouldn't instantly hard-delete."""
    old_image = Image.objects.create(digest="sha256:" + "c" * 64, ref="x:recent")
    finding = _finding(
        cluster, workload, old_image,
        last_seen=timezone.now() - timedelta(days=5),
    )

    result = prune_stale_findings(days=180)

    assert result.deleted == 0
    assert Finding.objects.filter(pk=finding.pk).exists()


@pytest.mark.django_db
def test_image_less_finding_unaffected_by_image_branch(cluster, workload):
    """Config/RBAC findings have no image at all — must be governed only
    by the pre-existing workload-deployed rule, not accidentally caught
    by the new image-based branch."""
    finding = _finding(
        cluster, workload, None,
        last_seen=timezone.now() - timedelta(days=200),
    )

    result = prune_stale_findings(days=180)

    # workload is still deployed=True and there's no image -> protected.
    assert result.deleted == 0
    assert Finding.objects.filter(pk=finding.pk).exists()

    Workload.objects.filter(pk=workload.pk).update(deployed=False)
    result = prune_stale_findings(days=180)
    assert result.deleted == 1
    assert not Finding.objects.filter(pk=finding.pk).exists()


@pytest.mark.django_db
def test_dry_run_does_not_delete_stale_image_finding(cluster, workload):
    old_image = Image.objects.create(digest="sha256:" + "d" * 64, ref="x:old2")
    finding = _finding(
        cluster, workload, old_image,
        last_seen=timezone.now() - timedelta(days=200),
    )

    result = prune_stale_findings(days=180, dry_run=True)

    assert result.scanned == 1
    assert result.deleted == 0
    assert Finding.objects.filter(pk=finding.pk).exists()
