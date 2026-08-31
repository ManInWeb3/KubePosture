"""Unit tests for `core.services.inventory.base_finding_filter` /
`default_finding_qs` — specifically the scanner-outage protection.

Without it, a Trivy outage long enough to let the (independent) inventory
cycle advance `cluster.last_complete_inventory_at` past a Finding's frozen
`last_seen` would silently hide that Finding from every default view —
indistinguishable from "actually fixed". An open ScanInconsistency row
(written by `reaper._write_scan_inconsistencies_for_outage` whenever a
scan kind reports zero input for a non-empty scope) for the exact
(cluster, workload, image) now keeps the Finding visible instead.
"""
from __future__ import annotations

from datetime import timedelta

import pytest
from django.utils import timezone

from core.constants import Category, Severity, Source
from core.models import (
    Cluster,
    Finding,
    Image,
    Namespace,
    ScanInconsistency,
    Workload,
)
from core.services.inventory import default_finding_qs


@pytest.fixture
def cluster(db):
    c = Cluster.objects.create(name="c-outage")
    Cluster.objects.filter(pk=c.pk).update(last_complete_inventory_at=timezone.now())
    c.refresh_from_db()
    return c


@pytest.fixture
def workload(cluster):
    ns = Namespace.objects.create(cluster=cluster, name="ns")
    return Workload.objects.create(
        cluster=cluster, namespace=ns, kind="Deployment", name="api", deployed=True,
    )


@pytest.fixture
def image():
    return Image.objects.create(digest="sha256:" + "e" * 64, ref="x:1")


def _stale_finding(cluster, workload, image) -> Finding:
    return Finding.objects.create(
        cluster=cluster,
        workload=workload,
        image=image,
        source=Source.TRIVY.value,
        category=Category.VULNERABILITY.value,
        vuln_id="CVE-2024-2",
        title="stale finding",
        severity=Severity.HIGH.value,
        hash_code="hash-outage-1",
        first_seen=cluster.last_complete_inventory_at - timedelta(days=10),
        last_seen=cluster.last_complete_inventory_at - timedelta(days=10),
    )


@pytest.mark.django_db
def test_stale_finding_hidden_by_default_with_no_outage_record(cluster, workload, image):
    finding = _stale_finding(cluster, workload, image)

    visible_ids = set(default_finding_qs().values_list("id", flat=True))

    assert finding.id not in visible_ids


@pytest.mark.django_db
def test_stale_finding_stays_visible_during_open_scan_outage(cluster, workload, image):
    finding = _stale_finding(cluster, workload, image)
    ScanInconsistency.objects.create(
        cluster=cluster,
        kind="trivy.VulnerabilityReport",
        workload=workload,
        image_digest=image.digest,
        seen_in_inventory=True,
        seen_in_scans=False,
    )

    visible_ids = set(default_finding_qs().values_list("id", flat=True))

    assert finding.id in visible_ids, (
        "an unresolved scan outage for this exact (workload, image) must "
        "keep the finding visible — we have no evidence it's fixed"
    )


@pytest.mark.django_db
def test_resolved_scan_inconsistency_does_not_protect_stale_finding(cluster, workload, image):
    """A ScanInconsistency row with seen_in_scans=True means the scanner
    DID report last cycle (not an active outage) — must not protect."""
    finding = _stale_finding(cluster, workload, image)
    ScanInconsistency.objects.create(
        cluster=cluster,
        kind="trivy.VulnerabilityReport",
        workload=workload,
        image_digest=image.digest,
        seen_in_inventory=True,
        seen_in_scans=True,
    )

    visible_ids = set(default_finding_qs().values_list("id", flat=True))

    assert finding.id not in visible_ids


@pytest.mark.django_db
def test_outage_on_different_image_does_not_protect_this_finding(cluster, workload, image):
    """A coverage gap for some OTHER image must not blanket-protect
    every stale finding on this workload."""
    other_image = Image.objects.create(digest="sha256:" + "f" * 64, ref="x:2")
    finding = _stale_finding(cluster, workload, image)
    ScanInconsistency.objects.create(
        cluster=cluster,
        kind="trivy.VulnerabilityReport",
        workload=workload,
        image_digest=other_image.digest,
        seen_in_inventory=True,
        seen_in_scans=False,
    )

    visible_ids = set(default_finding_qs().values_list("id", flat=True))

    assert finding.id not in visible_ids
