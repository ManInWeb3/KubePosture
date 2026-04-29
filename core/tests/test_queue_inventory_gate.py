"""Worker claim must hold non-inventory items until inventory is `done`.

Closes the silent-drop race documented in `core.services.queue` —
non-inventory parsers resolve workloads via aliases populated by the
inventory parser, so processing them before inventory lands drops the
report. The claim SQL gates them; this exercises that gate.
"""
from __future__ import annotations

import pytest
from django.utils import timezone

from core.constants import ImportMarkState, IngestQueueStatus
from core.models import Cluster, ImportMark, IngestQueue
from core.services.queue import claim_batch


def _seed_mark_and_queue(cluster, kind, import_id, *, status=IngestQueueStatus.PENDING.value):
    """Create one IngestQueue row + the matching draining ImportMark."""
    ImportMark.objects.update_or_create(
        cluster=cluster, kind=kind, import_id=import_id,
        defaults={
            "state": ImportMarkState.DRAINING.value,
            "started_at": timezone.now(),
        },
    )
    return IngestQueue.objects.create(
        cluster_name=cluster.name,
        kind=kind,
        import_id=import_id,
        raw_json={},
        status=status,
    )


@pytest.fixture
def cluster(db):
    return Cluster.objects.create(name="c-gate")


def test_inventory_claimed_first_when_both_pending(cluster):
    """With both inventory and a vuln report pending under the same import_id,
    only the inventory item is claimable."""
    inv = _seed_mark_and_queue(cluster, "inventory", "imp-1")
    vul = _seed_mark_and_queue(cluster, "trivy.VulnerabilityReport", "imp-1")

    claimed = claim_batch(limit=10)

    assert claimed == [inv.id], (
        f"expected only the inventory item to be claimed, got {claimed}"
    )
    # The vuln item must still be pending (not flipped to processing).
    vul.refresh_from_db()
    assert vul.status == IngestQueueStatus.PENDING.value


def test_vuln_claimable_once_inventory_is_done(cluster):
    """Once the inventory item flips to status='done', the vuln report for
    the same import_id becomes claimable."""
    inv = _seed_mark_and_queue(cluster, "inventory", "imp-2")
    vul = _seed_mark_and_queue(cluster, "trivy.VulnerabilityReport", "imp-2")

    inv.status = IngestQueueStatus.DONE.value
    inv.save(update_fields=["status"])

    claimed = claim_batch(limit=10)
    assert claimed == [vul.id]


def test_processing_inventory_blocks_vuln(cluster):
    """An inventory item mid-flight (status='processing') still blocks
    non-inventory items in the same import."""
    inv = _seed_mark_and_queue(
        cluster, "inventory", "imp-3", status=IngestQueueStatus.PROCESSING.value
    )
    vul = _seed_mark_and_queue(cluster, "trivy.VulnerabilityReport", "imp-3")

    claimed = claim_batch(limit=10)
    # Inventory is processing (not pending), vuln is gated → no claims.
    assert claimed == []
    vul.refresh_from_db()
    assert vul.status == IngestQueueStatus.PENDING.value


def test_failed_inventory_keeps_gate_closed(cluster):
    """If inventory `failed`, the gate stays shut — non-inventory items
    sit pending so the queue blocks visibly rather than dropping data."""
    inv = _seed_mark_and_queue(cluster, "inventory", "imp-4")
    inv.status = IngestQueueStatus.FAILED.value
    inv.save(update_fields=["status"])
    vul = _seed_mark_and_queue(cluster, "trivy.VulnerabilityReport", "imp-4")

    claimed = claim_batch(limit=10)
    assert claimed == [], "failed inventory must not unblock the gate"


def test_no_inventory_row_means_no_gate(cluster):
    """Imports that never carried an inventory item (e.g. webhook-only
    pushes) are unblocked — the gate only fires when an inventory row
    actually exists for the import_id."""
    vul = _seed_mark_and_queue(cluster, "trivy.VulnerabilityReport", "imp-5")

    claimed = claim_batch(limit=10)
    assert claimed == [vul.id]


def test_gate_is_per_import_id(cluster):
    """Inventory completion in import A must NOT unblock vuln items in
    import B that still has its own pending inventory."""
    inv_a = _seed_mark_and_queue(cluster, "inventory", "imp-A")
    inv_a.status = IngestQueueStatus.DONE.value
    inv_a.save(update_fields=["status"])
    vul_a = _seed_mark_and_queue(cluster, "trivy.VulnerabilityReport", "imp-A")

    inv_b = _seed_mark_and_queue(cluster, "inventory", "imp-B")
    vul_b = _seed_mark_and_queue(cluster, "trivy.VulnerabilityReport", "imp-B")

    claimed = set(claim_batch(limit=10))
    assert vul_a.id in claimed, "import A is past the gate, vuln should claim"
    assert inv_b.id in claimed, "inventory items always claim"
    assert vul_b.id not in claimed, "import B is still gated by its own inventory"
