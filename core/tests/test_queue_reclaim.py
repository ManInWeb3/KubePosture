"""Stale-`processing` reclaim in `claim_batch`.

A worker Job killed mid-item (e.g. by activeDeadlineSeconds) leaves its
claimed rows stuck in `processing` forever unless something revisits
them — `claim_batch` folds that reclaim into its own claim query rather
than a separate flip-to-pending pass. See core.services.queue module
docstring for the concurrency argument.
"""
from __future__ import annotations

from datetime import timedelta

import pytest
from django.utils import timezone

from core.constants import ImportMarkState, IngestQueueStatus
from core.models import Cluster, ImportMark, IngestQueue
from core.services.queue import claim_batch


def _seed_mark_and_queue(
    cluster, kind, import_id, *,
    status=IngestQueueStatus.PENDING.value,
    claimed_at=None,
    attempts=0,
):
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
        claimed_at=claimed_at,
        attempts=attempts,
    )


@pytest.fixture
def cluster(db):
    return Cluster.objects.create(name="c-reclaim")


def test_fresh_pending_item_claims_without_bumping_attempts(cluster):
    item = _seed_mark_and_queue(cluster, "inventory", "imp-1")

    claimed = claim_batch(limit=10, stale_after_seconds=60, max_attempts=3)

    assert claimed == [item.id]
    item.refresh_from_db()
    assert item.status == IngestQueueStatus.PROCESSING.value
    assert item.attempts == 0
    assert item.claimed_at is not None


def test_recently_claimed_processing_item_is_not_reclaimed(cluster):
    """An item claimed moments ago (a worker plausibly still running)
    must not be picked up by another claim_batch call."""
    item = _seed_mark_and_queue(
        cluster, "inventory", "imp-2",
        status=IngestQueueStatus.PROCESSING.value,
        claimed_at=timezone.now(),
    )

    claimed = claim_batch(limit=10, stale_after_seconds=60, max_attempts=3)

    assert claimed == []
    item.refresh_from_db()
    assert item.status == IngestQueueStatus.PROCESSING.value
    assert item.attempts == 0


def test_stale_processing_item_is_reclaimed_and_attempts_bumped(cluster):
    """An item whose worker never came back (claimed_at older than the
    staleness window) is picked back up like a fresh claim, with
    attempts incremented so a chronically-crashing item eventually hits
    the abandon path instead of bouncing forever."""
    stale_at = timezone.now() - timedelta(seconds=120)
    item = _seed_mark_and_queue(
        cluster, "inventory", "imp-3",
        status=IngestQueueStatus.PROCESSING.value,
        claimed_at=stale_at,
        attempts=1,
    )

    claimed = claim_batch(limit=10, stale_after_seconds=60, max_attempts=3)

    assert claimed == [item.id]
    item.refresh_from_db()
    assert item.status == IngestQueueStatus.PROCESSING.value
    assert item.attempts == 2, "reclaim must bump attempts, first-claim path must not"
    assert item.claimed_at > stale_at


def test_exhausted_stale_item_is_abandoned_not_reclaimed(cluster):
    """Past max_attempts, a stale item is excluded from claiming and
    flushed straight to `failed` — otherwise nothing would ever revisit
    it again and it would block its tuple's drain_check forever."""
    stale_at = timezone.now() - timedelta(seconds=120)
    item = _seed_mark_and_queue(
        cluster, "inventory", "imp-4",
        status=IngestQueueStatus.PROCESSING.value,
        claimed_at=stale_at,
        attempts=3,
    )

    claimed = claim_batch(limit=10, stale_after_seconds=60, max_attempts=3)

    assert claimed == []
    item.refresh_from_db()
    assert item.status == IngestQueueStatus.FAILED.value
    assert item.processed_at is not None
    assert "abandoned" in item.error_message


def test_stale_reclaim_does_not_bypass_the_inventory_gate(cluster):
    """A stale, gated non-inventory item stays gated — reclaim must not
    be a backdoor around the inventory-first ordering."""
    inv = _seed_mark_and_queue(cluster, "inventory", "imp-5")
    stale_at = timezone.now() - timedelta(seconds=120)
    vul = _seed_mark_and_queue(
        cluster, "trivy.VulnerabilityReport", "imp-5",
        status=IngestQueueStatus.PROCESSING.value,
        claimed_at=stale_at,
    )

    claimed = claim_batch(limit=10, stale_after_seconds=60, max_attempts=3)

    assert claimed == [inv.id]
    vul.refresh_from_db()
    assert vul.status == IngestQueueStatus.PROCESSING.value, (
        "still gated by open inventory — must not be reclaimed early"
    )
