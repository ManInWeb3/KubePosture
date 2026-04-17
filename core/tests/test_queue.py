"""
Tests for the async ingest queue.

Covers:
- IngestQueue model
- IngestView async mode (202) vs sync mode (200)
- claim_batch FIFO + skip_locked
- process_item success, failure, max_attempts
- recover_stuck
- cleanup_done
- get_queue_stats
"""
import json
from pathlib import Path

import pytest
from django.utils import timezone

from core.models import Finding, IngestQueue
from core.models.queue import QueueStatus
from core.services.queue import (
    claim_batch,
    cleanup_done,
    enqueue,
    get_queue_stats,
    process_batch,
    process_item,
    recover_stuck,
)

FIXTURES = Path(__file__).parent / "fixtures"


def _load_fixture(name: str) -> dict:
    return json.loads((FIXTURES / name).read_text())


# ── Model tests ────────────────────────────────────────────────


@pytest.mark.django_db
class TestIngestQueueModel:
    def test_create(self):
        item = IngestQueue.objects.create(
            cluster_name="test-cluster",
            raw_json={"kind": "VulnerabilityReport"},
        )
        assert item.status == QueueStatus.PENDING
        assert item.attempts == 0
        assert "VulnerabilityReport" in str(item)

    def test_default_ordering_is_fifo(self):
        IngestQueue.objects.create(cluster_name="c1", raw_json={"kind": "A"})
        IngestQueue.objects.create(cluster_name="c2", raw_json={"kind": "B"})
        items = list(IngestQueue.objects.all())
        assert items[0].cluster_name == "c1"
        assert items[1].cluster_name == "c2"


# ── Enqueue ────────────────────────────────────────────────────


@pytest.mark.django_db
class TestEnqueue:
    def test_enqueue_creates_pending_item(self):
        item = enqueue("test-cluster", {"kind": "VulnerabilityReport"})
        assert item.pk is not None
        assert item.status == QueueStatus.PENDING
        assert item.cluster_name == "test-cluster"
        assert item.raw_json["kind"] == "VulnerabilityReport"


# ── Claim batch ────────────────────────────────────────────────


@pytest.mark.django_db
class TestClaimBatch:
    def test_claims_pending_items(self):
        enqueue("c1", {"kind": "A"})
        enqueue("c2", {"kind": "B"})

        items = claim_batch(batch_size=2)
        assert len(items) == 2
        assert all(i.status == QueueStatus.PROCESSING for i in items)

        # Items are now processing in DB
        assert IngestQueue.objects.filter(status=QueueStatus.PROCESSING).count() == 2

    def test_fifo_ordering(self):
        enqueue("first", {"kind": "A"})
        enqueue("second", {"kind": "B"})

        items = claim_batch(batch_size=1)
        assert len(items) == 1
        assert items[0].cluster_name == "first"

    def test_skips_non_pending(self):
        item = enqueue("c1", {"kind": "A"})
        item.status = QueueStatus.PROCESSING
        item.save()

        items = claim_batch(batch_size=1)
        assert len(items) == 0

    def test_empty_queue(self):
        items = claim_batch(batch_size=1)
        assert items == []

    def test_respects_batch_size(self):
        for i in range(5):
            enqueue(f"c{i}", {"kind": "A"})

        items = claim_batch(batch_size=3)
        assert len(items) == 3
        assert IngestQueue.objects.filter(status=QueueStatus.PENDING).count() == 2


# ── Process item ───────────────────────────────────────────────


@pytest.mark.django_db
class TestProcessItem:
    def test_success(self):
        payload = _load_fixture("vulnerability_report.json")
        item = enqueue("test-cluster", payload)
        item.status = QueueStatus.PROCESSING
        item.save()

        result = process_item(item)
        assert result is True

        item.refresh_from_db()
        assert item.status == QueueStatus.DONE
        assert item.processed_at is not None
        assert item.error_message == ""

        # Findings were created
        assert Finding.objects.count() == 2

    def test_failure_retries(self):
        item = enqueue("test-cluster", {"kind": "FakeReport"})
        item.status = QueueStatus.PROCESSING
        item.save()

        result = process_item(item)
        assert result is False

        item.refresh_from_db()
        assert item.status == QueueStatus.PENDING  # back to pending for retry
        assert item.attempts == 1
        assert "IngestError" in item.error_message

    def test_max_attempts_marks_failed(self):
        item = enqueue("test-cluster", {"kind": "FakeReport"})
        item.status = QueueStatus.PROCESSING
        item.attempts = 2  # already tried twice
        item.save()

        result = process_item(item)
        assert result is False

        item.refresh_from_db()
        assert item.status == QueueStatus.FAILED  # 3rd attempt = max
        assert item.attempts == 3
        assert item.processed_at is not None


# ── Process batch ──────────────────────────────────────────────


@pytest.mark.django_db
class TestProcessBatch:
    def test_processes_batch(self):
        payload = _load_fixture("vulnerability_report.json")
        enqueue("test-cluster", payload)
        enqueue("test-cluster", _load_fixture("configaudit_report.json"))

        result = process_batch(batch_size=2)
        assert result["claimed"] == 2
        assert result["succeeded"] == 2
        assert result["failed"] == 0

    def test_empty_queue(self):
        result = process_batch(batch_size=1)
        assert result["claimed"] == 0


# ── Recover stuck ──────────────────────────────────────────────


@pytest.mark.django_db
class TestRecoverStuck:
    def test_recovers_stuck_items(self):
        item = enqueue("c1", {"kind": "A"})
        item.status = QueueStatus.PROCESSING
        # Simulate created 10 minutes ago
        IngestQueue.objects.filter(pk=item.pk).update(
            status=QueueStatus.PROCESSING,
            created_at=timezone.now() - timezone.timedelta(minutes=10),
        )

        recovered = recover_stuck()
        assert recovered == 1

        item.refresh_from_db()
        assert item.status == QueueStatus.PENDING
        assert item.attempts == 1

    def test_does_not_touch_recent_processing(self):
        item = enqueue("c1", {"kind": "A"})
        item.status = QueueStatus.PROCESSING
        item.save()

        recovered = recover_stuck()
        assert recovered == 0

    def test_marks_failed_after_max_attempts(self):
        item = enqueue("c1", {"kind": "A"})
        item.status = QueueStatus.PROCESSING
        item.attempts = 2
        item.save()
        IngestQueue.objects.filter(pk=item.pk).update(
            created_at=timezone.now() - timezone.timedelta(minutes=10),
        )

        recover_stuck()
        item.refresh_from_db()
        assert item.status == QueueStatus.FAILED
        assert item.attempts == 3


# ── Cleanup ────────────────────────────────────────────────────


@pytest.mark.django_db
class TestCleanupDone:
    def test_deletes_old_done_items(self):
        item = enqueue("c1", {"kind": "A"})
        item.status = QueueStatus.DONE
        item.processed_at = timezone.now() - timezone.timedelta(days=10)
        item.save()

        count = cleanup_done(days=7)
        assert count == 1
        assert IngestQueue.objects.count() == 0

    def test_keeps_recent_done(self):
        item = enqueue("c1", {"kind": "A"})
        item.status = QueueStatus.DONE
        item.processed_at = timezone.now() - timezone.timedelta(days=1)
        item.save()

        count = cleanup_done(days=7)
        assert count == 0
        assert IngestQueue.objects.count() == 1

    def test_keeps_pending_and_failed(self):
        enqueue("c1", {"kind": "A"})  # pending
        item2 = enqueue("c2", {"kind": "B"})
        item2.status = QueueStatus.FAILED
        item2.save()

        count = cleanup_done(days=0)
        assert count == 0


# ── Stats ──────────────────────────────────────────────────────


@pytest.mark.django_db
class TestGetQueueStats:
    def test_empty(self):
        stats = get_queue_stats()
        assert stats["pending"] == 0
        assert stats["total"] == 0

    def test_mixed(self):
        enqueue("c1", {"kind": "A"})
        item2 = enqueue("c2", {"kind": "B"})
        item2.status = QueueStatus.DONE
        item2.save()
        item3 = enqueue("c3", {"kind": "C"})
        item3.status = QueueStatus.FAILED
        item3.save()

        stats = get_queue_stats()
        assert stats["pending"] == 1
        assert stats["done"] == 1
        assert stats["failed"] == 1
        assert stats["total"] == 3


# View tests moved to test_api/test_ingest_endpoint.py
