"""
Ingest queue service — claim, process, recover, cleanup.

Uses PostgreSQL SELECT FOR UPDATE SKIP LOCKED for parallel-safe
queue processing. Multiple workers can run concurrently without
claiming the same item.

See: docs/architecture.md § Queue Processor: Parallel Safety
"""
import logging
import traceback

from django.conf import settings
from django.db import transaction
from django.utils import timezone

from core.models.queue import IngestQueue, QueueStatus
from core.services.ingest import ingest_scan

logger = logging.getLogger(__name__)

MAX_ATTEMPTS = getattr(settings, "INGEST_QUEUE_MAX_ATTEMPTS", 3)
STUCK_TIMEOUT_MINUTES = 5


def enqueue(cluster_name: str, raw_json: dict) -> IngestQueue:
    """Insert a raw CRD into the queue for async processing."""
    return IngestQueue.objects.create(
        cluster_name=cluster_name,
        raw_json=raw_json,
    )


def claim_batch(batch_size: int = 1) -> list[IngestQueue]:
    """Claim pending items using SELECT FOR UPDATE SKIP LOCKED.

    Returns a list of claimed items (status changed to PROCESSING).
    Uses a transaction to hold the lock during claim.
    """
    with transaction.atomic():
        items = list(
            IngestQueue.objects.select_for_update(skip_locked=True)
            .filter(status=QueueStatus.PENDING)
            .order_by("created_at")[:batch_size]
        )
        if items:
            pks = [item.pk for item in items]
            IngestQueue.objects.filter(pk__in=pks).update(
                status=QueueStatus.PROCESSING
            )
            # Refresh to get updated status
            for item in items:
                item.status = QueueStatus.PROCESSING
    return items


def process_item(item: IngestQueue) -> bool:
    """Process a single queue item by calling ingest_scan().

    Returns True on success, False on failure.
    On failure: increments attempts, marks pending for retry or failed if max attempts reached.
    """
    try:
        ingest_scan(item.raw_json, cluster_name_header=item.cluster_name)

        item.status = QueueStatus.DONE
        item.processed_at = timezone.now()
        item.error_message = ""
        item.save(update_fields=["status", "processed_at", "error_message"])

        logger.debug(
            "Queue item #%d processed: %s for %s",
            item.pk,
            item.raw_json.get("kind", "?"),
            item.cluster_name,
        )
        return True

    except Exception as e:
        item.attempts += 1
        item.error_message = f"{type(e).__name__}: {e}\n{traceback.format_exc()[-500:]}"

        if item.attempts >= MAX_ATTEMPTS:
            item.status = QueueStatus.FAILED
            item.processed_at = timezone.now()
            logger.error(
                "Queue item #%d failed after %d attempts: %s",
                item.pk,
                item.attempts,
                e,
            )
        else:
            item.status = QueueStatus.PENDING
            logger.warning(
                "Queue item #%d attempt %d/%d failed: %s — will retry",
                item.pk,
                item.attempts,
                MAX_ATTEMPTS,
                e,
            )

        item.save(update_fields=["status", "attempts", "error_message", "processed_at"])
        return False


def process_batch(batch_size: int = 1) -> dict:
    """Claim and process a batch of items.

    Returns: {"claimed": int, "succeeded": int, "failed": int}
    """
    items = claim_batch(batch_size)
    succeeded = 0
    failed = 0

    for item in items:
        if process_item(item):
            succeeded += 1
        else:
            failed += 1

    return {"claimed": len(items), "succeeded": succeeded, "failed": failed}


def recover_stuck() -> int:
    """Reset items stuck in 'processing' for longer than STUCK_TIMEOUT_MINUTES.

    This handles workers that crashed mid-processing. Items are reset to
    'pending' for retry (unless they've hit max attempts).
    """
    cutoff = timezone.now() - timezone.timedelta(minutes=STUCK_TIMEOUT_MINUTES)

    # Items stuck in processing that were claimed before the cutoff
    stuck = IngestQueue.objects.filter(
        status=QueueStatus.PROCESSING,
        created_at__lt=cutoff,
    )

    count = 0
    for item in stuck:
        item.attempts += 1
        if item.attempts >= MAX_ATTEMPTS:
            item.status = QueueStatus.FAILED
            item.error_message = f"Stuck in processing for >{STUCK_TIMEOUT_MINUTES}min (likely crashed worker)"
            item.processed_at = timezone.now()
        else:
            item.status = QueueStatus.PENDING
        item.save(update_fields=["status", "attempts", "error_message", "processed_at"])
        count += 1

    if count:
        logger.warning("Recovered %d stuck queue items", count)
    return count


def cleanup_done(days: int = 7) -> int:
    """Delete completed items older than `days`."""
    cutoff = timezone.now() - timezone.timedelta(days=days)
    count, _ = IngestQueue.objects.filter(
        status=QueueStatus.DONE,
        processed_at__lt=cutoff,
    ).delete()
    if count:
        logger.info("Cleaned up %d done queue items older than %d days", count, days)
    return count


def get_queue_stats() -> dict:
    """Get current queue statistics."""
    from django.db.models import Count

    stats = dict(
        IngestQueue.objects.values_list("status")
        .annotate(count=Count("id"))
        .values_list("status", "count")
    )
    return {
        "pending": stats.get(QueueStatus.PENDING, 0),
        "processing": stats.get(QueueStatus.PROCESSING, 0),
        "done": stats.get(QueueStatus.DONE, 0),
        "failed": stats.get(QueueStatus.FAILED, 0),
        "total": sum(stats.values()),
    }
