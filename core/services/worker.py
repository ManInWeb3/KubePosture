"""Worker — claim queue items, process them, fire reaps.

Public entry points:

  drain_once(limit=N)   — claim up to N items, process each in its own
                          transaction, fire `maybe_reap` for the
                          tuple's mark when its queue is empty.
                          Returns counters {claimed, ok, failed,
                          reaps_fired}.

  drain_until_empty()   — loop drain_once() until no more pending
                          items satisfy the worker gate. Used by the
                          synchronous test harness.
"""
from __future__ import annotations

import logging

from django.db import transaction
from django.utils import timezone

from core.constants import IngestQueueStatus
from core.models import ImportMark, IngestQueue
from core.services import ingest, queue, reaper

log = logging.getLogger("core.worker")


def _process_one(item_id: int) -> tuple[bool, str]:
    item = IngestQueue.objects.filter(id=item_id).first()
    if item is None:
        return False, "missing"
    try:
        with transaction.atomic():
            summary = ingest.process_item(item)
        item.refresh_from_db()
        item.status = IngestQueueStatus.DONE.value
        item.processed_at = timezone.now()
        item.save(update_fields=["status", "processed_at"])
        log.info(
            "worker.item.done",
            extra={
                "item_id": item.id,
                "kind": item.kind,
                "cluster": item.cluster_name,
                "summary": summary,
            },
        )
        return True, ""
    except Exception as exc:  # pragma: no cover
        log.exception("worker.item.failed id=%s", item_id)
        IngestQueue.objects.filter(id=item_id).update(
            status=IngestQueueStatus.FAILED.value,
            processed_at=timezone.now(),
            error_message=str(exc)[:2000],
        )
        return False, str(exc)


def drain_once(*, limit: int = 100) -> dict:
    claimed = queue.claim_batch(limit=limit)
    ok = 0
    failed = 0
    reaps_fired = 0

    # Track the (cluster_name, kind, import_id) tuples touched so we can
    # fire the matching reaps after the batch.
    touched: set[tuple[str, str, str]] = set()

    for item_id in claimed:
        item = IngestQueue.objects.filter(id=item_id).only(
            "id", "cluster_name", "kind", "import_id"
        ).first()
        if item is None:
            continue
        touched.add((item.cluster_name, item.kind, item.import_id))
        good, _ = _process_one(item_id)
        if good:
            ok += 1
        else:
            failed += 1

    for cluster_name, kind, import_id in touched:
        from core.models import Cluster
        cluster = Cluster.objects.filter(name=cluster_name).first()
        if cluster is None:
            continue
        mark = ImportMark.objects.filter(
            cluster=cluster, kind=kind, import_id=import_id
        ).first()
        if mark is None:
            continue
        result = reaper.maybe_reap(mark)
        if result is not None:
            reaps_fired += 1

    return {
        "claimed": len(claimed),
        "ok": ok,
        "failed": failed,
        "reaps_fired": reaps_fired,
    }


def drain_until_empty(*, limit: int = 100, max_iterations: int = 200) -> dict:
    """Loop `drain_once` until a pass claims zero items. Used by the
    /api/v1/testing/load_scenario/ harness so a scenario completes
    synchronously.
    """
    totals = {"claimed": 0, "ok": 0, "failed": 0, "reaps_fired": 0}
    for _ in range(max_iterations):
        round_ = drain_once(limit=limit)
        if round_["claimed"] == 0:
            break
        for k in totals:
            totals[k] += round_[k]
    # Final safety-net pass to fire any reap that was eligible after the
    # last drain (e.g. the last item of a tuple, processed in a
    # round that didn't itself claim anything new).
    leftover = reaper.reap_all_drainable()
    totals["reaps_fired"] += leftover
    return totals
