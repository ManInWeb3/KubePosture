"""Worker — claim queue items, process them, fire reaps.

Public entry points:

  drain_once(limit=N)   — claim up to N items, process each in its own
                          transaction, fire `maybe_reap` for the
                          tuple's mark when its queue is empty.
                          Returns counters {claimed, ok, failed,
                          reaps_fired}.

  drain_until_empty()   — loop drain_once() until a pass claims
                          nothing (queue empty, or everything left is
                          held by another worker / gated / not yet
                          committed — a later run picks it up). The
                          worker CronJob and the test harness.
"""
from __future__ import annotations

import itertools
import json
import logging
import time

from django.db import transaction
from django.utils import timezone

from core.constants import IngestQueueStatus
from core.models import ImportMark, IngestQueue
from core.services import ingest, queue, reaper

log = logging.getLogger("core.worker")

# Same SQLSTATE + retry shape as core.services.enrichment's
# _exec_with_deadlock_retry. Concurrent workers (parallelism > 1) upserting
# SbomComponent rows for overlapping images can lock in different orders;
# a deadlock loser's transaction is aborted and must be retried from
# scratch, not just the failing statement — so the retry wraps the whole
# per-item atomic block.
_DEADLOCK_SQLSTATE = "40P01"
_ITEM_DEADLOCK_MAX_ATTEMPTS = 3
_ITEM_DEADLOCK_BACKOFF_BASE = 0.2


def _is_deadlock(exc: BaseException) -> bool:
    pgcode = getattr(exc, "sqlstate", None) or getattr(
        getattr(exc, "__cause__", None), "sqlstate", None
    )
    return pgcode == _DEADLOCK_SQLSTATE


def _process_one(item_id: int) -> tuple[bool, str]:
    item = IngestQueue.objects.filter(id=item_id).first()
    if item is None:
        return False, "missing"

    delay = _ITEM_DEADLOCK_BACKOFF_BASE
    for attempt in range(1, _ITEM_DEADLOCK_MAX_ATTEMPTS + 1):
        # DEBUG only, and the payload_bytes estimate is gated behind
        # isEnabledFor so a full json.dumps of a large raw_json never runs
        # unless DEBUG logging is actually on — process_item logs nothing
        # until it returns, so for a large/slow item this is the only
        # trace of what a pod was working on if it dies before finishing
        # (OOMKilled, deadline-killed) with no "worker.item.done" ever
        # reaching Loki.
        if log.isEnabledFor(logging.DEBUG):
            log.debug(
                "worker.item.started",
                extra={
                    "item_id": item.id,
                    "kind": item.kind,
                    "cluster": item.cluster_name,
                    "import_id": item.import_id,
                    "attempt": attempt,
                    "payload_bytes": len(json.dumps(item.raw_json, default=str)),
                },
            )
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
            if _is_deadlock(exc) and attempt < _ITEM_DEADLOCK_MAX_ATTEMPTS:
                log.warning(
                    "worker.item.deadlock_retry",
                    extra={"item_id": item_id, "attempt": attempt},
                )
                time.sleep(delay)
                delay *= 2
                continue
            log.exception("worker.item.failed id=%s", item_id)
            IngestQueue.objects.filter(id=item_id).update(
                status=IngestQueueStatus.FAILED.value,
                processed_at=timezone.now(),
                error_message=str(exc)[:2000],
            )
            if item.kind == "inventory":
                # The inventory gate would hold every scan row of this
                # import forever; the import is unusable as a whole.
                try:
                    reaper.discard_import_for_failed_inventory(
                        cluster_name=item.cluster_name, import_id=item.import_id,
                    )
                except Exception:  # pragma: no cover - must not mask the item failure
                    log.exception(
                        "worker.discard_failed import_id=%s", item.import_id,
                    )
            return False, str(exc)
    # Unreachable — the loop always returns via the except branch on its
    # final attempt — but keeps the function's return type honest.
    return False, "deadlock_retries_exhausted"  # pragma: no cover


def drain_once(*, limit: int = 100) -> dict:
    # claim_batch reclaims stale `processing` rows (abandoned by a killed
    # worker) as part of the same claim query — see core.services.queue.
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


def drain_until_empty(*, limit: int = 100, max_iterations: int | None = 200) -> dict:
    """Loop `drain_once` until a pass claims zero items.

    `limit` rows are claimed per pass. With `limit=1` (the worker
    CronJob's default) a pod claims one row, processes it, claims the
    next — so parallel pods share an import row by row instead of one pod
    hoarding a batch. A pass that claims nothing ends the loop: the queue
    is empty, or every remaining row is held by another worker, gated
    behind its import's inventory, or not committed yet; the next run
    picks those up. `max_iterations` caps the passes; 0/None = no cap.
    """
    totals = {"claimed": 0, "ok": 0, "failed": 0, "reaps_fired": 0}
    passes = itertools.count() if not max_iterations else range(max_iterations)
    for _ in passes:
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
