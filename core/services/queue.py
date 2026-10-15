"""Ingest queue claim + drain helpers.

Rows are inserted by core.services.bundle_ingest (one bundle per
`(cluster, kind, import_id)`, stored atomically with its ImportMark in
state `open`). Worker claims pending IngestQueue items whose matching
ImportMark is in `state='draining'` — i.e. only after the importer has
committed the whole import. SKIP LOCKED partitions work cleanly across
parallel workers.

**Inventory gate.** Within a single `import_id`, a non-inventory item
is only claimable once that import's `inventory` queue row has reached
`status='done'` (or never existed at all). Non-inventory parsers
resolve workloads via aliases that the inventory parser populates;
processing them before inventory lands silently drops the report
because `_resolve_workload` returns None. Holding non-inventory items
until inventory is done closes that race. If inventory `failed`, the
gate stays closed; the worker then discards the whole import (see
core.services.reaper.discard_import_for_failed_inventory) rather than
leaving its rows blocked forever.

The drain check counts both `pending` AND `processing` rows so a
worker mid-item still keeps the count > 0 — preventing premature
reaps.

**Stale reclaim.** An item left in `processing` — e.g. its worker Job
was killed by `activeDeadlineSeconds` mid-item — would otherwise sit
stuck forever with nothing to ever revisit it, blocking its tuple's
drain_check (and therefore its reap) indefinitely. `claim_batch`
folds reclaiming those rows into the same claim query: it selects
`pending` rows OR `processing` rows claimed more than
`STALE_PROCESSING_SECONDS` ago, so an abandoned item is picked back up
exactly like a fresh one, with no separate flip-to-pending step. This
is still concurrency-safe with several workers claiming at once: SKIP
LOCKED only needs to hold for the claim query's own brief UPDATE, and
by the time any row can look "stale" its original worker is long past
`activeDeadlineSeconds` and can't still hold it — so two workers racing
over the same stale row still only ever have one of them win it, the
same guarantee that already applies to plain `pending` rows.

Rows reclaimed past `MAX_RECLAIM_ATTEMPTS` (a poison item reliably
crashing whatever worker touches it) are excluded from claiming and
instead marked `failed` outright — otherwise, with nothing left to
ever claim them again, they'd sit in `processing` forever anyway.

**Row lifetime.** Nothing reads a row's `raw_json` after it is `done`,
so the reap deletes the tuple's rows (see `delete_tuple_rows`) once it
has recorded what it needs on the ImportMark. The queue therefore only
ever holds in-flight work; `prune_stale_data` is a safety net.
"""
from __future__ import annotations

import logging
from datetime import timedelta

from django.db import connection, transaction
from django.utils import timezone

from core.constants import ImportMarkState, IngestQueueStatus
from core.models import ImportMark, IngestQueue

log = logging.getLogger("core.queue")

# Larger than the worker Job's activeDeadlineSeconds (1800s in
# deploy/charts/kubeposture/values.yaml) so a still-legitimately-running
# item is never mistaken for abandoned — only reclaim rows no
# currently-running worker could still hold. tests/test_chart_invariants.py
# pins the relation.
STALE_PROCESSING_SECONDS = 2100

# After this many reclaims, stop bouncing the item back to pending and
# mark it failed instead — protects against a poison item that reliably
# crashes/OOMs every worker that claims it.
MAX_RECLAIM_ATTEMPTS = 5

# `last_error` on ImportMark keeps this much of the newest failure.
LAST_ERROR_MAX_CHARS = 2000


# Worker claim: SKIP LOCKED + JOIN to ImportMark.state='draining', plus
# the inventory gate (see module docstring) — non-inventory items wait
# for their import's inventory row to reach status='done'. Also reclaims
# `processing` rows abandoned by a killed worker (see "Stale reclaim"
# above) in the same query, rather than a separate flip-to-pending pass.
#
# ORDER BY created_at, id: every row of a bundle shares one created_at
# (they are bulk-inserted in one transaction), so the id tie-break keeps
# claim order deterministic.
_CLAIM_SQL = """
WITH claimed AS (
    SELECT q.id
      FROM core_ingestqueue q
      JOIN core_importmark m
        ON m.cluster_id = (
                SELECT id FROM core_cluster WHERE name = q.cluster_name
            )
       AND m.kind = q.kind
       AND m.import_id = q.import_id
     WHERE (
             q.status = 'pending'
             OR (q.status = 'processing' AND q.claimed_at < %s)
           )
       AND q.attempts < %s
       AND m.state = 'draining'
       AND (
             q.kind = 'inventory'
             OR NOT EXISTS (
                 SELECT 1
                   FROM core_ingestqueue qi
                  WHERE qi.cluster_name = q.cluster_name
                    AND qi.import_id   = q.import_id
                    AND qi.kind        = 'inventory'
                    AND qi.status     <> 'done'
             )
       )
     ORDER BY q.created_at, q.id
     FOR UPDATE OF q SKIP LOCKED
     LIMIT %s
)
UPDATE core_ingestqueue q
   SET status = 'processing',
       claimed_at = %s,
       -- Django evaluates every SET expression against the pre-update
       -- row, so q.status here still reads the OLD value: 'processing'
       -- means this claim is a stale reclaim (bump attempts), 'pending'
       -- means it's a first claim (leave attempts alone).
       attempts = CASE WHEN q.status = 'processing' THEN q.attempts + 1 ELSE q.attempts END
  FROM claimed
 WHERE q.id = claimed.id
RETURNING q.id;
"""

# Rows stale for too long AND already past the reclaim attempt limit are
# excluded from _CLAIM_SQL above (nothing left to ever claim them again),
# so they need to be actively flushed to `failed` here — otherwise they'd
# sit in `processing` forever, still counted by drain_check as blocking
# their tuple's reap.
#
# SKIP LOCKED here for the same reason as _CLAIM_SQL: this runs first, on
# every single claim_batch() call from every parallel worker. A plain
# UPDATE with no lock-skipping blocks the caller on ANY matching row
# another worker currently holds a lock on — even one utterly unrelated
# to whatever batch this worker is about to claim — serializing what
# should be N independent workers behind whichever one is slowest. If a
# genuinely-abandoned row is skipped this round because something else
# transiently holds it, the next claim_batch() call (workers run every
# few minutes; drain_until_empty loops much faster within a run) picks
# it up once that lock clears — the abandon check doesn't need to be
# exhaustive on every single pass to remain correct.
_ABANDON_EXHAUSTED_SQL = """
WITH exhausted AS (
    SELECT id
      FROM core_ingestqueue
     WHERE status = 'processing'
       AND claimed_at < %s
       AND attempts >= %s
     FOR UPDATE SKIP LOCKED
)
UPDATE core_ingestqueue q
   SET status = 'failed', processed_at = %s,
       error_message = 'abandoned: stuck in processing past reclaim attempt limit'
  FROM exhausted
 WHERE q.id = exhausted.id
RETURNING q.id;
"""


def claim_batch(
    limit: int = 100,
    *,
    stale_after_seconds: int = STALE_PROCESSING_SECONDS,
    max_attempts: int = MAX_RECLAIM_ATTEMPTS,
) -> list[int]:
    """Atomically flip up to `limit` items to `processing` and return
    their IDs. Caller is expected to process + commit / fail each one.

    Claims both `pending` rows and `processing` rows abandoned by a
    killed worker in one query (see module docstring), and flushes any
    row that's exhausted its reclaim attempts to `failed`.
    """
    now = timezone.now()
    cutoff = now - timedelta(seconds=stale_after_seconds)
    with connection.cursor() as cur:
        cur.execute(_ABANDON_EXHAUSTED_SQL, [cutoff, max_attempts, now])
        abandoned = cur.rowcount
        if abandoned:
            log.warning("queue.abandoned_exhausted", extra={"count": abandoned})

        cur.execute(_CLAIM_SQL, [cutoff, max_attempts, limit, now])
        return [row[0] for row in cur.fetchall()]


def _tuple_qs(*, cluster_name: str, kind: str, import_id: str):
    return IngestQueue.objects.filter(
        cluster_name=cluster_name, kind=kind, import_id=import_id,
    )


def count_rows(*, cluster_name: str, kind: str, import_id: str) -> int:
    """Rows stored for the tuple, any status — what commit checks the
    importer's delivered count against."""
    return _tuple_qs(cluster_name=cluster_name, kind=kind, import_id=import_id).count()


def failure_summary(*, cluster_name: str, kind: str, import_id: str) -> tuple[int, str]:
    """`(failed_count, last_error)` for the tuple — the two facts the reap
    records on the ImportMark before the rows are deleted."""
    qs = _tuple_qs(cluster_name=cluster_name, kind=kind, import_id=import_id).filter(
        status=IngestQueueStatus.FAILED.value,
    )
    n = qs.count()
    if not n:
        return 0, ""
    last = qs.order_by("-id").values_list("error_message", flat=True).first() or ""
    return n, last[:LAST_ERROR_MAX_CHARS]


def delete_tuple_rows(*, cluster_name: str, kind: str, import_id: str, keep_failed: bool) -> int:
    """Delete the tuple's queue rows once the reap has recorded what it
    needs. `keep_failed=True` (settings.IMPORT_KEEP_FAILED_PAYLOADS — a
    debugging aid) leaves `failed` rows for the 14-day prune so a
    reproducible parse failure can be replayed from its exact payload.
    """
    qs = _tuple_qs(cluster_name=cluster_name, kind=kind, import_id=import_id)
    if keep_failed:
        qs = qs.exclude(status=IngestQueueStatus.FAILED.value)
    return qs.delete()[0]


def delete_import_rows(*, cluster_name: str, import_id: str, keep_failed: bool) -> int:
    """Every kind's rows for one import — the discard paths."""
    qs = IngestQueue.objects.filter(cluster_name=cluster_name, import_id=import_id)
    if keep_failed:
        qs = qs.exclude(status=IngestQueueStatus.FAILED.value)
    return qs.delete()[0]


def drain_check(*, cluster_name: str, kind: str, import_id: str) -> bool:
    """True iff no pending OR processing queue items remain for the tuple.

    Counts both states to prevent the reap from firing while a worker
    is mid-item on the same tuple.
    """
    return not _tuple_qs(cluster_name=cluster_name, kind=kind, import_id=import_id).filter(
        status__in=[
            IngestQueueStatus.PENDING.value,
            IngestQueueStatus.PROCESSING.value,
        ],
    ).exists()


@transaction.atomic
def transition_mark_to_reaped(mark: ImportMark) -> bool:
    """Non-blocking state-machine flip from `draining` → `reaped`. Returns
    True iff this caller won the claim.

    This is the reap's claim: callers run it FIRST and return without
    doing anything when it returns False. `FOR UPDATE SKIP LOCKED` is
    tried first: a mark whose row another transaction holds (a reap in
    flight on another pod) is skipped and we return False at once instead
    of queueing behind it — a plain conditional UPDATE used to block every
    other worker, at 0 CPU, for the whole duration of that reap. The lock
    taken here is held until the CALLER's transaction ends (this atomic is
    a savepoint inside the reap's), so the winner's claim is exclusive for
    the whole reap body; if the winner rolls back, the mark is `draining`
    again for a later sweep or the safety net.

    The query must stay join-free (no `select_related`) — `FOR UPDATE`
    would otherwise lock the cluster row too.
    """
    claimable = list(
        ImportMark.objects
        .select_for_update(skip_locked=True)
        .filter(id=mark.id, state=ImportMarkState.DRAINING.value)
        .values_list("id", flat=True)
    )
    if not claimable:
        return False
    affected = ImportMark.objects.filter(
        id=mark.id, state=ImportMarkState.DRAINING.value,
    ).update(state=ImportMarkState.REAPED.value)
    return affected == 1
