"""Ingest queue claim + drain helpers.

Worker claims pending IngestQueue items whose matching ImportMark is in
`state='draining'` — items posted while a cycle is still open sit
pending until the importer signals finish. SKIP LOCKED partitions
work cleanly across parallel workers.

**Inventory gate.** Within a single `import_id`, a non-inventory item
is only claimable once that import's `inventory` queue row has reached
`status='done'` (or never existed at all). Non-inventory parsers
resolve workloads via aliases that the inventory parser populates;
processing them before inventory lands silently drops the report
because `_resolve_workload` returns None. Holding non-inventory items
until inventory is done closes that race. If inventory `failed`, the
gate stays closed — the queue blocks visibly rather than dropping
data silently; operator intervention is then expected.

The drain check counts both `pending` AND `processing` rows so a
worker mid-item still keeps the count > 0 — preventing premature
reaps.
"""
from __future__ import annotations


from django.db import connection, transaction
from django.utils import timezone

from core.constants import ImportMarkState, IngestQueueStatus
from core.models import ImportMark, IngestQueue


def enqueue(
    *,
    cluster_name: str,
    kind: str,
    import_id: str,
    raw_json: dict,
    complete_snapshot: bool = False,
) -> IngestQueue:
    return IngestQueue.objects.create(
        cluster_name=cluster_name,
        kind=kind,
        import_id=import_id,
        raw_json=raw_json,
        complete_snapshot=complete_snapshot,
    )


# Worker claim: SKIP LOCKED + JOIN to ImportMark.state='draining', plus
# the inventory gate (see module docstring) — non-inventory items wait
# for their import's inventory row to reach status='done'.
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
     WHERE q.status = 'pending'
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
     ORDER BY q.created_at
     FOR UPDATE OF q SKIP LOCKED
     LIMIT %s
)
UPDATE core_ingestqueue q
   SET status = 'processing'
  FROM claimed
 WHERE q.id = claimed.id
RETURNING q.id;
"""


def claim_batch(limit: int = 100) -> list[int]:
    """Atomically flip up to `limit` pending items to `processing` and
    return their IDs. Caller is expected to process + commit / fail
    each one.
    """
    with connection.cursor() as cur:
        cur.execute(_CLAIM_SQL, [limit])
        return [row[0] for row in cur.fetchall()]


def mark_done(item_id: int) -> None:
    IngestQueue.objects.filter(id=item_id).update(
        status=IngestQueueStatus.DONE.value,
        processed_at=timezone.now(),
    )


def mark_failed(item_id: int, error: str) -> None:
    IngestQueue.objects.filter(id=item_id).update(
        status=IngestQueueStatus.FAILED.value,
        processed_at=timezone.now(),
        error_message=error[:2000],
        attempts=connection.ops.no_limit_value() if False else 0,  # stub
    )


def drain_check(*, cluster_name: str, kind: str, import_id: str) -> bool:
    """True iff no pending OR processing queue items remain for the tuple.

    Counts both states to prevent the reap from firing while a worker
    is mid-item on the same tuple.
    """
    return not IngestQueue.objects.filter(
        cluster_name=cluster_name,
        kind=kind,
        import_id=import_id,
        status__in=[
            IngestQueueStatus.PENDING.value,
            IngestQueueStatus.PROCESSING.value,
        ],
    ).exists()


@transaction.atomic
def transition_mark_to_reaped(mark: ImportMark) -> bool:
    """Idempotent state-machine flip from `draining` → `reaped`. Returns
    True if this caller won the race.
    """
    affected = ImportMark.objects.filter(
        id=mark.id, state=ImportMarkState.DRAINING.value,
    ).update(state=ImportMarkState.REAPED.value)
    return affected == 1
