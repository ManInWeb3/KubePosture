"""End-to-end regression test for the worker parallel-process incident.

Reproduces the actual production bug (2026-08-31, kubeposture-worker
CronJob): `claim_batch`'s abandon-exhausted sweep was a plain `UPDATE`
with no `SKIP LOCKED`. Every single call — every parallel worker's every
`drain_once` iteration — ran that unprotected statement first, so a
worker could block on it for as long as *any other* worker happened to
hold a lock on a matching row, even a row totally unrelated to whatever
batch that worker was trying to claim. In production this froze 3 of 4
parallel pods solid — near-zero CPU, zero items processed — behind
whichever single pod was slow, for the pod's entire lifetime.

Unlike the smaller, targeted tests in core/tests/ (which call
`claim_batch` or the command directly, one at a time), this drives the
real production entry point — `manage.py process_ingest_queue`, default
`drain_until_empty` mode, the exact command `worker.parallelism: 4` runs
every 3 minutes — from several concurrent threads with separate DB
connections, against a backlog that reproduces both halves of the
incident simultaneously: an ordinary multi-tuple pending backlog (the
throughput the fleet exists to provide) plus one exhausted, currently
*locked* "poison" row (the contention that froze it).

Before the fix, the parallel workers block on the poison row and the
wall-clock assertion fails (or the run drags out close to the lock-hold
window). After the fix, they drain the ordinary backlog in well under
that window, leaving the locked row alone for a later pass.
"""
from __future__ import annotations

import io
import threading
import time
from datetime import timedelta
from unittest.mock import patch

import pytest
from django.core.management import call_command
from django.db import connection, transaction
from django.utils import timezone

from core.constants import ImportMarkState, IngestQueueStatus
from core.models import Cluster, ImportMark, IngestQueue
from core.services.queue import MAX_RECLAIM_ATTEMPTS, STALE_PROCESSING_SECONDS

_UNKNOWN_KIND = "synthetic.E2EWorkerLoad"
_N_TUPLES = 5
_ITEMS_PER_TUPLE = 15
_N_PARALLEL_WORKERS = 4  # matches deploy/charts/kubeposture/values.yaml worker.parallelism
_LOCK_HOLD_SECONDS = 3.0
_MAX_ELAPSED_SECONDS = 2.0  # must finish well before the lock releases


@pytest.fixture(autouse=True)
def _quiet_heartbeat():
    """Snapshot heartbeat writes are not what this test is about."""
    with patch("core.services.reaper._maybe_capture_heartbeat"):
        yield


def _seed_backlog() -> list[IngestQueue]:
    """N independent (cluster, kind, import_id) tuples, each with several
    pending items — the ordinary backlog a fleet of pods is meant to
    drain concurrently and safely via claim_batch's SKIP LOCKED
    partitioning. An unknown `kind` so process_item short-circuits with
    `{"skipped": "unknown_kind"}` — this test is about the claim/lock
    layer, not parser correctness (see tests/integration/test_import_e2e.py
    for that)."""
    items = []
    for t in range(_N_TUPLES):
        cluster = Cluster.objects.create(name=f"c-e2e-worker-{t}")
        ImportMark.objects.create(
            cluster=cluster, kind=_UNKNOWN_KIND, import_id=f"imp-{t}",
            state=ImportMarkState.DRAINING.value, started_at=timezone.now(),
        )
        for _ in range(_ITEMS_PER_TUPLE):
            items.append(IngestQueue.objects.create(
                cluster_name=cluster.name, kind=_UNKNOWN_KIND, import_id=f"imp-{t}",
                raw_json={}, status=IngestQueueStatus.PENDING.value,
            ))
    return items


def _seed_poison_item() -> IngestQueue:
    """One row stuck in `processing`, stale past STALE_PROCESSING_SECONDS,
    already at its reclaim attempt limit — exactly what the abandon-sweep
    targets. Its own (cluster, kind, import_id) tuple, so it can never be
    part of any worker's ordinary claimable batch."""
    cluster = Cluster.objects.create(name="c-e2e-worker-poison")
    ImportMark.objects.create(
        cluster=cluster, kind=_UNKNOWN_KIND, import_id="imp-poison",
        state=ImportMarkState.DRAINING.value, started_at=timezone.now(),
    )
    stale_cutoff = timezone.now() - timedelta(seconds=STALE_PROCESSING_SECONDS + 60)
    return IngestQueue.objects.create(
        cluster_name=cluster.name, kind=_UNKNOWN_KIND, import_id="imp-poison",
        raw_json={}, status=IngestQueueStatus.PROCESSING.value,
        claimed_at=stale_cutoff, attempts=MAX_RECLAIM_ATTEMPTS,
    )


@pytest.mark.django_db(transaction=True)
def test_parallel_workers_drain_the_backlog_despite_one_locked_poison_item():
    normal_items = _seed_backlog()
    poison = _seed_poison_item()

    lock_acquired = threading.Event()
    release_lock = threading.Event()

    def hold_poison_lock():
        # Simulates the one slow pod from the incident — mid-transaction,
        # holding a real row lock, for longer than the other pods should
        # ever need to wait on anything unrelated to it.
        with transaction.atomic():
            IngestQueue.objects.select_for_update().get(pk=poison.pk)
            lock_acquired.set()
            release_lock.wait(timeout=_LOCK_HOLD_SECONDS)
        connection.close()

    holder = threading.Thread(target=hold_poison_lock)
    holder.start()
    assert lock_acquired.wait(timeout=5), "lock holder never acquired its lock"

    def run_worker():
        # The exact call `worker.command` makes in production (no --once
        # → drain_until_empty), from its own DB connection — this is
        # `parallelism: 4` reproduced with real threads, not a mock.
        call_command("process_ingest_queue", stdout=io.StringIO(), stderr=io.StringIO())
        connection.close()

    try:
        started = time.monotonic()
        workers = [threading.Thread(target=run_worker) for _ in range(_N_PARALLEL_WORKERS)]
        for w in workers:
            w.start()
        for w in workers:
            w.join(timeout=_LOCK_HOLD_SECONDS + 10)
        elapsed = time.monotonic() - started
    finally:
        release_lock.set()
        holder.join(timeout=10)
        connection.close()

    assert all(not w.is_alive() for w in workers), (
        "a worker thread never finished — it's still blocked somewhere"
    )
    assert elapsed < _MAX_ELAPSED_SECONDS, (
        f"{_N_PARALLEL_WORKERS} parallel `process_ingest_queue` runs took "
        f"{elapsed:.2f}s against a {_LOCK_HOLD_SECONDS:.1f}s lock hold on one "
        "unrelated row — they blocked instead of draining the rest of the "
        "backlog around it (this is the production incident, reproduced)"
    )

    done_count = IngestQueue.objects.filter(
        pk__in=[i.pk for i in normal_items], status=IngestQueueStatus.DONE.value,
    ).count()
    assert done_count == len(normal_items), (
        f"only {done_count}/{len(normal_items)} ordinary backlog items were "
        "drained — the parallel worker fleet failed to make full progress "
        "even though none of them needed the locked row"
    )

    poison.refresh_from_db()
    assert poison.status == IngestQueueStatus.PROCESSING.value, (
        "the locked poison row must be left alone for this pass, not "
        "abandoned or claimed while another transaction still holds it"
    )
    assert poison.attempts == MAX_RECLAIM_ATTEMPTS
