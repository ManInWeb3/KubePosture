"""Real-concurrency tests — separate threads, separate DB connections.

Every other "concurrency" test in this repo (test_queue_reclaim.py,
test_reaper.py's idempotence tests) simulates a race sequentially in one
connection/transaction — useful for the SQL logic, but it can't actually
prove the two guarantees that matter once `worker.parallelism` > 1 (see
deploy/charts/kubeposture/values.yaml): that `claim_batch`'s SKIP LOCKED
really does prevent two pods from claiming the same row, and that
`upsert_findings` really is safe against two pods resolving to the same
dedup key at once. These use `@pytest.mark.django_db(transaction=True)`
(real commits, no wrapping test-transaction) plus real `threading.Thread`s
so each gets its own DB connection, and a `Barrier` to force maximum
overlap.
"""
from __future__ import annotations

import threading
import time
from datetime import timedelta

import pytest
from django.db import connection, transaction
from django.utils import timezone

from core.constants import (
    Category,
    ImportMarkState,
    IngestQueueStatus,
    Severity,
    Source,
)
from core.models import Cluster, Finding, ImportMark, IngestQueue
from core.services.dedup import compute_hash, upsert_findings
from core.services.queue import MAX_RECLAIM_ATTEMPTS, STALE_PROCESSING_SECONDS, claim_batch


@pytest.fixture
def cluster(db):
    return Cluster.objects.create(name="c-concurrency")


@pytest.mark.django_db(transaction=True)
def test_claim_batch_no_double_claim_under_real_concurrency(cluster):
    """N pending items, several real threads racing claim_batch at once:
    every item is claimed by exactly one thread, none lost, none doubled.
    """
    n_items = 40
    n_workers = 4
    ImportMark.objects.create(
        cluster=cluster, kind="inventory", import_id="imp-race",
        state=ImportMarkState.DRAINING.value, started_at=timezone.now(),
    )
    item_ids = {
        IngestQueue.objects.create(
            cluster_name=cluster.name, kind="inventory", import_id="imp-race",
            raw_json={}, status=IngestQueueStatus.PENDING.value,
        ).id
        for _ in range(n_items)
    }

    results: list[list[int]] = []
    lock = threading.Lock()
    barrier = threading.Barrier(n_workers)

    def worker():
        barrier.wait()
        try:
            claimed = claim_batch(limit=n_items)
            with lock:
                results.append(claimed)
        finally:
            connection.close()

    threads = [threading.Thread(target=worker) for _ in range(n_workers)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    all_claimed = [i for batch in results for i in batch]
    assert len(all_claimed) == len(set(all_claimed)), (
        "the same item was claimed by more than one concurrent worker"
    )
    assert set(all_claimed) == item_ids, "every item must end up claimed exactly once"


@pytest.mark.django_db(transaction=True)
def test_abandon_exhausted_sweep_does_not_block_on_a_locked_exhausted_row(cluster):
    """claim_batch's abandon-exhausted sweep runs first, unconditionally, on
    every single call — including every parallel worker's every drain_once
    iteration. Regression test for the bug where that sweep was a plain
    UPDATE with no SKIP LOCKED: a row that's exhausted its reclaim attempts
    but happens to be locked by another in-flight transaction would block
    the *entire calling worker* until that lock released, even though the
    lock has nothing to do with whatever batch this worker is trying to
    claim. In production this froze 3 of 4 parallel pods solid — near-zero
    CPU, no progress — behind whichever single pod was slowly working
    through one item.

    This reproduces it directly: one thread holds a real row lock on an
    exhausted item; concurrently, claim_batch must (a) return promptly
    instead of waiting on that lock, (b) still claim an unrelated pending
    item in the same call, and (c) leave the locked exhausted row alone
    for a later pass rather than erroring or skipping the whole sweep.
    """
    ImportMark.objects.create(
        cluster=cluster, kind="inventory", import_id="imp-lock",
        state=ImportMarkState.DRAINING.value, started_at=timezone.now(),
    )
    stale_cutoff = timezone.now() - timedelta(seconds=STALE_PROCESSING_SECONDS + 60)
    exhausted = IngestQueue.objects.create(
        cluster_name=cluster.name, kind="inventory", import_id="imp-lock",
        raw_json={}, status=IngestQueueStatus.PROCESSING.value,
        claimed_at=stale_cutoff, attempts=MAX_RECLAIM_ATTEMPTS,
    )
    claimable = IngestQueue.objects.create(
        cluster_name=cluster.name, kind="inventory", import_id="imp-lock",
        raw_json={}, status=IngestQueueStatus.PENDING.value,
    )

    lock_acquired = threading.Event()
    release_lock = threading.Event()

    def hold_lock():
        with transaction.atomic():
            IngestQueue.objects.select_for_update().get(pk=exhausted.pk)
            lock_acquired.set()
            release_lock.wait(timeout=5)
        connection.close()

    holder = threading.Thread(target=hold_lock)
    holder.start()
    assert lock_acquired.wait(timeout=5), "lock holder never acquired its lock"

    try:
        started = time.monotonic()
        claimed = claim_batch(limit=10)
        elapsed = time.monotonic() - started
    finally:
        release_lock.set()
        holder.join(timeout=5)
        connection.close()

    assert elapsed < 2.0, (
        f"claim_batch took {elapsed:.2f}s — it blocked waiting on the "
        "locked exhausted row instead of skipping it"
    )
    assert claimed == [claimable.id], (
        "the unrelated pending item must still be claimed even while the "
        "exhausted row is locked elsewhere"
    )
    exhausted.refresh_from_db()
    assert exhausted.status == IngestQueueStatus.PROCESSING.value, (
        "the locked exhausted row must be left alone this pass, not abandoned"
    )


@pytest.mark.django_db(transaction=True)
def test_concurrent_upsert_same_finding_key_no_lost_update_no_crash(cluster):
    """Several threads upsert the SAME dedup key at once (the scenario a
    parallel worker fleet creates whenever two different IngestQueue items
    resolve to the same Finding — e.g. the same CVE re-reported across two
    queue items claimed by two different pods). Must not raise, must not
    create duplicate rows, and last_seen must land on the max observation
    time regardless of arrival order (no lost-update regression).
    """
    n_workers = 8
    base = timezone.now()
    # Deliberately NOT monotonic with thread start order — a real race
    # doesn't guarantee the thread with the latest observation_time also
    # wins the DB write last.
    times = [base + timedelta(seconds=(n_workers - i)) for i in range(n_workers)]

    errors: list[BaseException] = []
    barrier = threading.Barrier(n_workers)

    def worker(observation_time):
        barrier.wait()
        try:
            upsert_findings(
                cluster=cluster,
                workload=None,
                image=None,
                findings=[{
                    "source": Source.TRIVY.value,
                    "category": Category.VULNERABILITY.value,
                    "vuln_id": "CVE-2024-RACE",
                    "pkg_name": "pkgx",
                    "installed_version": "1.0",
                    "title": "race test finding",
                    "severity": Severity.HIGH.value,
                }],
                observation_time=observation_time,
            )
        except BaseException as exc:  # noqa: BLE001 - must capture across threads
            errors.append(exc)
        finally:
            connection.close()

    threads = [threading.Thread(target=worker, args=(t,)) for t in times]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert not errors, f"concurrent upsert_findings raised: {errors!r}"

    hc = compute_hash(
        source=Source.TRIVY.value,
        category=Category.VULNERABILITY.value,
        vuln_id="CVE-2024-RACE",
        workload_id=None,
        cluster_name=cluster.name,
        image_digest="",
        pkg_name="pkgx",
        installed_version="1.0",
    )
    matches = Finding.objects.filter(source=Source.TRIVY.value, hash_code=hc)
    assert matches.count() == 1, "concurrent creates must not produce duplicate rows"
    assert matches.first().last_seen == max(times), (
        "last_seen must reflect the max observation_time across all concurrent "
        "writers, not regress to whichever writer happened to commit last"
    )
