"""Integration tests for `manage.py process_ingest_queue`.

Covers the command wrapper and its interaction with the worker drain
loop:

- Default (`--once` absent) calls `drain_until_empty` and processes
  every claimable item until the queue settles.
- `--once` runs a single batch and returns.
- Items whose ImportMark is still in `open` are NOT claimed — they
  wait for the importer to commit.
- A successful drain reaps the matching ImportMark; the reap deletes
  the tuple's queue rows, so "drained" means the rows are gone and the
  mark is `reaped` (with `failed_count` / `last_error` recording any
  failures).
- A second invocation on an already-drained queue is a no-op.

End-to-end parser correctness is exercised by the per-parser test
suites; here we use an unknown `kind` so `process_item` short-
circuits with `{"skipped": "unknown_kind"}` and the worker still
runs the full claim → process → reap path.
"""
from __future__ import annotations

import io
from unittest.mock import patch

import pytest
from django.core.management import call_command
from django.test import override_settings
from django.utils import timezone

from core.constants import ImportDiscardReason, ImportMarkState, IngestQueueStatus
from core.models import Cluster, ImportMark, IngestQueue

# ── helpers ─────────────────────────────────────────────────────────


_UNKNOWN_KIND = "synthetic.UnknownKindForTest"


def _seed(cluster: Cluster, *, kind: str = _UNKNOWN_KIND, import_id: str = "imp-1",
          mark_state: str = ImportMarkState.DRAINING.value,
          queue_status: str = IngestQueueStatus.PENDING.value):
    """Create one draining ImportMark + one matching pending queue row."""
    mark, _ = ImportMark.objects.update_or_create(
        cluster=cluster, kind=kind, import_id=import_id,
        defaults={"state": mark_state, "started_at": timezone.now()},
    )
    item = IngestQueue.objects.create(
        cluster_name=cluster.name,
        kind=kind,
        import_id=import_id,
        raw_json={},
        status=queue_status,
    )
    return mark, item


def _gone(item: IngestQueue) -> bool:
    return not IngestQueue.objects.filter(pk=item.pk).exists()


@pytest.fixture
def cluster(db):
    return Cluster.objects.create(name="c-drain")


@pytest.fixture(autouse=True)
def _quiet_heartbeat():
    """Snapshot heartbeat writes are not what we're testing here."""
    with patch("core.services.reaper._maybe_capture_heartbeat"):
        yield


# ── default invocation (drain_until_empty) ──────────────────────────


@pytest.mark.django_db(transaction=True)
def test_command_drains_until_empty_by_default(cluster):
    """No `--once` → the command keeps draining until no claim returns
    anything. The seeded pending item is processed, the mark flips to
    `reaped`, and the reap deletes the row."""
    mark, item = _seed(cluster)

    out = io.StringIO()
    call_command("process_ingest_queue", stdout=out, stderr=io.StringIO())

    mark.refresh_from_db()
    assert _gone(item)
    assert mark.state == ImportMarkState.REAPED.value
    assert mark.failed_count == 0
    assert mark.last_error == ""
    body = out.getvalue()
    assert "claimed" in body
    assert "ok" in body
    assert "reaps_fired" in body


@pytest.mark.django_db(transaction=True)
def test_command_runs_when_queue_is_empty(cluster):
    """No queue items at all — the command exits cleanly with zero
    counters and writes nothing to the database."""
    out = io.StringIO()
    call_command("process_ingest_queue", stdout=out, stderr=io.StringIO())

    body = out.getvalue()
    assert "claimed" in body
    assert IngestQueue.objects.count() == 0
    assert ImportMark.objects.count() == 0


@pytest.mark.django_db(transaction=True)
def test_command_skips_items_whose_mark_is_still_open(cluster):
    """A pending item under an `open` ImportMark is not yet claimable —
    the worker gate (`m.state='draining'`) blocks it. The command
    finishes without touching the item."""
    mark, item = _seed(cluster, mark_state=ImportMarkState.OPEN.value)

    out = io.StringIO()
    call_command("process_ingest_queue", stdout=out, stderr=io.StringIO())

    item.refresh_from_db()
    mark.refresh_from_db()
    assert item.status == IngestQueueStatus.PENDING.value
    assert mark.state == ImportMarkState.OPEN.value


# ── --once invocation (single drain_once batch) ────────────────────


@pytest.mark.django_db(transaction=True)
def test_command_once_runs_a_single_batch(cluster):
    """`--once` invokes `drain_once` directly. With a single seeded
    item, one pass drains it; the reap fires because the queue is
    empty after the claim."""
    mark, item = _seed(cluster, import_id="imp-once")

    out = io.StringIO()
    call_command(
        "process_ingest_queue", "--once",
        stdout=out, stderr=io.StringIO(),
    )

    mark.refresh_from_db()
    assert _gone(item)
    assert mark.state == ImportMarkState.REAPED.value


@pytest.mark.django_db(transaction=True)
def test_command_once_respects_limit_flag(cluster):
    """`--once --limit 1` claims at most one item per pass. With two
    pending items in two tuples, one drain reaps one tuple (its row is
    deleted) and leaves the other pending."""
    _seed(cluster, import_id="imp-A")
    _seed(cluster, import_id="imp-B")

    call_command(
        "process_ingest_queue", "--once", "--limit", "1",
        stdout=io.StringIO(), stderr=io.StringIO(),
    )

    assert IngestQueue.objects.count() == 1
    assert IngestQueue.objects.filter(status=IngestQueueStatus.PENDING.value).count() == 1
    assert ImportMark.objects.filter(state=ImportMarkState.REAPED.value).count() == 1
    assert ImportMark.objects.filter(state=ImportMarkState.DRAINING.value).count() == 1


# ── idempotence ─────────────────────────────────────────────────────


@pytest.mark.django_db(transaction=True)
def test_command_is_idempotent_on_already_drained_state(cluster):
    """Running the command twice on the same seed leaves the system in
    the same state — no resurrection, no duplicate reaps."""
    mark, item = _seed(cluster, import_id="imp-idem")

    call_command("process_ingest_queue", stdout=io.StringIO(), stderr=io.StringIO())
    mark.refresh_from_db()
    assert _gone(item)
    assert mark.state == ImportMarkState.REAPED.value

    # Second run — nothing to do.
    out = io.StringIO()
    call_command("process_ingest_queue", stdout=out, stderr=io.StringIO())
    mark.refresh_from_db()
    assert mark.state == ImportMarkState.REAPED.value
    assert IngestQueue.objects.count() == 0
    assert "'claimed': 0" in out.getvalue()


# ── multi-tuple drain ──────────────────────────────────────────────


@pytest.mark.django_db(transaction=True)
def test_command_drains_multiple_independent_tuples(cluster):
    """Two unrelated `(kind, import_id)` tuples both drain in one
    invocation; each mark transitions to REAPED and its row is gone."""
    cluster_b = Cluster.objects.create(name="c-drain-b")
    m1, q1 = _seed(cluster, kind=_UNKNOWN_KIND, import_id="imp-1")
    m2, q2 = _seed(cluster_b, kind="synthetic.OtherKind", import_id="imp-2")

    call_command("process_ingest_queue", stdout=io.StringIO(), stderr=io.StringIO())

    m1.refresh_from_db()
    m2.refresh_from_db()
    assert _gone(q1) and _gone(q2)
    assert m1.state == ImportMarkState.REAPED.value
    assert m2.state == ImportMarkState.REAPED.value


# ── failure handling ──────────────────────────────────────────────


@pytest.mark.django_db(transaction=True)
def test_command_marks_item_failed_when_process_item_raises(cluster):
    """If `process_item` raises, the worker flips the row to FAILED. The
    queue then has no PENDING/PROCESSING rows, so the reap still fires:
    it records the failure on the mark and deletes the row."""
    mark, item = _seed(cluster, import_id="imp-fail")

    with patch(
        "core.services.ingest.process_item", side_effect=RuntimeError("boom"),
    ):
        call_command("process_ingest_queue", stdout=io.StringIO(), stderr=io.StringIO())

    mark.refresh_from_db()
    assert _gone(item)
    assert mark.state == ImportMarkState.REAPED.value
    assert mark.failed_count == 1
    assert "boom" in mark.last_error


@pytest.mark.django_db(transaction=True)
@override_settings(IMPORT_KEEP_FAILED_PAYLOADS=True)
def test_failed_row_is_kept_when_debug_flag_is_on(cluster):
    """IMPORT_KEEP_FAILED_PAYLOADS keeps the failed row (and its raw
    payload) for the 14-day prune so the failure can be replayed."""
    mark, item = _seed(cluster, import_id="imp-keep")

    with patch(
        "core.services.ingest.process_item", side_effect=RuntimeError("boom"),
    ):
        call_command("process_ingest_queue", stdout=io.StringIO(), stderr=io.StringIO())

    item.refresh_from_db()
    mark.refresh_from_db()
    assert item.status == IngestQueueStatus.FAILED.value
    assert "boom" in item.error_message
    assert mark.state == ImportMarkState.REAPED.value
    assert mark.failed_count == 1


@pytest.mark.django_db(transaction=True)
def test_failed_inventory_item_discards_the_whole_import(cluster):
    """An inventory item that fails would hold every scan row of its
    import behind the inventory gate forever. The worker discards the
    import instead: scan rows deleted, every mark `reaped` with
    `discard_reason=inventory_failed`, the inventory error on the
    inventory mark, and the cluster anchor untouched."""
    inv_mark, inv_item = _seed(cluster, kind="inventory", import_id="imp-inv-fail")
    vuln_mark, vuln_item = _seed(
        cluster, kind="trivy.VulnerabilityReport", import_id="imp-inv-fail",
    )

    with patch(
        "core.services.ingest.process_item", side_effect=RuntimeError("inventory exploded"),
    ):
        call_command("process_ingest_queue", stdout=io.StringIO(), stderr=io.StringIO())

    inv_mark.refresh_from_db()
    vuln_mark.refresh_from_db()
    cluster.refresh_from_db()
    assert _gone(inv_item) and _gone(vuln_item)
    for m in (inv_mark, vuln_mark):
        assert m.state == ImportMarkState.REAPED.value
        assert m.discard_reason == ImportDiscardReason.INVENTORY_FAILED.value
    assert inv_mark.failed_count == 1
    assert "inventory exploded" in inv_mark.last_error
    assert vuln_mark.failed_count == 0
    assert cluster.last_complete_inventory_at is None


# ── deadlock retry ──────────────────────────────────────────────────


class _FakeDeadlock(Exception):
    """Stands in for psycopg's DeadlockDetected (SQLSTATE 40P01) without
    needing a real Postgres deadlock — worker._is_deadlock only looks at
    `.sqlstate` (or `.__cause__.sqlstate`), so a plain exception carrying
    that attribute is enough to drive the retry path under test.
    """
    sqlstate = "40P01"


@pytest.mark.django_db(transaction=True)
def test_command_retries_and_recovers_from_a_transient_deadlock(cluster):
    """process_item raising a deadlock (SQLSTATE 40P01) is retried in
    place by _process_one rather than failing the item on the first hit —
    this is the concurrent-SbomComponent-upsert scenario the retry exists
    for (see core.services.worker._is_deadlock)."""
    mark, item = _seed(cluster, import_id="imp-deadlock-recover")

    calls = {"n": 0}

    def _flaky(_item):
        calls["n"] += 1
        if calls["n"] < 2:
            raise _FakeDeadlock("deadlock detected")
        return {"ok": True}

    with (
        patch("core.services.ingest.process_item", side_effect=_flaky),
        patch("core.services.worker.time.sleep"),
    ):
        call_command("process_ingest_queue", stdout=io.StringIO(), stderr=io.StringIO())

    mark.refresh_from_db()
    assert calls["n"] == 2, "must retry once after the first deadlock, not fail immediately"
    assert _gone(item)
    assert mark.state == ImportMarkState.REAPED.value
    assert mark.failed_count == 0


@pytest.mark.django_db(transaction=True)
def test_command_gives_up_after_max_deadlock_retries(cluster):
    """A deadlock that never clears still ends the item FAILED once
    retries are exhausted — the retry must not loop forever."""
    mark, item = _seed(cluster, import_id="imp-deadlock-exhaust")

    calls = {"n": 0}

    def _always_deadlocked(_item):
        calls["n"] += 1
        raise _FakeDeadlock("deadlock detected")

    with (
        patch("core.services.ingest.process_item", side_effect=_always_deadlocked),
        patch("core.services.worker.time.sleep"),
    ):
        call_command("process_ingest_queue", stdout=io.StringIO(), stderr=io.StringIO())

    mark.refresh_from_db()
    assert calls["n"] == 3, "must stop after max attempts, not retry forever"
    assert mark.failed_count == 1
    assert "deadlock" in mark.last_error.lower()


@pytest.mark.django_db(transaction=True)
def test_command_does_not_retry_a_non_deadlock_failure(cluster):
    """A plain exception (not a deadlock) must fail immediately on the
    first attempt — the retry path is specific to SQLSTATE 40P01, not a
    general retry-on-any-error."""
    mark, item = _seed(cluster, import_id="imp-non-deadlock-fail")

    calls = {"n": 0}

    def _boom(_item):
        calls["n"] += 1
        raise RuntimeError("not a deadlock")

    with patch("core.services.ingest.process_item", side_effect=_boom):
        call_command("process_ingest_queue", stdout=io.StringIO(), stderr=io.StringIO())

    mark.refresh_from_db()
    assert calls["n"] == 1, "a non-deadlock error must not be retried"
    assert mark.failed_count == 1
    assert "not a deadlock" in mark.last_error


# ── claim size / iteration cap ─────────────────────────────────────


def test_default_claims_one_row_per_pass_with_no_iteration_cap():
    with patch("core.services.worker.drain_until_empty", return_value={"claimed": 0}) as drain:
        call_command("process_ingest_queue", stdout=io.StringIO(), stderr=io.StringIO())
    drain.assert_called_once_with(limit=1, max_iterations=0, max_seconds=0)


def test_limit_and_max_iterations_flags_reach_the_drain_loop():
    with patch("core.services.worker.drain_until_empty", return_value={"claimed": 0}) as drain:
        call_command("process_ingest_queue", "--limit", "5", "--max-iterations", "3",
                     "--max-seconds", "1200", stdout=io.StringIO(), stderr=io.StringIO())
    drain.assert_called_once_with(limit=5, max_iterations=3, max_seconds=1200.0)


@pytest.mark.django_db(transaction=True)
def test_no_iteration_cap_drains_past_200_single_row_passes(cluster):
    """`--max-iterations 0` must not stop at the old 200-pass cap: 205
    rows claimed one at a time are all processed in one run."""
    from core.services import worker

    ImportMark.objects.create(cluster=cluster, kind=_UNKNOWN_KIND, import_id="imp-many",
                              state=ImportMarkState.DRAINING.value, started_at=timezone.now())
    IngestQueue.objects.bulk_create([
        IngestQueue(cluster_name=cluster.name, kind=_UNKNOWN_KIND, import_id="imp-many", raw_json={})
        for _ in range(205)
    ])
    totals = worker.drain_until_empty(limit=1, max_iterations=0)
    assert totals["claimed"] == totals["ok"] == 205
    assert IngestQueue.objects.count() == 0, "reaped once the last row was done"


@pytest.mark.django_db(transaction=True)
def test_run_exits_when_only_gated_or_uncommitted_rows_remain(cluster):
    """No waiting: a pass that claims nothing ends the run even though
    rows exist — scan rows gated behind an inventory another pod holds,
    and rows of an import that isn't committed yet. The next tick gets them."""
    from core.services import worker

    _seed(cluster, kind="inventory", import_id="imp-gated",
          queue_status=IngestQueueStatus.PROCESSING.value)          # another pod has it
    IngestQueue.objects.filter(kind="inventory").update(claimed_at=timezone.now())
    _seed(cluster, kind="trivy.VulnerabilityReport", import_id="imp-gated")  # gated
    _seed(cluster, import_id="imp-open", mark_state=ImportMarkState.OPEN.value)  # not committed

    started = timezone.now()
    totals = worker.drain_until_empty(limit=1, max_iterations=0)
    assert totals["claimed"] == 0
    assert (timezone.now() - started).total_seconds() < 5
    assert IngestQueue.objects.filter(status=IngestQueueStatus.PENDING.value).count() == 2


# ── wall-clock budget (--max-seconds) ──────────────────────────────


class _Clock:
    """Fake time.monotonic: advances `step` seconds per call."""

    def __init__(self, step):
        self.now, self.step = 0.0, step

    def __call__(self):
        self.now += self.step
        return self.now


def test_max_seconds_stops_new_passes_and_skips_final_reap_sweep(monkeypatch):
    from core.services import worker

    monkeypatch.setattr(worker.time, "monotonic", _Clock(step=10))
    one = {"claimed": 1, "ok": 1, "failed": 0, "reaps_fired": 0}
    with patch.object(worker, "drain_once", return_value=one) as drain, \
         patch.object(worker.reaper, "reap_all_drainable") as sweep:
        totals = worker.drain_until_empty(limit=1, max_iterations=0, max_seconds=35)

    # deadline=45 (first tick 10 + 35); checks at 20, 30, 40 pass, 50 stops.
    assert drain.call_count == 3
    assert totals["claimed"] == 3
    sweep.assert_not_called()


def test_max_seconds_unspent_still_runs_final_reap_sweep(monkeypatch):
    from core.services import worker

    monkeypatch.setattr(worker.time, "monotonic", _Clock(step=1))
    empty = {"claimed": 0, "ok": 0, "failed": 0, "reaps_fired": 0}
    with patch.object(worker, "drain_once", return_value=empty), \
         patch.object(worker.reaper, "reap_all_drainable", return_value=2) as sweep:
        totals = worker.drain_until_empty(limit=1, max_iterations=0, max_seconds=1200)

    sweep.assert_called_once()
    assert totals["reaps_fired"] == 2


def test_max_seconds_zero_means_no_budget(monkeypatch):
    from core.services import worker

    monkeypatch.setattr(worker.time, "monotonic", _Clock(step=10_000))
    rounds = iter([{"claimed": 1, "ok": 1, "failed": 0, "reaps_fired": 0}] * 5
                  + [{"claimed": 0, "ok": 0, "failed": 0, "reaps_fired": 0}])
    with patch.object(worker, "drain_once", side_effect=lambda limit: next(rounds)), \
         patch.object(worker.reaper, "reap_all_drainable", return_value=0) as sweep:
        totals = worker.drain_until_empty(limit=1, max_iterations=0, max_seconds=0)

    assert totals["claimed"] == 5
    sweep.assert_called_once()
