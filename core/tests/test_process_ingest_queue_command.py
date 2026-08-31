"""Integration tests for `manage.py process_ingest_queue`.

Covers the command wrapper and its interaction with the worker drain
loop:

- Default (`--once` absent) calls `drain_until_empty` and processes
  every claimable item until the queue settles.
- `--once` runs a single batch and returns.
- Items whose ImportMark is still in `open` are NOT claimed — they
  wait for the importer to finish.
- A successful drain transitions the queue items to `done` and the
  matching ImportMark to `reaped`.
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
from django.utils import timezone

from core.constants import ImportMarkState, IngestQueueStatus
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
    anything. The seeded pending item ends up `done` and the mark
    flips to `reaped`."""
    mark, item = _seed(cluster)

    out = io.StringIO()
    call_command("process_ingest_queue", stdout=out, stderr=io.StringIO())

    item.refresh_from_db()
    mark.refresh_from_db()
    assert item.status == IngestQueueStatus.DONE.value
    assert item.processed_at is not None
    assert mark.state == ImportMarkState.REAPED.value
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

    item.refresh_from_db()
    mark.refresh_from_db()
    assert item.status == IngestQueueStatus.DONE.value
    assert mark.state == ImportMarkState.REAPED.value


@pytest.mark.django_db(transaction=True)
def test_command_once_respects_limit_flag(cluster):
    """`--once --limit 1` claims at most one item per pass. With two
    pending items, one drain leaves the second pending."""
    _seed(cluster, import_id="imp-A")
    _seed(cluster, import_id="imp-B")

    call_command(
        "process_ingest_queue", "--once", "--limit", "1",
        stdout=io.StringIO(), stderr=io.StringIO(),
    )

    done = IngestQueue.objects.filter(status=IngestQueueStatus.DONE.value).count()
    pending = IngestQueue.objects.filter(status=IngestQueueStatus.PENDING.value).count()
    assert done == 1
    assert pending == 1


# ── idempotence ─────────────────────────────────────────────────────


@pytest.mark.django_db(transaction=True)
def test_command_is_idempotent_on_already_drained_state(cluster):
    """Running the command twice on the same seed leaves the system in
    the same state — no resurrection of DONE items, no duplicate
    reaps."""
    mark, item = _seed(cluster, import_id="imp-idem")

    call_command("process_ingest_queue", stdout=io.StringIO(), stderr=io.StringIO())
    item.refresh_from_db()
    mark.refresh_from_db()
    assert item.status == IngestQueueStatus.DONE.value
    assert mark.state == ImportMarkState.REAPED.value

    # Second run — nothing to do.
    out = io.StringIO()
    call_command("process_ingest_queue", stdout=out, stderr=io.StringIO())
    item.refresh_from_db()
    mark.refresh_from_db()
    assert item.status == IngestQueueStatus.DONE.value
    assert mark.state == ImportMarkState.REAPED.value


# ── multi-tuple drain ──────────────────────────────────────────────


@pytest.mark.django_db(transaction=True)
def test_command_drains_multiple_independent_tuples(cluster):
    """Two unrelated `(kind, import_id)` tuples both drain in one
    invocation; each mark transitions to REAPED."""
    cluster_b = Cluster.objects.create(name="c-drain-b")
    m1, q1 = _seed(cluster, kind=_UNKNOWN_KIND, import_id="imp-1")
    m2, q2 = _seed(cluster_b, kind="synthetic.OtherKind", import_id="imp-2")

    call_command("process_ingest_queue", stdout=io.StringIO(), stderr=io.StringIO())

    q1.refresh_from_db()
    q2.refresh_from_db()
    m1.refresh_from_db()
    m2.refresh_from_db()
    assert q1.status == IngestQueueStatus.DONE.value
    assert q2.status == IngestQueueStatus.DONE.value
    assert m1.state == ImportMarkState.REAPED.value
    assert m2.state == ImportMarkState.REAPED.value


# ── failure handling ──────────────────────────────────────────────


@pytest.mark.django_db(transaction=True)
def test_command_marks_item_failed_when_process_item_raises(cluster):
    """If `process_item` raises, the worker flips the row to FAILED
    and the mark stays draining (because the queue is technically
    drained, the reap WILL still fire — the failure doesn't block
    cleanup)."""
    mark, item = _seed(cluster, import_id="imp-fail")

    with patch(
        "core.services.ingest.process_item", side_effect=RuntimeError("boom"),
    ):
        call_command("process_ingest_queue", stdout=io.StringIO(), stderr=io.StringIO())

    item.refresh_from_db()
    mark.refresh_from_db()
    assert item.status == IngestQueueStatus.FAILED.value
    assert "boom" in (item.error_message or "")
    # After a failure the queue has no PENDING/PROCESSING rows, so the
    # drain_check passes and the reap fires anyway.
    assert mark.state == ImportMarkState.REAPED.value


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

    item.refresh_from_db()
    assert calls["n"] == 2, "must retry once after the first deadlock, not fail immediately"
    assert item.status == IngestQueueStatus.DONE.value
    assert not item.error_message


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

    item.refresh_from_db()
    assert calls["n"] == 3, "must stop after max attempts, not retry forever"
    assert item.status == IngestQueueStatus.FAILED.value
    assert "deadlock" in item.error_message.lower()


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

    item.refresh_from_db()
    assert calls["n"] == 1, "a non-deadlock error must not be retried"
    assert item.status == IngestQueueStatus.FAILED.value
