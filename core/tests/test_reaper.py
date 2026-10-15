"""Tests for `core.services.reaper` — ImportMark lifecycle + dispatch.

Covers:
- `maybe_reap` dispatcher gates: state guard, drain guard, inventory-
  vs-scan dispatch, and the claim-first race (two reapers, one body).
- Delete-at-reap: every terminal path deletes the tuple's queue rows
  (failed ones too unless IMPORT_KEEP_FAILED_PAYLOADS) after recording
  `failed_count` / `last_error` on the mark.
- `_reap_scan` zero-input no-op rule + ScanInconsistency emission for
  image-anchored kinds; partial-failure protective branch.
- `_reap_scan` signal clearing — stale Kyverno/Trivy signals flip
  `currently_active=False` when their `last_seen_at` is older than the
  reap's `started_at`.
- `transition_mark_to_reaped` idempotence under double-call, and the
  non-blocking claim: a mark held by an in-flight reap on another
  connection is skipped at once instead of waited on.
- Commit-before-recompute: the reap transaction (claim, body, row
  deletion) commits before the priority recompute runs; a recompute
  failure is recorded on the counters, never rolls the reap back.
- `reap_all_drainable` safety-net sweep over leftover draining marks.
- Discards: `reap_stuck_open` (never committed) and the inventory-failed
  paths never apply data and never advance the cluster anchor.

Inventory reap (`_reap_inventory`) is covered indirectly via
`test_inventory_parser.py` — its `reap_inventory_diff` body is the
non-trivial part and lives in the parser, not the reaper.
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
from django.test import override_settings
from django.utils import timezone

from core import urgency
from core.constants import (
    Environment,
    ImportDiscardReason,
    ImportMarkState,
    IngestQueueStatus,
    Severity,
)
from core.models import (
    Cluster,
    Finding,
    Image,
    ImportMark,
    IngestQueue,
    Namespace,
    ScanInconsistency,
    Workload,
    WorkloadImageObservation,
    WorkloadSignal,
)
from core.services.queue import transition_mark_to_reaped
from core.services.reaper import (
    STUCK_OPEN_TIMEOUT_SECONDS,
    _reap_inventory,
    _reap_scan,
    discard_import_for_failed_inventory,
    discard_inventory_failed_imports,
    maybe_reap,
    reap_all_drainable,
    reap_stuck_open,
)

# ── helpers ─────────────────────────────────────────────────────────


def _bump(obj, **fields):
    """Bypass auto_now/auto_now_add by writing via `.update()`."""
    type(obj).objects.filter(pk=obj.pk).update(**fields)
    obj.refresh_from_db()
    return obj


def _cluster(name: str = "c1") -> Cluster:
    return Cluster.objects.create(name=name, environment=Environment.PROD.value)


def _mark(
    cluster: Cluster,
    *,
    kind: str = "trivy.ConfigAuditReport",
    import_id: str = "imp-1",
    state: str = ImportMarkState.DRAINING.value,
    observed_count: int | None = 1,
    started_at=None,
) -> ImportMark:
    return ImportMark.objects.create(
        cluster=cluster,
        kind=kind,
        import_id=import_id,
        state=state,
        started_at=started_at or timezone.now(),
        observed_count=observed_count,
    )


def _row(mark: ImportMark, *, status: str = IngestQueueStatus.DONE.value,
         error: str = "", kind: str | None = None) -> IngestQueue:
    return IngestQueue.objects.create(
        cluster_name=mark.cluster.name, kind=kind or mark.kind, import_id=mark.import_id,
        raw_json={}, status=status, error_message=error,
    )


def _workload(cluster: Cluster, *, name: str = "api") -> Workload:
    ns = Namespace.objects.create(cluster=cluster, name="payments")
    return Workload.objects.create(
        cluster=cluster, namespace=ns, kind="Deployment", name=name, deployed=True,
    )


def _rows(mark: ImportMark) -> int:
    return IngestQueue.objects.filter(
        cluster_name=mark.cluster.name, kind=mark.kind, import_id=mark.import_id,
    ).count()


# ── maybe_reap dispatcher ───────────────────────────────────────────


@pytest.mark.django_db
def test_maybe_reap_returns_none_for_non_draining_mark():
    """OPEN marks are not yet ready for reap — dispatcher returns None."""
    c = _cluster()
    mark = _mark(c, state=ImportMarkState.OPEN.value)
    assert maybe_reap(mark) is None
    mark.refresh_from_db()
    assert mark.state == ImportMarkState.OPEN.value


@pytest.mark.django_db
def test_maybe_reap_returns_none_when_queue_not_drained():
    """A pending item under the same `(cluster, kind, import_id)` keeps
    the drain_check False — dispatcher returns None and leaves the
    mark in draining state."""
    c = _cluster()
    mark = _mark(c, import_id="imp-pending")
    _row(mark, status=IngestQueueStatus.PENDING.value)
    assert maybe_reap(mark) is None
    mark.refresh_from_db()
    assert mark.state == ImportMarkState.DRAINING.value
    assert _rows(mark) == 1


@pytest.mark.django_db
def test_maybe_reap_dispatches_to_scan_path_and_transitions_to_reaped():
    """A drained scan-kind mark fires `_reap_scan` and lands as REAPED."""
    c = _cluster()
    mark = _mark(c, kind="trivy.ConfigAuditReport", observed_count=3)
    result = maybe_reap(mark)
    assert result is not None
    assert "observed_count" in result
    assert result["observed_count"] == 3
    mark.refresh_from_db()
    assert mark.state == ImportMarkState.REAPED.value


@pytest.mark.django_db
def test_maybe_reap_returns_none_when_mark_already_reaped_in_db():
    """The in-memory mark says draining, the DB says reaped (another
    reaper won) — the claim fails and nothing runs."""
    c = _cluster()
    mark = _mark(c, kind="trivy.ConfigAuditReport")
    ImportMark.objects.filter(pk=mark.pk).update(state=ImportMarkState.REAPED.value)
    with patch("core.services.reaper._maybe_capture_heartbeat") as hb:
        assert maybe_reap(mark) is None
    hb.assert_not_called()


@pytest.mark.django_db(transaction=True)
def test_reap_scan_two_threads_only_one_applies():
    """Two workers see the same drained tuple at once. Exactly one runs
    the body: a zero-input VulnerabilityReport mark over one deployed
    image must produce ONE ScanInconsistency row with consecutive_cycles
    1 — not 2 (which the old reap-then-transition order allowed)."""
    c = _cluster()
    w = _workload(c)
    img = Image.objects.create(digest="sha256:" + "a" * 64, ref="img:v1")
    WorkloadImageObservation.objects.create(
        workload=w, image=img, container_name="app", currently_deployed=True,
    )
    mark = _mark(c, kind="trivy.VulnerabilityReport", observed_count=0)

    barrier = threading.Barrier(2)
    results: list = []
    errors: list = []

    def run():
        try:
            m = ImportMark.objects.select_related("cluster").get(pk=mark.pk)
            barrier.wait()
            results.append(_reap_scan(m))
        except BaseException as exc:  # noqa: BLE001
            errors.append(exc)
        finally:
            connection.close()

    threads = [threading.Thread(target=run) for _ in range(2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert not errors, errors
    assert sorted(r is None for r in results) == [False, True]
    rows = list(ScanInconsistency.objects.all())
    assert len(rows) == 1 and rows[0].consecutive_cycles == 1


@pytest.mark.django_db
def test_maybe_reap_dispatches_to_inventory_path_for_inventory_kind():
    """An inventory-kind mark routes through `_reap_inventory`: the
    cluster anchor advances to the mark's started_at (every committed
    inventory is a complete snapshot), the mark reaches REAPED, and the
    row is gone."""
    c = _cluster()
    mark = _mark(c, kind="inventory", import_id="imp-inv")
    _row(mark)
    result = maybe_reap(mark)
    assert result is not None
    c.refresh_from_db()
    assert c.last_complete_inventory_at == mark.started_at
    mark.refresh_from_db()
    assert mark.state == ImportMarkState.REAPED.value
    assert _rows(mark) == 0


@pytest.mark.django_db
def test_reap_inventory_skips_diff_when_superseded_by_newer_cycle():
    """A mark that finally drains (e.g. a stuck item was reclaimed) after
    a NEWER import_id for the same cluster already reaped must not apply
    its diff — that would use a stale cutoff and could resurrect
    workloads/observations the newer cycle already correctly retired,
    and would roll `last_complete_inventory_at` backward."""
    c = _cluster()
    newer_reap_time = timezone.now()
    c.last_complete_inventory_at = newer_reap_time
    c.save(update_fields=["last_complete_inventory_at"])

    stale_mark = _mark(
        c, kind="inventory", import_id="imp-stale",
        started_at=newer_reap_time - timedelta(minutes=10),
    )
    _row(stale_mark)

    result = maybe_reap(stale_mark)

    assert result is not None
    assert result.get("superseded") is True
    stale_mark.refresh_from_db()
    assert stale_mark.state == ImportMarkState.REAPED.value, (
        "must still reap (not stay stuck), just without applying the diff"
    )
    c.refresh_from_db()
    assert c.last_complete_inventory_at == newer_reap_time, (
        "a stale reap must not roll the cluster's watermark backward"
    )
    assert _rows(stale_mark) == 0, "superseded path still deletes the rows"


# ── delete-at-reap + failure bookkeeping ───────────────────────────


@pytest.mark.django_db
def test_reap_deletes_all_rows_and_records_failures_on_mark():
    c = _cluster()
    mark = _mark(c, kind="trivy.ConfigAuditReport", observed_count=3)
    _row(mark)
    _row(mark, status=IngestQueueStatus.FAILED.value, error="first boom")
    _row(mark, status=IngestQueueStatus.FAILED.value, error="second boom")

    result = maybe_reap(mark)

    assert result["queue_rows_deleted"] == 3
    assert result["failed_count"] == 2
    assert _rows(mark) == 0
    mark.refresh_from_db()
    assert mark.failed_count == 2
    assert mark.last_error == "second boom"


@pytest.mark.django_db
@override_settings(IMPORT_KEEP_FAILED_PAYLOADS=True)
def test_reap_keeps_failed_rows_under_debug_flag():
    c = _cluster()
    mark = _mark(c, kind="trivy.ConfigAuditReport", observed_count=2)
    _row(mark)
    failed = _row(mark, status=IngestQueueStatus.FAILED.value, error="boom")

    maybe_reap(mark)

    assert list(IngestQueue.objects.values_list("pk", flat=True)) == [failed.pk]
    mark.refresh_from_db()
    assert mark.failed_count == 1


@pytest.mark.django_db
def test_reap_inventory_advances_anchor_then_deletes_rows():
    c = _cluster()
    mark = _mark(c, kind="inventory", import_id="imp-c")
    _row(mark)

    result = maybe_reap(mark)

    assert result is not None
    c.refresh_from_db()
    assert c.last_complete_inventory_at == mark.started_at
    assert _rows(mark) == 0


@pytest.mark.django_db
def test_reap_body_exception_rolls_back_claim_and_rows():
    """A failing body must leave the mark draining and the rows in
    place for the safety net — the claim is part of the transaction."""
    c = _cluster()
    mark = _mark(c, kind="trivy.ConfigAuditReport", observed_count=2)
    _row(mark)
    with patch("core.services.reaper._reap_scan_body", side_effect=RuntimeError("body exploded")):
        with pytest.raises(RuntimeError):
            maybe_reap(mark)
    mark.refresh_from_db()
    assert mark.state == ImportMarkState.DRAINING.value
    assert _rows(mark) == 1


# ── _reap_scan zero-input no-op ────────────────────────────────────


@pytest.mark.django_db
def test_reap_scan_zero_input_with_no_inventory_does_not_clear():
    """When `observed_count=0` AND the cluster has no deployed
    workloads, the scope-empty gate fires — reap proceeds normally
    (nothing to do). No ScanInconsistency rows written."""
    c = _cluster()
    mark = _mark(c, kind="trivy.ConfigAuditReport", observed_count=0)
    result = _reap_scan(mark)
    assert "skipped_zero_input" not in result
    assert ScanInconsistency.objects.count() == 0
    mark.refresh_from_db()
    assert mark.state == ImportMarkState.REAPED.value


@pytest.mark.django_db
def test_reap_scan_zero_input_with_inventory_writes_inconsistency():
    """Vuln/Secret kinds with `observed_count=0` AND a currently-
    observed (workload, image) inventory produce ScanInconsistency rows
    for Scan Health surfacing."""
    c = _cluster()
    w = _workload(c)
    img = Image.objects.create(digest="sha256:" + "a" * 64, ref="img:v1")
    WorkloadImageObservation.objects.create(
        workload=w, image=img, container_name="app", currently_deployed=True,
    )
    mark = _mark(c, kind="trivy.VulnerabilityReport", observed_count=0)
    result = _reap_scan(mark)
    assert result.get("skipped_zero_input") is True

    rows = list(ScanInconsistency.objects.all())
    assert len(rows) == 1
    row = rows[0]
    assert row.kind == "trivy.VulnerabilityReport"
    assert row.workload_id == w.id
    assert row.image_digest == img.digest
    assert row.seen_in_inventory is True
    assert row.seen_in_scans is False
    assert row.consecutive_cycles == 1

    mark.refresh_from_db()
    assert mark.state == ImportMarkState.REAPED.value


@pytest.mark.django_db
def test_reap_scan_zero_input_increments_existing_inconsistency():
    """A repeated outage bumps `consecutive_cycles` on the same
    (cluster, kind, workload, image) row instead of creating a new one."""
    c = _cluster()
    w = _workload(c)
    img = Image.objects.create(digest="sha256:" + "a" * 64, ref="img:v1")
    WorkloadImageObservation.objects.create(
        workload=w, image=img, container_name="app", currently_deployed=True,
    )

    # First outage cycle.
    m1 = _mark(c, kind="trivy.VulnerabilityReport", observed_count=0, import_id="imp-1")
    _reap_scan(m1)
    assert ScanInconsistency.objects.count() == 1

    # Second outage cycle — same scope.
    m2 = _mark(c, kind="trivy.VulnerabilityReport", observed_count=0, import_id="imp-2")
    _reap_scan(m2)
    rows = list(ScanInconsistency.objects.all())
    assert len(rows) == 1, "second outage must update, not duplicate"
    assert rows[0].consecutive_cycles == 2


@pytest.mark.django_db
def test_reap_scan_zero_input_non_image_kind_skips_inconsistency():
    """ConfigAudit / RBAC kinds key off `≥ 1 deployed workload`, not
    per-image — so the zero-input branch does NOT write
    ScanInconsistency rows for them."""
    c = _cluster()
    _workload(c)
    mark = _mark(c, kind="trivy.ConfigAuditReport", observed_count=0)
    result = _reap_scan(mark)
    assert result.get("skipped_zero_input") is True
    assert ScanInconsistency.objects.count() == 0


@pytest.mark.django_db
def test_reap_scan_partial_failure_takes_protective_branch():
    """Some of the kind's payloads failed → their signals were never
    bumped. Clearing "everything not bumped" would retire real findings,
    so the reap keeps them and flags the failure on the mark instead."""
    c = _cluster()
    w = _workload(c)
    started_at = timezone.now()
    stale_signal = WorkloadSignal.objects.create(
        workload=w, signal_id="kyverno:disallow-privileged-containers", currently_active=True,
    )
    _bump(stale_signal, last_seen_at=started_at - timedelta(minutes=10))
    mark = _mark(c, kind="kyverno.PolicyReport", observed_count=5, started_at=started_at)
    _row(mark)
    _row(mark, status=IngestQueueStatus.FAILED.value, error="parser blew up")

    result = _reap_scan(mark)

    assert result.get("skipped_partial_failure") is True
    assert "signals_cleared" not in result
    stale_signal.refresh_from_db()
    assert stale_signal.currently_active is True
    mark.refresh_from_db()
    assert mark.failed_count == 1 and mark.last_error == "parser blew up"
    assert _rows(mark) == 0


# ── _reap_scan signal clearing ─────────────────────────────────────


@pytest.mark.django_db
def test_reap_scan_clears_stale_kyverno_signals():
    """A Kyverno signal not bumped this cycle (its `last_seen_at` is
    older than the mark's `started_at`) flips `currently_active=False`
    when a kyverno reap runs."""
    c = _cluster()
    w = _workload(c)
    started_at = timezone.now()
    stale_signal = WorkloadSignal.objects.create(
        workload=w,
        signal_id="kyverno:disallow-privileged-containers",
        currently_active=True,
    )
    # Stamp it as observed before the reap window opened.
    _bump(stale_signal, last_seen_at=started_at - timedelta(minutes=10))

    mark = _mark(
        c, kind="kyverno.PolicyReport", observed_count=5, started_at=started_at,
    )
    result = _reap_scan(mark)

    stale_signal.refresh_from_db()
    assert stale_signal.currently_active is False
    assert result.get("signals_cleared") == 1


@pytest.mark.django_db
def test_reap_scan_keeps_fresh_signals_active():
    """A signal bumped within this cycle (its `last_seen_at` is at or
    after the reap's `started_at`) stays `currently_active=True`."""
    c = _cluster()
    w = _workload(c)
    started_at = timezone.now() - timedelta(minutes=5)
    fresh_signal = WorkloadSignal.objects.create(
        workload=w,
        signal_id="kyverno:disallow-privileged-containers",
        currently_active=True,
    )
    # Stamp it as observed AFTER the reap window opened.
    _bump(fresh_signal, last_seen_at=started_at + timedelta(minutes=1))

    mark = _mark(
        c, kind="kyverno.PolicyReport", observed_count=5, started_at=started_at,
    )
    _reap_scan(mark)

    fresh_signal.refresh_from_db()
    assert fresh_signal.currently_active is True


@pytest.mark.django_db
def test_reap_scan_only_clears_signals_in_scope_for_its_kind():
    """A Trivy reap must NOT flip a Kyverno-origin signal (different
    source means different reap responsibility), even if the Kyverno
    signal looks stale."""
    c = _cluster()
    w = _workload(c)
    started_at = timezone.now()

    kyverno_signal = WorkloadSignal.objects.create(
        workload=w,
        signal_id="kyverno:disallow-privileged-containers",
        currently_active=True,
    )
    _bump(kyverno_signal, last_seen_at=started_at - timedelta(minutes=10))

    # Trivy ConfigAuditReport reap — its scope is TRIVY signals only.
    mark = _mark(
        c, kind="trivy.ConfigAuditReport", observed_count=5, started_at=started_at,
    )
    _reap_scan(mark)

    kyverno_signal.refresh_from_db()
    assert kyverno_signal.currently_active is True, (
        "Trivy reap must not flip a Kyverno-source signal"
    )


@pytest.mark.django_db
def test_config_audit_reap_does_not_clear_rbac_only_signals():
    """A healthy ConfigAuditReport reap must not clear KSV-0041/KSV-0044 —
    RBAC checks that only RbacAssessmentReport can ever report/bump.
    Regression test: `_signal_ids_for_kind`'s old `startswith("ksv:KSV-005")`
    heuristic for RBAC scope missed these two ids, so ConfigAuditReport's
    (much broader, TRIVY-wide) set incorrectly swept them up — bypassing
    RbacAssessmentReport's own zero-input outage protection as a side
    effect of an unrelated, healthy scan."""
    c = _cluster()
    w = _workload(c)
    started_at = timezone.now()

    rbac_signal = WorkloadSignal.objects.create(
        workload=w, signal_id="ksv:KSV-0041", currently_active=True,
    )
    _bump(rbac_signal, last_seen_at=started_at - timedelta(minutes=10))

    mark = _mark(
        c, kind="trivy.ConfigAuditReport", observed_count=5, started_at=started_at,
    )
    _reap_scan(mark)

    rbac_signal.refresh_from_db()
    assert rbac_signal.currently_active is True, (
        "ConfigAuditReport reap must not own RBAC-only signals"
    )


@pytest.mark.django_db
def test_rbac_report_reap_clears_its_own_stale_signals():
    """RbacAssessmentReport's own healthy reap DOES correctly clear a
    stale KSV-0041/KSV-0044 signal — confirms the fix didn't just widen
    the exclusion without the RBAC kind still owning its full signal set."""
    c = _cluster()
    w = _workload(c)
    started_at = timezone.now()

    for signal_id in ("ksv:KSV-0041", "ksv:KSV-0044"):
        sig = WorkloadSignal.objects.create(
            workload=w, signal_id=signal_id, currently_active=True,
        )
        _bump(sig, last_seen_at=started_at - timedelta(minutes=10))

    mark = _mark(
        c, kind="trivy.RbacAssessmentReport", observed_count=5, started_at=started_at,
    )
    result = _reap_scan(mark)

    assert result.get("signals_cleared") == 2
    for signal_id in ("ksv:KSV-0041", "ksv:KSV-0044"):
        sig = WorkloadSignal.objects.get(workload=w, signal_id=signal_id)
        assert sig.currently_active is False


# ── transition_mark_to_reaped idempotence ───────────────────────────


@pytest.mark.django_db
def test_transition_mark_to_reaped_is_idempotent_under_double_call():
    """Two workers racing the same drain — only one wins the
    state-machine flip; the other returns False without raising."""
    c = _cluster()
    mark = _mark(c, kind="trivy.ConfigAuditReport")
    first = transition_mark_to_reaped(mark)
    second = transition_mark_to_reaped(mark)
    assert first is True
    assert second is False
    mark.refresh_from_db()
    assert mark.state == ImportMarkState.REAPED.value


@pytest.mark.django_db
def test_transition_mark_to_reaped_rejects_non_draining_mark():
    """A mark in `open` state is not yet eligible for transition. The
    helper returns False (no race won) and the state stays unchanged."""
    c = _cluster()
    mark = _mark(c, kind="trivy.ConfigAuditReport", state=ImportMarkState.OPEN.value)
    assert transition_mark_to_reaped(mark) is False
    mark.refresh_from_db()
    assert mark.state == ImportMarkState.OPEN.value


# ── reap_all_drainable safety-net sweep ────────────────────────────


@pytest.mark.django_db
def test_reap_all_drainable_fires_only_for_drained_tuples():
    """The safety-net sweep picks up only the draining marks whose
    queue is empty. A mark with a pending queue item must remain
    draining."""
    c = _cluster()
    drained = _mark(c, kind="trivy.ConfigAuditReport", import_id="imp-drained")
    not_drained = _mark(c, kind="trivy.ConfigAuditReport", import_id="imp-busy")
    _row(not_drained, status=IngestQueueStatus.PENDING.value)

    # Suppress the heartbeat — the sweep would otherwise try to write
    # a Snapshot row; that path is exercised by snapshot tests.
    with patch("core.services.reaper._maybe_capture_heartbeat"):
        fired = reap_all_drainable()

    assert fired == 1
    drained.refresh_from_db()
    not_drained.refresh_from_db()
    assert drained.state == ImportMarkState.REAPED.value
    assert not_drained.state == ImportMarkState.DRAINING.value


@pytest.mark.django_db
def test_reap_all_drainable_ignores_open_marks():
    """A mark still in OPEN state — the importer hasn't committed yet —
    must not be reaped by the safety-net sweep."""
    c = _cluster()
    open_mark = _mark(c, kind="trivy.ConfigAuditReport", state=ImportMarkState.OPEN.value)

    with patch("core.services.reaper._maybe_capture_heartbeat"):
        fired = reap_all_drainable()

    assert fired == 0
    open_mark.refresh_from_db()
    assert open_mark.state == ImportMarkState.OPEN.value


@pytest.mark.django_db
def test_reap_all_drainable_ignores_already_reaped_marks():
    """A mark already in REAPED state is a no-op — the sweep should
    not double-reap it."""
    c = _cluster()
    already = _mark(c, kind="trivy.ConfigAuditReport", state=ImportMarkState.REAPED.value)

    with patch("core.services.reaper._maybe_capture_heartbeat"):
        fired = reap_all_drainable()

    assert fired == 0
    already.refresh_from_db()
    assert already.state == ImportMarkState.REAPED.value


# ── reap_stuck_open: discard, don't promote ─────────────────────────


def _stale():
    return timezone.now() - timedelta(seconds=STUCK_OPEN_TIMEOUT_SECONDS + 60)


@pytest.mark.django_db
def test_reap_stuck_open_leaves_fresh_open_mark():
    """An `open` mark well within the timeout is left alone — the
    importer may still be legitimately mid-upload."""
    c = _cluster()
    mark = _mark(c, state=ImportMarkState.OPEN.value, started_at=timezone.now())
    _row(mark, status=IngestQueueStatus.PENDING.value)

    assert reap_stuck_open() == 0
    mark.refresh_from_db()
    assert mark.state == ImportMarkState.OPEN.value
    assert _rows(mark) == 1


@pytest.mark.django_db
def test_reap_stuck_open_ignores_draining_and_reaped_marks():
    """Only `state=open` is in scope — draining/reaped marks (even with
    an ancient `started_at`) are untouched by this sweep."""
    c = _cluster()
    draining = _mark(
        c, kind="trivy.ConfigAuditReport", import_id="imp-d",
        state=ImportMarkState.DRAINING.value, started_at=_stale(),
    )
    reaped = _mark(
        c, kind="trivy.ConfigAuditReport", import_id="imp-r",
        state=ImportMarkState.REAPED.value, started_at=_stale(),
    )

    assert reap_stuck_open() == 0
    draining.refresh_from_db()
    reaped.refresh_from_db()
    assert draining.state == ImportMarkState.DRAINING.value
    assert reaped.state == ImportMarkState.REAPED.value


@pytest.mark.django_db
def test_reap_stuck_open_discards_rows_and_all_marks_of_the_import():
    """An import the importer never committed: every one of its marks
    goes to reaped/stuck_open together, its rows are deleted, and
    nothing is ever applied."""
    c = _cluster()
    inv = _mark(c, kind="inventory", import_id="imp-stuck", state=ImportMarkState.OPEN.value,
                observed_count=None, started_at=_stale())
    vuln = _mark(c, kind="trivy.VulnerabilityReport", import_id="imp-stuck",
                 state=ImportMarkState.OPEN.value, observed_count=None, started_at=_stale())
    _row(inv, status=IngestQueueStatus.PENDING.value)
    _row(vuln, status=IngestQueueStatus.PENDING.value)
    _row(vuln, status=IngestQueueStatus.PENDING.value)
    other = _mark(c, kind="inventory", import_id="imp-other", state=ImportMarkState.OPEN.value,
                  started_at=timezone.now())
    _row(other, status=IngestQueueStatus.PENDING.value)

    assert reap_stuck_open() == 2

    for m in (inv, vuln):
        m.refresh_from_db()
        assert m.state == ImportMarkState.REAPED.value
        assert m.discard_reason == ImportDiscardReason.STUCK_OPEN.value
        assert m.completed_at is not None
        assert m.observed_count is None
        assert m.failed_count == 0
    assert IngestQueue.objects.filter(import_id="imp-stuck").count() == 0
    other.refresh_from_db()
    assert other.state == ImportMarkState.OPEN.value and _rows(other) == 1
    c.refresh_from_db()
    assert c.last_complete_inventory_at is None


@pytest.mark.django_db
def test_reap_stuck_open_discarded_scan_mark_never_clears_signals():
    """Core safety property: a discarded scan mark must never reach the
    signal-clearing branch — an interrupted cycle must not look like a
    complete, clean scan that found nothing."""
    c = _cluster()
    w = _workload(c)
    live_signal = WorkloadSignal.objects.create(
        workload=w, signal_id="kyverno:disallow-privileged-containers",
        currently_active=True,
    )
    _bump(live_signal, last_seen_at=_stale() - timedelta(minutes=5))
    _mark(
        c, kind="kyverno.PolicyReport", import_id="imp-stuck",
        state=ImportMarkState.OPEN.value, observed_count=None, started_at=_stale(),
    )

    assert reap_stuck_open() == 1
    with patch("core.services.reaper._maybe_capture_heartbeat"):
        assert reap_all_drainable() == 0, "a discarded mark is terminal — nothing left to reap"

    live_signal.refresh_from_db()
    assert live_signal.currently_active is True


# ── inventory-failed discard ───────────────────────────────────────


@pytest.mark.django_db
def test_discard_import_for_failed_inventory_keeps_nothing_but_the_facts():
    c = _cluster()
    inv = _mark(c, kind="inventory", import_id="imp-f", observed_count=1)
    vuln = _mark(c, kind="trivy.VulnerabilityReport", import_id="imp-f", observed_count=2)
    _row(inv, status=IngestQueueStatus.FAILED.value, error="inventory parser exploded")
    _row(vuln, status=IngestQueueStatus.PENDING.value)
    _row(vuln, status=IngestQueueStatus.PENDING.value)

    result = discard_import_for_failed_inventory(cluster_name=c.name, import_id="imp-f")

    assert result == {"marks": 2, "rows": 3}
    inv.refresh_from_db()
    vuln.refresh_from_db()
    assert inv.discard_reason == vuln.discard_reason == ImportDiscardReason.INVENTORY_FAILED.value
    assert inv.state == vuln.state == ImportMarkState.REAPED.value
    assert inv.failed_count == 1 and inv.last_error == "inventory parser exploded"
    assert vuln.failed_count == 0
    assert IngestQueue.objects.count() == 0
    c.refresh_from_db()
    assert c.last_complete_inventory_at is None


@pytest.mark.django_db
@override_settings(IMPORT_KEEP_FAILED_PAYLOADS=True)
def test_discard_keeps_failed_inventory_row_under_debug_flag():
    c = _cluster()
    inv = _mark(c, kind="inventory", import_id="imp-f", observed_count=1)
    failed = _row(inv, status=IngestQueueStatus.FAILED.value, error="boom")
    _row(inv, status=IngestQueueStatus.PENDING.value, kind="trivy.VulnerabilityReport")

    discard_import_for_failed_inventory(cluster_name=c.name, import_id="imp-f")

    assert list(IngestQueue.objects.values_list("pk", flat=True)) == [failed.pk]


@pytest.mark.django_db
def test_discard_inventory_failed_sweep_catches_rows_failed_outside_the_worker():
    """`claim_batch`'s abandon-exhausted SQL flips rows to failed without
    the worker's discard hook running; the hourly sweep covers it."""
    c = _cluster()
    inv = _mark(c, kind="inventory", import_id="imp-abandoned", observed_count=1)
    _row(inv, status=IngestQueueStatus.FAILED.value,
         error="abandoned: stuck in processing past reclaim attempt limit")
    scan = _mark(c, kind="trivy.ConfigAuditReport", import_id="imp-abandoned", observed_count=1)
    _row(scan, status=IngestQueueStatus.PENDING.value)
    # An unrelated, healthy draining import is untouched.
    healthy = _mark(c, kind="inventory", import_id="imp-healthy", observed_count=1)
    _row(healthy, status=IngestQueueStatus.PENDING.value)

    assert discard_inventory_failed_imports() == 2

    inv.refresh_from_db()
    scan.refresh_from_db()
    healthy.refresh_from_db()
    assert inv.discard_reason == scan.discard_reason == ImportDiscardReason.INVENTORY_FAILED.value
    assert "abandoned" in inv.last_error
    assert healthy.state == ImportMarkState.DRAINING.value and _rows(healthy) == 1


@pytest.mark.django_db
def test_reap_safety_net_command_discards_and_reaps_in_one_run():
    """End-to-end: `manage.py reap_safety_net` discards a stuck-open
    import, discards an inventory-failed import, and reaps a healthy
    drained mark — all in one invocation."""
    c = _cluster()
    _mark(c, kind="trivy.ConfigAuditReport", import_id="imp-stuck",
          state=ImportMarkState.OPEN.value, observed_count=None, started_at=_stale())
    inv = _mark(c, kind="inventory", import_id="imp-f", observed_count=1)
    _row(inv, status=IngestQueueStatus.FAILED.value, error="boom")
    _mark(c, kind="trivy.ConfigAuditReport", import_id="imp-ok", observed_count=1)

    out = io.StringIO()
    with patch("core.services.reaper._maybe_capture_heartbeat"):
        call_command("reap_safety_net", stdout=out)

    body = out.getvalue()
    assert "discarded_stuck_open: 1" in body
    assert "discarded_inventory_failed: 1" in body
    assert "reaped: 1" in body
    assert set(ImportMark.objects.values_list("state", flat=True)) == {ImportMarkState.REAPED.value}


@pytest.mark.django_db
def test_inventory_reap_scaled_to_zero_image_not_currently_deployed():
    """End-to-end inventory reap: a Deployment scaled to replicas=0 has
    its image observation bumped this cycle, but because the workload
    ends deployed=False the observation must NOT be marked
    currently_deployed (else its image would show as running in
    /images). Covers the reaper's workload__deployed join."""
    c = _cluster()
    ns = Namespace.objects.create(cluster=c, name="ns")
    mark = _mark(c, kind="inventory", import_id="imp-scale")

    w = Workload.objects.create(
        cluster=c, namespace=ns, kind="Deployment", name="scaled-down",
        replicas=0, deployed=True,
    )
    # Seen this cycle (inventory bumped last_inventory_at to the mark).
    _bump(w, last_inventory_at=mark.started_at + timedelta(seconds=1))

    img = Image.objects.create(digest="sha256:" + "c" * 64, ref="x:1")
    obs = WorkloadImageObservation.objects.create(
        workload=w, image=img, container_name="app", currently_deployed=True,
    )
    _bump(obs, last_seen_at=mark.started_at + timedelta(seconds=1))

    _row(mark)

    result = maybe_reap(mark)
    assert result is not None

    w.refresh_from_db()
    obs.refresh_from_db()
    assert w.deployed is False
    assert obs.currently_deployed is False
    assert img.digest not in set(
        Image.objects.currently_running(cluster=c).values_list("digest", flat=True)
    )


# ── Non-blocking claim + commit-before-recompute ───────────────────
#
# Regression tests for the production stall where every worker pod sat
# at 0 CPU behind one pod's inventory reap: the claim UPDATE blocked on
# the winner's row lock, which was held for the whole reap including the
# whole-cluster priority recompute (minutes), until the holder was killed
# at activeDeadlineSeconds and the next waiter inherited the lock.


def _finding(workload: Workload, *, vuln_id: str) -> Finding:
    return Finding.objects.create(
        cluster=workload.cluster, workload=workload, source="trivy",
        category="vulnerability", vuln_id=vuln_id, title="t",
        severity=Severity.HIGH.value, hash_code=vuln_id,
    )


def _claim_holder(mark: ImportMark, *, lock_acquired: threading.Event,
                  release_lock: threading.Event, fail: bool = False) -> threading.Thread:
    """Thread that wins the claim on `mark` on its own connection and keeps
    that transaction open until `release_lock` is set (then commits, or
    rolls back when `fail`)."""
    def run():
        try:
            with transaction.atomic():
                m = ImportMark.objects.select_related("cluster").get(pk=mark.pk)
                assert transition_mark_to_reaped(m) is True
                lock_acquired.set()
                release_lock.wait(timeout=5)
                if fail:
                    raise RuntimeError("holder rolled back")
        except RuntimeError:
            pass
        finally:
            connection.close()
    return threading.Thread(target=run)


@pytest.mark.django_db(transaction=True)
def test_transition_mark_to_reaped_returns_false_fast_while_another_reaper_holds_the_mark():
    c = _cluster()
    mark = _mark(c, kind="inventory")
    lock_acquired, release_lock = threading.Event(), threading.Event()
    holder = _claim_holder(mark, lock_acquired=lock_acquired, release_lock=release_lock)
    holder.start()
    assert lock_acquired.wait(timeout=5), "holder never won its claim"

    try:
        started = time.monotonic()
        won = transition_mark_to_reaped(mark)
        elapsed = time.monotonic() - started
        assert won is False
        assert elapsed < 2.0, f"claim took {elapsed:.2f}s — it waited on the holder's lock"
        assert ImportMark.objects.get(pk=mark.pk).state == ImportMarkState.DRAINING.value, (
            "the holder has not committed yet; the loser must not have flipped anything"
        )
    finally:
        release_lock.set()
        holder.join(timeout=5)
        connection.close()

    assert ImportMark.objects.get(pk=mark.pk).state == ImportMarkState.REAPED.value, (
        "exactly one winner: the holder's commit"
    )


@pytest.mark.django_db(transaction=True)
def test_lost_claim_whose_winner_rolls_back_leaves_the_mark_for_a_later_sweep():
    c = _cluster()
    mark = _mark(c, kind="inventory")
    lock_acquired, release_lock = threading.Event(), threading.Event()
    holder = _claim_holder(
        mark, lock_acquired=lock_acquired, release_lock=release_lock, fail=True,
    )
    holder.start()
    assert lock_acquired.wait(timeout=5)
    try:
        assert transition_mark_to_reaped(mark) is False
    finally:
        release_lock.set()
        holder.join(timeout=5)
        connection.close()

    assert ImportMark.objects.get(pk=mark.pk).state == ImportMarkState.DRAINING.value
    assert transition_mark_to_reaped(mark) is True, "the next sweep claims it"


@pytest.mark.django_db(transaction=True)
def test_maybe_reap_does_not_block_behind_an_in_flight_inventory_reap():
    """The production scenario: pod A is inside the inventory reap body;
    pod B's drain finds the same tuple drained and calls maybe_reap. B
    must get None at once, and A's reap must still complete."""
    c = _cluster()
    mark = _mark(c, kind="inventory")
    _row(mark)
    body_entered, release_body = threading.Event(), threading.Event()
    holder_result: list = []

    def slow_body(m):
        body_entered.set()
        release_body.wait(timeout=5)
        return {}

    def hold():
        try:
            m = ImportMark.objects.select_related("cluster").get(pk=mark.pk)
            holder_result.append(_reap_inventory(m))
        finally:
            connection.close()

    with patch("core.services.reaper._reap_inventory_body", side_effect=slow_body):
        holder = threading.Thread(target=hold)
        holder.start()
        assert body_entered.wait(timeout=5), "holder never entered the reap body"
        try:
            started = time.monotonic()
            result = maybe_reap(mark)
            elapsed = time.monotonic() - started
        finally:
            release_body.set()
            holder.join(timeout=5)
            connection.close()

    assert result is None
    assert elapsed < 2.0, f"maybe_reap took {elapsed:.2f}s — it blocked on the holder's lock"
    assert holder_result and holder_result[0] is not None, "the holder's reap completed"
    assert ImportMark.objects.get(pk=mark.pk).state == ImportMarkState.REAPED.value
    assert _rows(mark) == 0


@pytest.mark.django_db
def test_inventory_reap_commits_even_when_the_priority_recompute_fails():
    c = _cluster()
    mark = _mark(c, kind="inventory")
    _row(mark)
    with patch("core.services.reaper.recompute_ids", side_effect=RuntimeError("recompute exploded")), \
         patch("core.services.reaper._maybe_capture_heartbeat"):
        result = maybe_reap(mark)

    assert result is not None and result.get("recompute_failed") is True
    mark.refresh_from_db()
    c.refresh_from_db()
    assert mark.state == ImportMarkState.REAPED.value
    assert c.last_complete_inventory_at == mark.started_at
    assert _rows(mark) == 0


@pytest.mark.django_db(transaction=True)
def test_inventory_reap_recomputes_after_its_transaction_committed():
    c = _cluster()
    w = _workload(c)
    findings = [_finding(w, vuln_id=f"CVE-2024-{i}") for i in range(3)]
    mark = _mark(c, kind="inventory")
    _row(mark)
    seen: list[list[int]] = []

    def spy(ids):
        assert connection.in_atomic_block is False, "recompute ran inside the reap transaction"
        assert ImportMark.objects.get(pk=mark.pk).state == ImportMarkState.REAPED.value, (
            "the reap must be committed before the recompute starts"
        )
        ids = list(ids)
        seen.append(ids)
        return urgency.recompute_ids(ids)

    with patch("core.services.reaper.recompute_ids", side_effect=spy), \
         patch("core.services.reaper._maybe_capture_heartbeat"):
        result = maybe_reap(mark)

    assert len(seen) == 1 and sorted(seen[0]) == sorted(f.pk for f in findings)
    assert isinstance(result.get("priorities_recomputed"), int)


@pytest.mark.django_db
def test_superseded_inventory_reap_does_not_recompute():
    c = _cluster()
    newer_reap_time = timezone.now()
    c.last_complete_inventory_at = newer_reap_time
    c.save(update_fields=["last_complete_inventory_at"])
    stale_mark = _mark(
        c, kind="inventory", import_id="imp-stale",
        started_at=newer_reap_time - timedelta(minutes=10),
    )
    _row(stale_mark)

    with patch("core.services.reaper.recompute_ids") as recompute, \
         patch("core.services.reaper._maybe_capture_heartbeat"):
        result = maybe_reap(stale_mark)

    recompute.assert_not_called()
    assert result.get("superseded") is True
    assert "priorities_recomputed" not in result


@pytest.mark.django_db
def test_scan_reap_commits_signal_clear_even_when_the_recompute_fails():
    c = _cluster()
    w = _workload(c)
    started_at = timezone.now()
    stale_signal = WorkloadSignal.objects.create(
        workload=w, signal_id="kyverno:disallow-privileged-containers", currently_active=True,
    )
    _bump(stale_signal, last_seen_at=started_at - timedelta(minutes=10))
    mark = _mark(c, kind="kyverno.PolicyReport", observed_count=5, started_at=started_at)

    with patch("core.services.reaper.recompute_ids", side_effect=RuntimeError("recompute exploded")):
        result = _reap_scan(mark)

    assert result.get("signals_cleared") == 1
    assert result.get("recompute_failed") is True
    stale_signal.refresh_from_db()
    assert stale_signal.currently_active is False
    mark.refresh_from_db()
    assert mark.state == ImportMarkState.REAPED.value


@pytest.mark.django_db(transaction=True)
def test_scan_reap_recomputes_only_the_affected_workloads_after_commit():
    c = _cluster()
    w1 = _workload(c)
    w2 = Workload.objects.create(
        cluster=c, namespace=w1.namespace, kind="Deployment", name="other", deployed=True,
    )
    f1 = _finding(w1, vuln_id="CVE-2024-1")
    _finding(w2, vuln_id="CVE-2024-2")
    started_at = timezone.now()
    stale_signal = WorkloadSignal.objects.create(
        workload=w1, signal_id="kyverno:disallow-privileged-containers", currently_active=True,
    )
    _bump(stale_signal, last_seen_at=started_at - timedelta(minutes=10))
    mark = _mark(c, kind="kyverno.PolicyReport", observed_count=5, started_at=started_at)
    seen: list[list[int]] = []

    def spy(ids):
        assert connection.in_atomic_block is False
        ids = list(ids)
        seen.append(ids)
        return urgency.recompute_ids(ids)

    with patch("core.services.reaper.recompute_ids", side_effect=spy):
        _reap_scan(mark)

    assert seen == [[f1.pk]]


@pytest.mark.django_db
def test_scan_reap_skips_the_recompute_when_nothing_was_cleared():
    c = _cluster()
    w = _workload(c)
    started_at = timezone.now()
    stale_signal = WorkloadSignal.objects.create(
        workload=w, signal_id="kyverno:disallow-privileged-containers", currently_active=True,
    )
    _bump(stale_signal, last_seen_at=started_at - timedelta(minutes=10))
    mark = _mark(c, kind="kyverno.PolicyReport", observed_count=5, started_at=started_at)
    _row(mark, status=IngestQueueStatus.FAILED.value, error="parser blew up")

    with patch("core.services.reaper.recompute_ids") as recompute:
        result = _reap_scan(mark)

    recompute.assert_not_called()
    assert result.get("skipped_partial_failure") is True


# ── discard, don't promote: a failed inventory row reaching the sweep ──


@pytest.mark.django_db
def test_inventory_reap_with_failed_row_discards_instead_of_advancing_anchor():
    """`drain_check` only counts pending/processing rows, so an inventory
    whose single row ended `failed` looks drained. The worker discards the
    import when it fails the row itself, but the abandon-exhausted SQL
    flips a poison row to `failed` with no discard — the sweep used to reap
    it as a complete cycle (anchor advanced, every workload retired)."""
    c = _cluster()
    w = _workload(c)
    mark = _mark(c, kind="inventory", import_id="imp-poison")
    sibling = _mark(c, kind="trivy.ConfigAuditReport", import_id="imp-poison")
    _row(mark, status=IngestQueueStatus.FAILED.value, error="abandoned: poison")
    _row(sibling, status=IngestQueueStatus.PENDING.value)

    with patch("core.services.reaper._maybe_capture_heartbeat") as hb:
        fired = reap_all_drainable()

    assert fired == 0
    hb.assert_not_called()
    c.refresh_from_db()
    w.refresh_from_db()
    assert c.last_complete_inventory_at is None, "a cycle that never landed must not become the anchor"
    assert w.deployed is True, "nothing was retired"
    for m in (mark, sibling):
        m.refresh_from_db()
        assert m.state == ImportMarkState.REAPED.value
        assert m.discard_reason == ImportDiscardReason.INVENTORY_FAILED.value
    assert mark.last_error == "abandoned: poison"
    assert _rows(mark) == 0 and _rows(sibling) == 0, "the whole import's rows are gone"


@pytest.mark.django_db
def test_maybe_reap_discards_failed_inventory_without_a_heartbeat():
    c = _cluster()
    mark = _mark(c, kind="inventory", import_id="imp-poison")
    _row(mark, status=IngestQueueStatus.FAILED.value, error="x")

    with patch("core.services.reaper._maybe_capture_heartbeat") as hb:
        assert maybe_reap(mark) is None

    hb.assert_not_called()
    mark.refresh_from_db()
    assert mark.discard_reason == ImportDiscardReason.INVENTORY_FAILED.value
