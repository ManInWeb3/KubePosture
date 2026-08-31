"""Tests for `core.services.reaper` — ImportMark lifecycle + dispatch.

Covers:
- `maybe_reap` dispatcher gates: state guard, drain guard, inventory-
  vs-scan dispatch.
- `_reap_scan` zero-input no-op rule + ScanInconsistency emission for
  image-anchored kinds.
- `_reap_scan` signal clearing — stale Kyverno/Trivy signals flip
  `currently_active=False` when their `last_seen_at` is older than the
  reap's `started_at`.
- `transition_mark_to_reaped` idempotence under double-call (two
  workers racing the same drain).
- `reap_all_drainable` safety-net sweep over leftover draining marks.

Inventory reap (`_reap_inventory`) is covered indirectly via
`test_inventory_parser.py` — its `reap_inventory_diff` body is the
non-trivial part and lives in the parser, not the reaper.
"""
from __future__ import annotations

from datetime import timedelta
from unittest.mock import patch

import pytest
from django.utils import timezone

from core.constants import (
    Environment,
    ImportMarkState,
    IngestQueueStatus,
)
from core.models import (
    Cluster,
    ImportMark,
    IngestQueue,
    Namespace,
    ScanInconsistency,
    Workload,
    WorkloadImageObservation,
    WorkloadSignal,
)
from core.models import Image
from core.services.queue import transition_mark_to_reaped
from core.services.reaper import (
    _reap_scan,
    maybe_reap,
    reap_all_drainable,
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


def _workload(cluster: Cluster, *, name: str = "api") -> Workload:
    ns = Namespace.objects.create(cluster=cluster, name="payments")
    return Workload.objects.create(
        cluster=cluster, namespace=ns, kind="Deployment", name=name, deployed=True,
    )


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
    IngestQueue.objects.create(
        cluster_name=c.name,
        kind=mark.kind,
        import_id=mark.import_id,
        raw_json={},
        status=IngestQueueStatus.PENDING.value,
    )
    assert maybe_reap(mark) is None
    mark.refresh_from_db()
    assert mark.state == ImportMarkState.DRAINING.value


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
def test_maybe_reap_dispatches_to_inventory_path_for_inventory_kind():
    """An inventory-kind mark routes through `_reap_inventory`. The
    payload had no `complete_snapshot=true` so the consecutive
    counter bumps and the mark still reaches REAPED."""
    c = _cluster()
    mark = _mark(c, kind="inventory", import_id="imp-inv")
    IngestQueue.objects.create(
        cluster_name=c.name, kind="inventory", import_id=mark.import_id,
        raw_json={}, status=IngestQueueStatus.DONE.value,
        complete_snapshot=False,
    )
    result = maybe_reap(mark)
    assert result is not None
    assert result.get("complete_snapshot") is False
    c.refresh_from_db()
    assert c.consecutive_incomplete_inventories == 1
    mark.refresh_from_db()
    assert mark.state == ImportMarkState.REAPED.value


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
    IngestQueue.objects.create(
        cluster_name=c.name, kind="inventory", import_id=stale_mark.import_id,
        raw_json={}, status=IngestQueueStatus.DONE.value,
        complete_snapshot=True,
    )

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
    IngestQueue.objects.create(
        cluster_name=c.name,
        kind=not_drained.kind,
        import_id=not_drained.import_id,
        raw_json={},
        status=IngestQueueStatus.PENDING.value,
    )

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
    """A mark still in OPEN state — the importer hasn't finished yet —
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

    # Complete-snapshot payload so the reap runs the deployed diff + mirror.
    IngestQueue.objects.create(
        cluster_name=c.name, kind="inventory", import_id=mark.import_id,
        raw_json={}, status=IngestQueueStatus.DONE.value,
        complete_snapshot=True,
    )

    result = maybe_reap(mark)
    assert result is not None
    assert result.get("complete_snapshot") is True

    w.refresh_from_db()
    obs.refresh_from_db()
    assert w.deployed is False
    assert obs.currently_deployed is False
    assert img.digest not in set(
        Image.objects.currently_running(cluster=c).values_list("digest", flat=True)
    )
