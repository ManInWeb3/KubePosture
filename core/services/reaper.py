"""Reaper — kind-dispatched wrap-up after a `(cluster, kind, import_id)`
queue drains. Idempotent against marks already in `state=reaped`.
"""
from __future__ import annotations

import logging
from datetime import timedelta

from django.db import transaction

from core.constants import (
    ImageSetChangeKind,
    ImportMarkState,
    SnapshotScope,
    WORKLOAD_OBSERVATION_RETENTION_DAYS,
)
from core.models import (
    Cluster,
    Image,
    ImportMark,
    IngestQueue,
    ScanInconsistency,
    Snapshot,
    Workload,
    WorkloadImageObservation,
    WorkloadSignal,
)
from core.parsers.inventory import reap_inventory_diff
from core.signals import SIGNALS
from core.urgency import recompute_batch
from core.services.queue import drain_check, transition_mark_to_reaped

log = logging.getLogger("core.reaper")


# ── Inventory reap ------------------------------------------------

@transaction.atomic
def _reap_inventory(mark: ImportMark) -> dict:
    cluster = mark.cluster
    # Did any payload this cycle carry complete_snapshot=true?
    has_complete = IngestQueue.objects.filter(
        cluster_name=cluster.name,
        kind="inventory",
        import_id=mark.import_id,
        complete_snapshot=True,
    ).exists()

    counters: dict = {"complete_snapshot": has_complete}
    if not has_complete:
        cluster.consecutive_incomplete_inventories = (
            cluster.consecutive_incomplete_inventories + 1
        )
        cluster.save(update_fields=["consecutive_incomplete_inventories"])
        log.info(
            "reap.inventory.incomplete",
            extra={
                "cluster": cluster.name,
                "import_id": mark.import_id,
                "consecutive": cluster.consecutive_incomplete_inventories,
            },
        )
        if cluster.consecutive_incomplete_inventories >= 3:
            log.warning(
                "reap.inventory.persistent_incomplete",
                extra={
                    "cluster": cluster.name,
                    "consecutive": cluster.consecutive_incomplete_inventories,
                },
            )
        transition_mark_to_reaped(mark)
        return counters

    # Reset the incomplete counter — this cycle was clean.
    update_fields = []
    if cluster.consecutive_incomplete_inventories != 0:
        cluster.consecutive_incomplete_inventories = 0
        update_fields.append("consecutive_incomplete_inventories")
    # Anchor for Image.objects.currently_running() — this is what
    # makes the manager's "is image deployed?" query partial-cycle
    # safe. Only complete cycles advance this; partial cycles leave
    # it where it is, so observations from prior complete cycles
    # remain valid.
    cluster.last_complete_inventory_at = mark.started_at
    update_fields.append("last_complete_inventory_at")
    cluster.save(update_fields=update_fields)

    # Run the deployed-flag diff.
    diff = reap_inventory_diff(cluster, mark.started_at)
    counters.update(diff)

    # Mirror Workload.deployed onto WorkloadImageObservation rows:
    # bumped this cycle → currently_deployed=True; the rest → False.
    # Source of truth for the workload-detail Images table.
    obs_qs = WorkloadImageObservation.objects.filter(workload__cluster=cluster)
    obs_deployed = obs_qs.filter(last_seen_at__gte=mark.started_at).update(
        currently_deployed=True,
    )
    obs_undeployed = obs_qs.exclude(last_seen_at__gte=mark.started_at).update(
        currently_deployed=False,
    )
    counters["obs_deployed"] = obs_deployed
    counters["obs_undeployed"] = obs_undeployed

    # Retention sweep — drop stale observations older than the window.
    threshold = mark.started_at - timedelta(
        days=WORKLOAD_OBSERVATION_RETENTION_DAYS
    )
    obs_swept, _ = obs_qs.filter(
        currently_deployed=False,
        last_seen_at__lt=threshold,
    ).delete()
    counters["obs_swept"] = obs_swept

    # Image-set change snapshots (event-path). Runs AFTER the
    # currently_deployed flip so the snapshot writer can rely on it.
    _write_event_path_workload_snapshots(cluster, mark)

    # Recompute priority for all findings on workloads in this cluster
    # (publicly_exposed / namespace.internet_exposed may have moved).
    affected = list(
        cluster.findings.all().only("id")
    )
    recompute_batch(affected)

    transition_mark_to_reaped(mark)
    log.info("reap.inventory", extra={"cluster": cluster.name, **counters})
    return counters


def _write_event_path_workload_snapshots(cluster: Cluster, mark: ImportMark) -> None:
    """For each deployed workload, write a Snapshot iff its image-set
    changed since the previous snapshot for that workload.

    `current_set` is built from observations marked currently_deployed
    by the reaper's flag diff above — stale rows from prior cycles are
    excluded so they don't contaminate the current image set.
    """
    for wl in cluster.workloads.filter(deployed=True).iterator():
        current_set = sorted({
            obs.image.digest
            for obs in wl.image_observations.select_related("image").filter(
                currently_deployed=True,
            )
        })
        # Compare against the most recent snapshot whose digest set is
        # populated. Daily-heartbeat rows (change_kind=none) without
        # an explicit image_digest_set must not break the diff.
        previous = (
            wl.snapshots
            .exclude(image_digest_set=[])
            .order_by("-captured_at")
            .first()
        )
        previous_set = sorted(previous.image_digest_set) if previous else None

        if previous is None:
            change_kind = ImageSetChangeKind.FIRST_SEEN.value
            changed = False
        elif current_set == previous_set:
            continue  # No change — daily heartbeat handles continuity.
        else:
            cur_s = set(current_set)
            prev_s = set(previous_set or [])
            added = cur_s - prev_s
            removed = prev_s - cur_s
            if added and not removed:
                change_kind = ImageSetChangeKind.ADDED.value
            elif removed and not added:
                change_kind = ImageSetChangeKind.REMOVED.value
            elif len(added) == 1 and len(removed) == 1:
                change_kind = ImageSetChangeKind.REPLACED.value
            else:
                change_kind = ImageSetChangeKind.MIXED.value
            changed = True

        Snapshot.objects.create(
            scope_kind=SnapshotScope.WORKLOAD.value,
            cluster=cluster,
            namespace=wl.namespace,
            workload=wl,
            severity_counts=_severity_counts_for_workload(wl),
            priority_counts=_priority_counts_for_workload(wl),
            total_active=wl.findings.count(),
            total_actioned=0,  # FindingAction overlay computed at query time
            import_id=mark.import_id,
            image_digest_set=current_set,
            image_set_changed_from_previous=changed,
            change_kind=change_kind,
        )


def _severity_counts_for_workload(workload) -> dict:
    counts = workload.findings.values_list("severity").order_by()
    out: dict[str, int] = {}
    for (sev,) in counts:
        out[sev] = out.get(sev, 0) + 1
    return out


def _priority_counts_for_workload(workload) -> dict:
    counts = workload.findings.values_list("effective_priority").order_by()
    out: dict[str, int] = {}
    for (band,) in counts:
        out[band] = out.get(band, 0) + 1
    return out


# ── Scan-kind reap (zero-input gate) ------------------------------

def _scope_has_items(cluster: Cluster, kind: str) -> bool:
    """For zero-input no-op gating: is the relevant scope actually
    non-empty in this cluster's inventory?

    Most scan kinds key off "≥ 1 deployed workload"; image-anchored
    kinds key off "≥ 1 deployed image observation".
    """
    if kind in (
        "trivy.VulnerabilityReport",
        "trivy.ExposedSecretReport",
    ):
        return WorkloadImageObservation.objects.filter(
            workload__cluster=cluster,
            workload__deployed=True,
        ).exists()
    return cluster.workloads.filter(deployed=True).exists()


@transaction.atomic
def _reap_scan(mark: ImportMark) -> dict:
    cluster = mark.cluster
    counters: dict = {"observed_count": mark.observed_count or 0}
    if (mark.observed_count or 0) == 0 and _scope_has_items(cluster, mark.kind):
        log.info(
            "reap.skipped_zero_input",
            extra={"cluster": cluster.name, "kind": mark.kind, "import_id": mark.import_id},
        )
        counters["skipped_zero_input"] = True
        # Record coverage gap as ScanInconsistency rows so Scan
        # Health can surface them. One row per (workload, image)
        # currently observed in the inventory.
        if mark.kind in (
            "trivy.VulnerabilityReport",
            "trivy.ExposedSecretReport",
        ):
            _write_scan_inconsistencies_for_outage(cluster, mark)
        transition_mark_to_reaped(mark)
        return counters

    # Source-specific signal clearing — only Kyverno/Trivy signals seen
    # by this kind get cleared. Per the no-canonical-dedup rule, each
    # WorkloadSignal row stands on its own; we flip currently_active to
    # False on rows whose last_seen_at is older than this mark's
    # started_at (i.e. not bumped this cycle) AND whose signal_id was
    # in scope for this kind.
    in_scope_signal_ids = _signal_ids_for_kind(mark.kind)
    if in_scope_signal_ids:
        affected = list(
            WorkloadSignal.objects.filter(
                workload__cluster=cluster,
                signal_id__in=list(in_scope_signal_ids),
                currently_active=True,
                last_seen_at__lt=mark.started_at,
            )
        )
        for sig in affected:
            sig.currently_active = False
        if affected:
            WorkloadSignal.objects.bulk_update(affected, ["currently_active"])
            counters["signals_cleared"] = len(affected)
            # Recompute the affected workloads' findings.
            workload_ids = {s.workload_id for s in affected}
            from core.models import Finding
            findings = list(Finding.objects.filter(workload_id__in=workload_ids))
            recompute_batch(findings)

    transition_mark_to_reaped(mark)
    log.info("reap.scan", extra={"cluster": cluster.name, "kind": mark.kind, **counters})
    return counters


def _write_scan_inconsistencies_for_outage(cluster: Cluster, mark: ImportMark) -> None:
    """One ScanInconsistency row per currently-observed (workload, image)
    pair when a per-image scanner kind reports zero items. Lets Scan
    Health surface a coverage gap for the outage.
    """
    obs_qs = (
        WorkloadImageObservation.objects
        .filter(workload__cluster=cluster, workload__deployed=True)
        .select_related("workload", "image")
    )
    for obs in obs_qs:
        existing = ScanInconsistency.objects.filter(
            cluster=cluster,
            kind=mark.kind,
            workload=obs.workload,
            image_digest=obs.image.digest,
        ).first()
        if existing:
            existing.consecutive_cycles = (existing.consecutive_cycles or 0) + 1
            existing.seen_in_inventory = True
            existing.seen_in_scans = False
            existing.save(update_fields=["consecutive_cycles", "seen_in_inventory", "seen_in_scans", "last_observed_at"])
        else:
            ScanInconsistency.objects.create(
                cluster=cluster,
                kind=mark.kind,
                workload=obs.workload,
                image_digest=obs.image.digest,
                seen_in_inventory=True,
                seen_in_scans=False,
                consecutive_cycles=1,
            )


def _signal_ids_for_kind(kind: str) -> set[str]:
    """Which signal_ids could plausibly be reported by `kind`?"""
    from core.signals import SignalSource
    if kind in ("kyverno.PolicyReport", "kyverno.ClusterPolicyReport"):
        return {sid for sid, sd in SIGNALS.items() if sd.source is SignalSource.KYVERNO}
    if kind == "trivy.ConfigAuditReport":
        return {sid for sid, sd in SIGNALS.items() if sd.source is SignalSource.TRIVY}
    if kind in ("trivy.RbacAssessmentReport", "trivy.ClusterRbacAssessmentReport"):
        return {sid for sid, sd in SIGNALS.items() if sd.source is SignalSource.TRIVY and sid.startswith("ksv:KSV-005")}
    if kind == "trivy.ExposedSecretReport":
        return {"kp:exposed-secret-in-image"}
    return set()


# ── Public dispatch -----------------------------------------------

def maybe_reap(mark: ImportMark) -> dict | None:
    """Call after a worker commits an item. If the queue for this tuple
    is drained AND the mark is in `state='draining'`, fire the appropriate
    reap. Returns the counters dict, or None if nothing fired.
    """
    if mark.state != ImportMarkState.DRAINING.value:
        return None
    if not drain_check(
        cluster_name=mark.cluster.name,
        kind=mark.kind,
        import_id=mark.import_id,
    ):
        return None
    if mark.kind == "inventory":
        return _reap_inventory(mark)
    return _reap_scan(mark)


def reap_all_drainable() -> int:
    """Safety-net entry point. Sweep every `state=draining` mark whose
    queue is drained and fire its reap. Returns count of marks reaped.
    """
    fired = 0
    qs = ImportMark.objects.filter(state=ImportMarkState.DRAINING.value).select_related("cluster")
    for mark in qs:
        if not drain_check(
            cluster_name=mark.cluster.name,
            kind=mark.kind,
            import_id=mark.import_id,
        ):
            continue
        try:
            if mark.kind == "inventory":
                _reap_inventory(mark)
            else:
                _reap_scan(mark)
            fired += 1
        except Exception:  # pragma: no cover
            log.exception("reap_all_drainable failed for mark id=%s", mark.id)
    return fired
