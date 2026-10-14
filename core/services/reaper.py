"""Reaper — kind-dispatched wrap-up after a `(cluster, kind, import_id)`
queue drains, plus the two ways an import is *discarded* instead.

**Claim first.** Both reaps begin with `transition_mark_to_reaped` and
return `None` when they lose that conditional UPDATE — two workers
seeing the same drained tuple (or a worker racing the safety net) can
never both run a reap body. Everything after the claim runs in the same
transaction, so a failing body rolls the claim back and the mark stays
`draining` for the next sweep.

**Rows go at reap.** Nothing reads `IngestQueue.raw_json` after an item
is `done`. Once the reap has recorded `failed_count` / `last_error` on
the mark, the tuple's rows are deleted (`failed` ones too, unless
settings.IMPORT_KEEP_FAILED_PAYLOADS says to keep them for debugging).
The queue only ever holds in-flight work.

**Discard, don't promote.** The importer sends a full snapshot every
cycle, so a cycle that didn't land whole is worth nothing — processing
part of it would look like "these workloads/findings disappeared".
`discard_import` deletes an import's rows and moves its marks to
`reaped` with a `discard_reason`, never touching
`last_complete_inventory_at`. It is used for marks stuck `open` (the
importer never committed) and for imports whose inventory payload
failed (the inventory gate would otherwise hold every scan row of that
import forever).
"""
from __future__ import annotations

import logging
from datetime import timedelta

from django.conf import settings
from django.db import transaction
from django.db.models import Q
from django.utils import timezone

from core.constants import (
    WORKLOAD_OBSERVATION_RETENTION_DAYS,
    ImageSetChangeKind,
    ImportDiscardReason,
    ImportMarkState,
    IngestQueueStatus,
    SnapshotScope,
)
from core.models import (
    Cluster,
    ImportMark,
    IngestQueue,
    ScanInconsistency,
    Snapshot,
    WorkloadImageObservation,
    WorkloadSignal,
)
from core.parsers.inventory import reap_inventory_diff
from core.services.inventory import (
    default_finding_qs,
    restrict_to_currently_deployed_images,
)
from core.services.queue import (
    delete_import_rows,
    delete_tuple_rows,
    drain_check,
    failure_summary,
    transition_mark_to_reaped,
)
from core.services.snapshot import (
    _priority_counts,
    _severity_counts,
    capture_cluster_heartbeat,
)
from core.signals import SIGNALS
from core.urgency import recompute_batch

log = logging.getLogger("core.reaper")


def _keep_failed() -> bool:
    return bool(getattr(settings, "IMPORT_KEEP_FAILED_PAYLOADS", False))


# ── Claim / release ------------------------------------------------

def _claim_reap(mark: ImportMark) -> bool:
    """Win the `draining → reaped` flip or return False. On success the
    in-memory mark mirrors the DB and carries the tuple's failure facts
    so the body can consult them (e.g. `_reap_scan`'s partial-failure
    branch) before the rows are gone."""
    if not transition_mark_to_reaped(mark):
        return False
    mark.state = ImportMarkState.REAPED.value
    mark.failed_count, mark.last_error = failure_summary(
        cluster_name=mark.cluster.name, kind=mark.kind, import_id=mark.import_id,
    )
    return True


def _release_reap(mark: ImportMark, counters: dict) -> dict:
    counters["failed_count"] = mark.failed_count
    counters["queue_rows_deleted"] = delete_tuple_rows(
        cluster_name=mark.cluster.name, kind=mark.kind, import_id=mark.import_id,
        keep_failed=_keep_failed(),
    )
    mark.save(update_fields=["failed_count", "last_error"])
    return counters


# ── Inventory reap ------------------------------------------------

@transaction.atomic
def _reap_inventory(mark: ImportMark) -> dict | None:
    if not _claim_reap(mark):
        return None
    return _release_reap(mark, _reap_inventory_body(mark))


def _reap_inventory_body(mark: ImportMark) -> dict:
    cluster = mark.cluster
    # Did any payload this cycle carry complete_snapshot=true? Read
    # before `_release_reap` deletes the rows.
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
        return counters

    # Monotonic guard: a mark can reap late — e.g. its queue drained
    # slowly, or one of its items was reclaimed after a worker was
    # killed mid-item (see core.services.queue) — and reap for a NEWER
    # import_id of the same cluster may have already run by then.
    # Applying this (older) cycle's diff now would use a stale cutoff:
    # reap_inventory_diff would resurrect workloads/observations the
    # newer cycle already correctly retired, and last_complete_inventory_at
    # would roll backward. Only ever advance on a strictly newer cycle.
    if (
        cluster.last_complete_inventory_at is not None
        and mark.started_at <= cluster.last_complete_inventory_at
    ):
        counters["superseded"] = True
        log.warning(
            "reap.inventory.superseded",
            extra={
                "cluster": cluster.name,
                "import_id": mark.import_id,
                "mark_started_at": mark.started_at.isoformat(),
                "cluster_last_complete_inventory_at":
                    cluster.last_complete_inventory_at.isoformat(),
            },
        )
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
    # bumped this cycle AND owning workload deployed → currently_deployed=True;
    # the rest → False. The workload-deployed clause keeps a scaled-to-zero
    # workload's declared image (still bumped this cycle) from showing as
    # running. reap_inventory_diff above already set Workload.deployed, so
    # the join here reads the finalized value. Source of truth for the
    # workload-detail Images table.
    obs_qs = WorkloadImageObservation.objects.filter(workload__cluster=cluster)
    obs_deployed = obs_qs.filter(
        last_seen_at__gte=mark.started_at, workload__deployed=True,
    ).update(
        currently_deployed=True,
    )
    obs_undeployed = obs_qs.exclude(
        Q(last_seen_at__gte=mark.started_at) & Q(workload__deployed=True)
    ).update(
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

        # Scope to findings on currently-deployed images (or image-less
        # workload-level findings). Without this, the snapshot captures
        # findings tied to the just-rolled-out image — Trivy can hold a
        # stale VulnerabilityReport CRD past Pod deletion, and the
        # ingest path bumps `last_seen` past `last_complete_inventory_at`,
        # so `default_finding_qs` alone wouldn't filter them out.
        wf = restrict_to_currently_deployed_images(
            default_finding_qs(cluster=cluster).filter(workload=wl)
        )
        Snapshot.objects.create(
            scope_kind=SnapshotScope.WORKLOAD.value,
            cluster=cluster,
            namespace=wl.namespace,
            workload=wl,
            severity_counts=_severity_counts(wf),
            priority_counts=_priority_counts(wf),
            total_active=wf.count(),
            import_id=mark.import_id,
            image_digest_set=current_set,
            image_set_changed_from_previous=changed,
            change_kind=change_kind,
        )


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
def _reap_scan(mark: ImportMark) -> dict | None:
    if not _claim_reap(mark):
        return None
    return _release_reap(mark, _reap_scan_body(mark))


def _reap_scan_body(mark: ImportMark) -> dict:
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
        return counters

    # Some of this kind's payloads failed to process, so their signals
    # were never bumped this cycle. Clearing "everything not bumped"
    # would silently retire real findings; keep them instead (the
    # project errs toward not hiding) and leave the failure visible on
    # the mark (failed_count / last_error).
    if mark.failed_count:
        log.warning(
            "reap.scan.partial_failure",
            extra={
                "cluster": cluster.name, "kind": mark.kind, "import_id": mark.import_id,
                "failed_count": mark.failed_count, "last_error": mark.last_error[:200],
            },
        )
        counters["skipped_partial_failure"] = True
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
    """Which signal_ids could plausibly be reported by `kind`?

    Scope must be a strict partition across sibling Trivy report kinds:
    a signal only ever bumped by kind A must never be in kind B's set,
    or a healthy reap of B can incorrectly clear a signal that A's own
    (possibly currently outage-affected) mark should exclusively own —
    bypassing A's zero-input protection as a side effect.

    RBAC checks are identified by `SignalCategory.RBAC_ELEVATION`
    (all four are: KSV-0041/0044/0051/0053) rather than an AVD-id
    prefix — the previous `startswith("ksv:KSV-005")` heuristic missed
    KSV-0041/KSV-0044, which ConfigAuditReport's (much broader) TRIVY-wide
    set then incorrectly swept up as its own.

    Kyverno's PolicyReport vs ClusterPolicyReport aren't split: every
    `kyverno:*` signal currently defined targets Pod-level policies,
    which only ever surface via the namespaced PolicyReport CRD in
    practice — there's no live case where a cluster-scoped policy result
    could be misattributed. If a cluster-scoped-resource Kyverno policy
    is ever added to the registry, this will need its own discriminator
    (SignalDef has none today) to keep the two kinds' clearing scopes
    correctly separated the same way RBAC/ConfigAudit now are.
    """
    from core.signals import SignalCategory, SignalSource
    if kind in ("kyverno.PolicyReport", "kyverno.ClusterPolicyReport"):
        return {sid for sid, sd in SIGNALS.items() if sd.source is SignalSource.KYVERNO}
    if kind == "trivy.ConfigAuditReport":
        return {
            sid for sid, sd in SIGNALS.items()
            if sd.source is SignalSource.TRIVY
            and sd.category is not SignalCategory.RBAC_ELEVATION
        }
    if kind in ("trivy.RbacAssessmentReport", "trivy.ClusterRbacAssessmentReport"):
        return {
            sid for sid, sd in SIGNALS.items()
            if sd.source is SignalSource.TRIVY
            and sd.category is SignalCategory.RBAC_ELEVATION
        }
    if kind == "trivy.ExposedSecretReport":
        return {"kp:exposed-secret-in-image"}
    return set()


# ── Discard -------------------------------------------------------

# TTL for an `open` ImportMark before it's presumed abandoned (importer
# crashed / was killed before `/imports/<id>/commit/`) and the whole
# import is discarded. Deliberately larger than api.views'
# IMPORT_LOCK_TIMEOUT (2700s — a read-only gate on starting a NEW cycle,
# never mutates a row) — this performs an actual state mutation, which
# is less reversible. It's also comfortably past the importer Job's own
# activeDeadlineSeconds (1800s, deploy/charts/kubeposture-import/
# values.yaml) — by the time this fires, Kubernetes has already
# SIGKILLed the importer, so "still alive but slow" isn't possible.
STUCK_OPEN_TIMEOUT_SECONDS = 3600


@transaction.atomic
def discard_import(
    *,
    cluster: Cluster,
    import_id: str,
    reason: str,
    from_states: tuple[str, ...],
) -> dict:
    """Move every mark of the import currently in `from_states` to
    `reaped` with `discard_reason=reason`, record each tuple's failure
    facts, and delete the import's queue rows. Never advances the
    cluster anchor, never runs a diff, never captures a heartbeat —
    the cycle simply never happened, except for the audit row."""
    marks = list(
        ImportMark.objects.select_for_update().filter(
            cluster=cluster, import_id=import_id, state__in=list(from_states),
        )
    )
    if not marks:
        return {"marks": 0, "rows": 0}
    now = timezone.now()
    for m in marks:
        m.failed_count, m.last_error = failure_summary(
            cluster_name=cluster.name, kind=m.kind, import_id=import_id,
        )
        m.state = ImportMarkState.REAPED.value
        m.discard_reason = reason
        m.completed_at = now
    rows = delete_import_rows(
        cluster_name=cluster.name, import_id=import_id, keep_failed=_keep_failed(),
    )
    ImportMark.objects.bulk_update(
        marks, ["state", "discard_reason", "completed_at", "failed_count", "last_error"],
    )
    log.warning(
        "import.discarded",
        extra={
            "cluster": cluster.name, "import_id": import_id, "reason": reason,
            "marks": len(marks), "rows": rows,
        },
    )
    return {"marks": len(marks), "rows": rows}


def reap_stuck_open() -> int:
    """Safety net for imports the importer never committed: every mark
    still `open` past STUCK_OPEN_TIMEOUT_SECONDS belongs to an import
    that was uploaded (fully or partly) and then abandoned. Discard it
    — a partial snapshot must never be processed. Returns the number of
    marks discarded.

    A commit landing concurrently is safe: `discard_import` re-filters
    on `state=open` under a row lock, and committed marks are
    `draining`, so they are left alone.
    """
    cutoff = timezone.now() - timedelta(seconds=STUCK_OPEN_TIMEOUT_SECONDS)
    stuck = (
        ImportMark.objects
        .filter(state=ImportMarkState.OPEN.value, started_at__lt=cutoff)
        .values_list("cluster_id", "import_id")
        .distinct()
    )
    discarded = 0
    for cluster_id, import_id in list(stuck):
        cluster = Cluster.objects.filter(pk=cluster_id).first()
        if cluster is None:
            continue
        result = discard_import(
            cluster=cluster, import_id=import_id,
            reason=ImportDiscardReason.STUCK_OPEN.value,
            from_states=(ImportMarkState.OPEN.value,),
        )
        discarded += result["marks"]
    return discarded


def discard_import_for_failed_inventory(*, cluster_name: str, import_id: str) -> dict:
    """The worker calls this the moment an inventory item fails. The
    inventory gate holds every other row of the import behind that
    failure forever; the import is unusable as a whole, so discard it.
    `last_error` on the inventory mark carries the exception."""
    cluster = Cluster.objects.filter(name=cluster_name).first()
    if cluster is None:
        return {"marks": 0, "rows": 0}
    return discard_import(
        cluster=cluster, import_id=import_id,
        reason=ImportDiscardReason.INVENTORY_FAILED.value,
        from_states=(ImportMarkState.DRAINING.value,),
    )


def discard_inventory_failed_imports() -> int:
    """Safety-net sweep for inventory rows that reached `failed` without
    passing through the worker's failure path — `claim_batch`'s
    abandon-exhausted SQL flips rows straight to `failed`. Returns the
    number of marks discarded."""
    pairs = (
        IngestQueue.objects
        .filter(kind="inventory", status=IngestQueueStatus.FAILED.value)
        .values_list("cluster_name", "import_id")
        .distinct()
    )
    discarded = 0
    for cluster_name, import_id in list(pairs):
        result = discard_import_for_failed_inventory(
            cluster_name=cluster_name, import_id=import_id,
        )
        discarded += result["marks"]
    return discarded


# ── Public dispatch -----------------------------------------------

def maybe_reap(mark: ImportMark) -> dict | None:
    """Call after a worker commits an item. If the queue for this tuple
    is drained AND the mark is in `state='draining'`, fire the appropriate
    reap. Returns the counters dict, or None if nothing fired (including
    losing the claim to a concurrent reaper).
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
        result = _reap_inventory(mark)
    else:
        result = _reap_scan(mark)
    if result is None:
        return None
    _maybe_capture_heartbeat(mark.cluster)
    return result


def reap_all_drainable() -> int:
    """Safety-net entry point. Sweep every `state=draining` mark whose
    queue is drained and fire its reap. Returns count of marks reaped.
    """
    fired = 0
    touched_clusters: set[int] = set()
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
                result = _reap_inventory(mark)
            else:
                result = _reap_scan(mark)
            if result is None:
                continue
            fired += 1
            touched_clusters.add(mark.cluster_id)
        except Exception:  # pragma: no cover
            log.exception("reap_all_drainable failed for mark id=%s", mark.id)
    # Run the heartbeat once per touched cluster, after all of its
    # marks have settled — avoids re-capturing per-kind in the sweep.
    for cluster in Cluster.objects.filter(pk__in=touched_clusters):
        _maybe_capture_heartbeat(cluster)
    return fired


def _maybe_capture_heartbeat(cluster: Cluster) -> None:
    """If `cluster` has no remaining `draining` marks, capture a
    cluster-scope heartbeat to refresh trend datapoints with the
    post-reap state. No-op while other kinds are still draining for
    the same import session.
    """
    remaining = ImportMark.objects.filter(
        cluster=cluster,
        state=ImportMarkState.DRAINING.value,
    ).count()
    if remaining:
        return
    try:
        n = capture_cluster_heartbeat(cluster)
        log.info(
            "reap.heartbeat",
            extra={"cluster": cluster.name, "rows": n},
        )
    except Exception:  # pragma: no cover
        log.exception(
            "reap.heartbeat failed for cluster=%s", cluster.name,
        )
