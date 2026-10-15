"""Snapshot capture — daily heartbeat path.

Workload-scope *event* snapshots are written by the inventory reap on
image-set change (`core.services.reaper`), using the grouped-count
helpers here; the daily heartbeat covers continuity for all scopes.

Every writer here is set-based: one GROUP BY query per counted
dimension for ALL targets of a scope, then one `bulk_create`. Query
cost is therefore flat in the number of clusters / namespaces /
workloads (pinned by core/tests/test_reaper_snapshots.py).
"""
from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable

from django.db import transaction
from django.db.models import Count

from core.constants import ImageSetChangeKind, SnapshotScope
from core.models import Cluster, Finding, Namespace, Snapshot, Workload
from core.services.inventory import (
    default_finding_qs,
    restrict_to_currently_deployed_images,
)
from core.urgency import finding_ids, recompute_ids


def grouped_counts(qs, key: str) -> tuple[dict, dict]:
    """`(severity_counts_by_key, priority_counts_by_key)` for the findings
    in `qs`, in two GROUP BY queries. `key` is the column the targets are
    keyed on (`cluster_id`, `workload__namespace_id`, `workload_id`);
    rows whose key is NULL (cluster-scoped findings under a workload key)
    are dropped. Targets with no findings are simply absent."""
    severity: dict = defaultdict(dict)
    for k, sev, n in qs.values_list(key, "severity").annotate(n=Count("id")):
        if k is not None:
            severity[k][sev] = n
    priority: dict = defaultdict(dict)
    for k, band, n in qs.values_list(key, "effective_priority").annotate(n=Count("id")):
        if k is not None:
            priority[k][band] = n
    return severity, priority


def snapshot_row(scope_kind: str, *, severity_counts: dict, priority_counts: dict, **fields) -> Snapshot:
    """An unsaved Snapshot. `total_active` is the sum of the severity
    tally — every finding has exactly one severity, so it equals the
    count of the same queryset without a third query."""
    return Snapshot(
        scope_kind=scope_kind,
        severity_counts=severity_counts,
        priority_counts=priority_counts,
        total_active=sum(severity_counts.values()),
        **fields,
    )


def _merged(by_key: dict) -> dict:
    out: dict = defaultdict(int)
    for counts in by_key.values():
        for k, n in counts.items():
            out[k] += n
    return dict(out)


def _cluster_rows(clusters: Iterable[Cluster], severity: dict, priority: dict) -> list[Snapshot]:
    return [
        snapshot_row(
            SnapshotScope.CLUSTER.value, cluster=c,
            severity_counts=severity.get(c.id, {}), priority_counts=priority.get(c.id, {}),
            change_kind=ImageSetChangeKind.NONE.value,
        )
        for c in clusters
    ]


def _namespace_rows(namespaces: Iterable[Namespace], *, findings) -> list[Snapshot]:
    severity, priority = grouped_counts(findings, "workload__namespace_id")
    return [
        snapshot_row(
            SnapshotScope.NAMESPACE.value, cluster_id=ns.cluster_id, namespace=ns,
            severity_counts=severity.get(ns.id, {}), priority_counts=priority.get(ns.id, {}),
            change_kind=ImageSetChangeKind.NONE.value,
        )
        for ns in namespaces
    ]


def _workload_heartbeat_rows(workloads: Iterable[Workload], *, findings) -> list[Snapshot]:
    """Continuity rows for deployed workloads, counting findings on their
    currently-deployed images (plus image-less rows) — the same scope the
    reap's event path and the workload-detail page use."""
    severity, priority = grouped_counts(restrict_to_currently_deployed_images(findings), "workload_id")
    return [
        snapshot_row(
            SnapshotScope.WORKLOAD.value, cluster_id=w.cluster_id, namespace_id=w.namespace_id, workload=w,
            severity_counts=severity.get(w.id, {}), priority_counts=priority.get(w.id, {}),
            change_kind=ImageSetChangeKind.NONE.value,
        )
        for w in workloads
    ]


def capture_cluster_snapshot(cluster: Cluster) -> Snapshot:
    """Write one cluster-scope Snapshot row from current finding state.

    Used by the daily heartbeat and by admin cluster-save (pre/post
    around a priority recompute) to bracket flag transitions on the
    trend.
    """
    [row] = _cluster_rows([cluster], *grouped_counts(default_finding_qs(cluster=cluster), "cluster_id"))
    row.save()
    return row


def capture_namespace_snapshot(namespace: Namespace) -> Snapshot:
    """Write one namespace-scope Snapshot row from current finding state.

    Used by the daily heartbeat and by exposure / sensitivity flip
    handlers (pre/post around a priority recompute) to bracket flag
    transitions on the trend.
    """
    [row] = _namespace_rows(
        [namespace],
        findings=default_finding_qs(cluster=namespace.cluster).filter(workload__namespace=namespace),
    )
    row.save()
    return row


@transaction.atomic
def bracketed_recompute(cluster: Cluster, mutate, *, namespace: Namespace | None = None) -> int:
    """Run `mutate()` (a cluster / namespace flag edit) between pre and post
    Snapshot rows around a whole-cluster priority recompute, so the trend
    charts show a clean before/after step at the moment of the edit
    instead of waiting for the next daily heartbeat. Shared by the admin
    `save_model` hooks and the UI edit views. Returns the number of
    findings whose band changed.
    """
    capture_cluster_snapshot(cluster)
    if namespace is not None:
        capture_namespace_snapshot(namespace)
    mutate()
    _scanned, updated = recompute_ids(finding_ids(Finding.objects.filter(cluster=cluster)))
    capture_cluster_snapshot(cluster)
    if namespace is not None:
        capture_namespace_snapshot(namespace)
    return updated


@transaction.atomic
def capture_cluster_heartbeat(cluster: Cluster) -> int:
    """Write a heartbeat snapshot covering one cluster: cluster row +
    one row per active namespace in the cluster.

    Used at the end of an import session (last drainable mark for the
    cluster) to refresh trend datapoints with the post-reap state.
    Workload-scope rows are NOT written here — those are owned by the
    inventory reap's event path (`first_seen`/`replaced`/...) and by
    the daily heartbeat (`none` continuity rows). Skips the global row
    — that's the daily heartbeat's job.
    """
    findings = default_finding_qs(cluster=cluster)
    rows = _cluster_rows([cluster], *grouped_counts(findings, "cluster_id"))
    rows += _namespace_rows(Namespace.objects.filter(cluster=cluster, active=True), findings=findings)
    Snapshot.objects.bulk_create(rows)
    return len(rows)


@transaction.atomic
def capture_daily_heartbeat() -> int:
    """Write today's heartbeat snapshots — one global, one per cluster,
    one per active namespace, one per deployed workload, in that order.
    Returns row count written."""
    findings = default_finding_qs()
    # Every finding belongs to exactly one cluster, so the global tally
    # is the per-cluster tally summed — no separate fleet-wide query.
    by_cluster_severity, by_cluster_priority = grouped_counts(findings, "cluster_id")
    rows = [
        snapshot_row(
            SnapshotScope.GLOBAL.value,
            severity_counts=_merged(by_cluster_severity), priority_counts=_merged(by_cluster_priority),
            change_kind=ImageSetChangeKind.NONE.value,
        ),
    ]
    rows += _cluster_rows(Cluster.objects.all(), by_cluster_severity, by_cluster_priority)
    rows += _namespace_rows(Namespace.objects.filter(active=True), findings=findings)
    rows += _workload_heartbeat_rows(Workload.objects.filter(deployed=True), findings=findings)
    Snapshot.objects.bulk_create(rows)
    return len(rows)
