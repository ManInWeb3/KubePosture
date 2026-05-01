"""Snapshot capture — daily heartbeat path.

Workload-scope *event* snapshots are written by the inventory reap on
image-set change; the daily heartbeat covers continuity for all scopes.
"""
from __future__ import annotations

from collections import defaultdict

from django.db import transaction
from django.db.models import Count

from core.constants import ImageSetChangeKind, SnapshotScope
from core.models import Cluster, Namespace, Snapshot, Workload
from core.services.inventory import (
    default_finding_qs,
    restrict_to_currently_deployed_images,
)


def _severity_counts(qs) -> dict:
    out = defaultdict(int)
    for sev, n in qs.values_list("severity").annotate(n=Count("id")):
        out[sev] = n
    return dict(out)


def _priority_counts(qs) -> dict:
    out = defaultdict(int)
    for band, n in qs.values_list("effective_priority").annotate(n=Count("id")):
        out[band] = n
    return dict(out)


def capture_cluster_snapshot(cluster: Cluster) -> Snapshot:
    """Write one cluster-scope Snapshot row from current finding state.

    Used by the daily heartbeat and by admin cluster-save (pre/post
    around a priority recompute) to bracket flag transitions on the
    trend.
    """
    cf = default_finding_qs(cluster=cluster)
    return Snapshot.objects.create(
        scope_kind=SnapshotScope.CLUSTER.value,
        cluster=cluster,
        severity_counts=_severity_counts(cf),
        priority_counts=_priority_counts(cf),
        total_active=cf.count(),
        change_kind=ImageSetChangeKind.NONE.value,
    )


def capture_namespace_snapshot(namespace: Namespace) -> Snapshot:
    """Write one namespace-scope Snapshot row from current finding state.

    Used by the daily heartbeat and by exposure / sensitivity flip
    handlers (pre/post around a priority recompute) to bracket flag
    transitions on the trend.
    """
    nf = default_finding_qs(cluster=namespace.cluster).filter(
        workload__namespace=namespace,
    )
    return Snapshot.objects.create(
        scope_kind=SnapshotScope.NAMESPACE.value,
        cluster=namespace.cluster,
        namespace=namespace,
        severity_counts=_severity_counts(nf),
        priority_counts=_priority_counts(nf),
        total_active=nf.count(),
        change_kind=ImageSetChangeKind.NONE.value,
    )


@transaction.atomic
def capture_cluster_heartbeat(cluster: Cluster) -> int:
    """Write a heartbeat snapshot covering one cluster: cluster row +
    one row per active namespace in the cluster + one row per deployed
    workload in the cluster.

    Used at the end of an import session (last drainable mark for the
    cluster) to refresh trend datapoints with the post-reap state.
    Skips the global row — that's the daily heartbeat's job.
    """
    written = 0
    capture_cluster_snapshot(cluster)
    written += 1
    for ns in Namespace.objects.filter(cluster=cluster, active=True):
        capture_namespace_snapshot(ns)
        written += 1
    for wl in Workload.objects.filter(
        cluster=cluster, deployed=True,
    ).select_related("namespace"):
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
            change_kind=ImageSetChangeKind.NONE.value,
        )
        written += 1
    return written


@transaction.atomic
def capture_daily_heartbeat() -> int:
    """Write today's heartbeat snapshots. Returns row count written."""
    written = 0
    all_findings = default_finding_qs()
    Snapshot.objects.create(
        scope_kind=SnapshotScope.GLOBAL.value,
        severity_counts=_severity_counts(all_findings),
        priority_counts=_priority_counts(all_findings),
        total_active=all_findings.count(),
        change_kind=ImageSetChangeKind.NONE.value,
    )
    written += 1

    for cluster in Cluster.objects.all():
        capture_cluster_snapshot(cluster)
        written += 1

    for ns in Namespace.objects.filter(active=True):
        capture_namespace_snapshot(ns)
        written += 1

    for wl in Workload.objects.filter(deployed=True).select_related("cluster", "namespace"):
        wf = restrict_to_currently_deployed_images(
            default_finding_qs(cluster=wl.cluster).filter(workload=wl)
        )
        Snapshot.objects.create(
            scope_kind=SnapshotScope.WORKLOAD.value,
            cluster=wl.cluster,
            namespace=wl.namespace,
            workload=wl,
            severity_counts=_severity_counts(wf),
            priority_counts=_priority_counts(wf),
            total_active=wf.count(),
            change_kind=ImageSetChangeKind.NONE.value,
        )
        written += 1

    return written
