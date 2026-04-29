"""Snapshot capture — daily heartbeat path.

Workload-scope *event* snapshots are written by the inventory reap on
image-set change; the daily heartbeat covers continuity for all scopes.
"""
from __future__ import annotations

from collections import defaultdict

from django.db import transaction
from django.db.models import Count

from core.constants import ImageSetChangeKind, SnapshotScope
from core.models import Cluster, Finding, Namespace, Snapshot, Workload


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


@transaction.atomic
def capture_daily_heartbeat() -> int:
    """Write today's heartbeat snapshots. Returns row count written."""
    written = 0
    all_findings = Finding.objects.all()
    Snapshot.objects.create(
        scope_kind=SnapshotScope.GLOBAL.value,
        severity_counts=_severity_counts(all_findings),
        priority_counts=_priority_counts(all_findings),
        total_active=all_findings.count(),
        total_actioned=0,
        change_kind=ImageSetChangeKind.NONE.value,
    )
    written += 1

    for cluster in Cluster.objects.all():
        cf = all_findings.filter(cluster=cluster)
        Snapshot.objects.create(
            scope_kind=SnapshotScope.CLUSTER.value,
            cluster=cluster,
            severity_counts=_severity_counts(cf),
            priority_counts=_priority_counts(cf),
            total_active=cf.count(),
            total_actioned=0,
            change_kind=ImageSetChangeKind.NONE.value,
        )
        written += 1

    for ns in Namespace.objects.filter(active=True):
        nf = all_findings.filter(workload__namespace=ns)
        Snapshot.objects.create(
            scope_kind=SnapshotScope.NAMESPACE.value,
            cluster=ns.cluster,
            namespace=ns,
            severity_counts=_severity_counts(nf),
            priority_counts=_priority_counts(nf),
            total_active=nf.count(),
            total_actioned=0,
            change_kind=ImageSetChangeKind.NONE.value,
        )
        written += 1

    for wl in Workload.objects.filter(deployed=True).select_related("cluster", "namespace"):
        wf = all_findings.filter(workload=wl)
        Snapshot.objects.create(
            scope_kind=SnapshotScope.WORKLOAD.value,
            cluster=wl.cluster,
            namespace=wl.namespace,
            workload=wl,
            severity_counts=_severity_counts(wf),
            priority_counts=_priority_counts(wf),
            total_active=wf.count(),
            total_actioned=0,
            change_kind=ImageSetChangeKind.NONE.value,
        )
        written += 1

    return written
