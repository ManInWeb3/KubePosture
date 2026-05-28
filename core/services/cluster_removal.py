"""Complete removal of a cluster and every row tied to it.

`Cluster.delete()` already cascades to all FK-linked children — every
foreign key pointing at Cluster, or at one of its children, is
`on_delete=CASCADE`: Namespace, Workload, Finding, ImportMark, Snapshot,
WorkloadAlias, ScanInconsistency, and transitively FindingAction,
WorkloadSignal, WorkloadImageObservation. The one gap is `IngestQueue`:
it references the cluster by the *string* `cluster_name`, not an FK
(see ingest_queue.py), so cascade can't reach it and its rows would be
orphaned. This module deletes those explicitly, then drops the cluster,
in one transaction.

Intentionally NOT deleted — global / shared / append-only data that
isn't owned by any single cluster:
  Image, IngestToken, EpssScore, KevEntry, SbomComponent, SupplyChainIoc.
An `Image` (and its SbomComponents) may be observed in other clusters;
the daily `prune_stale_data` job reclaims images that fall out of use
everywhere (see pruning.py).
"""
from __future__ import annotations

from dataclasses import dataclass, field

from django.db import transaction
from django.db.models import Q

from core.models import (
    Cluster,
    FindingAction,
    IngestQueue,
    Snapshot,
    WorkloadImageObservation,
    WorkloadSignal,
)


@dataclass(frozen=True)
class ClusterRemovalResult:
    cluster_name: str
    dry_run: bool
    deleted: dict[str, int] = field(default_factory=dict)

    @property
    def total(self) -> int:
        return sum(self.deleted.values())


def _dry_run_counts(cluster: Cluster) -> dict[str, int]:
    """Best-effort per-table counts of what a real removal would delete.

    Mirrors the cascade graph with explicit scoped queries. The real
    path instead reports the authoritative dict that `Cluster.delete()`
    returns, so a future FK to Cluster is still deleted even if it is
    missing from this preview. The cluster row itself is not counted
    here — callers note it separately.
    """
    counts = {
        "core.Namespace": cluster.namespaces.count(),
        "core.Workload": cluster.workloads.count(),
        "core.Finding": cluster.findings.count(),
        "core.FindingAction": FindingAction.objects.filter(
            finding__cluster=cluster).count(),
        "core.ImportMark": cluster.import_marks.count(),
        "core.WorkloadAlias": cluster.workload_aliases.count(),
        "core.ScanInconsistency": cluster.scan_inconsistencies.count(),
        "core.WorkloadImageObservation": WorkloadImageObservation.objects.filter(
            workload__cluster=cluster).count(),
        "core.WorkloadSignal": WorkloadSignal.objects.filter(
            workload__cluster=cluster).count(),
        # Snapshot.cluster is nullable; namespace/workload-scoped rows may
        # carry a null cluster FK but still belong to this cluster's tree.
        "core.Snapshot": Snapshot.objects.filter(
            Q(cluster=cluster)
            | Q(namespace__cluster=cluster)
            | Q(workload__cluster=cluster)
        ).distinct().count(),
        "core.IngestQueue": IngestQueue.objects.filter(
            cluster_name=cluster.name).count(),
    }
    return {label: n for label, n in counts.items() if n}


def remove_cluster(cluster: Cluster, *, dry_run: bool = False) -> ClusterRemovalResult:
    """Delete `cluster` and every row tied to it.

    When `dry_run` is True nothing is written; the result carries the
    counts a real run would delete. The real path reports the dict
    `Cluster.delete()` returns (which includes the cluster row itself)
    plus the IngestQueue rows that cascade can't reach.
    """
    name = cluster.name

    if dry_run:
        return ClusterRemovalResult(name, dry_run=True, deleted=_dry_run_counts(cluster))

    with transaction.atomic():
        # IngestQueue has no FK to Cluster — cascade can't reach it.
        queue_deleted = IngestQueue.objects.filter(cluster_name=name).delete()[0]
        # Cascades the entire FK-linked subtree, including the cluster row.
        _total, per_model = cluster.delete()

    deleted = {label: n for label, n in per_model.items() if n}
    if queue_deleted:
        deleted["core.IngestQueue"] = queue_deleted
    return ClusterRemovalResult(name, dry_run=False, deleted=deleted)
