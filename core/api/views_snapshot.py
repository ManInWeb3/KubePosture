"""Time-series snapshot endpoint for trend charts.

Powers the workload-detail trend block (per
Architecture/dev_docs/08-ui.md §Workload detail) and the
global/per-cluster trend block on the workloads list.

URL surface (mounted at /api/v1/):
    /snapshots/series/?scope=...&...
"""
from __future__ import annotations

from datetime import timedelta

from django.conf import settings
from django.utils import timezone
from rest_framework.exceptions import ValidationError
from rest_framework.response import Response
from rest_framework.views import APIView

from core.constants import (
    ImageSetChangeKind,
    PriorityBand,
    Severity,
    SnapshotScope,
)
from core.models import Cluster, Namespace, Snapshot, Workload


_SEVERITY_KEYS = [s.value for s in Severity]
_PRIORITY_KEYS = [p.value for p in PriorityBand]


def _series_lists(rows, key_set, source_attr):
    """Build {key: [n0, n1, …]} aligned to rows order.

    `rows` is a list of Snapshot instances ordered by captured_at asc;
    `source_attr` is "severity_counts" or "priority_counts".
    Missing keys default to 0 so series have uniform length.
    """
    out = {k: [] for k in key_set}
    for row in rows:
        bag = getattr(row, source_attr) or {}
        for k in key_set:
            out[k].append(int(bag.get(k, 0)))
    return out


def _digest_set_diff(prev: list[str] | None, curr: list[str]) -> dict:
    if not prev:
        return {"added": list(curr), "removed": []}
    p, c = set(prev), set(curr)
    return {"added": sorted(c - p), "removed": sorted(p - c)}


class SnapshotSeriesView(APIView):
    """Return chart-ready time series for a Snapshot scope.

    Query params:
        scope     — global | cluster | namespace | workload   (required)
        cluster   — name (required for cluster / namespace / workload scope)
        namespace — name (required for namespace scope)
        workload_id — pk  (required for workload scope)
        days      — lookback window, default 90, capped at SNAPSHOT_RETENTION_DAYS
        mode      — all | image_changes_only  (workload scope only;
                    default all)

    Response shape:
        {
          "scope_kind": "...",
          "captured_at": ["...", ...],
          "totals":   [N, ...],
          "severity": {critical: [...], high: [...], ...},
          "priority": {immediate: [...], out_of_cycle: [...], ...},
          "events":   [{captured_at, import_id, change_kind, added, removed}]
        }
    """

    def get(self, request):
        scope = request.query_params.get("scope")
        if scope not in SnapshotScope.values:
            raise ValidationError(
                f"scope must be one of {SnapshotScope.values}"
            )

        days = int(request.query_params.get("days") or 90)
        days = max(1, min(days, settings.SNAPSHOT_RETENTION_DAYS))
        cutoff = timezone.now() - timedelta(days=days)

        qs = Snapshot.objects.filter(scope_kind=scope, captured_at__gte=cutoff)

        if scope == SnapshotScope.CLUSTER:
            cluster_name = request.query_params.get("cluster")
            if not cluster_name:
                raise ValidationError("cluster scope requires ?cluster=<name>")
            cluster = Cluster.objects.filter(name=cluster_name).first()
            if cluster is None:
                raise ValidationError(f"unknown cluster: {cluster_name}")
            qs = qs.filter(cluster=cluster, namespace__isnull=True, workload__isnull=True)

        elif scope == SnapshotScope.NAMESPACE:
            cluster_name = request.query_params.get("cluster")
            ns_name = request.query_params.get("namespace")
            if not (cluster_name and ns_name):
                raise ValidationError(
                    "namespace scope requires ?cluster=<name>&namespace=<name>"
                )
            ns = Namespace.objects.filter(
                cluster__name=cluster_name, name=ns_name,
            ).first()
            if ns is None:
                raise ValidationError(f"unknown namespace: {cluster_name}/{ns_name}")
            qs = qs.filter(namespace=ns, workload__isnull=True)

        elif scope == SnapshotScope.WORKLOAD:
            wl_id = request.query_params.get("workload_id")
            if not wl_id:
                raise ValidationError("workload scope requires ?workload_id=<pk>")
            workload = Workload.objects.filter(pk=wl_id).first()
            if workload is None:
                raise ValidationError(f"unknown workload pk: {wl_id}")
            qs = qs.filter(workload=workload)
            if request.query_params.get("mode") == "image_changes_only":
                qs = qs.exclude(change_kind=ImageSetChangeKind.NONE.value)

        # GLOBAL: no extra filter; the scope_kind filter is sufficient.

        rows = list(qs.order_by("captured_at"))

        captured_at = [r.captured_at.isoformat() for r in rows]
        totals = [r.total_active for r in rows]
        severity = _series_lists(rows, _SEVERITY_KEYS, "severity_counts")
        priority = _series_lists(rows, _PRIORITY_KEYS, "priority_counts")

        events = []
        if scope == SnapshotScope.WORKLOAD:
            prev_set: list[str] | None = None
            for r in rows:
                if r.change_kind != ImageSetChangeKind.NONE.value:
                    diff = _digest_set_diff(prev_set, r.image_digest_set or [])
                    events.append({
                        "captured_at": r.captured_at.isoformat(),
                        "import_id": r.import_id or "",
                        "change_kind": r.change_kind,
                        **diff,
                    })
                # Track the most recent populated digest set for diffs.
                if r.image_digest_set:
                    prev_set = r.image_digest_set

        return Response({
            "scope_kind": scope,
            "captured_at": captured_at,
            "totals": totals,
            "severity": severity,
            "priority": priority,
            "events": events,
        })
