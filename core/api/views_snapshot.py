"""Time-series snapshot endpoint for trend charts.

Powers the workload-detail trend block (per
Architecture/dev_docs/08-ui.md §Workload detail) and the
global/per-cluster trend block on the workloads list.

URL surface (mounted at /api/v1/):
    /snapshots/series/?scope=...&...
"""
from __future__ import annotations

from collections import defaultdict
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


def _aggregate_by_day(qs, scope: str) -> Response:
    """Sum total_active / severity_counts / priority_counts over `qs`,
    bucketed by `captured_at.date()`. Returns the standard response.

    Snapshots can be re-captured multiple times per day for the same
    source (heartbeat cron + admin flag toggles + ingest flow), so a
    raw SUM would multiply the latest reading by the number of
    captures. We first dedup to the LATEST row per
    (date, cluster_id, namespace_id, workload_id) and then sum across
    sources for each day.
    """
    latest: dict[tuple, dict] = {}
    # Latest captured_at observed inside each day bucket. The emitted
    # x-axis timestamp uses this so today's point lands at the moment
    # of the most recent capture (real wall clock) rather than a
    # synthetic noon-UTC mark — a UTC+8 user reading the chart at 5pm
    # would otherwise see today's point at 8pm "in the future".
    day_max_ts: dict[str, str] = {}
    for row in qs.only(
        "captured_at", "cluster_id", "namespace_id", "workload_id",
        "total_active", "severity_counts", "priority_counts",
    ).order_by("captured_at"):
        day = row.captured_at.date().isoformat()
        key = (day, row.cluster_id, row.namespace_id, row.workload_id)
        # Iteration is asc by captured_at, so a later assignment wins
        # for both the dedup payload and the day's max timestamp.
        latest[key] = {
            "total": int(row.total_active or 0),
            "sev": dict(row.severity_counts or {}),
            "pri": dict(row.priority_counts or {}),
        }
        day_max_ts[day] = row.captured_at.isoformat()

    buckets: dict[str, dict] = {}
    for (day, _c, _n, _w), v in latest.items():
        b = buckets.get(day)
        if b is None:
            b = {"total": 0, "sev": defaultdict(int), "pri": defaultdict(int)}
            buckets[day] = b
        b["total"] += v["total"]
        for k, n in v["sev"].items():
            b["sev"][k] += int(n)
        for k, n in v["pri"].items():
            b["pri"][k] += int(n)

    keys = sorted(buckets.keys())
    captured_at = [day_max_ts[k] for k in keys]
    return Response({
        "scope_kind": scope,
        "captured_at": captured_at,
        "totals": [buckets[k]["total"] for k in keys],
        "severity": {
            sk: [int(buckets[k]["sev"].get(sk, 0)) for k in keys]
            for sk in _SEVERITY_KEYS
        },
        "priority": {
            pk: [int(buckets[k]["pri"].get(pk, 0)) for k in keys]
            for pk in _PRIORITY_KEYS
        },
        "events": [],
    })


def _aggregate_namespace_by_name(scope: str, ns_name: str, cutoff, name_substr: str = "") -> Response:
    """Namespace-only filter (no cluster). When `name_substr` is set,
    pivot to workload-scope heartbeats matching both namespace name and
    workload name. Otherwise sum every cluster's namespace-scope
    heartbeat for `ns_name`.
    """
    if name_substr:
        qs = Snapshot.objects.filter(
            scope_kind=SnapshotScope.WORKLOAD,
            change_kind=ImageSetChangeKind.NONE.value,
            captured_at__gte=cutoff,
            namespace__name=ns_name,
            workload__name__icontains=name_substr,
        )
    else:
        qs = Snapshot.objects.filter(
            scope_kind=SnapshotScope.NAMESPACE,
            captured_at__gte=cutoff,
            namespace__name=ns_name,
            workload__isnull=True,
        )
    return _aggregate_by_day(qs, scope)


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
        name      — workload name substring (optional; ignored for
                    workload scope). When set, the response sums
                    workload-scoped heartbeat snapshots whose
                    workload.name icontains the substring, scoped to
                    cluster/namespace if those are also set. No events.

    Response shape:
        {
          "scope_kind": "...",
          "captured_at": ["...", ...],
          "totals":   [N, ...],
          "severity": {critical: [...], high: [...], ...},
          "priority": {immediate: [...], out_of_band: [...], ...},
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
        name_substr = (request.query_params.get("name") or "").strip()

        qs = Snapshot.objects.filter(scope_kind=scope, captured_at__gte=cutoff)
        cluster_obj: Cluster | None = None
        ns_obj: Namespace | None = None

        if scope == SnapshotScope.CLUSTER:
            cluster_name = request.query_params.get("cluster")
            if not cluster_name:
                raise ValidationError("cluster scope requires ?cluster=<name>")
            cluster_obj = Cluster.objects.filter(name=cluster_name).first()
            if cluster_obj is None:
                raise ValidationError(f"unknown cluster: {cluster_name}")
            qs = qs.filter(cluster=cluster_obj, namespace__isnull=True, workload__isnull=True)

        elif scope == SnapshotScope.NAMESPACE:
            cluster_name = request.query_params.get("cluster")
            ns_name = request.query_params.get("namespace")
            if not ns_name:
                raise ValidationError(
                    "namespace scope requires ?namespace=<name>"
                )
            if cluster_name:
                ns_obj = Namespace.objects.filter(
                    cluster__name=cluster_name, name=ns_name,
                ).first()
                if ns_obj is None:
                    raise ValidationError(f"unknown namespace: {cluster_name}/{ns_name}")
                cluster_obj = ns_obj.cluster
                qs = qs.filter(namespace=ns_obj, workload__isnull=True)
            else:
                # Namespace-only (no cluster picked): aggregate every
                # NAMESPACE-kind heartbeat row whose namespace.name
                # matches, across clusters, bucketed by day.
                return _aggregate_namespace_by_name(scope, ns_name, cutoff, name_substr=name_substr)

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

        # When a name substring is supplied (and scope isn't already a
        # single workload), aggregate workload-scoped heartbeat rows on
        # the fly. We restrict to change_kind=NONE so per-workload
        # event-path rows (sporadic timestamps) don't appear as 1-workload
        # spikes/drops in the aggregate.
        if name_substr and scope != SnapshotScope.WORKLOAD:
            wqs = Snapshot.objects.filter(
                scope_kind=SnapshotScope.WORKLOAD,
                change_kind=ImageSetChangeKind.NONE.value,
                captured_at__gte=cutoff,
                workload__name__icontains=name_substr,
            )
            if cluster_obj is not None:
                wqs = wqs.filter(cluster=cluster_obj)
            if ns_obj is not None:
                wqs = wqs.filter(namespace=ns_obj)
            return _aggregate_by_day(wqs, scope)

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
