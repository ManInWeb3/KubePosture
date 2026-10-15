"""Custom Prometheus collector for KubePosture business gauges.

All gauges are wrapped in a TTL cache (see ``core.metrics.registry``)
so the scrape rate decouples from the DB-query rate.
"""
from __future__ import annotations

from django.db.models import Count, Min
from django.utils import timezone
from prometheus_client.core import GaugeMetricFamily

from core.constants import ImportMarkState, IngestQueueStatus
from core.models import Cluster, ImportMark, IngestQueue, Namespace, Workload
from core.services.inventory import default_finding_qs

from .registry import cached, queue_ttl_seconds


def _findings_open():
    rows = (
        default_finding_qs(include_muted=False)
        .values("cluster__name", "workload__namespace__name", "effective_priority")
        .annotate(n=Count("id"))
    )
    return [
        (
            r["cluster__name"] or "",
            r["workload__namespace__name"] or "_cluster_scoped",
            r["effective_priority"],
            r["n"],
        )
        for r in rows
    ]


def _findings_by_category():
    rows = (
        default_finding_qs(include_muted=False)
        .values("cluster__name", "category", "source")
        .annotate(n=Count("id"))
    )
    return [
        (r["cluster__name"] or "", r["category"], r["source"], r["n"])
        for r in rows
    ]


def _workloads_total():
    rows = (
        Workload.objects.filter(deployed=True)
        .values("cluster__name", "namespace__name", "kind")
        .annotate(n=Count("id"))
    )
    return [
        (r["cluster__name"], r["namespace__name"], r["kind"], r["n"]) for r in rows
    ]


def _workloads_publicly_exposed():
    rows = (
        Workload.objects.filter(deployed=True, publicly_exposed=True)
        .values("cluster__name", "namespace__name")
        .annotate(n=Count("id"))
    )
    return [(r["cluster__name"], r["namespace__name"], r["n"]) for r in rows]


def _namespaces_total():
    rows = (
        Namespace.objects.filter(active=True)
        .values("cluster__name", "internet_exposed")
        .annotate(n=Count("id"))
    )
    return [
        (r["cluster__name"], "true" if r["internet_exposed"] else "false", r["n"])
        for r in rows
    ]


def _clusters_total():
    rows = Cluster.objects.values("environment").annotate(n=Count("id"))
    return [(r["environment"], r["n"]) for r in rows]


def _ingest_queue_depth():
    """Every status, 0 when empty — an absent row used to mean an absent
    series, so the drained queue showed up as gaps instead of 0."""
    counts = dict.fromkeys(IngestQueueStatus.values, 0)
    for r in IngestQueue.objects.values("status").annotate(n=Count("id")):
        counts[r["status"]] = r["n"]
    return list(counts.items())


def _ingest_queue_oldest_age_seconds():
    """Age of the oldest row per status. The queue only holds in-flight
    work now (rows are deleted at reap), so a growing `pending` age means
    the worker isn't keeping up or an import can't be claimed."""
    now = timezone.now()
    ages = dict.fromkeys(IngestQueueStatus.values, 0.0)  # empty status → 0, not absent
    for r in IngestQueue.objects.values("status").annotate(oldest=Min("created_at")):
        ages[r["status"]] = (now - r["oldest"]).total_seconds()
    return list(ages.items())


def _import_scan_coverage_ratio():
    """matched / expected from the newest committed, non-discarded mark
    per (cluster, kind) that reported a coverage denominator."""
    rows = (
        ImportMark.objects
        .filter(
            coverage_expected__gt=0,
            state__in=[ImportMarkState.DRAINING.value, ImportMarkState.REAPED.value],
            discard_reason="",
        )
        .order_by("cluster__name", "kind", "-started_at")
        .distinct("cluster__name", "kind")
        .values_list("cluster__name", "kind", "coverage_expected", "coverage_matched")
    )
    return [
        (cluster, kind, (matched or 0) / expected)
        for cluster, kind, expected, matched in rows
    ]


def _inventory_age_seconds():
    now = timezone.now()
    return [
        (c.name, (now - c.last_complete_inventory_at).total_seconds())
        for c in Cluster.objects.only("name", "last_complete_inventory_at")
        if c.last_complete_inventory_at is not None
    ]


_METRIC_DESCRIPTORS = (
    ("kubeposture_findings_open",
     "Open findings (excludes accepted / false-positive overlays).",
     ["cluster", "namespace", "effective_priority"]),
    ("kubeposture_findings_open_by_category",
     "Open findings grouped by category and source.",
     ["cluster", "category", "source"]),
    ("kubeposture_workloads_total",
     "Currently deployed workloads.",
     ["cluster", "namespace", "kind"]),
    ("kubeposture_workloads_publicly_exposed",
     "Deployed workloads backed by external Ingress or non-internal LoadBalancer.",
     ["cluster", "namespace"]),
    ("kubeposture_namespaces_total",
     "Active namespaces, sliced by exposure rollup.",
     ["cluster", "internet_exposed"]),
    ("kubeposture_clusters_total",
     "Registered clusters by environment.",
     ["environment"]),
    ("kubeposture_ingest_queue_depth",
     "Items in the ingest queue, by status.",
     ["status"]),
    ("kubeposture_ingest_queue_oldest_age_seconds",
     "Age of the oldest ingest queue item, by status.",
     ["status"]),
    ("kubeposture_import_scan_coverage_ratio",
     "Importer-reported scan coverage (matched / expected) of the latest committed import, per cluster and kind.",
     ["cluster", "kind"]),
    ("kubeposture_last_inventory_age_seconds",
     "Seconds since the most recent complete inventory cycle, per cluster.",
     ["cluster"]),
)


class KubePostureCollector:
    """Yields KubePosture business gauges; safe to register on any registry."""

    def describe(self):
        # Without describe(), REGISTRY.register() falls back to calling collect()
        # for name discovery — which would hit the DB at URL-config time, before
        # migrations have run. Yield empty families so registration only learns
        # the names.
        for name, doc, labels in _METRIC_DESCRIPTORS:
            yield GaugeMetricFamily(name, doc, labels=labels)

    def collect(self):
        g = GaugeMetricFamily(
            "kubeposture_findings_open",
            "Open findings (excludes accepted / false-positive overlays).",
            labels=["cluster", "namespace", "effective_priority"],
        )
        for cluster, namespace, priority, n in cached("findings_open", _findings_open):
            g.add_metric([cluster, namespace, priority], n)
        yield g

        g = GaugeMetricFamily(
            "kubeposture_findings_open_by_category",
            "Open findings grouped by category and source.",
            labels=["cluster", "category", "source"],
        )
        for cluster, category, source, n in cached(
            "findings_by_category", _findings_by_category
        ):
            g.add_metric([cluster, category, source], n)
        yield g

        g = GaugeMetricFamily(
            "kubeposture_workloads_total",
            "Currently deployed workloads.",
            labels=["cluster", "namespace", "kind"],
        )
        for cluster, namespace, kind, n in cached("workloads_total", _workloads_total):
            g.add_metric([cluster, namespace, kind], n)
        yield g

        g = GaugeMetricFamily(
            "kubeposture_workloads_publicly_exposed",
            "Deployed workloads backed by external Ingress or non-internal LoadBalancer.",
            labels=["cluster", "namespace"],
        )
        for cluster, namespace, n in cached(
            "workloads_publicly_exposed", _workloads_publicly_exposed
        ):
            g.add_metric([cluster, namespace], n)
        yield g

        g = GaugeMetricFamily(
            "kubeposture_namespaces_total",
            "Active namespaces, sliced by exposure rollup.",
            labels=["cluster", "internet_exposed"],
        )
        for cluster, exposed, n in cached("namespaces_total", _namespaces_total):
            g.add_metric([cluster, exposed], n)
        yield g

        g = GaugeMetricFamily(
            "kubeposture_clusters_total",
            "Registered clusters by environment.",
            labels=["environment"],
        )
        for env, n in cached("clusters_total", _clusters_total):
            g.add_metric([env], n)
        yield g

        g = GaugeMetricFamily(
            "kubeposture_ingest_queue_depth",
            "Items in the ingest queue, by status.",
            labels=["status"],
        )
        for status, n in cached("ingest_queue_depth", _ingest_queue_depth, ttl=queue_ttl_seconds()):
            g.add_metric([status], n)
        yield g

        g = GaugeMetricFamily(
            "kubeposture_ingest_queue_oldest_age_seconds",
            "Age of the oldest ingest queue item, by status.",
            labels=["status"],
        )
        for status, age in cached("ingest_queue_oldest_age", _ingest_queue_oldest_age_seconds, ttl=queue_ttl_seconds()):
            g.add_metric([status], age)
        yield g

        g = GaugeMetricFamily(
            "kubeposture_import_scan_coverage_ratio",
            "Importer-reported scan coverage (matched / expected) of the latest committed import, per cluster and kind.",
            labels=["cluster", "kind"],
        )
        for cluster, kind, ratio in cached("import_scan_coverage", _import_scan_coverage_ratio):
            g.add_metric([cluster, kind], ratio)
        yield g

        g = GaugeMetricFamily(
            "kubeposture_last_inventory_age_seconds",
            "Seconds since the most recent complete inventory cycle, per cluster.",
            labels=["cluster"],
        )
        for cluster, age in cached("inventory_age_seconds", _inventory_age_seconds):
            g.add_metric([cluster], age)
        yield g
