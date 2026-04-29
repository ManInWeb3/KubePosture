"""Inventory + workload query helpers shared by the UI views.

The default-filter predicate from
[Architecture/dev_docs/08-ui.md:39-48](Architecture/dev_docs/08-ui.md#L39-L48) lives here, in one place,
so list and detail views can't drift.

For v1 the FindingAction overlay check is per-finding scope only.
The per-vuln / per-vuln-image cascade in
[Architecture/dev_docs/09-risk-acceptance.md](Architecture/dev_docs/09-risk-acceptance.md) lands with F1.
"""
from __future__ import annotations

from collections import defaultdict
from typing import Iterable

from django.db.models import Exists, F, OuterRef, Q
from django.utils import timezone

from core.constants import (
    FindingActionScope,
    FindingActionType,
    PriorityBand,
    Severity,
)
from core.models import (
    Cluster,
    Finding,
    FindingAction,
    Image,
    Workload,
    WorkloadImageObservation,
)


def _resolve_cluster(cluster):
    """Accept a Cluster instance, a name string, or None. Returns a
    Cluster instance or None (None when name doesn't match anything).
    """
    if cluster is None or isinstance(cluster, Cluster):
        return cluster
    return Cluster.objects.filter(name=cluster).first()


# ── Filter primitives ────────────────────────────────────────────


def base_finding_filter() -> Q:
    """Default-filter predicate as a Q expression on Finding.

    - Workload deployed (or NULL for cluster-scoped findings).
    - last_seen >= cluster.last_complete_inventory_at (NULL means
      no complete cycle has landed yet — keep the row visible).
    """
    return (
        (Q(workload__deployed=True) | Q(workload__isnull=True))
        & (
            Q(cluster__last_complete_inventory_at__isnull=True)
            | Q(last_seen__gte=F("cluster__last_complete_inventory_at"))
        )
    )


def _muted_subquery():
    """Active per-finding ACCEPT/FALSE_POSITIVE FindingAction for OuterRef("pk")."""
    return FindingAction.objects.filter(
        finding=OuterRef("pk"),
        scope_kind=FindingActionScope.PER_FINDING,
        action_type__in=[
            FindingActionType.ACCEPT,
            FindingActionType.FALSE_POSITIVE,
        ],
        revoked_at__isnull=True,
    ).filter(Q(expires_at__isnull=True) | Q(expires_at__gt=timezone.now()))


def default_finding_qs(*, include_muted: bool = False, cluster=None):
    """All currently-relevant findings, default-filtered.

    `cluster`: optional Cluster instance OR cluster name string to scope.
    `include_muted`: if False, drop findings with an active per-finding
    accept / false-positive overlay.
    """
    qs = Finding.objects.select_related(
        "cluster",
        "workload",
        "workload__namespace",
        "image",
    ).filter(base_finding_filter())
    if cluster is not None:
        if isinstance(cluster, Cluster):
            qs = qs.filter(cluster=cluster)
        else:
            qs = qs.filter(cluster__name=cluster)
    if not include_muted:
        qs = qs.annotate(_muted=Exists(_muted_subquery())).filter(_muted=False)
    return qs


# ── Per-image priority-band counts ───────────────────────────────


_BANDS = (
    PriorityBand.IMMEDIATE,
    PriorityBand.OUT_OF_CYCLE,
    PriorityBand.SCHEDULED,
    PriorityBand.DEFER,
)


def _empty_band_counts() -> dict[str, int]:
    return {b.value: 0 for b in _BANDS}


# ── Per-workload priority-band counts ────────────────────────────


_ALLOWED_SORTS = {
    "n_immediate", "n_out_of_cycle", "n_scheduled", "n_defer",
    "name", "cluster", "namespace",
}


def list_workloads(
    *,
    cluster: str | None = None,
    namespace: str | None = None,
    name_contains: str | None = None,
    has_immediate: bool = False,
    has_out_of_cycle: bool = False,
    include_muted: bool = False,
    deployed_only: bool = True,
    sort: str | None = None,
    sort_dir: str = "desc",
):
    """Return display rows for the Workloads landing.

    One dict per Workload — `(cluster, namespace, kind, name)` plus the
    four priority-band counts, default-filtered through `default_finding_qs`.
    Mirrors [Architecture/dev_docs/08-ui.md §1](Architecture/dev_docs/08-ui.md#L100).
    """
    qs = Workload.objects.select_related("cluster", "namespace")
    if deployed_only:
        qs = qs.filter(deployed=True)
    if cluster:
        qs = qs.filter(cluster__name=cluster)
    if namespace:
        qs = qs.filter(namespace__name=namespace)
    if name_contains:
        qs = qs.filter(name__icontains=name_contains)

    workload_ids = list(qs.values_list("pk", flat=True))
    if not workload_ids:
        return []

    findings_qs = default_finding_qs(include_muted=include_muted).filter(
        workload_id__in=workload_ids,
    )

    counts: dict[int, dict[str, int]] = defaultdict(_empty_band_counts)
    for wid, priority in findings_qs.values_list(
        "workload_id", "effective_priority",
    ):
        counts[wid][priority] = counts[wid].get(priority, 0) + 1

    rows: list[dict] = []
    for w in qs:
        c = counts.get(w.pk, _empty_band_counts())
        n_immediate = c[PriorityBand.IMMEDIATE.value]
        n_out_of_cycle = c[PriorityBand.OUT_OF_CYCLE.value]
        if has_immediate and n_immediate == 0:
            continue
        if has_out_of_cycle and n_out_of_cycle == 0:
            continue
        rows.append(
            {
                "workload": w,
                "cluster": w.cluster.name,
                "namespace": w.namespace.name,
                "kind": w.kind,
                "name": w.name,
                "n_immediate": n_immediate,
                "n_out_of_cycle": n_out_of_cycle,
                "n_scheduled": c[PriorityBand.SCHEDULED.value],
                "n_defer": c[PriorityBand.DEFER.value],
            }
        )

    sort_key = sort if sort in _ALLOWED_SORTS else None
    reverse = sort_dir != "asc"
    if sort_key:
        rows.sort(
            key=lambda r: (r[sort_key], r["name"].lower()),
            reverse=reverse,
        )
    else:
        rows.sort(
            key=lambda r: (
                -r["n_immediate"],
                -r["n_out_of_cycle"],
                -r["n_scheduled"],
                r["name"].lower(),
            )
        )
    return rows


# ── Findings list ordered by priority → severity → EPSS ──────────


_PRIORITY_ORDER = {b.value: i for i, b in enumerate(_BANDS)}
_SEVERITY_ORDER = {
    Severity.CRITICAL.value: 0,
    Severity.HIGH.value: 1,
    Severity.MEDIUM.value: 2,
    Severity.LOW.value: 3,
    Severity.INFO.value: 4,
    Severity.UNKNOWN.value: 5,
}


def order_findings(findings: Iterable[Finding]) -> list[Finding]:
    return sorted(
        findings,
        key=lambda f: (
            _PRIORITY_ORDER.get(f.effective_priority, 99),
            _SEVERITY_ORDER.get(f.severity, 99),
            -(f.epss_score or 0.0),
        ),
    )


# ── Workload detail helpers ──────────────────────────────────────


def workloads_for_kind_name(kind: str, name: str, *, cluster_name: str | None = None):
    """Return all Workload rows matching (kind, name), optionally
    narrowed to a single cluster. Empty queryset if none match.
    """
    qs = Workload.objects.filter(kind=kind, name=name).select_related(
        "cluster", "namespace",
    ).prefetch_related("signals")
    if cluster_name:
        qs = qs.filter(cluster__name=cluster_name)
    return qs


def list_workload_images(workloads, *, include_history: bool = False):
    """Per-(workload, image) rows for the detail page's images block.

    Joined across the supplied workloads (one Workload row per cluster
    that has a (kind, name) instance). Each row: image · cluster ·
    namespace · container · digest · first_seen · currently_deployed ·
    band counts (scoped to this workload × this image).

    By default returns only `currently_deployed=True` rows. Set
    `include_history=True` to also include historical observations
    (rows the reaper has flipped to False but not yet swept by the
    retention window).
    """
    workloads = list(workloads)
    if not workloads:
        return []

    workload_ids = [w.pk for w in workloads]
    obs_filter = {"workload_id__in": workload_ids}
    if not include_history:
        obs_filter["currently_deployed"] = True
    obs_qs = (
        WorkloadImageObservation.objects.filter(**obs_filter)
        .select_related("image", "workload", "workload__cluster", "workload__namespace")
    )

    image_ids = {obs.image_id for obs in obs_qs}

    findings_qs = default_finding_qs().filter(
        workload_id__in=workload_ids, image_id__in=image_ids,
    )
    band_counts: dict[tuple[int, int], dict[str, int]] = defaultdict(_empty_band_counts)
    for wid, image_id, priority in findings_qs.values_list(
        "workload_id", "image_id", "effective_priority"
    ):
        band_counts[(wid, image_id)][priority] = (
            band_counts[(wid, image_id)].get(priority, 0) + 1
        )

    rows = []
    for obs in obs_qs:
        c = band_counts.get((obs.workload_id, obs.image_id), _empty_band_counts())
        rows.append(
            {
                "observation": obs,
                "image": obs.image,
                "workload": obs.workload,
                "cluster": obs.workload.cluster,
                "namespace": obs.workload.namespace,
                "container_name": obs.container_name,
                "init_container": obs.init_container,
                "currently_deployed": obs.currently_deployed,
                "first_seen_at": obs.first_seen_at,
                "last_seen_at": obs.last_seen_at,
                "n_immediate": c[PriorityBand.IMMEDIATE.value],
                "n_out_of_cycle": c[PriorityBand.OUT_OF_CYCLE.value],
                "n_scheduled": c[PriorityBand.SCHEDULED.value],
                "n_defer": c[PriorityBand.DEFER.value],
                "n_total": sum(c.values()),
            }
        )
    rows.sort(
        key=lambda r: (
            not r["currently_deployed"],  # deployed rows first
            -r["n_immediate"],
            -r["n_out_of_cycle"],
            -r["n_scheduled"],
            -r["n_defer"],
            r["cluster"].name,
            r["container_name"] or "",
        )
    )
    return rows


def findings_for_workload_image(
    workload: Workload,
    image: Image | None,
    *,
    include_muted: bool = False,
) -> list[Finding]:
    """Findings scoped to a single (workload, image) pair, urgency-ordered.

    Used by the per-image findings panel on the Workload detail page.
    `image=None` matches workload-scoped findings with no image
    (cluster RBAC, infra assessment); the master Images table doesn't
    expose those rows in v1, but the helper handles the case anyway.
    """
    qs = default_finding_qs(include_muted=include_muted).filter(workload=workload)
    if image is not None:
        qs = qs.filter(image=image)
    else:
        qs = qs.filter(image__isnull=True)
    return order_findings(qs)
