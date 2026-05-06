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

from datetime import timedelta

from django.db.models import Case, Exists, F, IntegerField, OuterRef, Q, Value, When
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


# ── Filter primitives ────────────────────────────────────────────


def base_finding_filter(*, include_stale: bool = False) -> Q:
    """Default-filter predicate as a Q expression on Finding.

    - Workload deployed (or NULL for cluster-scoped findings).
    - last_seen >= cluster.last_complete_inventory_at (NULL means
      no complete cycle has landed yet — keep the row visible).

    `include_stale=True` drops the last_seen predicate, exposing rows
    whose last observation predates the most recent complete inventory.
    Used to show historical band counts for former (workload, image)
    pairs on the Workload detail page.
    """
    q = Q(workload__deployed=True) | Q(workload__isnull=True)
    if not include_stale:
        q &= (
            Q(cluster__last_complete_inventory_at__isnull=True)
            | Q(last_seen__gte=F("cluster__last_complete_inventory_at"))
        )
    return q


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


def default_finding_qs(
    *, include_muted: bool = False, include_stale: bool = False, cluster=None,
):
    """All currently-relevant findings, default-filtered.

    `cluster`: optional Cluster instance OR cluster name string to scope.
    `include_muted`: if False, drop findings with an active per-finding
    accept / false-positive overlay.
    `include_stale`: if True, drop the last_seen >= last_complete_inventory_at
    predicate so historical (former) findings are returned. See
    `base_finding_filter`.
    """
    qs = Finding.objects.select_related(
        "cluster",
        "workload",
        "workload__namespace",
        "image",
    ).filter(base_finding_filter(include_stale=include_stale))
    if cluster is not None:
        if isinstance(cluster, Cluster):
            qs = qs.filter(cluster=cluster)
        else:
            qs = qs.filter(cluster__name=cluster)
    if not include_muted:
        qs = qs.annotate(_muted=Exists(_muted_subquery())).filter(_muted=False)
    return qs


def restrict_to_currently_deployed_images(qs):
    """Narrow a Finding queryset to (workload, image) pairs that are
    currently deployed — plus image-less rows (workload-level findings
    like config-audit / RBAC / cluster-scoped).

    Why: `default_finding_qs` keeps any finding whose `last_seen` is at
    or after `cluster.last_complete_inventory_at`, but Trivy can hold a
    stale VulnerabilityReport CRD for an image that's already been
    rolled out, and re-ingesting it bumps `last_seen` past the anchor.
    Without this filter, the workload-detail Images table (which scopes
    by current image) and the per-workload trend chart (which doesn't)
    drift apart whenever an image change leaves a stale CRD behind.
    """
    deployed_obs = WorkloadImageObservation.objects.filter(
        workload_id=OuterRef("workload_id"),
        image_id=OuterRef("image_id"),
        currently_deployed=True,
    )
    return qs.filter(
        Q(image__isnull=True) | Exists(deployed_obs)
    )


# ── Per-image priority-band counts ───────────────────────────────


_BANDS = (
    PriorityBand.IMMEDIATE,
    PriorityBand.OUT_OF_BAND,
    PriorityBand.SCHEDULED,
    PriorityBand.DEFER,
)


def _empty_band_counts() -> dict[str, int]:
    return {b.value: 0 for b in _BANDS}


def _band_counts_by(qs, *key_fields: str):
    """Group findings by the given column(s) and tally `effective_priority`.

    Single key field → keys are scalars; multiple → keys are tuples.
    """
    counts: dict = defaultdict(_empty_band_counts)
    for row in qs.values_list(*key_fields, "effective_priority"):
        *key_parts, priority = row
        key = key_parts[0] if len(key_parts) == 1 else tuple(key_parts)
        counts[key][priority] = counts[key].get(priority, 0) + 1
    return counts


# ── Per-workload priority-band counts ────────────────────────────


_ALLOWED_SORTS = {
    "n_immediate", "n_out_of_band", "n_scheduled", "n_defer",
    "name", "cluster", "namespace",
}


def list_workloads(
    *,
    cluster: str | None = None,
    namespace: str | None = None,
    name_contains: str | None = None,
    sort: str | None = None,
    sort_dir: str = "desc",
):
    """Return display rows for the Workloads landing.

    One dict per Workload — `(cluster, namespace, kind, name)` plus the
    four priority-band counts, default-filtered through `default_finding_qs`.
    Mirrors [Architecture/dev_docs/08-ui.md §1](Architecture/dev_docs/08-ui.md#L100).
    """
    qs = Workload.objects.select_related("cluster", "namespace").filter(deployed=True)
    if cluster:
        qs = qs.filter(cluster__name=cluster)
    if namespace:
        qs = qs.filter(namespace__name=namespace)
    if name_contains:
        qs = qs.filter(name__icontains=name_contains)

    workload_ids = list(qs.values_list("pk", flat=True))
    if not workload_ids:
        return []

    # Scope to (workload, image) pairs that are currently deployed —
    # plus image-less workload-level findings — so a stale Trivy
    # VulnerabilityReport CRD held for a rolled-out image can't inflate
    # the row's count past what the workload-detail Images table shows.
    findings_qs = restrict_to_currently_deployed_images(
        default_finding_qs().filter(workload_id__in=workload_ids)
    )

    counts = _band_counts_by(findings_qs, "workload_id")

    rows: list[dict] = []
    for w in qs:
        c = counts.get(w.pk, _empty_band_counts())
        rows.append(
            {
                "workload": w,
                "cluster": w.cluster.name,
                "namespace": w.namespace.name,
                "kind": w.kind,
                "name": w.name,
                "n_immediate": c[PriorityBand.IMMEDIATE.value],
                "n_out_of_band": c[PriorityBand.OUT_OF_BAND.value],
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
                -r["n_out_of_band"],
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

    current_image_ids = {o.image_id for o in obs_qs if o.currently_deployed}
    former_image_ids = {o.image_id for o in obs_qs if not o.currently_deployed}

    band_counts: dict = {}
    if current_image_ids:
        live_qs = default_finding_qs().filter(
            workload_id__in=workload_ids, image_id__in=current_image_ids,
        )
        band_counts.update(_band_counts_by(live_qs, "workload_id", "image_id"))
    if former_image_ids:
        # Former (workload, image) pairs fail the live last_seen predicate;
        # use the stale-aware queryset so we surface the last-observed counts.
        stale_qs = default_finding_qs(include_stale=True).filter(
            workload_id__in=workload_ids, image_id__in=former_image_ids,
        )
        band_counts.update(_band_counts_by(stale_qs, "workload_id", "image_id"))

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
                "n_out_of_band": c[PriorityBand.OUT_OF_BAND.value],
                "n_scheduled": c[PriorityBand.SCHEDULED.value],
                "n_defer": c[PriorityBand.DEFER.value],
                "n_total": sum(c.values()),
            }
        )
    rows.sort(
        key=lambda r: (
            not r["currently_deployed"],  # deployed rows first
            -r["n_immediate"],
            -r["n_out_of_band"],
            -r["n_scheduled"],
            -r["n_defer"],
            r["cluster"].name,
            r["container_name"] or "",
        )
    )
    return rows


# ── /findings/ list-page query helpers ──────────────────────────


_EXPOSURE_VALUES = {"internet", "sensitive", "either"}
_FINDING_LIST_SORTS = {
    "last_seen": "last_seen",
    "first_seen": "first_seen",
    "title": "title",
    "epss": "epss_score",
    "priority": "_priority_rank",  # numeric annotation, see _priority_rank_annotation
    "severity": "_severity_rank",
}


def _priority_rank_annotation():
    """Numeric ranking on `effective_priority` so the SQL sort orders
    immediate→defer regardless of the alphabetic value. Higher = more urgent.
    """
    return Case(
        When(effective_priority=PriorityBand.IMMEDIATE, then=Value(3)),
        When(effective_priority=PriorityBand.OUT_OF_BAND, then=Value(2)),
        When(effective_priority=PriorityBand.SCHEDULED, then=Value(1)),
        When(effective_priority=PriorityBand.DEFER, then=Value(0)),
        default=Value(-1),
        output_field=IntegerField(),
    )


def _severity_rank_annotation():
    return Case(
        When(severity=Severity.CRITICAL, then=Value(5)),
        When(severity=Severity.HIGH, then=Value(4)),
        When(severity=Severity.MEDIUM, then=Value(3)),
        When(severity=Severity.LOW, then=Value(2)),
        When(severity=Severity.INFO, then=Value(1)),
        When(severity=Severity.UNKNOWN, then=Value(0)),
        default=Value(-1),
        output_field=IntegerField(),
    )


def _exposure_q(value: str) -> Q | None:
    """Q expression for the exposure filter. Cluster-scoped findings
    (workload IS NULL) are excluded — they don't have a namespace
    exposure context. This matches `core/urgency.py` semantics, where
    only workload-scoped findings get the exposure boost.
    """
    if value == "internet":
        return Q(workload__namespace__internet_exposed=True)
    if value == "sensitive":
        return Q(workload__namespace__contains_sensitive_data=True)
    if value == "either":
        return (
            Q(workload__namespace__internet_exposed=True)
            | Q(workload__namespace__contains_sensitive_data=True)
        )
    return None


def list_findings(
    *,
    name_contains: str | None = None,
    priority: str | None = None,
    source: str | None = None,
    exposure: str | None = None,
    kev: bool = False,
    epss_min: float | None = None,
    age_days: int | None = None,
    sort: str | None = None,
    sort_dir: str = "desc",
):
    """Return a Finding queryset for the `/findings/` triage page.

    Triage-signal filters only — topology (cluster / namespace / workload)
    is NOT exposed here; that drill-down lives on `/workloads/`. Severity
    and `fixed_version` are not filterable either; severity is folded
    into `effective_priority` and `fixed_version` is upstream metadata,
    not a KubePosture mitigation state.

    `exposure` excludes cluster-scoped findings (workload IS NULL) — see
    `_exposure_q`. Set to None / empty to include them.

    Default ordering when `sort` is None: priority rank desc, then
    last_seen desc. Sort keys: see `_FINDING_LIST_SORTS`.
    """
    qs = restrict_to_currently_deployed_images(default_finding_qs())

    if name_contains:
        qs = qs.filter(
            Q(title__icontains=name_contains)
            | Q(vuln_id__icontains=name_contains)
        )
    if priority:
        qs = qs.filter(effective_priority=priority)
    if source:
        qs = qs.filter(source=source)
    if exposure:
        eq = _exposure_q(exposure)
        if eq is not None:
            qs = qs.filter(eq)
    if kev:
        qs = qs.filter(kev_listed=True)
    if epss_min is not None:
        qs = qs.filter(epss_score__gte=epss_min)
    if age_days is not None:
        qs = qs.filter(first_seen__gte=timezone.now() - timedelta(days=age_days))

    qs = qs.annotate(
        _priority_rank=_priority_rank_annotation(),
        _severity_rank=_severity_rank_annotation(),
    )

    field = _FINDING_LIST_SORTS.get(sort or "")
    if field is None:
        # Default: priority desc, last_seen desc.
        return qs.order_by("-_priority_rank", "-last_seen")
    prefix = "" if sort_dir == "asc" else "-"
    return qs.order_by(f"{prefix}{field}", "-last_seen")


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
