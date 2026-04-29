"""Urgency scorer — pure decision tree for Finding.effective_priority.

`score(finding)` is the editable function (decision tree per
dev_docs/07-urgency-formula.md). `recompute_batch(findings)` is the
bulk fan-out path used by enrichment / signal-change triggers.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

from django.db import transaction

from core.constants import Environment, PriorityBand, Severity
from core.models import Finding
from core.signals import (
    HOST_ESCAPE_SIGNALS,
    PRIV_ESCALATION_SIGNALS,
    RBAC_ELEVATION_SIGNALS,
)


@dataclass(frozen=True)
class PriorityResult:
    band: str  # PriorityBand value
    reasons: tuple[str, ...]


# ── Defaults / null-safety helpers ────────────────────────────────

def _epss(finding: Finding) -> float:
    return float(finding.epss_percentile or 0.0)


def _has_fix(finding: Finding) -> bool:
    return bool(finding.fixed_version)


def _is_exposed(workload, namespace) -> bool:
    """workload.publicly_exposed OR namespace.internet_exposed.

    Namespace is the rollup; either firing is enough for the decision
    tree.
    """
    if workload is None:
        return False
    if workload.publicly_exposed:
        return True
    if namespace is not None and namespace.internet_exposed:
        return True
    return False


def _active_signal_ids(workload) -> set[str]:
    """All signal_ids on this workload with currently_active=true."""
    if workload is None:
        return set()
    # signals is a related manager prefetched by callers.
    return {s.signal_id for s in workload.signals.all() if s.currently_active}


# ── The editable scoring function ─────────────────────────────────

def score(finding: Finding) -> PriorityResult:
    """v1 decision tree. Pure: no DB I/O beyond preloaded relations."""
    # KEV short-circuits to Immediate.
    if finding.kev_listed:
        return PriorityResult(PriorityBand.IMMEDIATE.value, ("KEV",))

    severity = finding.severity
    epss = _epss(finding)
    has_fix = _has_fix(finding)

    # Cluster-scoped finding (e.g. ClusterRole RBAC) — no workload.
    # Cluster-scoped findings cap at OutOfCycle in v1; the absence of
    # a workload context means we can't reason about exposure or
    # escalation, so we deliberately don't promote to Immediate.
    if finding.workload_id is None:
        env = (finding.cluster.environment or Environment.DEV.value) if finding.cluster else Environment.DEV.value
        if severity == Severity.CRITICAL.value:
            return PriorityResult(
                PriorityBand.OUT_OF_CYCLE.value,
                ("critical", "cluster-scoped", env),
            )
        if severity == Severity.HIGH.value and env == Environment.PROD.value:
            return PriorityResult(
                PriorityBand.OUT_OF_CYCLE.value,
                ("high", "cluster-scoped", "prod"),
            )
        return PriorityResult(PriorityBand.SCHEDULED.value, ("cluster-scoped",))

    workload = finding.workload
    namespace = workload.namespace
    cluster = workload.cluster
    env = cluster.environment or Environment.DEV.value

    is_exposed = _is_exposed(workload, namespace)
    signal_ids = _active_signal_ids(workload)

    has_host_escape = bool(signal_ids & HOST_ESCAPE_SIGNALS)
    has_rbac_elevation = bool(signal_ids & RBAC_ELEVATION_SIGNALS)
    has_priv_escalation = bool(signal_ids & PRIV_ESCALATION_SIGNALS)
    has_escalation = has_host_escape or has_rbac_elevation or has_priv_escalation

    # Highest band — Immediate
    if severity in (Severity.CRITICAL.value, Severity.HIGH.value) and epss >= 0.9 \
            and is_exposed and env == Environment.PROD.value:
        return PriorityResult(
            PriorityBand.IMMEDIATE.value,
            ("severity", "EPSS>=0.9", "exposed", "prod"),
        )

    if severity == Severity.CRITICAL.value and is_exposed and env == Environment.PROD.value:
        return PriorityResult(
            PriorityBand.IMMEDIATE.value,
            ("critical", "exposed", "prod"),
        )

    # Out-of-cycle
    if severity in (Severity.CRITICAL.value, Severity.HIGH.value) \
            and env == Environment.PROD.value and has_escalation:
        return PriorityResult(
            PriorityBand.OUT_OF_CYCLE.value,
            ("severity", "prod", "escalation-signal"),
        )

    if epss >= 0.9 and env == Environment.PROD.value:
        return PriorityResult(
            PriorityBand.OUT_OF_CYCLE.value,
            ("EPSS>=0.9", "prod"),
        )

    if severity == Severity.CRITICAL.value and env == Environment.PROD.value:
        return PriorityResult(
            PriorityBand.OUT_OF_CYCLE.value,
            ("critical", "prod"),
        )

    if severity == Severity.HIGH.value and is_exposed and env == Environment.PROD.value:
        return PriorityResult(
            PriorityBand.OUT_OF_CYCLE.value,
            ("high", "exposed", "prod"),
        )

    # Sensitive-namespace bump for no-fix medium/high findings —
    # checked *before* the no-fix-Defer rule so an unfixed CVE in a
    # sensitive namespace surfaces as Scheduled rather than Defer.
    if severity in (Severity.HIGH.value, Severity.MEDIUM.value) \
            and not has_fix \
            and namespace is not None and namespace.contains_sensitive_data:
        return PriorityResult(
            PriorityBand.SCHEDULED.value,
            ("severity", "sensitive-ns", "no-fix"),
        )

    # No-fix / no-context branches
    if not has_fix and not is_exposed and not has_escalation:
        return PriorityResult(
            PriorityBand.DEFER.value,
            ("no-fix", "no-exposure", "no-escalation"),
        )

    if not has_fix and severity in (Severity.CRITICAL.value, Severity.HIGH.value) \
            and (is_exposed or has_escalation):
        return PriorityResult(
            PriorityBand.SCHEDULED.value,
            ("no-fix", "exposed-or-escalation"),
        )

    if severity == Severity.CRITICAL.value and env != Environment.PROD.value:
        return PriorityResult(
            PriorityBand.SCHEDULED.value,
            ("critical", "non-prod"),
        )

    if severity == Severity.HIGH.value and env == Environment.PROD.value:
        return PriorityResult(
            PriorityBand.SCHEDULED.value,
            ("high", "prod"),
        )

    # Medium-severity finding on a prod workload that has an
    # escalation signal: bump to Scheduled. Without escalation the
    # default Defer below applies.
    if severity == Severity.MEDIUM.value and env == Environment.PROD.value and has_escalation:
        return PriorityResult(
            PriorityBand.SCHEDULED.value,
            ("medium", "prod", "escalation-signal"),
        )

    return PriorityResult(PriorityBand.DEFER.value, ("default",))


# ── Public API ────────────────────────────────────────────────────

_FINDING_RELATIONS = (
    "workload__namespace",
    "workload__cluster",
    "cluster",
    "image",
)


def compute_priority(finding: Finding) -> PriorityResult:
    """Single-finding entry point. Reloads relations + calls score()."""
    finding = (
        Finding.objects
        .select_related(*_FINDING_RELATIONS)
        .prefetch_related("workload__signals")
        .get(pk=finding.pk)
    )
    return score(finding)


def recompute_batch(findings: Iterable[Finding]) -> int:
    """Bulk recompute. One query pass loads relations, then score() each in
    memory, then a single bulk_update.

    Returns the count updated.
    """
    pks = [f.pk for f in findings]
    if not pks:
        return 0
    loaded = list(
        Finding.objects
        .filter(pk__in=pks)
        .select_related(*_FINDING_RELATIONS)
        .prefetch_related("workload__signals")
    )
    changed: list[Finding] = []
    for f in loaded:
        new_band = score(f).band
        if f.effective_priority != new_band:
            f.effective_priority = new_band
            changed.append(f)
    if changed:
        with transaction.atomic():
            Finding.objects.bulk_update(changed, ["effective_priority"])
    return len(changed)


def apply_score(finding: Finding) -> Finding:
    """Compute + assign in-memory (no save). Caller controls persistence —
    used by ingest where the Finding is being upserted anyway.
    """
    result = score(finding)
    finding.effective_priority = result.band
    return finding
