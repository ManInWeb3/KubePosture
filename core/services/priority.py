"""
Effective priority — SSVC-inspired decision tree.

Combines scanner severity + threat intelligence (EPSS, KEV) + deployment
context (cluster environment, per-namespace exposure) to produce an action
priority.

Exposure and sensitivity live on Namespace (per-cluster). Findings with
no namespace (cluster-scoped resources like ClusterRole) derive their
context from the cluster rollup: exposed if ANY namespace in the cluster
is exposed; sensitive if ANY namespace is sensitive.

See: docs/vulnerability-misconfiguration-management.md
"""
import logging
from dataclasses import dataclass

from core.constants import EPSS_HIGH_THRESHOLD, Priority, Severity, Status

logger = logging.getLogger(__name__)


VALID_ENVIRONMENTS = ("prod", "staging", "dev")


@dataclass
class PriorityContext:
    """Pre-loaded cluster + namespace exposure state, passed into
    compute_priority_with_context to avoid N+1 DB hits during bulk recalc."""

    exposure_map: dict          # {namespace_name: bool}
    sensitive_map: dict         # {namespace_name: bool}
    cluster_has_exposure: bool
    cluster_has_sensitive: bool


def load_context(cluster) -> PriorityContext:
    """Load exposure/sensitivity rollups for one cluster in O(1) queries.

    Only active namespaces contribute — an inactive (deleted) namespace's
    stale exposure flag must not inflate priority for cluster-scoped
    findings, matching Cluster.has_public_exposure semantics.
    """
    from core.models import Namespace

    rows = Namespace.objects.filter(cluster=cluster, active=True).values_list(
        "name", "internet_exposed", "contains_sensitive_data"
    )
    exposure_map = {}
    sensitive_map = {}
    for name, exposed, sensitive in rows:
        exposure_map[name] = exposed
        sensitive_map[name] = sensitive
    return PriorityContext(
        exposure_map=exposure_map,
        sensitive_map=sensitive_map,
        cluster_has_exposure=any(exposure_map.values()),
        cluster_has_sensitive=any(sensitive_map.values()),
    )


def _is_exposed(finding, cluster, ctx: PriorityContext | None = None) -> bool:
    """True if the finding's namespace is internet-exposed.

    Cluster-scoped findings (no namespace FK) fall back to the cluster
    rollup — exposed if ANY namespace in the cluster is exposed.
    """
    if finding.namespace_id is None:
        if ctx is not None:
            return ctx.cluster_has_exposure
        return cluster.has_public_exposure
    # Namespace-scoped finding
    if ctx is not None:
        name = finding.namespace.name if hasattr(finding, "_namespace_cache") else None
        # Prefer map lookup to avoid additional FK traversal
        ns_obj = getattr(finding, "namespace", None)
        if ns_obj is not None:
            return ctx.exposure_map.get(ns_obj.name, False)
        return False
    # No context → read from FK directly
    return bool(finding.namespace and finding.namespace.internet_exposed)


def _is_sensitive(finding, cluster, ctx: PriorityContext | None = None) -> bool:
    """True if the finding's namespace contains sensitive data.

    Cluster-scoped findings fall back to the cluster rollup — sensitive if
    ANY namespace in the cluster is sensitive.
    """
    if finding.namespace_id is None:
        if ctx is not None:
            return ctx.cluster_has_sensitive
        return cluster.has_sensitive_data
    if ctx is not None:
        ns_obj = getattr(finding, "namespace", None)
        if ns_obj is not None:
            return ctx.sensitive_map.get(ns_obj.name, False)
        return False
    return bool(finding.namespace and finding.namespace.contains_sensitive_data)


def compute_priority(finding, cluster, ctx: PriorityContext | None = None):
    """
    SSVC-inspired decision tree for action priority.

    Decision order (highest urgency first):
      1. KEV-listed → IMMEDIATE (any environment)
      2. High EPSS + exposed production → IMMEDIATE
      3. CRITICAL + exposed production → IMMEDIATE
      4. High EPSS + production (not exposed) → OUT-OF-CYCLE
      5. CRITICAL + production (not exposed) → OUT-OF-CYCLE
      6. HIGH + exposed production → OUT-OF-CYCLE
      7. CRITICAL + dev/staging → SCHEDULED
      8. HIGH + production (not exposed) → SCHEDULED
      9. HIGH/MEDIUM + sensitive data → SCHEDULED
     10. Everything else → DEFER
    """
    if cluster is None:
        return Priority.SCHEDULED

    if cluster.environment not in VALID_ENVIRONMENTS:
        logger.warning(
            "Cluster %s has unconfigured environment '%s' — priorities will degrade. "
            "Set it in Settings → Clusters.",
            cluster.name,
            cluster.environment,
        )

    # Threat signals (per-finding, automatic)
    kev = finding.kev_listed or False
    high_epss = (finding.epss_score or 0) > EPSS_HIGH_THRESHOLD
    critical = finding.severity == Severity.CRITICAL
    high = finding.severity == Severity.HIGH
    medium = finding.severity == Severity.MEDIUM

    # Deployment context
    production = cluster.environment == "prod"
    exposed = _is_exposed(finding, cluster, ctx) and production
    sensitive = _is_sensitive(finding, cluster, ctx)

    # Decision tree
    if kev:
        return Priority.IMMEDIATE
    if high_epss and exposed:
        return Priority.IMMEDIATE
    if critical and exposed:
        return Priority.IMMEDIATE
    if high_epss and production:
        return Priority.OUT_OF_CYCLE
    if critical and production:
        return Priority.OUT_OF_CYCLE
    if high and exposed:
        return Priority.OUT_OF_CYCLE
    if critical:
        return Priority.SCHEDULED
    if high and production:
        return Priority.SCHEDULED
    if (high or medium) and sensitive:
        return Priority.SCHEDULED
    return Priority.DEFER


def compute_priority_reason(finding, cluster):
    """Return a short human-readable reason for the computed priority."""
    if cluster is None:
        return "No cluster context"

    kev = finding.kev_listed or False
    high_epss = (finding.epss_score or 0) > EPSS_HIGH_THRESHOLD
    critical = finding.severity == Severity.CRITICAL
    high = finding.severity == Severity.HIGH
    medium = finding.severity == Severity.MEDIUM

    production = cluster.environment == "prod"
    exposed = _is_exposed(finding, cluster) and production
    sensitive = _is_sensitive(finding, cluster)

    if kev:
        return "Actively exploited (CISA KEV)"
    if high_epss and exposed:
        return "High exploit probability on exposed production"
    if critical and exposed:
        return "Critical severity on exposed production"
    if high_epss and production:
        return "High exploit probability in production"
    if critical and production:
        return "Critical severity in production"
    if high and exposed:
        return "High severity on exposed production"
    if critical:
        return "Critical severity in non-production"
    if high and production:
        return "High severity in production"
    if (high or medium) and sensitive:
        return "Significant severity with sensitive data"
    return "Low risk in deployment context"


def recalculate_cluster_priorities(cluster):
    """
    Bulk recalculate effective_priority for all active findings in a cluster.

    Called when cluster/namespace flags change or after enrichment.

    Pre-loads exposure/sensitivity maps once so we don't hit the DB per
    finding.  Returns the number of findings updated.
    """
    from core.models import Finding

    ctx = load_context(cluster)

    findings = (
        Finding.objects.filter(
            cluster=cluster,
            status__in=[Status.ACTIVE, Status.ACKNOWLEDGED],
        )
        .select_related("cluster", "namespace")
    )

    updates = []
    for finding in findings.iterator(chunk_size=1000):
        new_priority = compute_priority(finding, cluster, ctx)
        if finding.effective_priority != new_priority:
            finding.effective_priority = new_priority
            updates.append(finding)

    if updates:
        Finding.objects.bulk_update(updates, ["effective_priority"], batch_size=1000)

    logger.info(
        "Recalculated priorities for cluster %s: %d findings updated",
        cluster.name,
        len(updates),
    )
    return len(updates)


def recalculate_all_priorities():
    """Recalculate priorities across all clusters. Returns total updated."""
    from core.models import Cluster

    total = 0
    for cluster in Cluster.objects.all():
        total += recalculate_cluster_priorities(cluster)
    return total
