"""
Effective priority — SSVC-inspired decision tree.

Combines scanner severity + threat intelligence (EPSS, KEV) + deployment
context (cluster environment, internet exposure) to produce an action priority.

Cluster flags are required (admin-set). Namespace overrides are optional —
they inherit from the cluster default when not set.

See: docs/vulnerability-misconfiguration-management.md § KubePosture Coverage Matrix
"""
import logging

from core.constants import EPSS_HIGH_THRESHOLD, Priority, Severity, Status

logger = logging.getLogger(__name__)


def _is_exposed(cluster, namespace):
    """Check if namespace is internet-exposed, with override inheritance."""
    if namespace and cluster.namespace_overrides:
        override = cluster.namespace_overrides.get(namespace)
        if override and "internet_exposed" in override:
            return override["internet_exposed"]
    return cluster.internet_exposed


def _is_sensitive(cluster, namespace):
    """Check if namespace contains sensitive data, with override inheritance."""
    if namespace and cluster.namespace_overrides:
        override = cluster.namespace_overrides.get(namespace)
        if override and "contains_sensitive_data" in override:
            return override["contains_sensitive_data"]
    return cluster.contains_sensitive_data


def compute_priority(finding, cluster):
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

    # Threat signals (per-finding, automatic)
    kev = finding.kev_listed or False
    high_epss = (finding.epss_score or 0) > EPSS_HIGH_THRESHOLD
    critical = finding.severity == Severity.CRITICAL
    high = finding.severity == Severity.HIGH
    medium = finding.severity == Severity.MEDIUM

    # Deployment context (cluster + namespace override)
    production = cluster.environment == "prod"
    exposed = _is_exposed(cluster, finding.namespace) and production
    sensitive = _is_sensitive(cluster, finding.namespace)

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
    exposed = _is_exposed(cluster, finding.namespace) and production
    sensitive = _is_sensitive(cluster, finding.namespace)

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

    Called when cluster flags (internet_exposed, contains_sensitive_data,
    namespace_overrides) change.

    Returns the number of findings updated.
    """
    from core.models import Finding

    findings = Finding.objects.filter(
        cluster=cluster,
        status__in=[Status.ACTIVE, Status.ACKNOWLEDGED],
    ).select_related("cluster")

    updates = []
    for finding in findings.iterator(chunk_size=1000):
        new_priority = compute_priority(finding, cluster)
        if finding.effective_priority != new_priority:
            finding.effective_priority = new_priority
            updates.append(finding)

    if updates:
        Finding.objects.bulk_update(updates, ["effective_priority"], batch_size=1000)

    logger.info(
        "Recalculated priorities for cluster %s: %d/%d findings updated",
        cluster.name,
        len(updates),
        findings.count() if not updates else len(updates),
    )
    return len(updates)


def recalculate_all_priorities():
    """Recalculate priorities across all clusters. Returns total updated."""
    from core.models import Cluster

    total = 0
    for cluster in Cluster.objects.all():
        total += recalculate_cluster_priorities(cluster)
    return total
