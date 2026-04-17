"""
Deduplication engine — hash computation, upsert, stale resolution.

Extracted from DefectDojo (BSD-3 licensed) and simplified for K8s-only use case.
See: docs/architecture.md § Deduplication Algorithm

Key insight: Trivy sends one CRD per resource (e.g., VulnerabilityReport for
ReplicaSet/backend-xyz). resolve_stale must be scoped to that specific resource,
not the entire cluster — otherwise ingesting report B resolves report A's findings.
"""
import hashlib
import logging

from django.db import IntegrityError, transaction
from django.utils import timezone

from core.constants import Origin, Status

logger = logging.getLogger(__name__)


def compute_hash(finding_dict: dict) -> str:
    """Compute dedup hash from K8s identity fields.

    hash = sha256(source|title|severity|vuln_id|namespace|resource_kind|resource_name)
    All inputs are column fields (not from JSONB details).
    """
    parts = "|".join(
        [
            str(finding_dict.get("source", "")),
            str(finding_dict.get("title", "")),
            str(finding_dict.get("severity", "")),
            str(finding_dict.get("vuln_id", "")),
            str(finding_dict.get("namespace", "")),
            str(finding_dict.get("resource_kind", "")),
            str(finding_dict.get("resource_name", "")),
        ]
    )
    return hashlib.sha256(parts.encode()).hexdigest()


def upsert_findings(cluster, source: str, finding_dicts: list[dict]) -> dict:
    """Upsert findings by (origin, cluster, hash_code).

    Uses select_for_update() to prevent race conditions when multiple
    queue workers process findings for the same resource concurrently.

    Returns: {"created": int, "updated": int, "reactivated": int,
              "hashes": set, "scope": dict}
    The scope identifies the resource this batch covers (for resolve_stale).
    """
    from core.models import Finding
    from core.services.priority import compute_priority

    now = timezone.now()
    stats = {"created": 0, "updated": 0, "reactivated": 0}
    seen_hashes = set()

    # Extract scope from first finding — all findings in a CRD share the same resource
    scope = {}
    if finding_dicts:
        first = finding_dicts[0]
        scope = {
            "namespace": first.get("namespace", ""),
            "resource_kind": first.get("resource_kind", ""),
            "resource_name": first.get("resource_name", ""),
            "category": first.get("category", ""),
        }

    for fd in finding_dicts:
        hash_code = compute_hash(fd)
        seen_hashes.add(hash_code)

        with transaction.atomic():
            try:
                existing = Finding.objects.select_for_update().get(
                    origin=Origin.CLUSTER, cluster=cluster, hash_code=hash_code
                )

                if existing.status == Status.RESOLVED:
                    existing.status = Status.ACTIVE
                    existing.resolved_at = None
                    existing.last_seen = now
                    existing.details = fd.get("details", {})
                    existing.effective_priority = compute_priority(existing, cluster)
                    existing.save(
                        update_fields=[
                            "status", "resolved_at", "last_seen", "details",
                            "effective_priority",
                        ]
                    )
                    stats["reactivated"] += 1
                elif existing.status in (Status.ACTIVE, Status.ACKNOWLEDGED):
                    existing.last_seen = now
                    existing.details = fd.get("details", {})
                    existing.effective_priority = compute_priority(existing, cluster)
                    existing.save(
                        update_fields=["last_seen", "details", "effective_priority"]
                    )
                    stats["updated"] += 1
                else:
                    # risk_accepted or false_positive — update last_seen only
                    existing.last_seen = now
                    existing.save(update_fields=["last_seen"])
                    stats["updated"] += 1

            except Finding.DoesNotExist:
                try:
                    finding = Finding(
                        origin=Origin.CLUSTER,
                        cluster=cluster,
                        namespace=fd.get("namespace", ""),
                        resource_kind=fd.get("resource_kind", ""),
                        resource_name=fd.get("resource_name", ""),
                        title=fd["title"],
                        severity=fd["severity"],
                        vuln_id=fd.get("vuln_id", ""),
                        category=fd["category"],
                        source=source,
                        status=Status.ACTIVE,
                        hash_code=hash_code,
                        details=fd.get("details", {}),
                    )
                    finding.effective_priority = compute_priority(finding, cluster)
                    finding.save()
                    stats["created"] += 1
                except IntegrityError:
                    # Concurrent worker created the same finding — treat as update
                    existing = Finding.objects.get(
                        origin=Origin.CLUSTER, cluster=cluster, hash_code=hash_code
                    )
                    existing.last_seen = now
                    existing.save(update_fields=["last_seen"])
                    stats["updated"] += 1

    stats["hashes"] = seen_hashes
    stats["scope"] = scope
    return stats


def resolve_stale(cluster, source: str, current_hashes: set[str], scope: dict) -> int:
    """Resolve findings for the same resource that are not in the current batch.

    Scoped to (cluster, source, namespace, resource_kind, resource_name, category)
    so ingesting a VulnerabilityReport for resource A doesn't resolve findings
    from resource B.

    Skips cluster-level reports (empty namespace + resource_kind) to avoid
    incorrectly resolving unrelated findings.

    Only resolves active/acknowledged findings.
    Does NOT touch risk_accepted or false_positive.
    """
    from core.models import Finding

    if not scope:
        return 0

    # Don't resolve stale for cluster-level reports where scope is too broad
    if not scope.get("namespace") and not scope.get("resource_name"):
        logger.debug(
            "Skipping stale resolution for cluster-level scope: %s/%s",
            cluster.name,
            scope.get("category", ""),
        )
        return 0

    now = timezone.now()
    stale_qs = Finding.objects.filter(
        origin=Origin.CLUSTER,
        cluster=cluster,
        source=source,
        namespace=scope["namespace"],
        resource_kind=scope["resource_kind"],
        resource_name=scope["resource_name"],
        category=scope["category"],
        status__in=[Status.ACTIVE, Status.ACKNOWLEDGED],
    ).exclude(hash_code__in=current_hashes)

    count = stale_qs.update(status=Status.RESOLVED, resolved_at=now)
    if count:
        logger.info(
            "Resolved %d stale %s findings for %s/%s/%s",
            count,
            scope["category"],
            cluster.name,
            scope["namespace"],
            scope["resource_name"],
        )
    return count
