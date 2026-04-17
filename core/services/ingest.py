"""
Ingest orchestrator — the central entry point for all scanner data.

Flow:
  1. Detect envelope format (verb + operatorObject), unwrap if present
  2. Extract kind and cluster name
  3. Auto-register cluster (Convention D2)
  4. Dispatch to parser via KIND_ROUTER
  5. Dedup + upsert + resolve stale
  6. Update ScanStatus
  7. Return summary

See: docs/architecture.md § Data Flow
"""
import logging

from django.db import transaction
from django.utils import timezone

from core.constants import Source, Status
from core.parsers import KIND_ROUTER
from core.parsers.metadata import parse_cluster_meta
from core.services.dedup import resolve_stale, upsert_findings

logger = logging.getLogger(__name__)


class IngestError(Exception):
    """Raised when ingest fails due to bad data."""


def get_or_create_cluster(name: str):
    """Auto-register cluster on first ingest (Convention D2)."""
    from core.models import Cluster

    meta = parse_cluster_meta(name)
    cluster, created = Cluster.objects.get_or_create(
        name=name,
        defaults={
            "provider": meta.get("provider", "unknown"),
            "environment": meta.get("environment", "unknown"),
            "region": meta.get("region", ""),
            "project": meta.get("project", ""),
        },
    )
    if created:
        logger.info("Auto-registered cluster: %s (%s)", name, meta)
    return cluster


def _unwrap_envelope(payload: dict) -> tuple[str | None, dict]:
    """Handle webhook envelope format (OPERATOR_SEND_DELETED_REPORTS).

    Returns (verb, crd_payload). If no envelope, returns (None, original).
    """
    if "operatorObject" in payload and "verb" in payload:
        return payload["verb"], payload["operatorObject"]
    return None, payload


def _extract_cluster_name(payload: dict, header_value: str | None) -> str:
    """Extract cluster name from header or CRD metadata labels."""
    if header_value:
        return header_value

    # Try to get from CRD metadata
    labels = payload.get("metadata", {}).get("labels", {})
    # Trivy sets cluster name in some label configurations
    for key in ("trivy-operator.cluster.name", "cluster"):
        if key in labels:
            return labels[key]

    raise IngestError(
        "Cluster name required: set X-Cluster-Name header or include in CRD metadata"
    )


def ingest_scan(payload: dict, cluster_name_header: str | None = None) -> dict:
    """Main ingest entry point.

    Args:
        payload: Raw CRD JSON (or envelope with verb + operatorObject)
        cluster_name_header: Value of X-Cluster-Name header (optional)

    Returns:
        Summary dict with counts and metadata
    """
    from core.models import RawReport, ScanStatus

    # 1. Unwrap envelope
    verb, crd = _unwrap_envelope(payload)
    if verb == "delete":
        logger.debug("Ignoring delete webhook event")
        return {"status": "skipped", "reason": "delete event"}

    # 2. Extract kind
    kind = crd.get("kind", "")
    if not kind:
        raise IngestError("Missing 'kind' field in CRD payload")

    # 3. Find parser
    parser = KIND_ROUTER.get(kind)
    if not parser:
        raise IngestError(f"Unknown CRD kind: {kind}")

    # 4. Extract cluster name
    cluster_name = _extract_cluster_name(crd, cluster_name_header)
    cluster = get_or_create_cluster(cluster_name)

    # 5. Parse
    finding_dicts = parser(cluster_name, crd)

    # 6a. Handle compliance reports — structured processing
    if finding_dicts and finding_dicts[0].get("_compliance"):
        from core.services.compliance import save_compliance_snapshot

        return save_compliance_snapshot(cluster, finding_dicts[0], crd)

    # 6b. Handle SBOM reports — component upsert
    if finding_dicts and finding_dicts[0].get("_sbom"):
        from core.services.sbom import save_sbom_components

        return save_sbom_components(cluster, finding_dicts[0])

    # 6c. Handle raw storage (future CRD types)
    if finding_dicts and finding_dicts[0].get("_store_raw"):
        raw_kind = finding_dicts[0].get("kind", kind)
        RawReport.objects.create(
            cluster=cluster,
            kind=raw_kind,
            source=Source.TRIVY,
            raw_json=crd,
        )
        logger.info("Stored raw %s for %s", raw_kind, cluster_name)
        return {
            "status": "stored_raw",
            "cluster": cluster_name,
            "kind": raw_kind,
            "source": Source.TRIVY,
        }

    # 7. Handle Kyverno PolicyReport — mixed findings + summary
    kyverno_summary = None
    if finding_dicts and finding_dicts[-1].get("_kyverno_summary"):
        kyverno_summary = finding_dicts.pop()
        # Remaining items are finding dicts (failures only)

    # 8. Detect source from findings
    source = Source.TRIVY
    if finding_dicts and finding_dicts[0].get("source") == Source.KYVERNO:
        source = Source.KYVERNO

    # 9-12: Upsert + resolve stale + snapshot + scan status — all in one transaction
    # If any step fails, everything rolls back (no orphaned findings).
    from core.models import Finding

    with transaction.atomic():
        # 9. Dedup + upsert findings
        stats = upsert_findings(cluster, source, finding_dicts)

        # 10. Resolve stale findings — scoped to the same resource
        # Skip for Kyverno: a PolicyReport spans multiple resources,
        # so per-resource stale resolution doesn't apply per-CRD.
        hashes = stats.pop("hashes")
        scope = stats.pop("scope")
        resolved = 0
        if source == Source.TRIVY and scope:
            resolved = resolve_stale(cluster, source, hashes, scope)

        # 11. Save Kyverno PolicyComplianceSnapshot if present
        if kyverno_summary:
            from core.models.kyverno import PolicyComplianceSnapshot

            now = timezone.now()
            results_data = kyverno_summary.get("results", [])
            PolicyComplianceSnapshot.objects.create(
                cluster=cluster,
                scanned_at=now,
                total_pass=kyverno_summary["total_pass"],
                total_fail=kyverno_summary["total_fail"],
                total_warn=kyverno_summary["total_warn"],
                total_skip=kyverno_summary["total_skip"],
                pass_rate=kyverno_summary["pass_rate"],
                raw_json={"results": results_data},
            )

        # 12. Update ScanStatus
        now = timezone.now()
        ScanStatus.objects.update_or_create(
            cluster=cluster,
            source=source,
            defaults={
                "last_ingest": now,
                "finding_count": Finding.objects.filter(
                    cluster=cluster, source=source, status=Status.ACTIVE
                ).count(),
            },
        )

    result = {
        "status": "success",
        "cluster": cluster_name,
        "kind": kind,
        "source": source,
        "created": stats["created"],
        "updated": stats["updated"],
        "reactivated": stats["reactivated"],
        "resolved": resolved,
    }
    logger.info(
        "Ingested %s from %s: %d created, %d updated, %d reactivated, %d resolved",
        kind,
        cluster_name,
        stats["created"],
        stats["updated"],
        stats["reactivated"],
        resolved,
    )
    return result
