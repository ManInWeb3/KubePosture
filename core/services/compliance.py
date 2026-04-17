"""
Compliance service — creates Snapshots and ControlResults from parsed data.

Called by the ingest orchestrator when a ClusterComplianceReport is received.
Also provides backfill_raw_reports() to process Phase 1 RawReport entries.
"""
import logging

from django.utils import timezone

from core.models.compliance import (
    CheckType,
    Control,
    ControlResult,
    ControlStatus,
    Framework,
    Snapshot,
)

logger = logging.getLogger(__name__)


def _get_or_create_framework(data: dict) -> Framework:
    """Get or create a Framework from parsed compliance data.

    Uses slug from framework_id. Updates title/description/version if changed.
    """
    slug = data["framework_id"]
    defaults = {
        "name": data.get("framework_title", slug),
        "description": data.get("framework_description", ""),
        "version": data.get("framework_version", ""),
        "source": "trivy",
    }

    framework, created = Framework.objects.get_or_create(
        slug=slug, defaults=defaults
    )
    if not created:
        # Update metadata if it changed (e.g. Trivy Operator upgrade)
        changed = False
        for field, value in defaults.items():
            if value and getattr(framework, field) != value:
                setattr(framework, field, value)
                changed = True
        if changed:
            framework.save()

    return framework


def _ensure_controls(framework: Framework, spec_controls: list[dict]) -> dict[str, Control]:
    """Ensure Control records exist for this framework.

    Creates controls from the CRD spec.compliance.controls section.
    Returns a dict mapping control_id -> Control for quick lookup.
    """
    existing = {c.control_id: c for c in framework.controls.all()}

    for sc in spec_controls:
        cid = sc["control_id"]
        if cid in existing:
            continue
        check_ids = sc.get("check_ids", [])
        existing[cid] = Control.objects.create(
            framework=framework,
            control_id=cid,
            title=sc.get("name", ""),
            description=sc.get("description", ""),
            severity=sc.get("severity", "Medium"),
            check_type=CheckType.AUTOMATED if check_ids else CheckType.MANUAL,
            check_ids=check_ids,
        )

    # Update total_controls
    total = framework.controls.count()
    if framework.total_controls != total:
        framework.total_controls = total
        framework.save(update_fields=["total_controls"])

    return existing


def save_compliance_snapshot(cluster, data: dict, raw_json: dict) -> dict:
    """Create a Snapshot + ControlResults from parsed compliance data.

    Args:
        cluster: Cluster model instance
        data: Parsed dict from parse_trivy_compliance (with _compliance=True)
        raw_json: Original CRD payload for audit storage

    Returns:
        Summary dict for ingest response
    """
    framework = _get_or_create_framework(data)
    controls_map = _ensure_controls(framework, data.get("spec_controls", []))

    now = timezone.now()
    snapshot = Snapshot.objects.create(
        cluster=cluster,
        framework=framework,
        scanned_at=now,
        total_pass=data["total_pass"],
        total_fail=data["total_fail"],
        pass_rate=data["pass_rate"],
        raw_json=raw_json,
    )

    # Create ControlResults
    results_created = 0
    for cr in data.get("controls", []):
        control = controls_map.get(cr["control_id"])
        if not control:
            logger.warning(
                "Control %s not found in framework %s — skipping result",
                cr["control_id"],
                framework.slug,
            )
            continue

        status_map = {
            "PASS": ControlStatus.PASS,
            "FAIL": ControlStatus.FAIL,
            "MANUAL": ControlStatus.MANUAL,
        }
        ControlResult.objects.create(
            snapshot=snapshot,
            control=control,
            status=status_map.get(cr["status"], ControlStatus.MANUAL),
            total_pass=cr.get("total_pass", 0),
            total_fail=cr.get("total_fail", 0),
        )
        results_created += 1

    logger.info(
        "Compliance snapshot: %s / %s — %d/%d pass (%s%%), %d control results",
        cluster.name,
        framework.slug,
        data["total_pass"],
        data["total_pass"] + data["total_fail"],
        data["pass_rate"],
        results_created,
    )

    return {
        "status": "success",
        "cluster": cluster.name,
        "kind": "ClusterComplianceReport",
        "source": "trivy",
        "framework": framework.slug,
        "pass_rate": str(data["pass_rate"]),
        "controls_processed": results_created,
    }


def backfill_raw_reports(cluster_name: str | None = None) -> dict:
    """Backfill Phase 1 RawReport compliance entries into structured models.

    Processes all RawReport entries with kind=ClusterComplianceReport
    that haven't been parsed yet. Optionally filter by cluster name.

    Returns summary dict with counts.
    """
    from core.models import Cluster, RawReport
    from core.parsers.trivy import parse_trivy_compliance
    from core.services.ingest import get_or_create_cluster

    qs = RawReport.objects.filter(kind="ClusterComplianceReport")
    if cluster_name:
        qs = qs.filter(cluster__name=cluster_name)

    processed = 0
    errors = 0
    for raw in qs.select_related("cluster"):
        try:
            parsed = parse_trivy_compliance(raw.cluster.name, raw.raw_json)
            if parsed and parsed[0].get("_compliance"):
                save_compliance_snapshot(raw.cluster, parsed[0], raw.raw_json)
                processed += 1
        except Exception:
            logger.exception(
                "Failed to backfill compliance report %d for %s",
                raw.id,
                raw.cluster.name,
            )
            errors += 1

    logger.info("Backfilled %d compliance reports (%d errors)", processed, errors)
    return {"processed": processed, "errors": errors}
