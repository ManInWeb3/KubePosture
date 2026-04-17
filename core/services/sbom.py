"""
SBOM service — bulk upsert Components from parsed SbomReport data.

Convention D4: Latest state only. Each ingest replaces the previous
component list for that cluster+image (delete absent, upsert present).

Called by the ingest orchestrator when a SbomReport is received.
Also provides backfill_raw_sbom() to process Phase 1 RawReport entries.
"""
import logging

from django.utils import timezone

from core.models.sbom import Component

logger = logging.getLogger(__name__)


def save_sbom_components(cluster, data: dict) -> dict:
    """Upsert components from parsed SBOM data.

    Uses update_or_create per component. Components not in the current
    report for this cluster+image are deleted (Convention D4: latest state).

    Args:
        cluster: Cluster model instance
        data: Parsed dict from parse_trivy_sbom (with _sbom=True)

    Returns:
        Summary dict for ingest response
    """
    image = data.get("image", "")
    namespace = data.get("namespace", "")
    resource_name = data.get("resource_name", "")
    components = data.get("components", [])

    if not image:
        logger.warning("SbomReport missing image reference, skipping")
        return {"status": "skipped", "reason": "no image reference"}

    now = timezone.now()
    created = 0
    updated = 0

    seen_pks = set()
    for comp in components:
        if not comp.get("name") or not comp.get("version"):
            continue

        obj, was_created = Component.objects.update_or_create(
            cluster=cluster,
            image=image,
            name=comp["name"],
            version=comp["version"],
            defaults={
                "namespace": namespace,
                "resource_name": resource_name,
                "component_type": comp.get("component_type", "library"),
                "purl": comp.get("purl", ""),
                "licenses": comp.get("licenses", []),
            },
        )
        seen_pks.add(obj.pk)
        if was_created:
            created += 1
        else:
            updated += 1

    # Delete components for this cluster+image that are no longer in the BOM
    deleted, _ = (
        Component.objects.filter(cluster=cluster, image=image)
        .exclude(pk__in=seen_pks)
        .delete()
    )

    logger.info(
        "SBOM %s/%s: %d created, %d updated, %d removed (%d total components)",
        cluster.name,
        image,
        created,
        updated,
        deleted,
        len(components),
    )

    return {
        "status": "success",
        "cluster": cluster.name,
        "kind": "SbomReport",
        "source": "trivy",
        "image": image,
        "components_created": created,
        "components_updated": updated,
        "components_removed": deleted,
    }


def backfill_raw_sbom(cluster_name: str | None = None) -> dict:
    """Backfill Phase 1 RawReport SBOM entries into Component model.

    Processes all RawReport entries with kind=SbomReport.
    Optionally filter by cluster name.
    """
    from core.models import RawReport
    from core.parsers.trivy import parse_trivy_sbom

    qs = RawReport.objects.filter(kind="SbomReport")
    if cluster_name:
        qs = qs.filter(cluster__name=cluster_name)

    processed = 0
    errors = 0
    for raw in qs.select_related("cluster"):
        try:
            parsed = parse_trivy_sbom(raw.cluster.name, raw.raw_json)
            if parsed and parsed[0].get("_sbom"):
                save_sbom_components(raw.cluster, parsed[0])
                processed += 1
        except Exception:
            logger.exception(
                "Failed to backfill SBOM report %d for %s",
                raw.id,
                raw.cluster.name,
            )
            errors += 1

    logger.info("Backfilled %d SBOM reports (%d errors)", processed, errors)
    return {"processed": processed, "errors": errors}
