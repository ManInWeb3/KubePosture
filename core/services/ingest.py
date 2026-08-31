"""Ingest dispatch — parse one queued payload, apply to the DB.

`process_item(IngestQueue)` is the public entry point.
"""
from __future__ import annotations

import logging

from django.db import transaction
from django.utils import timezone

from core.models import (
    Cluster,
    Image,
    ImportMark,
    IngestQueue,
    Namespace,
    SbomComponent,
    Workload,
    WorkloadAlias,
    WorkloadImageObservation,
    WorkloadSignal,
)
from core.parsers import inventory as inventory_parser
from core.parsers import kyverno as kyverno_parser
from core.parsers import trivy as trivy_parser
from core.services.dedup import upsert_findings
from core.signals import SIGNALS

log = logging.getLogger("core.ingest")


# ── Helpers --------------------------------------------------------

def _get_cluster(name: str) -> Cluster | None:
    return Cluster.objects.filter(name=name).first()


def _fit(model: type, field_name: str, value: str | None) -> str:
    """Truncate a string to the model field's max_length.

    Upstream CycloneDX data occasionally exceeds our CharField limits
    (e.g. generated component names, multi-value license/supplier
    strings) — truncate rather than let the whole item fail with an
    unhandled DataError.
    """
    value = value or ""
    max_length = model._meta.get_field(field_name).max_length
    return value[:max_length] if max_length else value


def _get_or_create_image(*, ref: str, digest: str) -> Image | None:
    """Return / create an Image row keyed by digest. Empty digest → None.

    Don't overwrite a longer-already-stored ref with a shorter one —
    the inventory typically has the fully-qualified ref while Trivy's
    artifact often omits the registry. Same digest, different display
    forms; we keep the more informative one.
    """
    if not digest:
        return None
    img, _ = Image.objects.get_or_create(
        digest=digest,
        defaults={"ref": ref or ""},
    )
    if ref and ref != img.ref and len(ref) > len(img.ref or ""):
        img.ref = ref
        img.save(update_fields=["ref"])
    return img


def _resolve_workload(
    cluster: Cluster, namespace_name: str, kind: str, name: str
) -> Workload | None:
    """Walk alias chain to top-level workload. Returns None if not found."""
    if not name:
        return None
    ns = Namespace.objects.filter(cluster=cluster, name=namespace_name).first()
    if ns is None and namespace_name:
        return None  # cluster-scoped namespace = ""
    if ns is not None:
        wl = Workload.objects.filter(
            cluster=cluster, namespace=ns, kind=kind, name=name
        ).first()
        if wl:
            return wl
    # Try alias.
    alias = WorkloadAlias.objects.filter(
        cluster=cluster,
        namespace=ns,
        alias_kind=kind,
        alias_name=name,
    ).select_related("target_workload").first() if ns else None
    if alias:
        return alias.target_workload
    return None


def _upsert_signal(workload: Workload, signal_id: str) -> None:
    if signal_id not in SIGNALS:
        return
    obj = WorkloadSignal.objects.filter(workload=workload, signal_id=signal_id).first()
    if obj:
        obj.currently_active = True
        obj.save(update_fields=["currently_active", "last_seen_at"])
    else:
        WorkloadSignal.objects.create(
            workload=workload,
            signal_id=signal_id,
            currently_active=True,
        )


# ── Per-kind handlers ---------------------------------------------

@transaction.atomic
def _process_inventory(item: IngestQueue) -> dict:
    cluster = _get_cluster(item.cluster_name)
    if cluster is None:
        return {"skipped": "cluster_not_registered"}

    mark = ImportMark.objects.filter(
        cluster=cluster, kind="inventory", import_id=item.import_id
    ).first()
    if mark is None:
        # Should be unreachable: a mark always transitions to `draining`
        # (see ImportMark docstring) before the worker can claim any of
        # its queue items. Falling back to "now" rather than failing
        # loudly silently masks that invariant being violated — surface
        # it so a real occurrence gets noticed.
        log.warning(
            "ingest.inventory.missing_mark",
            extra={"cluster": cluster.name, "import_id": item.import_id},
        )
    started_at = mark.started_at if mark else timezone.now()

    staging = inventory_parser.parse_envelope(item.raw_json or {}, cluster)
    counters = inventory_parser.persist(staging, mark_started_at=started_at)
    return counters


def _process_trivy_per_workload(item: IngestQueue, parser_func) -> dict:
    cluster = _get_cluster(item.cluster_name)
    if cluster is None:
        return {"skipped": "cluster_not_registered"}
    parsed = parser_func(item.raw_json or {})
    if not parsed:
        return {"skipped": "empty"}

    workload = None
    if not parsed.get("cluster_scoped"):
        workload = _resolve_workload(
            cluster,
            parsed.get("namespace") or "",
            parsed.get("resource_kind") or "",
            parsed.get("resource_name") or "",
        )
        if workload is None and parsed.get("namespace"):
            return {"skipped": "workload_not_resolved", "kind": item.kind}

    image = _get_or_create_image(
        ref=parsed.get("image_ref") or "",
        digest=parsed.get("image_digest") or "",
    )
    if image and workload:
        WorkloadImageObservation.objects.get_or_create(
            workload=workload,
            image=image,
            container_name=parsed.get("container_name") or "",
        )

    # ConfigAuditReport produces signal upserts, not Findings — its
    # `findings` list is dropped here. Other Trivy kinds emit findings
    # normally.
    findings_to_upsert: list = []
    if item.kind != "trivy.ConfigAuditReport":
        findings_to_upsert = parsed.get("findings") or []

    created, updated = upsert_findings(
        cluster=cluster,
        workload=workload,
        image=image,
        findings=findings_to_upsert,
        observation_time=item.created_at or timezone.now(),
    )

    # Signal upserts (ConfigAudit / RBAC reports).
    if workload:
        for sid in parsed.get("signal_ids") or set():
            _upsert_signal(workload, sid)

    # Image OS metadata (Vuln reports).
    if image and parsed.get("os_family"):
        changed_fields = []
        if image.os_family != parsed["os_family"]:
            image.os_family = parsed["os_family"]
            changed_fields.append("os_family")
        if image.os_version != (parsed.get("os_version") or ""):
            image.os_version = parsed.get("os_version") or ""
            changed_fields.append("os_version")
        if image.base_eosl != parsed.get("base_eosl", False):
            image.base_eosl = parsed.get("base_eosl", False)
            changed_fields.append("base_eosl")
        if changed_fields:
            image.save(update_fields=changed_fields)

    return {"created": created, "updated": updated}


def _process_kyverno(item: IngestQueue) -> dict:
    """Kyverno PolicyReport → WorkloadSignal upserts only.

    Kyverno fail-results don't produce Finding rows in v1 (Findings come
    from vuln / secret / RBAC scans). The fail tells us a registry
    signal is currently active on the targeted workload.
    """
    cluster = _get_cluster(item.cluster_name)
    if cluster is None:
        return {"skipped": "cluster_not_registered"}
    parsed = kyverno_parser.parse_policy_report(item.raw_json or {})
    if not parsed["results"]:
        return {"signals_set": 0}

    signals_set = 0
    for r in parsed["results"]:
        sub_kind, sub_name = r["subject"]
        sub_ns = r["namespace_for_subject"]
        sig_id = r["signal_id"]

        if not sig_id:
            continue
        if sub_kind in ("ClusterRole", "ClusterRoleBinding") or not sub_ns:
            # Cluster-scoped policy result has no workload to attach a
            # signal to in v1; skip silently.
            continue

        workload = _resolve_workload(cluster, sub_ns, sub_kind, sub_name)
        if workload is None:
            continue

        _upsert_signal(workload, sig_id)
        signals_set += 1

    return {"signals_set": signals_set}


def _process_sbom(item: IngestQueue, parser_func) -> dict:
    """Trivy SbomReport → SbomComponent rows keyed by (image, purl).

    The CRD ships the image's full CycloneDX BOM. We persist one row per
    (image, purl); cluster/workload activity is derived later via
    `WorkloadImageObservation.currently_deployed`, so we don't touch
    those tables here. The workload only matters for image observation
    upsert (so the image is linked to a workload even if Trivy scanned
    it before inventory observed the workload).
    """
    cluster = _get_cluster(item.cluster_name)
    if cluster is None:
        return {"skipped": "cluster_not_registered"}
    parsed = parser_func(item.raw_json or {})
    if not parsed:
        return {"skipped": "empty"}

    image = _get_or_create_image(
        ref=parsed.get("image_ref") or "",
        digest=parsed.get("image_digest") or "",
    )
    if image is None:
        return {"skipped": "no_image_digest"}

    workload = _resolve_workload(
        cluster,
        parsed.get("namespace") or "",
        parsed.get("resource_kind") or "",
        parsed.get("resource_name") or "",
    )
    if workload:
        WorkloadImageObservation.objects.get_or_create(
            workload=workload,
            image=image,
            container_name=parsed.get("container_name") or "",
        )

    components = parsed.get("components") or []
    created, updated = 0, 0
    # Sorted by purl so concurrent workers upserting overlapping images'
    # components acquire row locks in the same relative order — the
    # SbomComponent unique key is (image, purl), and update_or_create's
    # internal select_for_update() deadlocks when two transactions lock
    # the same two rows in reverse order (see core.services.worker's
    # deadlock retry, which recovers whatever this doesn't prevent).
    for c in sorted(components, key=lambda comp: comp["purl"]):
        _, was_created = SbomComponent.objects.update_or_create(
            image=image,
            purl=_fit(SbomComponent, "purl", c["purl"]),
            defaults={
                "name": _fit(SbomComponent, "name", c["name"]),
                "version": _fit(SbomComponent, "version", c["version"]),
                "ecosystem": _fit(SbomComponent, "ecosystem", c["ecosystem"]),
                "component_type": _fit(SbomComponent, "component_type", c["component_type"]),
                "supplier": _fit(SbomComponent, "supplier", c["supplier"]),
                "license": _fit(SbomComponent, "license", c["license"]),
                "layer_digest": _fit(SbomComponent, "layer_digest", c["layer_digest"]),
                "raw": c["raw"],
            },
        )
        if was_created:
            created += 1
        else:
            updated += 1

    return {"components": len(components), "created": created, "updated": updated}


# ── Top-level dispatch --------------------------------------------

def process_item(item: IngestQueue) -> dict:
    kind = item.kind
    if kind == "inventory":
        return _process_inventory(item)

    if kind == "trivy.SbomReport":
        return _process_sbom(item, trivy_parser.PARSERS_BY_KIND[kind])

    if kind in trivy_parser.PARSERS_BY_KIND:
        return _process_trivy_per_workload(item, trivy_parser.PARSERS_BY_KIND[kind])

    if kind in kyverno_parser.PARSERS_BY_KIND:
        return _process_kyverno(item)

    return {"skipped": "unknown_kind", "kind": kind}
