"""Ingest dispatch — parse one queued payload, apply to the DB.

`process_item(IngestQueue)` is the public entry point.
"""
from __future__ import annotations

from django.db import transaction
from django.utils import timezone

from core.constants import ImportMarkState
from core.models import (
    Cluster,
    Image,
    ImportMark,
    IngestQueue,
    Namespace,
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


# ── Helpers --------------------------------------------------------

def _get_cluster(name: str) -> Cluster | None:
    return Cluster.objects.filter(name=name).first()


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
        defaults={"ref": ref or "", "deployed": True},
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
        if image.os_version != parsed.get("os_version") or "":
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


# ── Top-level dispatch --------------------------------------------

def process_item(item: IngestQueue) -> dict:
    kind = item.kind
    if kind == "inventory":
        return _process_inventory(item)

    if kind in trivy_parser.PARSERS_BY_KIND:
        return _process_trivy_per_workload(item, trivy_parser.PARSERS_BY_KIND[kind])

    if kind in kyverno_parser.PARSERS_BY_KIND:
        return _process_kyverno(item)

    return {"skipped": "unknown_kind", "kind": kind}
