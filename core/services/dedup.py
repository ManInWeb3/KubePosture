"""Finding dedup + bulk upsert.

Dedup hash per dev_docs/03-data-model.md *Finding — Dedup key*.
"""
from __future__ import annotations

import hashlib
from collections.abc import Iterable

from django.db import transaction

from core.models import (
    Cluster,
    EpssScore,
    Finding,
    Image,
    KevEntry,
    Workload,
)
from core.urgency import apply_score


def compute_hash(
    *,
    source: str,
    category: str,
    vuln_id: str,
    workload_id: int | None,
    cluster_name: str,
    image_digest: str,
    pkg_name: str,
    installed_version: str,
) -> str:
    if workload_id is not None:
        parts = (
            source,
            category,
            vuln_id,
            str(workload_id),
            image_digest or "",
            pkg_name or "",
            installed_version or "",
        )
    else:
        parts = (
            source,
            category,
            vuln_id,
            cluster_name,
            pkg_name or "",
            installed_version or "",
        )
    h = hashlib.sha256()
    h.update("|".join(parts).encode("utf-8"))
    return h.hexdigest()


def _enrichment_for(vuln_id: str) -> dict:
    """Look up enrichment values for a fresh Finding upsert.

    Returns a dict of fields ready to merge into the Finding defaults.
    """
    out = {
        "epss_score": None,
        "epss_percentile": None,
        "kev_listed": False,
    }
    if not vuln_id:
        return out
    if vuln_id.startswith("CVE-"):
        epss = EpssScore.objects.filter(vuln_id=vuln_id).first()
        if epss:
            out["epss_score"] = epss.score
            out["epss_percentile"] = epss.percentile
        if KevEntry.objects.filter(vuln_id=vuln_id).exists():
            out["kev_listed"] = True
    return out


@transaction.atomic
def upsert_findings(
    *,
    cluster: Cluster,
    workload: Workload | None,
    image: Image | None,
    findings: Iterable[dict],
    observation_time,
) -> tuple[int, int]:
    """Bulk-upsert finding dicts. Returns (created, updated) counts.

    Each finding dict needs:
      source, category, vuln_id, pkg_name, installed_version,
      fixed_version, title, severity, cvss_score, cvss_vector, details
    """
    created = 0
    updated = 0
    cluster_name = cluster.name

    for f in findings:
        hc = compute_hash(
            source=f["source"],
            category=f["category"],
            vuln_id=f.get("vuln_id") or "",
            workload_id=workload.id if workload else None,
            cluster_name=cluster_name,
            image_digest=image.digest if image else "",
            pkg_name=f.get("pkg_name") or "",
            installed_version=f.get("installed_version") or "",
        )
        defaults = {
            "cluster": cluster,
            "workload": workload,
            "image": image,
            "category": f["category"],
            "vuln_id": f.get("vuln_id") or "",
            "pkg_name": f.get("pkg_name") or "",
            "installed_version": f.get("installed_version") or "",
            "fixed_version": f.get("fixed_version") or "",
            "title": f["title"][:512],
            "severity": f["severity"],
            "cvss_score": f.get("cvss_score"),
            "cvss_vector": f.get("cvss_vector") or "",
            "details": f.get("details") or {},
        }
        # Fold in enrichment values.
        defaults.update(_enrichment_for(defaults["vuln_id"]))

        existing = Finding.objects.filter(source=f["source"], hash_code=hc).first()
        if existing is None:
            obj = Finding(
                source=f["source"],
                hash_code=hc,
                first_seen=observation_time,
                last_seen=observation_time,
                **defaults,
            )
            apply_score(obj)
            obj.save()
            created += 1
        else:
            for k, v in defaults.items():
                setattr(existing, k, v)
            if existing.last_seen is None or observation_time > existing.last_seen:
                existing.last_seen = observation_time
            apply_score(existing)
            existing.save()
            updated += 1

    return created, updated
