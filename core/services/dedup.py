"""Finding dedup + bulk upsert.

Dedup hash per dev_docs/03-data-model.md *Finding — Dedup key*.
"""
from __future__ import annotations

import hashlib
from collections.abc import Iterable

from django.db import IntegrityError, transaction

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

        if _upsert_one_finding(
            source=f["source"], hash_code=hc,
            defaults=defaults, observation_time=observation_time,
        ):
            created += 1
        else:
            updated += 1

    return created, updated


def _upsert_one_finding(
    *, source: str, hash_code: str, defaults: dict, observation_time,
) -> bool:
    """Race-safe create-or-update for one (source, hash_code) Finding.
    Returns True if created, False if an existing row was updated.

    Two different IngestQueue items — plausibly claimed and processed
    by two different worker pods at once — can resolve to the same
    dedup key. The previous plain SELECT-then-INSERT/UPDATE was
    vulnerable two ways: a lost update (the `last_seen = max(...)`
    monotonicity check compared against each worker's own stale
    in-memory read, so it could regress), and a hard failure (the
    unique constraint rejects the second concurrent INSERT, raising
    IntegrityError, which propagated up through `_process_one` and
    failed the WHOLE queue item — silently dropping every finding in
    that payload with no automatic retry).

    `select_for_update()` serializes concurrent UPDATEs to the same row
    (the second transaction blocks until the first commits, then reads
    the now-current row), making the monotonic last_seen check safe.
    The nested `atomic()` + IntegrityError retry handles the
    create/create race the same way Django's own `get_or_create` does:
    if a concurrent transaction wins the INSERT first, this savepoint
    rolls back cleanly and a second attempt finds the row via SELECT.
    """
    for attempt in range(2):
        existing = (
            Finding.objects.select_for_update()
            .filter(source=source, hash_code=hash_code)
            .first()
        )
        if existing is not None:
            for k, v in defaults.items():
                setattr(existing, k, v)
            if existing.last_seen is None or observation_time > existing.last_seen:
                existing.last_seen = observation_time
            apply_score(existing)
            existing.save()
            return False

        try:
            with transaction.atomic():
                obj = Finding(
                    source=source,
                    hash_code=hash_code,
                    first_seen=observation_time,
                    last_seen=observation_time,
                    **defaults,
                )
                apply_score(obj)
                obj.save()
            return True
        except IntegrityError:
            if attempt == 0:
                continue
            raise
    raise AssertionError("unreachable")  # pragma: no cover
