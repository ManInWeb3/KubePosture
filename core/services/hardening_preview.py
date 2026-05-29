"""Hardening preview — "what-if" priority scoring for a candidate image.

A sec engineer hardening a container can produce a Trivy CLI scan
(`trivy image --format json my-image:tag`) but has no way to see what
`effective_priority` each finding would get in a real workload's context
without deploying first. This service answers that question without any
database writes: it parses the CLI JSON, runs each vulnerability through
the same `core.urgency.score` pipeline used at ingest, and returns a list
of unsaved priority results plus per-band counts.

The result is stashed in the Django session (per-user) so the workload
detail page can render it as an ephemeral "candidate" image row.
"""
from __future__ import annotations

import secrets
import time
from collections import Counter
from dataclasses import dataclass

from core.constants import PriorityBand, Severity, Source
from core.models import EpssScore, Finding, KevEntry, Workload
from core.parsers.trivy import parse_trivy_cli_vulnerabilities
from core.urgency import apply_score

# Matches inventory.order_findings — preview rows are sorted the same way the
# real findings panel does it, so users don't have to scroll past low-priority
# CLI-order rows to find the IMMEDIATE ones.
_PRIORITY_RANK = {
    PriorityBand.IMMEDIATE.value: 0,
    PriorityBand.OUT_OF_BAND.value: 1,
    PriorityBand.SCHEDULED.value: 2,
    PriorityBand.DEFER.value: 3,
}
_SEVERITY_RANK = {
    Severity.CRITICAL.value: 0,
    Severity.HIGH.value: 1,
    Severity.MEDIUM.value: 2,
    Severity.LOW.value: 3,
    Severity.INFO.value: 4,
    Severity.UNKNOWN.value: 5,
}

SESSION_PREFIX = "hardening_preview"
SESSION_TTL_SECONDS = 30 * 60
_CANDIDATE_PREFIX = "candidate:"


@dataclass(frozen=True)
class PreviewResult:
    candidate_id: str          # short token used in URLs
    digest: str                # "candidate:<token>" — sentinel digest for the image row
    image_ref: str             # ArtifactName from the CLI JSON (display)
    findings: list[dict]       # render-ready dicts; see `_serialize_finding`
    counts: dict[str, int]     # priority-band → count (all 4 bands present)
    total: int


# ── Parser shape detection ───────────────────────────────────────


def is_trivy_cli_json(obj: object) -> bool:
    """True iff the document looks like a raw Trivy CLI scan."""
    return isinstance(obj, dict) and isinstance(obj.get("Results"), list)


# ── Batch enrichment ─────────────────────────────────────────────


def batch_enrichment(vuln_ids):
    """One query each against EpssScore + KevEntry for a list of CVE ids.

    Returns:
        (epss_map, kev_set)
        epss_map: {vuln_id: (score, percentile)}
        kev_set: {vuln_id, ...}
    """
    cve_ids = [v for v in set(vuln_ids) if v and v.startswith("CVE-")]
    if not cve_ids:
        return {}, set()
    epss_rows = EpssScore.objects.filter(vuln_id__in=cve_ids).values_list(
        "vuln_id", "score", "percentile",
    )
    epss_map = {v: (s, p) for v, s, p in epss_rows}
    kev_set = set(
        KevEntry.objects.filter(vuln_id__in=cve_ids).values_list(
            "vuln_id", flat=True,
        )
    )
    return epss_map, kev_set


# ── Core ─────────────────────────────────────────────────────────


def preview_trivy_cli_scan(workload: Workload, cli_json: dict) -> PreviewResult:
    """Score CLI-scan vulnerabilities as if they ran in `workload`.

    No DB writes. Workload must be loaded with `signals` prefetched so
    `apply_score` does not issue N queries.
    """
    parsed = parse_trivy_cli_vulnerabilities(cli_json)
    finding_dicts = parsed["findings"]

    epss_map, kev_set = batch_enrichment([f["vuln_id"] for f in finding_dicts])

    rendered: list[dict] = []
    bands = Counter()
    for fd in finding_dicts:
        vuln_id = fd["vuln_id"]
        epss_score, epss_percentile = epss_map.get(vuln_id, (None, None))
        kev = vuln_id in kev_set

        # Unsaved Finding bound to the target workload's relations. urgency.score
        # reads only attributes — no DB writes happen here, even if .save() is
        # never called.
        f = Finding(
            source=Source.TRIVY.value,
            category=fd["category"],
            vuln_id=vuln_id,
            pkg_name=fd["pkg_name"],
            installed_version=fd["installed_version"],
            fixed_version=fd["fixed_version"],
            title=fd["title"][:512],
            severity=fd["severity"],
            cvss_score=fd.get("cvss_score"),
            cvss_vector=fd.get("cvss_vector") or "",
            details=fd.get("details") or {},
            epss_score=epss_score,
            epss_percentile=epss_percentile,
            kev_listed=kev,
            workload=workload,
            cluster=workload.cluster,
            image=None,
        )
        apply_score(f)
        bands[f.effective_priority] += 1
        rendered.append(_serialize_finding(f))

    counts = {b.value: int(bands.get(b.value, 0)) for b in PriorityBand}

    rendered.sort(key=lambda r: (
        _PRIORITY_RANK.get(r["effective_priority"], 99),
        _SEVERITY_RANK.get(r["severity"], 99),
        -(r["epss_score"] or 0.0),
    ))

    candidate_id = secrets.token_urlsafe(8)
    return PreviewResult(
        candidate_id=candidate_id,
        digest=_CANDIDATE_PREFIX + candidate_id,
        image_ref=parsed.get("artifact_name") or "candidate image",
        findings=rendered,
        counts=counts,
        total=sum(counts.values()),
    )


def _serialize_finding(f: Finding) -> dict:
    """Subset of Finding attributes the workload findings panel renders.

    Templates access via dot-notation, which falls through to dict keys, so
    no model instance is needed downstream. `pk=None` lets the row template's
    detail-link guard skip the HTMX offcanvas link.
    """
    return {
        "pk": None,
        "vuln_id": f.vuln_id,
        "title": f.title,
        "pkg_name": f.pkg_name,
        "installed_version": f.installed_version,
        "fixed_version": f.fixed_version,
        "severity": f.severity,
        "effective_priority": f.effective_priority,
        "epss_score": f.epss_score,
        "kev_listed": f.kev_listed,
    }


# ── Session stash ────────────────────────────────────────────────


def _session_key(workload_id: int, candidate_id: str) -> str:
    return f"{SESSION_PREFIX}:{workload_id}:{candidate_id}"


def stash(request, workload_id: int, result: PreviewResult) -> None:
    request.session[_session_key(workload_id, result.candidate_id)] = {
        "candidate_id": result.candidate_id,
        "digest": result.digest,
        "image_ref": result.image_ref,
        "findings": result.findings,
        "counts": result.counts,
        "total": result.total,
        "ts": time.time(),
    }
    request.session.modified = True


def load(request, workload_id: int, candidate_id: str) -> PreviewResult | None:
    """Return the stashed preview if it exists and is within TTL.

    Stale entries are removed on read so the session does not grow indefinitely.
    """
    key = _session_key(workload_id, candidate_id)
    entry = request.session.get(key)
    if not entry:
        return None
    if time.time() - float(entry.get("ts", 0)) > SESSION_TTL_SECONDS:
        request.session.pop(key, None)
        request.session.modified = True
        return None
    return PreviewResult(
        candidate_id=entry["candidate_id"],
        digest=entry["digest"],
        image_ref=entry["image_ref"],
        findings=entry["findings"],
        counts=entry["counts"],
        total=entry["total"],
    )


def clear(request, workload_id: int, candidate_id: str) -> None:
    request.session.pop(_session_key(workload_id, candidate_id), None)
    request.session.modified = True


def is_candidate_digest(digest: str | None) -> bool:
    return bool(digest) and digest.startswith(_CANDIDATE_PREFIX)


def candidate_id_from_digest(digest: str) -> str:
    return digest[len(_CANDIDATE_PREFIX):] if is_candidate_digest(digest) else ""
