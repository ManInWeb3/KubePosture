"""OSV vulnerability matcher.

Joins `OsvAffected × SbomComponent × WorkloadImageObservation
(currently_deployed=True)` and emits one `Finding(source="osv",
category="vulnerability")` per (workload, image, package@version, vuln).

Gap-fill, not a second opinion: a component already carried by an open
Trivy finding for the same workload / image / package / version — under
any of the advisory's ids (CVE, GHSA, GO…) — is skipped, otherwise every
CVE Trivy reports would appear twice. Where Trivy has no report for an
image (its VulnerabilityReport is missing or failed) the OSV lane is the
only coverage.

Runs in two places: per image at SBOM ingest (`core.services.ingest`),
which keeps `last_seen` in step with the inventory cycle like Trivy's
own reports do, and fleet-wide after each feed refresh
(`enrichment.refresh_osv`) so new advisories reach already-stored SBOMs
without a rescan. Findings leave the default views the usual way: once
nothing bumps `last_seen` past the cluster's next complete inventory.
"""
from __future__ import annotations

import logging
from collections import defaultdict
from collections.abc import Iterable, Iterator

from django.utils import timezone

from core.constants import Category, Severity, Source
from core.models import Finding, Image, OsvAffected, SbomComponent, WorkloadImageObservation
from core.osv_ranges import describe_blocks, evaluate
from core.purl import normalize_purl, parse_purl_name_version
from core.services.dedup import upsert_findings

log = logging.getLogger("core.osv_matcher")

# purl types the OSV bulk feed covers (keys of enrichment.PURL_TO_OSV;
# repeated here to avoid importing the fetcher into the matcher).
SUPPORTED_PURL_TYPES = frozenset({
    "npm", "pypi", "golang", "cargo", "gem", "maven", "nuget", "hex", "composer",
})

_COMPONENT_CHUNK = 2000
# Enumerated affected versions kept on a finding when the advisory has no
# ranges: PyPI / Maven list every affected release, and the list is stored
# once per finding.
_MAX_AFFECTED_VERSIONS = 50
_SEVERITY_RANK = {
    Severity.CRITICAL.value: 4, Severity.HIGH.value: 3, Severity.MEDIUM.value: 2,
    Severity.LOW.value: 1, Severity.INFO.value: 0, Severity.UNKNOWN.value: -1, "": -1,
}


def package_name(purl_type: str, name: str) -> str:
    """The package name as both sides are compared: OSV's `package.name`
    convention per ecosystem. Maven is `group:artifact`, PyPI is
    PEP 503-normalised, Go module paths are lower-cased (Trivy writes
    `github.com/datadog/dd-trace-go/v2` in the purl, OSV and Trivy's own
    vuln reports keep `DataDog`), the rest are used as published."""
    if purl_type == "maven":
        return name.replace("/", ":", 1) if "/" in name and ":" not in name else name
    if purl_type == "pypi":
        return name.lower().replace("_", "-").replace(".", "-")
    if purl_type == "golang":
        return name.lower()
    return name


def _component_key(comp: SbomComponent) -> tuple[str, str, str]:
    """`(purl_type, name, version)` derived from the purl — the one field
    every producer fills consistently."""
    purl = normalize_purl(comp.purl)
    name, version = parse_purl_name_version(purl)
    return comp.ecosystem, package_name(comp.ecosystem, name), version or comp.version


def _chunked(items: Iterable, size: int) -> Iterator[list]:
    chunk: list = []
    for item in items:
        chunk.append(item)
        if len(chunk) >= size:
            yield chunk
            chunk = []
    if chunk:
        yield chunk


def _affected_rows(keys: set[tuple[str, str]]) -> dict[tuple[str, str], list[OsvAffected]]:
    """Live (non-withdrawn) affected blocks for these `(purl_type, name)`
    pairs, one `IN (...)` per purl type."""
    by_type: dict[str, set[str]] = defaultdict(set)
    for purl_type, name in keys:
        by_type[purl_type].add(name)
    out: dict[tuple[str, str], list[OsvAffected]] = defaultdict(list)
    for purl_type, names in by_type.items():
        rows = (
            OsvAffected.objects
            .filter(purl_type=purl_type, name__in=names, advisory__withdrawn_at__isnull=True)
            .select_related("advisory")
        )
        for row in rows:
            out[(purl_type, row.name)].append(row)
    return out


def _vuln_id(ids: set[str]) -> str:
    """CVE wins so the EPSS / KEV join and Trivy's own naming line up;
    otherwise the advisory's own id."""
    cves = sorted(i for i in ids if i.startswith("CVE-"))
    return cves[0] if cves else min(ids)


def _trivy_coverage(workload_id: int, image_id: int) -> set[tuple[str, str, str]]:
    """`{(vuln_id, pkg_name, installed_version)}` Trivy already reports for
    this workload / image."""
    rows = Finding.objects.filter(
        source=Source.TRIVY.value, category=Category.VULNERABILITY.value,
        workload_id=workload_id, image_id=image_id,
    ).values_list("vuln_id", "pkg_name", "installed_version")
    out = set()
    for vuln_id, pkg, ver in rows:
        out.add((vuln_id, pkg, ver))
        out.add((vuln_id, pkg, ver.lstrip("v")))
    return out


def _matches_for_image(components: list[SbomComponent], affected: dict) -> list[dict]:
    """Finding dicts (without the Trivy filter) for one image's components,
    one per (component, vuln) — several advisories for the same CVE
    (GHSA + PYSEC) merge into one."""
    out: list[dict] = []
    for comp in components:
        purl_type, name, version = _component_key(comp)
        rows = affected.get((purl_type, name))
        if not rows:
            continue
        by_vuln: dict[str, dict] = {}
        for row in rows:
            res = evaluate(version, versions=row.versions or [], ranges=row.ranges or [])
            if res.unsupported:
                log.debug("osv_matcher.unsupported",
                          extra={"purl": comp.purl, "osv_id": row.advisory_id})
            if not res.affected:
                continue
            adv = row.advisory
            ids = adv.ids
            key = _vuln_id(ids)
            m = by_vuln.setdefault(key, {
                "ids": set(), "osv_ids": set(), "fixed": "", "severity": "",
                "cvss_vector": "", "summary": "", "references": [], "blocks": [],
            })
            m["ids"] |= ids
            m["osv_ids"].add(adv.osv_id)
            m["fixed"] = m["fixed"] or res.fixed_version
            if _SEVERITY_RANK.get(adv.severity, -1) > _SEVERITY_RANK.get(m["severity"], -1):  # noqa: E501
                m["severity"] = adv.severity
            m["cvss_vector"] = m["cvss_vector"] or adv.cvss_vector
            m["summary"] = m["summary"] or adv.summary
            m["references"] = m["references"] or list(adv.references or [])
            m["blocks"].append({"versions": row.versions or [], "ranges": row.ranges or []})
        for vuln_id, m in by_vuln.items():
            severity = m["severity"] or Severity.UNKNOWN.value
            affected_versions, affected_ranges = describe_blocks(m["blocks"])
            if affected_ranges:
                # The intervals say it all; PyPI / Maven also enumerate
                # every release inside them.
                affected_versions = []
            title = f"{vuln_id}: {m['summary']}" if m["summary"] else f"{vuln_id} in {comp.name}"
            out.append({
                "source": Source.OSV.value,
                "category": Category.VULNERABILITY.value,
                "vuln_id": vuln_id,
                "pkg_name": comp.name,
                "installed_version": comp.version,
                "fixed_version": m["fixed"],
                "title": title[:512],
                "severity": severity,
                "cvss_score": None,
                "cvss_vector": m["cvss_vector"][:128],
                "details": {
                    "purl": comp.purl,
                    "ecosystem": comp.ecosystem,
                    "osv_ids": sorted(m["osv_ids"]),
                    "aliases": sorted(m["ids"] - {vuln_id}),
                    "references": m["references"][:5],
                    "affected_versions": affected_versions[:_MAX_AFFECTED_VERSIONS],
                    "affected_ranges": affected_ranges,
                    "summary": m["summary"],
                    "primary_link": f"https://osv.dev/vulnerability/{sorted(m['osv_ids'])[0]}",
                },
                "_ids": m["ids"],
            })
    return out


def _emit(image: Image, matches: list[dict], now) -> int:
    observations = list(
        WorkloadImageObservation.objects
        .filter(image=image, currently_deployed=True)
        .select_related("workload", "workload__cluster")
    )
    if not observations:
        return 0
    total = 0
    for obs in observations:
        workload = obs.workload
        covered = _trivy_coverage(workload.id, image.id)
        dicts = []
        for m in matches:
            if any((i, m["pkg_name"], m["installed_version"]) in covered for i in m["_ids"]):
                continue
            dicts.append({k: v for k, v in m.items() if k != "_ids"})
        if not dicts:
            continue
        created, updated = upsert_findings(
            cluster=workload.cluster, workload=workload, image=image,
            findings=dicts, observation_time=now,
        )
        total += created + updated
    return total


def match_osv_vulns(*, image: Image | None = None) -> int:
    """Match deployed SBOM components against the OSV advisory tables and
    upsert findings. `image` restricts the run to that image (SBOM ingest);
    without it every currently-deployed component is matched.

    Returns the number of findings created + updated.
    """
    comps = SbomComponent.objects.filter(ecosystem__in=SUPPORTED_PURL_TYPES)
    comps = comps.filter(image=image) if image is not None else comps.active()
    comps = comps.select_related("image").order_by("image_id", "id")

    now = timezone.now()
    total = 0
    for chunk in _chunked(comps.iterator(chunk_size=_COMPONENT_CHUNK), _COMPONENT_CHUNK):
        # One lookup of the advisory tables per chunk, then per-image emission.
        affected = _affected_rows({_component_key(c)[:2] for c in chunk})
        if not affected:
            continue
        by_image: dict[int, list[SbomComponent]] = defaultdict(list)
        for c in chunk:
            by_image[c.image_id].append(c)
        for image_id, components in by_image.items():
            matches = _matches_for_image(components, affected)
            if matches:
                total += _emit(components[0].image, matches, now)
    log.info(
        "osv_matcher.done",
        extra={"image": image.digest if image else "all", "findings_touched": total},
    )
    return total
