"""Supply-chain matcher.

Joins `SupplyChainIoc × SbomComponent × WorkloadImageObservation
(currently_deployed=True)` and emits one `Finding` per (workload,
advisory_id, purl) tuple.

The matcher does **not** write to `Finding` directly. It builds finding
dicts and calls `core.services.dedup.upsert_findings`, which:

- computes `hash_code` via `compute_hash` (workload-scoped),
- folds in EPSS/KEV enrichment (no-op for MAL-/GHSA- IDs),
- runs `apply_score` to set `effective_priority`,
- handles the lifecycle (create / bump last_seen).

The supply-chain `effective_priority` short-circuit lives in
`core.urgency.score` so any new Finding with `category=supply_chain`
lands as IMMEDIATE.
"""
from __future__ import annotations

from collections.abc import Iterable, Iterator

from django.db.models import Q
from django.utils import timezone

from core.constants import Category, Severity, Source
from core.models import SbomComponent, SupplyChainIoc, WorkloadImageObservation
from core.models.sbom_component import name_purl_expr
from core.purl import normalize_purl, parse_purl_name_version
from core.services.dedup import upsert_findings

# Purls per `IN (...)` when intersecting the feed's touched purls with the
# SBOM table. npm's MAL-* feed touches 100k+ purls per cycle.
_PURL_CHUNK_SIZE = 5000


def _chunked(items: Iterable, size: int) -> Iterator[list]:
    chunk: list = []
    for item in items:
        chunk.append(item)
        if len(chunk) >= size:
            yield chunk
            chunk = []
    if chunk:
        yield chunk


def _is_sentinel(purl: str) -> bool:
    """A name-only IoC purl (`pkg:npm/foo`, no version): the advisory
    covers every version of the package. Stored by the OSV loader when an
    advisory has no explicit versions (`ranges: [{introduced: "0"}]`)."""
    _name, version = parse_purl_name_version(purl)
    return not version


def _components():
    """SbomComponent rows annotated with `name_purl` (purl minus the
    trailing `@version`, backed by the `sbomcomp_name_purl` functional
    index) so a sentinel IoC matches every version of its package."""
    return SbomComponent.objects.annotate(name_purl=name_purl_expr())


def _deployed_among(touched: set[str]) -> set[str]:
    """`touched ∩ {purls in SbomComponent}`, computed by Postgres one
    chunk of `touched` at a time. Sentinel purls are intersected with the
    components' name purls. The result is bounded by the number of
    malicious purls actually deployed — normally a handful."""
    found: set[str] = set()
    for chunk in _chunked(sorted(touched), _PURL_CHUNK_SIZE):
        exact = [p for p in chunk if not _is_sentinel(p)]
        sentinels = [p for p in chunk if _is_sentinel(p)]
        if exact:
            found.update(
                SbomComponent.objects.filter(purl__in=exact).values_list("purl", flat=True).distinct()
            )
        if sentinels:
            found.update(
                _components().filter(name_purl__in=sentinels)
                .values_list("name_purl", flat=True).distinct()
            )
    return found


def match_iocs_to_components(
    touched_purls: Iterable[str] | None = None,
) -> int:
    """Match IoCs against currently-deployed components, upsert Findings.

    Args:
        touched_purls: Restrict the join to these purls (incremental
            mode, called from fetchers with the purls they just
            upserted). Pass None for a full re-scan.

    Returns:
        Count of Findings created + updated.
    """
    # The matcher only emits Findings for purls a deployed component
    # carries, so IoCs are restricted to that intersection — and the
    # intersection stays in SQL. The previous `set(SbomComponent.values_
    # list("purl").distinct())` pulled every distinct purl of a multi-GB
    # table into Python strings on each hourly run, which was the largest
    # allocation of the OSV job.
    if touched_purls is not None:
        touched = {normalize_purl(p) for p in touched_purls if p}
        if not touched:
            return 0
        deployed = _deployed_among(touched)
        if not deployed:
            return 0
        ioc_qs = SupplyChainIoc.objects.filter(purl__in=deployed)
    else:
        # Semi-joins: versioned IoCs against component purls, sentinels
        # against the components' name purls.
        ioc_qs = SupplyChainIoc.objects.filter(
            Q(purl__in=SbomComponent.objects.values("purl"))
            | Q(purl__in=_components().values("name_purl"))
        )

    # `raw` is the full advisory JSON and is never read by the matcher.
    # Loading it dominates row memory for npm scans.
    ioc_qs = ioc_qs.defer("raw")

    iocs_by_purl: dict[str, list[SupplyChainIoc]] = {}
    for ioc in ioc_qs.iterator(chunk_size=2000):
        iocs_by_purl.setdefault(ioc.purl, []).append(ioc)
    if not iocs_by_purl:
        return 0

    exact_keys = [p for p in iocs_by_purl if not _is_sentinel(p)]
    sentinel_keys = [p for p in iocs_by_purl if _is_sentinel(p)]
    comp_qs = (
        _components()
        .filter(Q(purl__in=exact_keys) | Q(name_purl__in=sentinel_keys))
        .select_related("image")
    )
    total = 0
    now = timezone.now()

    for comp in comp_qs:
        matched = list(iocs_by_purl.get(comp.purl, ()))
        if comp.name_purl != comp.purl:
            matched += iocs_by_purl.get(comp.name_purl, ())
        if not matched:
            continue
        observations = list(
            WorkloadImageObservation.objects
            .filter(image=comp.image, currently_deployed=True)
            .select_related("workload", "workload__cluster")
        )
        if not observations:
            continue

        finding_dicts = []
        for ioc in matched:
            finding_dicts.append({
                "source": Source.SUPPLY_CHAIN_IOC.value,
                "category": Category.SUPPLY_CHAIN.value,
                "vuln_id": ioc.advisory_id,
                "pkg_name": comp.name,
                "installed_version": comp.version,
                "fixed_version": "",
                "title": (
                    f"Malicious package: {comp.name}@{comp.version} "
                    f"({ioc.feed_source}:{ioc.advisory_id})"
                )[:512],
                "severity": ioc.severity or Severity.CRITICAL.value,
                "cvss_score": None,
                "cvss_vector": "",
                "details": {
                    "purl": comp.purl,
                    "ecosystem": comp.ecosystem,
                    "feed_source": ioc.feed_source,
                    "advisory_id": ioc.advisory_id,
                    "advisory_url": ioc.advisory_url,
                    "summary": ioc.summary,
                    "published_at": (
                        ioc.published_at.isoformat() if ioc.published_at else None
                    ),
                },
            })

        for obs in observations:
            workload = obs.workload
            created, updated = upsert_findings(
                cluster=workload.cluster,
                workload=workload,
                image=comp.image,
                findings=finding_dicts,
                observation_time=now,
            )
            total += created + updated

    return total
