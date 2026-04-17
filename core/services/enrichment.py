"""
Enrichment service — EPSS scores and CISA KEV data.

Two daily cron jobs fetch external intelligence to enrich findings:
- EPSS: exploit probability per CVE (0.0-1.0)
- KEV: whether a CVE is actively exploited in the wild

Both use stdlib only (no requests/httpx) for zero extra dependencies.

See: docs/architecture.md § Enrichment Sources
"""
import csv
import gzip
import io
import json
import logging
from decimal import Decimal, InvalidOperation
from urllib.error import URLError
from urllib.request import Request, urlopen

from django.utils import timezone

logger = logging.getLogger(__name__)

EPSS_URL = "https://epss.cyentia.com/epss_scores-current.csv.gz"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


# ── EPSS ───────────────────────────────────────────────────────


def fetch_epss_scores(url: str = EPSS_URL) -> dict[str, Decimal]:
    """Download EPSS CSV and return {cve_id: score} dict.

    The CSV is gzipped, ~7MB compressed. Format:
      #model_version:v2024.01.01,score_date:2026-04-15
      cve,epss,percentile
      CVE-2024-1234,0.00091,0.38200
    """
    logger.info("Downloading EPSS scores from %s", url)

    req = Request(url, headers={"Accept-Encoding": "gzip"})
    try:
        with urlopen(req, timeout=60) as resp:
            raw = resp.read()
    except URLError as e:
        logger.error("Failed to download EPSS: %s", e)
        return {}

    # Decompress gzip
    try:
        data = gzip.decompress(raw).decode("utf-8")
    except Exception:
        # Maybe not gzipped (in tests)
        data = raw.decode("utf-8")

    scores = {}
    reader = csv.reader(io.StringIO(data))
    for row in reader:
        # Skip comments and header
        if not row or row[0].startswith("#") or row[0] == "cve":
            continue
        try:
            cve_id = row[0].strip()
            score = Decimal(row[1].strip())
            scores[cve_id] = score
        except (IndexError, InvalidOperation):
            continue

    logger.info("Parsed %d EPSS scores", len(scores))
    return scores


def apply_epss_scores(scores: dict[str, Decimal]) -> int:
    """Bulk update epss_score on findings with matching CVE IDs."""
    from core.models import Finding

    if not scores:
        return 0

    now = timezone.now()
    # Get all active CVE findings that have a vuln_id
    findings = Finding.objects.filter(
        vuln_id__startswith="CVE-",
    ).only("id", "vuln_id", "epss_score")

    updated = 0
    batch = []
    for f in findings.iterator(chunk_size=2000):
        score = scores.get(f.vuln_id)
        if score is not None and f.epss_score != score:
            f.epss_score = score
            batch.append(f)

        if len(batch) >= 2000:
            Finding.objects.bulk_update(batch, ["epss_score"], batch_size=2000)
            updated += len(batch)
            batch = []

    if batch:
        Finding.objects.bulk_update(batch, ["epss_score"], batch_size=2000)
        updated += len(batch)

    logger.info("Updated EPSS scores on %d findings", updated)
    return updated


def enrich_epss(url: str = EPSS_URL) -> dict:
    """Download EPSS and apply to findings. Recalculates priorities. Returns summary."""
    scores = fetch_epss_scores(url)
    updated = apply_epss_scores(scores)

    # Recalculate priorities since EPSS changes affect the decision tree
    priorities_updated = 0
    if updated > 0:
        from core.services.priority import recalculate_all_priorities

        priorities_updated = recalculate_all_priorities()
        logger.info("Recalculated %d priorities after EPSS update", priorities_updated)

    return {
        "scores_downloaded": len(scores),
        "findings_updated": updated,
        "priorities_recalculated": priorities_updated,
    }


# ── CISA KEV ───────────────────────────────────────────────────


def fetch_kev_cves(url: str = KEV_URL) -> set[str]:
    """Download CISA KEV JSON and return set of CVE IDs.

    JSON format:
      {"title": "...", "catalogVersion": "...",
       "vulnerabilities": [{"cveID": "CVE-2024-1234", ...}, ...]}
    """
    logger.info("Downloading CISA KEV from %s", url)

    req = Request(url, headers={"Accept": "application/json"})
    try:
        with urlopen(req, timeout=60) as resp:
            data = json.loads(resp.read())
    except URLError as e:
        logger.error("Failed to download KEV: %s", e)
        return set()
    except json.JSONDecodeError:
        logger.error("KEV response is not valid JSON")
        return set()

    cves = set()
    for vuln in data.get("vulnerabilities", []):
        cve_id = vuln.get("cveID", "")
        if cve_id:
            cves.add(cve_id)

    logger.info("Parsed %d KEV CVEs", len(cves))
    return cves


def apply_kev_flags(kev_cves: set[str]) -> dict:
    """Bulk update kev_listed on findings. Sets True for matches, False for non-matches."""
    from core.models import Finding

    if not kev_cves:
        return {"marked_kev": 0, "cleared_kev": 0}

    # Mark matching findings as KEV-listed
    marked = Finding.objects.filter(
        vuln_id__in=kev_cves,
    ).exclude(kev_listed=True).update(kev_listed=True)

    # Clear KEV flag on findings no longer in the list
    cleared = Finding.objects.filter(
        kev_listed=True,
        vuln_id__startswith="CVE-",
    ).exclude(vuln_id__in=kev_cves).update(kev_listed=False)

    logger.info("KEV: %d marked, %d cleared", marked, cleared)
    return {"marked_kev": marked, "cleared_kev": cleared}


def enrich_kev(url: str = KEV_URL) -> dict:
    """Download KEV and apply to findings. Recalculates priorities. Returns summary."""
    kev_cves = fetch_kev_cves(url)
    result = apply_kev_flags(kev_cves)
    result["kev_cves_downloaded"] = len(kev_cves)

    # Recalculate priorities since KEV changes affect the decision tree
    total_changed = result["marked_kev"] + result["cleared_kev"]
    if total_changed > 0:
        from core.services.priority import recalculate_all_priorities

        result["priorities_recalculated"] = recalculate_all_priorities()
        logger.info(
            "Recalculated %d priorities after KEV update",
            result["priorities_recalculated"],
        )
    else:
        result["priorities_recalculated"] = 0

    return result
