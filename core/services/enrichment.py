"""Enrichment loaders — file-driven and HTTP-driven.

Each loader applies the universal zero-input no-op rule: an empty or
unreadable input skips the removal phase so existing rows stay intact.
"""
from __future__ import annotations

import csv
import gzip
import io
import json
import logging
import os
import socket
import tempfile
import time
import zipfile
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from django.db import transaction
from django.utils import timezone

from core.constants import Severity
from core.models import (
    EpssScore,
    FeedFetchState,
    Finding,
    KevEntry,
    SbomComponent,
    SupplyChainIoc,
)
from core.purl import normalize_purl
from core.urgency import recompute_batch

log = logging.getLogger("core.enrichment")


# ── HTTP fetch ────────────────────────────────────────────────────

EPSS_URL = "https://epss.cyentia.com/epss_scores-current.csv.gz"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
OSV_ZIP_URL = "https://osv-vulnerabilities.storage.googleapis.com/{eco}/all.zip"
# Aikido's old public feed (intel.aikido.dev/api/?format=json) was retired
# in favour of an OAuth-gated endpoint at
# app.aikido.dev/api/public/v1/research/malware/packages — so there is no
# longer a working out-of-the-box URL. Operators wanting Aikido coverage
# must set AIKIDO_INTEL_URL to a feed they can read (private mirror,
# internal proxy, or org-specific compatible shape). Leaving the default
# empty makes the cron a no-op instead of a 404 loop.
AIKIDO_INTEL_URL_DEFAULT = ""

# purl ecosystem (as stored on SbomComponent.ecosystem) → OSV bulk-zip path.
PURL_TO_OSV = {
    "npm": "npm",
    "pypi": "PyPI",
    "golang": "Go",
    "gomod": "Go",
    "cargo": "crates.io",
    "gem": "RubyGems",
    "maven": "Maven",
    "nuget": "NuGet",
    "hex": "Hex",
    "composer": "Packagist",
}

_HTTP_TIMEOUT = 60
_HTTP_MAX_ATTEMPTS = 3
_HTTP_BACKOFF_BASE = 1.5
_USER_AGENT = "kubepostureng-enrichment/1.0"


def _http_get(url: str) -> bytes | None:
    """Fetch `url` with retries. Returns None on persistent failure
    so callers honour the zero-input no-op rule.
    """
    last_err = ""
    for attempt in range(1, _HTTP_MAX_ATTEMPTS + 1):
        try:
            req = Request(url, headers={"User-Agent": _USER_AGENT})
            with urlopen(req, timeout=_HTTP_TIMEOUT) as resp:
                return resp.read()
        except HTTPError as e:
            last_err = f"HTTP {e.code}"
            if 400 <= e.code < 500:
                break  # don't retry client errors
        except (URLError, socket.timeout) as e:
            last_err = f"transport: {e}"

        if attempt < _HTTP_MAX_ATTEMPTS:
            time.sleep(_HTTP_BACKOFF_BASE * (2 ** (attempt - 1)))

    log.warning("enrichment.fetch.failed url=%s last_err=%s", url, last_err)
    return None


def _http_get_conditional(url: str, *, state_key: str) -> bytes | None:
    """Fetch `url` with If-Modified-Since / If-None-Match headers from
    `FeedFetchState[state_key]`. Returns:
      - bytes on 200 (and persists new ETag/Last-Modified)
      - None on 304, network failure, or non-2xx
    """
    state = FeedFetchState.objects.filter(state_key=state_key).first()
    headers = {"User-Agent": _USER_AGENT}
    if state and state.etag:
        headers["If-None-Match"] = state.etag
    if state and state.last_modified:
        headers["If-Modified-Since"] = state.last_modified

    last_err = ""
    for attempt in range(1, _HTTP_MAX_ATTEMPTS + 1):
        try:
            req = Request(url, headers=headers)
            with urlopen(req, timeout=_HTTP_TIMEOUT) as resp:
                body = resp.read()
                etag = resp.headers.get("ETag", "")
                last_modified = resp.headers.get("Last-Modified", "")
                FeedFetchState.objects.update_or_create(
                    state_key=state_key,
                    defaults={
                        "etag": etag,
                        "last_modified": last_modified,
                        "last_success_at": timezone.now(),
                    },
                )
                return body
        except HTTPError as e:
            if e.code == 304:
                log.info("enrichment.fetch.not_modified url=%s", url)
                return None
            last_err = f"HTTP {e.code}"
            if 400 <= e.code < 500:
                break
        except (URLError, socket.timeout) as e:
            last_err = f"transport: {e}"

        if attempt < _HTTP_MAX_ATTEMPTS:
            time.sleep(_HTTP_BACKOFF_BASE * (2 ** (attempt - 1)))

    log.warning("enrichment.fetch.failed url=%s last_err=%s", url, last_err)
    return None


def fetch_epss() -> int:
    """Download the latest EPSS dump (gzipped CSV), apply via the
    file loader. Returns the number of rows upserted (0 on failure).
    """
    body = _http_get(EPSS_URL)
    if body is None:
        return 0
    try:
        text = gzip.decompress(body).decode("utf-8", errors="replace")
    except OSError:
        log.warning("enrichment.epss.gunzip_failed")
        return 0
    with tempfile.NamedTemporaryFile("w", suffix=".csv", delete=False) as tmp:
        tmp.write(text)
        tmp_path = tmp.name
    try:
        return load_epss_from_file(tmp_path)
    finally:
        Path(tmp_path).unlink(missing_ok=True)


def fetch_kev() -> int:
    """Download the latest CISA KEV catalog JSON, apply via the file
    loader. Returns the number of rows upserted (0 on failure).
    """
    body = _http_get(KEV_URL)
    if body is None:
        return 0
    text = body.decode("utf-8", errors="replace")
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as tmp:
        tmp.write(text)
        tmp_path = tmp.name
    try:
        return load_kev_from_file(tmp_path)
    finally:
        Path(tmp_path).unlink(missing_ok=True)


# ── EPSS ----------------------------------------------------------

def load_epss_from_file(path: str) -> int:
    """Accepts the FIRST.org CSV format (`cve,epss,percentile`).

    Returns the number of rows upserted.
    """
    text = _read(path)
    if not text:
        log.info("enrichment.epss.empty_input", extra={"path": path})
        return 0

    rows = list(csv.reader(io.StringIO(text)))
    # Skip blank rows + a possible 1-line preamble + 1 header row.
    cleaned: list[tuple[str, float, float]] = []
    for r in rows:
        if not r or len(r) < 3:
            continue
        if r[0].startswith("#"):
            continue
        if r[0].lower() == "cve":
            continue
        try:
            cleaned.append((r[0], float(r[1]), float(r[2])))
        except ValueError:
            continue

    if not cleaned:
        log.info("enrichment.epss.no_rows_after_parse", extra={"path": path})
        return 0

    seen_ids = [cve for cve, _, _ in cleaned]
    n = 0
    with transaction.atomic():
        # Bulk UPSERT — the dump is ~250k rows; per-row update_or_create
        # is unworkable (~5 min). bulk_create + update_conflicts gets it
        # under 5s.
        rows = [
            EpssScore(vuln_id=cve, score=score, percentile=pct)
            for cve, score, pct in cleaned
        ]
        EpssScore.objects.bulk_create(
            rows,
            update_conflicts=True,
            update_fields=["score", "percentile"],
            unique_fields=["vuln_id"],
            batch_size=5000,
        )
        n = len(rows)
        # Removal phase: drop rows for CVEs no longer in the dump.
        EpssScore.objects.exclude(vuln_id__in=seen_ids).delete()

        # Refresh the Finding-side cache for vuln_ids we touched. We
        # only update findings whose vuln_id appears in the dump; a
        # vuln_id that dropped out gets its cache cleared too.
        for cve, score, pct in cleaned:
            Finding.objects.filter(vuln_id=cve).update(
                epss_score=score,
                epss_percentile=pct,
            )
        Finding.objects.exclude(vuln_id__in=seen_ids).filter(
            epss_score__isnull=False
        ).update(epss_score=None, epss_percentile=None)

    affected = list(Finding.objects.filter(vuln_id__in=seen_ids))
    recompute_batch(affected)
    return n


# ── KEV -----------------------------------------------------------

def load_kev_from_file(path: str) -> int:
    """Accepts the CISA KEV JSON format (`{"vulnerabilities": [...]}`)."""
    text = _read(path)
    if not text:
        log.info("enrichment.kev.empty_input", extra={"path": path})
        return 0
    try:
        doc = json.loads(text)
    except json.JSONDecodeError:
        log.warning("enrichment.kev.invalid_json", extra={"path": path})
        return 0
    vulns = doc.get("vulnerabilities") or []
    if not vulns:
        log.info("enrichment.kev.no_rows", extra={"path": path})
        return 0

    seen_ids = [v["cveID"] for v in vulns if v.get("cveID")]
    n = 0
    with transaction.atomic():
        rows = [
            KevEntry(
                vuln_id=v["cveID"],
                added_at=_date(v.get("dateAdded")),
                short_description=v.get("shortDescription") or "",
                required_action=v.get("requiredAction") or "",
                due_date=_date(v.get("dueDate")),
            )
            for v in vulns if v.get("cveID")
        ]
        KevEntry.objects.bulk_create(
            rows,
            update_conflicts=True,
            update_fields=["added_at", "short_description", "required_action", "due_date"],
            unique_fields=["vuln_id"],
            batch_size=2000,
        )
        n = len(rows)
        KevEntry.objects.exclude(vuln_id__in=seen_ids).delete()

        # Update Finding caches.
        Finding.objects.filter(vuln_id__in=list(seen_ids)).update(kev_listed=True)
        Finding.objects.exclude(vuln_id__in=list(seen_ids)).filter(kev_listed=True).update(
            kev_listed=False
        )

    affected = list(
        Finding.objects.filter(vuln_id__in=list(seen_ids))
    )
    recompute_batch(affected)
    return n


# ── Helpers -------------------------------------------------------

def _read(path: str) -> str:
    p = Path(path)
    if not p.is_file():
        return ""
    try:
        return p.read_text()
    except OSError:
        return ""


def _date(value):
    if not value:
        return None
    from datetime import date
    try:
        return date.fromisoformat(str(value)[:10])
    except ValueError:
        return None


def _parse_iso_dt(value):
    """Parse an ISO 8601 datetime to an aware datetime, or None."""
    if not value:
        return None
    try:
        from datetime import datetime
        s = str(value).replace("Z", "+00:00")
        dt = datetime.fromisoformat(s)
        if dt.tzinfo is None:
            return timezone.make_aware(dt)
        return dt
    except (ValueError, TypeError):
        return None


# ── Supply-chain IoC feeds -----------------------------------------

def _osv_severity(advisory: dict) -> str:
    """Best-effort severity extraction from an OSV advisory.

    OSV uses `database_specific.severity` (informal) and/or
    `severity[]` (CVSS-style). Malicious-publish advisories most often
    omit a numeric score; default to CRITICAL because the act of
    publishing malicious code is by definition critical.
    """
    dbs = advisory.get("database_specific") or {}
    val = (dbs.get("severity") or "").upper()
    mapping = {
        "CRITICAL": Severity.CRITICAL.value,
        "HIGH": Severity.HIGH.value,
        "MODERATE": Severity.MEDIUM.value,
        "MEDIUM": Severity.MEDIUM.value,
        "LOW": Severity.LOW.value,
    }
    if val in mapping:
        return mapping[val]
    return Severity.CRITICAL.value


def _is_malicious_advisory(advisory: dict) -> bool:
    """Filter to malicious-publish entries.

    True when:
      - id startswith "MAL-" (OSV's malicious-package namespace), OR
      - `database_specific.malicious` is true, OR
      - any alias matches MAL-*
    """
    if advisory.get("id", "").startswith("MAL-"):
        return True
    dbs = advisory.get("database_specific") or {}
    if dbs.get("malicious") is True:
        return True
    for alias in advisory.get("aliases") or []:
        if isinstance(alias, str) and alias.startswith("MAL-"):
            return True
    return False


def _purl_from_osv_affected(affected: dict, osv_eco: str) -> str:
    """Build a purl from an OSV `affected[].package` dict. Returns "" if
    we can't construct one (e.g. ecosystem we don't map).
    """
    pkg = affected.get("package") or {}
    if pkg.get("purl"):
        return pkg["purl"]
    name = pkg.get("name") or ""
    if not name:
        return ""
    # Reverse-map OSV ecosystem → purl prefix.
    reverse = {v: k for k, v in PURL_TO_OSV.items()}
    purl_eco = reverse.get(osv_eco)
    if not purl_eco:
        return ""
    # We don't know the affected version here — most malicious-publish
    # advisories carry it inside `ranges[].events` (introduced/fixed),
    # but for IoC matching we want a purl per affected version. Walk
    # ranges below in the fetcher; this helper just builds the
    # name-only purl for callers that already know the version.
    return f"pkg:{purl_eco}/{name}"


def _affected_versions(affected: dict) -> list[str]:
    """Pull explicit versions from an OSV `affected[]` block.

    Walks `versions[]` if present; otherwise walks `ranges[].events[]`
    for `introduced` entries. Returns a deduped list. Empty when only
    a SEMVER range is given (we don't expand ranges in v1).
    """
    versions: list[str] = []
    for v in affected.get("versions") or []:
        if v and v not in versions:
            versions.append(v)
    if versions:
        return versions
    for rng in affected.get("ranges") or []:
        for ev in rng.get("events") or []:
            v = ev.get("introduced")
            if v and v != "0" and v not in versions:
                versions.append(v)
    return versions


def fetch_osv_supply_chain() -> int:
    """Download per-ecosystem OSV bulk-zip for ecosystems we actually
    deploy (read from `SbomComponent.ecosystem`), filter to malicious-
    publish entries, upsert `SupplyChainIoc` rows, and run the matcher.

    Returns the number of `SupplyChainIoc` rows touched (created+updated).
    """
    from core.services.supply_chain_matcher import match_iocs_to_components

    deployed = set(
        SbomComponent.objects.active()
        .values_list("ecosystem", flat=True)
        .distinct()
    )
    osv_ecosystems = sorted({PURL_TO_OSV[e] for e in deployed if e in PURL_TO_OSV})

    if not osv_ecosystems:
        log.info("enrichment.osv.skip reason=no_deployed_ecosystems")
        return 0

    touched_purls: set[str] = set()
    upserted = 0
    for osv_eco in osv_ecosystems:
        url = OSV_ZIP_URL.format(eco=osv_eco)
        body = _http_get_conditional(url, state_key=f"osv:{osv_eco}")
        if body is None:
            continue
        try:
            zf = zipfile.ZipFile(io.BytesIO(body))
        except zipfile.BadZipFile:
            log.warning("enrichment.osv.bad_zip eco=%s", osv_eco)
            continue

        with transaction.atomic():
            for name in zf.namelist():
                if not name.endswith(".json"):
                    continue
                try:
                    advisory = json.loads(zf.read(name))
                except (json.JSONDecodeError, OSError):
                    continue
                if not _is_malicious_advisory(advisory):
                    continue
                advisory_id = advisory.get("id") or ""
                if not advisory_id:
                    continue
                severity = _osv_severity(advisory)
                title = (advisory.get("summary") or advisory_id)[:512]
                summary = advisory.get("details") or ""
                refs = advisory.get("references") or []
                advisory_url = ""
                for ref in refs:
                    if ref.get("type") in ("ADVISORY", "WEB") and ref.get("url"):
                        advisory_url = ref["url"][:512]
                        break
                published_at = _parse_iso_dt(advisory.get("published"))
                reverse = {v: k for k, v in PURL_TO_OSV.items()}
                purl_eco = reverse.get(osv_eco)

                for affected in advisory.get("affected") or []:
                    pkg = affected.get("package") or {}
                    name_ = pkg.get("name") or ""
                    explicit_purl = normalize_purl(pkg.get("purl") or "")
                    versions = _affected_versions(affected)
                    if explicit_purl and "@" in explicit_purl:
                        purls = [explicit_purl]
                    elif purl_eco and name_ and versions:
                        purls = [f"pkg:{purl_eco}/{name_}@{v}" for v in versions]
                    elif purl_eco and name_:
                        # No explicit version → store name-only purl as
                        # a sentinel; matcher uses prefix match for these.
                        purls = [f"pkg:{purl_eco}/{name_}"]
                    else:
                        continue

                    for purl in purls:
                        purl = normalize_purl(purl)
                        SupplyChainIoc.objects.update_or_create(
                            feed_source="osv",
                            advisory_id=advisory_id,
                            purl=purl,
                            defaults={
                                "severity": severity,
                                "title": title,
                                "summary": summary,
                                "advisory_url": advisory_url,
                                "published_at": published_at,
                                "raw": advisory,
                            },
                        )
                        touched_purls.add(purl)
                        upserted += 1

    if touched_purls:
        match_iocs_to_components(touched_purls=touched_purls)
    return upserted


def fetch_aikido_iocs() -> int:
    """Pull the Aikido Intel JSON feed (env-configurable URL),
    upsert `SupplyChainIoc` rows, and run the matcher.

    Feed shape is intentionally lenient — we accept either a list of
    entries at the top level or a wrapper `{"entries": [...]}` /
    `{"data": [...]}` / `{"malware": [...]}`. Each entry should carry
    `purl` (preferred) or `package` + `version` + `ecosystem`.
    """
    from core.services.supply_chain_matcher import match_iocs_to_components

    url = os.environ.get("AIKIDO_INTEL_URL", AIKIDO_INTEL_URL_DEFAULT)
    if not url:
        log.info("enrichment.aikido.skip reason=no_url")
        return 0

    body = _http_get(url)
    if body is None:
        return 0
    try:
        doc = json.loads(body.decode("utf-8", errors="replace"))
    except json.JSONDecodeError:
        log.warning("enrichment.aikido.invalid_json url=%s", url)
        return 0

    if isinstance(doc, list):
        entries = doc
    elif isinstance(doc, dict):
        entries = (
            doc.get("entries")
            or doc.get("data")
            or doc.get("malware")
            or []
        )
    else:
        entries = []

    if not entries:
        log.info("enrichment.aikido.no_entries")
        return 0

    touched_purls: set[str] = set()
    upserted = 0
    with transaction.atomic():
        for entry in entries:
            advisory_id = (
                entry.get("id")
                or entry.get("advisory_id")
                or entry.get("aikido_id")
                or ""
            )
            if not advisory_id:
                continue
            purl = normalize_purl(
                entry.get("purl") or _aikido_reconstruct_purl(entry)
            )
            if not purl:
                continue

            severity = (entry.get("severity") or "").lower() or Severity.CRITICAL.value
            if severity not in {s.value for s in Severity}:
                severity = Severity.CRITICAL.value

            SupplyChainIoc.objects.update_or_create(
                feed_source="aikido",
                advisory_id=advisory_id,
                purl=purl,
                defaults={
                    "severity": severity,
                    "title": (entry.get("title") or entry.get("summary") or advisory_id)[:512],
                    "summary": entry.get("summary") or entry.get("description") or "",
                    "advisory_url": (entry.get("url") or entry.get("advisory_url") or "")[:512],
                    "published_at": _parse_iso_dt(
                        entry.get("published_at") or entry.get("published")
                    ),
                    "raw": entry,
                },
            )
            touched_purls.add(purl)
            upserted += 1

    if touched_purls:
        match_iocs_to_components(touched_purls=touched_purls)
    return upserted


_AIKIDO_ECO_TO_PURL = {
    "npm": "npm",
    "pypi": "pypi",
    "rubygems": "gem",
    "gem": "gem",
    "go": "golang",
    "golang": "golang",
    "cargo": "cargo",
    "maven": "maven",
    "nuget": "nuget",
}


def _aikido_reconstruct_purl(entry: dict) -> str:
    """Build a purl from Aikido entry fields when an explicit purl
    isn't supplied. Returns "" if we don't have enough.
    """
    eco_raw = (entry.get("ecosystem") or entry.get("package_ecosystem") or "").lower()
    eco = _AIKIDO_ECO_TO_PURL.get(eco_raw)
    name = entry.get("package_name") or entry.get("package") or entry.get("name") or ""
    version = entry.get("package_version") or entry.get("version") or ""
    if not eco or not name:
        return ""
    if version:
        return f"pkg:{eco}/{name}@{version}"
    return f"pkg:{eco}/{name}"
