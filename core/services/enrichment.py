"""Enrichment loaders — file-driven and HTTP-driven.

Each loader applies the universal zero-input no-op rule: an empty or
unreadable input skips the removal phase so existing rows stay intact.
"""
from __future__ import annotations

import contextlib
import csv
import gzip
import http.client
import io
import json
import logging
import os
import shutil
import socket
import tempfile
import time
import zipfile
import zlib
from collections.abc import Iterable, Iterator
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from django.db import OperationalError, connection
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
from core.urgency import finding_ids, recompute_ids

log = logging.getLogger("core.enrichment")


# ── HTTP fetch ────────────────────────────────────────────────────

EPSS_URL = "https://epss.cyentia.com/epss_scores-current.csv.gz"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
OSV_ZIP_URL = "https://osv-vulnerabilities.storage.googleapis.com/{eco}/all.zip"

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
# Everything a streamed body can raise after the headers arrived: socket
# errors (OSError), a truncated chunked response (IncompleteRead is an
# HTTPException, not an OSError), corrupt gzip (BadGzipFile is an OSError
# but raw deflate errors are zlib.error), premature EOF in the gzip member.
_STREAM_ERRORS = (OSError, http.client.HTTPException, zlib.error, EOFError)


@contextlib.contextmanager
def _http_open(url: str) -> Iterator[io.BufferedIOBase | None]:
    """Open `url` for **streaming** reads, retrying the connection.
    Yields the response (a file-like object) or None on persistent
    failure so callers honour the zero-input no-op rule.

    Only the connect/headers phase is retried; a stream that dies
    mid-body raises inside the caller's loop, which treats it as a
    failed fetch. The body is never read into one `bytes`: EPSS's
    ~330k-row CSV used to live in RAM five times over (gz bytes, the
    decompressed str, the temp-file copy, the row list, the model
    list) and OOM-killed a 512Mi pod.
    """
    last_err = ""
    for attempt in range(1, _HTTP_MAX_ATTEMPTS + 1):
        try:
            req = Request(url, headers={"User-Agent": _USER_AGENT})
            resp = urlopen(req, timeout=_HTTP_TIMEOUT)
        except HTTPError as e:
            last_err = f"HTTP {e.code}"
            if 400 <= e.code < 500:
                break  # don't retry client errors
        except (URLError, socket.timeout) as e:
            last_err = f"transport: {e}"
        else:
            with resp:
                yield resp
            return

        if attempt < _HTTP_MAX_ATTEMPTS:
            time.sleep(_HTTP_BACKOFF_BASE * (2 ** (attempt - 1)))

    log.warning("enrichment.fetch.failed url=%s last_err=%s", url, last_err)
    yield None


def _http_download_conditional(
    url: str, *, state_key: str, suffix: str = ".bin"
) -> str | None:
    """Conditional GET that **streams** the response body to a temp file
    and returns its path (the caller must unlink it). Same
    If-Modified-Since / If-None-Match handling as a plain conditional GET,
    but the payload never lives in RAM as one object.

    This matters for OSV's bulk zips (npm/all.zip is hundreds of MB):
    `resp.read()` into a `bytes` plus the `io.BytesIO` copy briefly held
    ~2× the compressed size and tripped the cgroup OOM killer. Streaming
    to disk with `shutil.copyfileobj` keeps memory flat, and
    `zipfile.ZipFile` then decompresses one entry at a time off the file.

    Returns:
      - path to a temp file on 200 (and persists new ETag/Last-Modified)
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
                fd, tmp_path = tempfile.mkstemp(suffix=suffix)
                try:
                    with os.fdopen(fd, "wb") as out:
                        shutil.copyfileobj(resp, out, length=1024 * 1024)
                except BaseException:
                    Path(tmp_path).unlink(missing_ok=True)
                    raise
                FeedFetchState.objects.update_or_create(
                    state_key=state_key,
                    defaults={
                        "etag": resp.headers.get("ETag", ""),
                        "last_modified": resp.headers.get("Last-Modified", ""),
                        "last_success_at": timezone.now(),
                    },
                )
                return tmp_path
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
    """Stream the latest EPSS dump (gzipped CSV) straight from the
    response into the loader: HTTP body → gunzip → csv.reader → chunked
    upserts. Nothing larger than one chunk is ever held. Returns the
    number of rows upserted (0 on failure).
    """
    with _http_open(EPSS_URL) as resp:
        if resp is None:
            return 0
        text = io.TextIOWrapper(gzip.GzipFile(fileobj=resp), encoding="utf-8", errors="replace", newline="")
        try:
            return _load_epss_rows(text, source=EPSS_URL)
        except _STREAM_ERRORS as e:
            # Transport died mid-body or the gzip stream is corrupt. Rows
            # already upserted are harmless (idempotent on vuln_id); the
            # stale-row delete and cache refresh did not run.
            log.warning("enrichment.epss.stream_failed err=%s", e)
            return 0


def fetch_kev() -> int:
    """Download the latest CISA KEV catalog JSON to a temp file (it is
    one JSON document, so it has to be parsed whole — but ~2 MB, and
    it never lives in RAM as a second `bytes` copy), then apply via the
    file loader. Returns the number of rows upserted (0 on failure).
    """
    with _http_open(KEV_URL) as resp:
        if resp is None:
            return 0
        fd, tmp_path = tempfile.mkstemp(suffix=".json")
        try:
            with os.fdopen(fd, "wb") as out:
                shutil.copyfileobj(resp, out, length=1024 * 1024)
        except _STREAM_ERRORS as e:
            log.warning("enrichment.kev.stream_failed err=%s", e)
            Path(tmp_path).unlink(missing_ok=True)
            return 0
    try:
        return load_kev_from_file(tmp_path)
    finally:
        Path(tmp_path).unlink(missing_ok=True)


# ── Finding-cache bulk refresh (deadlock-resistant) ───────────────

# PostgreSQL deadlock SQLSTATE. We retry transient deadlocks with backoff
# rather than aborting the whole refresh — the ingest queue worker also
# updates Finding rows, and the two writers can collide on shared CVEs.
_PG_DEADLOCK = "40P01"
_DEADLOCK_MAX_ATTEMPTS = 5
_DEADLOCK_BACKOFF_BASE = 0.5

def _exec_with_deadlock_retry(sql: str) -> None:
    """Run `sql` in autocommit mode with a deadlock-detect retry loop.

    Running outside an outer `transaction.atomic()` is the point: the
    statement's row locks release immediately on completion instead of
    being held for the whole enrichment cycle (250k+ rows worth, which
    consistently deadlocked with the ingest queue worker — see
    Finding.objects.filter(vuln_id=cve).update(...) loop this replaces).
    """
    delay = _DEADLOCK_BACKOFF_BASE
    for attempt in range(1, _DEADLOCK_MAX_ATTEMPTS + 1):
        try:
            with connection.cursor() as cur:
                cur.execute(sql)
            return
        except OperationalError as exc:
            pgcode = getattr(getattr(exc, "__cause__", None), "sqlstate", None)
            if pgcode != _PG_DEADLOCK or attempt == _DEADLOCK_MAX_ATTEMPTS:
                raise
            log.warning("enrichment.deadlock_retry attempt=%d", attempt)
            time.sleep(delay)
            delay *= 2


def _recompute_affected_findings(vuln_ids) -> int:
    """Recompute priority for every Finding matching `vuln_ids`, streamed
    and chunked by `recompute_ids` — `vuln_id__in=<catalog>` (250k+ CVEs)
    can match far more Finding rows than the feed has CVEs, and
    materializing them at once was the cause of the enrich-epss OOMs.
    Returns the count updated.

    `vuln_ids` is a list or a `values("vuln_id")` queryset; the loaders
    pass the latter so the whole catalog (330k ids for EPSS) becomes a
    subquery instead of a Python list shipped as `IN (...)`.
    """
    _scanned, updated = recompute_ids(finding_ids(Finding.objects.filter(vuln_id__in=vuln_ids)))
    return updated


def _refresh_finding_epss_cache() -> None:
    """Propagate the (refreshed) EpssScore table into the Finding cache.

    Two bulk UPDATEs replace the prior per-CVE Python loop:
      1) push current EpssScore values into matching Finding rows;
      2) clear cache for Findings whose CVE is no longer in EpssScore.

    `IS DISTINCT FROM` skips rows that already match so we don't acquire
    write locks on unchanged tuples. Each statement runs in autocommit
    with deadlock retry.
    """
    _exec_with_deadlock_retry("""
        UPDATE core_finding f
        SET epss_score = e.score, epss_percentile = e.percentile
        FROM core_epssscore e
        WHERE f.vuln_id = e.vuln_id
          AND (f.epss_score IS DISTINCT FROM e.score
               OR f.epss_percentile IS DISTINCT FROM e.percentile)
    """)
    _exec_with_deadlock_retry("""
        UPDATE core_finding f
        SET epss_score = NULL, epss_percentile = NULL
        WHERE f.vuln_id LIKE 'CVE-%'
          AND f.epss_score IS NOT NULL
          AND NOT EXISTS (
              SELECT 1 FROM core_epssscore e WHERE e.vuln_id = f.vuln_id
          )
    """)


def _refresh_finding_kev_cache() -> None:
    """Propagate the (refreshed) KevEntry table into the Finding cache."""
    _exec_with_deadlock_retry("""
        UPDATE core_finding f
        SET kev_listed = TRUE
        WHERE f.kev_listed = FALSE
          AND EXISTS (
              SELECT 1 FROM core_keventry k WHERE k.vuln_id = f.vuln_id
          )
    """)
    _exec_with_deadlock_retry("""
        UPDATE core_finding f
        SET kev_listed = FALSE
        WHERE f.kev_listed = TRUE
          AND NOT EXISTS (
              SELECT 1 FROM core_keventry k WHERE k.vuln_id = f.vuln_id
          )
    """)


# ── EPSS ----------------------------------------------------------

# Rows per upsert statement. Also the memory high-water mark of a feed
# refresh: the loaders build at most one chunk of model instances.
_UPSERT_CHUNK_SIZE = 5000


def _chunked(items: Iterable, size: int) -> Iterator[list]:
    chunk: list = []
    for item in items:
        chunk.append(item)
        if len(chunk) >= size:
            yield chunk
            chunk = []
    if chunk:
        yield chunk


def _parse_epss_rows(lines: Iterable[str]) -> Iterator[tuple[str, float, float]]:
    """FIRST.org CSV (`cve,epss,percentile`): skip blank rows, the
    `#model_version` preamble and the header; drop unparsable rows."""
    for r in csv.reader(lines):
        if not r or len(r) < 3 or r[0].startswith("#") or r[0].lower() == "cve":
            continue
        try:
            yield r[0], float(r[1]), float(r[2])
        except ValueError:
            continue


def _load_epss_rows(lines: Iterable[str], *, source: str) -> int:
    """Upsert EPSS rows from an iterable of CSV lines in chunks of
    `_UPSERT_CHUNK_SIZE`, then drop every row the feed no longer lists.

    Each chunk autocommits (idempotent on vuln_id, so a failure mid-way
    leaves nothing to undo). "No longer listed" is `fetched_at <
    run_started`: the upsert bumps `fetched_at` on every row it touches,
    which keeps the whole set operation in SQL instead of shipping the
    feed's 330k ids back as `NOT IN (...)`.

    Zero-input rule: a feed that parses to no rows changes nothing.
    """
    run_started = timezone.now()
    n = 0
    for chunk in _chunked(_parse_epss_rows(lines), _UPSERT_CHUNK_SIZE):
        EpssScore.objects.bulk_create(
            [EpssScore(vuln_id=cve, score=score, percentile=pct) for cve, score, pct in chunk],
            update_conflicts=True,
            update_fields=["score", "percentile", "fetched_at"],
            unique_fields=["vuln_id"],
        )
        n += len(chunk)
    if n == 0:
        log.info("enrichment.epss.no_rows_after_parse source=%s", source)
        return 0
    EpssScore.objects.filter(fetched_at__lt=run_started).delete()

    # Finding-cache refresh in autocommit + deadlock retry. The prior
    # per-CVE UPDATE loop inside one atomic block held thousands of row
    # locks and deadlocked with the ingest queue worker; bulk SQL via JOIN
    # finishes in one statement and releases locks immediately on commit.
    _refresh_finding_epss_cache()

    _recompute_affected_findings(EpssScore.objects.values("vuln_id"))
    return n


def load_epss_from_file(path: str) -> int:
    """Accepts the FIRST.org CSV format (`cve,epss,percentile`), read
    line by line. Returns the number of rows upserted.
    """
    p = Path(path)
    if not p.is_file():
        log.info("enrichment.epss.empty_input path=%s", path)
        return 0
    try:
        with p.open(encoding="utf-8", errors="replace", newline="") as fh:
            return _load_epss_rows(fh, source=path)
    except OSError:
        log.info("enrichment.epss.empty_input path=%s", path)
        return 0


# ── KEV -----------------------------------------------------------

def load_kev_from_file(path: str) -> int:
    """Accepts the CISA KEV JSON format (`{"vulnerabilities": [...]}`).
    Same chunked-upsert + `fetched_at` sweep as EPSS (the catalog is
    ~1.5k rows, so this is for one pattern everywhere, not for memory).
    """
    p = Path(path)
    if not p.is_file():
        log.info("enrichment.kev.empty_input path=%s", path)
        return 0
    try:
        with p.open("rb") as fh:
            doc = json.load(fh)
    except OSError:
        log.info("enrichment.kev.empty_input path=%s", path)
        return 0
    except (json.JSONDecodeError, UnicodeDecodeError):
        log.warning("enrichment.kev.invalid_json path=%s", path)
        return 0
    vulns = [v for v in (doc.get("vulnerabilities") or []) if isinstance(v, dict) and v.get("cveID")]
    if not vulns:
        log.info("enrichment.kev.no_rows path=%s", path)
        return 0

    run_started = timezone.now()
    n = 0
    for chunk in _chunked(vulns, _UPSERT_CHUNK_SIZE):
        KevEntry.objects.bulk_create(
            [
                KevEntry(
                    vuln_id=v["cveID"],
                    added_at=_date(v.get("dateAdded")),
                    short_description=v.get("shortDescription") or "",
                    required_action=v.get("requiredAction") or "",
                    due_date=_date(v.get("dueDate")),
                )
                for v in chunk
            ],
            update_conflicts=True,
            update_fields=["added_at", "short_description", "required_action", "due_date", "fetched_at"],
            unique_fields=["vuln_id"],
        )
        n += len(chunk)
    KevEntry.objects.filter(fetched_at__lt=run_started).delete()

    _refresh_finding_kev_cache()

    _recompute_affected_findings(KevEntry.objects.values("vuln_id"))
    return n


# ── Helpers -------------------------------------------------------

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
        zip_path = _http_download_conditional(
            url, state_key=f"osv:{osv_eco}", suffix=".zip"
        )
        if zip_path is None:
            continue
        try:
            # No outer transaction.atomic(): npm's MAL feed yields hundreds
            # of thousands of upserts, and holding all those row locks in
            # one transaction OOM-killed the pod (Python + PG state) and
            # tripped the 15-min activeDeadlineSeconds. Autocommitting each
            # update_or_create is safe — it's idempotent on the unique key.
            with zipfile.ZipFile(zip_path) as zf:
                for name in zf.namelist():
                    if not name.endswith(".json"):
                        continue
                    # Cheap bytes-level prefilter — ~99% of npm entries are
                    # GHSA-* vulns we don't ingest here. Avoids json.loads
                    # of every advisory in the 200MB zip.
                    raw_bytes = zf.read(name)
                    if b"MAL-" not in raw_bytes and b'"malicious"' not in raw_bytes:
                        continue
                    try:
                        advisory = json.loads(raw_bytes)
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
        except zipfile.BadZipFile:
            log.warning("enrichment.osv.bad_zip eco=%s", osv_eco)
        finally:
            Path(zip_path).unlink(missing_ok=True)

    if touched_purls:
        match_iocs_to_components(touched_purls=touched_purls)
    return upserted
