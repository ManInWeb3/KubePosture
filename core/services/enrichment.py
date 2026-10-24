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

from django.db import OperationalError, connection, transaction
from django.utils import timezone

from core.constants import Severity
from core.iterutils import chunked
from core.models import (
    EpssScore,
    FeedFetchState,
    Finding,
    KevEntry,
    OsvAdvisory,
    OsvAffected,
    SbomComponent,
    SupplyChainIoc,
)
from core.osv_ranges import ioc_purls
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
    "cargo": "crates.io",
    "gem": "RubyGems",
    "maven": "Maven",
    "nuget": "NuGet",
    "hex": "Hex",
    "composer": "Packagist",
}
# OSV ecosystem → purl type, for synthesising IoC purls from `package.name`
# when an advisory carries no explicit purl. Must stay one-to-one with
# PURL_TO_OSV: Trivy emits `pkg:golang/...`, so a second alias mapping to
# "Go" (there used to be a "gomod" entry) made every synthesised Go purl
# unmatchable.
_OSV_TO_PURL = {v: k for k, v in PURL_TO_OSV.items()}

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


class _DownloadPath(str):
    """Temp-file path returned by `_http_download_conditional`, carrying
    the response validators to persist once the file has been applied."""

    fetch_state: dict | None = None


def _commit_fetch_state(state_key: str, fetch_state: dict | None) -> None:
    """Persist ETag / Last-Modified for `state_key` — called by the feed
    loader only after it has applied the download successfully."""
    if not fetch_state:
        return
    FeedFetchState.objects.update_or_create(
        state_key=state_key,
        defaults={**fetch_state, "last_success_at": timezone.now()},
    )


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
      - path to a temp file on 200, as a `_DownloadPath` carrying the
        response's ETag / Last-Modified. The caller persists them with
        `_commit_fetch_state` once it has *applied* the file: persisting
        on download used to mean a failure after download (bad zip, pod
        killed) got a 304 on the next run and skipped the feed until
        upstream republished.
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
                path = _DownloadPath(tmp_path)
                path.fetch_state = {
                    "etag": resp.headers.get("ETag", ""),
                    "last_modified": resp.headers.get("Last-Modified", ""),
                }
                return path
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

def _exec_with_deadlock_retry(sql: str) -> list[int]:
    """Run `sql` in autocommit mode with a deadlock-detect retry loop.
    Returns the first column of a `RETURNING` clause (empty otherwise).

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
                return [row[0] for row in cur.fetchall()] if cur.description else []
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


def _refresh_finding_epss_cache() -> list[int]:
    """Propagate the (refreshed) EpssScore table into the Finding cache.

    Two bulk UPDATEs replace the prior per-CVE Python loop:
      1) push current EpssScore values into matching Finding rows;
      2) clear cache for Findings whose CVE is no longer in EpssScore.

    `IS DISTINCT FROM` skips rows that already match so we don't acquire
    write locks on unchanged tuples. Each statement runs in autocommit
    with deadlock retry.

    Returns the ids cleared by (2): those CVEs are no longer in the feed,
    so the feed-driven recompute would miss them — the caller recomputes
    them explicitly or their band stays where the old score put it.
    """
    _exec_with_deadlock_retry("""
        UPDATE core_finding f
        SET epss_score = e.score, epss_percentile = e.percentile
        FROM core_epssscore e
        WHERE f.vuln_id = e.vuln_id
          AND (f.epss_score IS DISTINCT FROM e.score
               OR f.epss_percentile IS DISTINCT FROM e.percentile)
    """)
    return _exec_with_deadlock_retry("""
        UPDATE core_finding f
        SET epss_score = NULL, epss_percentile = NULL
        WHERE f.vuln_id LIKE 'CVE-%'
          AND f.epss_score IS NOT NULL
          AND NOT EXISTS (
              SELECT 1 FROM core_epssscore e WHERE e.vuln_id = f.vuln_id
          )
        RETURNING f.id
    """)


def _refresh_finding_kev_cache() -> list[int]:
    """Propagate the (refreshed) KevEntry table into the Finding cache.
    Returns the ids of Findings de-listed from KEV (see the EPSS twin)."""
    _exec_with_deadlock_retry("""
        UPDATE core_finding f
        SET kev_listed = TRUE
        WHERE f.kev_listed = FALSE
          AND EXISTS (
              SELECT 1 FROM core_keventry k WHERE k.vuln_id = f.vuln_id
          )
    """)
    return _exec_with_deadlock_retry("""
        UPDATE core_finding f
        SET kev_listed = FALSE
        WHERE f.kev_listed = TRUE
          AND NOT EXISTS (
              SELECT 1 FROM core_keventry k WHERE k.vuln_id = f.vuln_id
          )
        RETURNING f.id
    """)


# ── EPSS ----------------------------------------------------------

# Rows per upsert statement. Also the memory high-water mark of a feed
# refresh: the loaders build at most one chunk of model instances.
_UPSERT_CHUNK_SIZE = 5000


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
    for chunk in chunked(_parse_epss_rows(lines), _UPSERT_CHUNK_SIZE):
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
    cleared = _refresh_finding_epss_cache()

    _recompute_affected_findings(EpssScore.objects.values("vuln_id"))
    recompute_ids(cleared)
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
    for chunk in chunked(vulns, _UPSERT_CHUNK_SIZE):
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

    cleared = _refresh_finding_kev_cache()

    _recompute_affected_findings(KevEntry.objects.values("vuln_id"))
    recompute_ids(cleared)
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


def _upsert_ioc_rows(advisory: dict, osv_eco: str, touched_purls: set[str]) -> int:
    """One malicious-package advisory → `SupplyChainIoc` rows (one per
    affected purl). Returns the number of rows touched."""
    advisory_id = advisory["id"]
    severity = _osv_severity(advisory)
    title = (advisory.get("summary") or advisory_id)[:512]
    summary = advisory.get("details") or ""
    advisory_url = ""
    for ref in advisory.get("references") or []:
        if ref.get("type") in ("ADVISORY", "WEB") and ref.get("url"):
            advisory_url = ref["url"][:512]
            break
    published_at = _parse_iso_dt(advisory.get("published"))
    purl_eco = _OSV_TO_PURL.get(osv_eco)

    n = 0
    for affected in advisory.get("affected") or []:
        # One purl per enumerated version, or a name-only purl when the
        # block only has ranges (`core.osv_ranges.ioc_purls`); the
        # matcher resolves a name-only IoC against the block's ranges.
        purls = ioc_purls(affected, purl_eco or "")
        for purl in purls:
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
            n += 1
    return n


# ── OSV vulnerability advisories ------------------------------------

# Advisories per bulk upsert; also the high-water mark of advisory
# objects held in memory while a zip is applied.
_OSV_BATCH = 1000

_ADVISORY_SEVERITY = {
    "CRITICAL": Severity.CRITICAL.value,
    "HIGH": Severity.HIGH.value,
    "MODERATE": Severity.MEDIUM.value,
    "MEDIUM": Severity.MEDIUM.value,
    "LOW": Severity.LOW.value,
}


def _advisory_severity(advisory: dict) -> str:
    """`database_specific.severity` (GHSA's informal label) mapped, or ""
    — unlike the malicious lane there is no default: Go vulndb and
    RustSec entries carry none and the finding says UNKNOWN."""
    dbs = advisory.get("database_specific") or {}
    return _ADVISORY_SEVERITY.get(str(dbs.get("severity") or "").upper(), "")


def _advisory_cvss_vector(advisory: dict) -> str:
    """First CVSS vector string, v3 preferred over v4 over v2."""
    by_type = {s.get("type"): s.get("score") for s in advisory.get("severity") or [] if isinstance(s, dict)}
    for t in ("CVSS_V3", "CVSS_V4", "CVSS_V2"):
        score = by_type.get(t)
        if isinstance(score, str) and score.startswith("CVSS:"):
            return score[:128]
    return ""


def _advisory_rows(advisory: dict, osv_eco: str) -> tuple[OsvAdvisory, list[OsvAffected]]:
    from core.services.osv_vuln_matcher import package_name

    osv_id = advisory["id"]
    adv = OsvAdvisory(
        osv_id=osv_id,
        ecosystem=osv_eco,
        aliases=sorted({a for a in advisory.get("aliases") or [] if isinstance(a, str)}),
        severity=_advisory_severity(advisory),
        cvss_vector=_advisory_cvss_vector(advisory),
        summary=(advisory.get("summary") or "")[:512],
        references=[r["url"][:512] for r in (advisory.get("references") or []) if isinstance(r, dict) and r.get("url")][:10],
        published_at=_parse_iso_dt(advisory.get("published")),
        modified_at=_parse_iso_dt(advisory.get("modified")),
        withdrawn_at=_parse_iso_dt(advisory.get("withdrawn")),
    )
    rows = []
    for block in advisory.get("affected") or []:
        pkg = block.get("package") or {}
        purl_type = _OSV_TO_PURL.get(str(pkg.get("ecosystem") or "").split(":")[0])
        name = pkg.get("name") or ""
        versions = [v for v in (block.get("versions") or []) if isinstance(v, str)]
        ranges = [
            {"type": r.get("type"), "events": [e for e in (r.get("events") or []) if isinstance(e, dict)]}
            for r in (block.get("ranges") or []) if isinstance(r, dict) and r.get("type") in ("SEMVER", "ECOSYSTEM")
        ]
        if not purl_type or not name or not (versions or ranges):
            continue
        rows.append(OsvAffected(
            advisory=adv, purl_type=purl_type, name=package_name(purl_type, name)[:255],
            versions=versions, ranges=ranges,
        ))
    return adv, rows


def _upsert_advisories(batch: list[tuple[dict, str]]) -> int:
    """Bulk-upsert one batch of advisories and replace their affected
    rows. One short transaction per batch, so the matcher never sees an
    advisory without its blocks and no lock outlives the batch."""
    advisories, affected = [], []
    for advisory, osv_eco in batch:
        adv, rows = _advisory_rows(advisory, osv_eco)
        advisories.append(adv)
        affected.extend(rows)
    with transaction.atomic():
        OsvAdvisory.objects.bulk_create(
            advisories,
            update_conflicts=True,
            unique_fields=["osv_id"],
            update_fields=["ecosystem", "aliases", "severity", "cvss_vector", "summary", "references",
                           "published_at", "modified_at", "withdrawn_at", "fetched_at"],
        )
        OsvAffected.objects.filter(advisory_id__in=[a.osv_id for a in advisories]).delete()
        OsvAffected.objects.bulk_create(affected, batch_size=_OSV_BATCH)
    return len(advisories)


def fetch_osv() -> int:
    """Download the per-ecosystem OSV bulk zips for the ecosystems we
    actually deploy (read from `SbomComponent.ecosystem`) and apply every
    advisory: malicious-package entries → `SupplyChainIoc` (+ the IoC
    matcher on the purls touched), everything else → `OsvAdvisory` /
    `OsvAffected` (entries whose `modified` is unchanged are skipped).

    Does not run the vulnerability matcher — see `refresh_osv`, which the
    cron uses, so a load can be tested on its own.

    Returns the number of rows touched (IoC rows + advisories upserted),
    0 when nothing was fetched.
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
    touched = 0
    for osv_eco in osv_ecosystems:
        url = OSV_ZIP_URL.format(eco=osv_eco)
        zip_path = _http_download_conditional(
            url, state_key=f"osv:{osv_eco}", suffix=".zip"
        )
        if zip_path is None:
            continue
        # `modified` of what we already hold: npm's 230k advisories
        # change a few hundred a day, so the hourly refresh re-upserts
        # only those. ~15 MB of Python for npm, released per ecosystem.
        known_modified = dict(
            OsvAdvisory.objects.filter(ecosystem=osv_eco).values_list("osv_id", "modified_at")
        )
        batch: list[tuple[dict, str]] = []
        advisories_seen = skipped = 0
        try:
            # No outer transaction.atomic(): npm's MAL feed yields hundreds
            # of thousands of upserts, and holding all those row locks in
            # one transaction OOM-killed the pod (Python + PG state) and
            # tripped the 15-min activeDeadlineSeconds. The IoC path
            # autocommits each update_or_create (idempotent on the unique
            # key); advisories go in short per-batch transactions.
            with zipfile.ZipFile(zip_path) as zf:
                for name in zf.namelist():
                    if not name.endswith(".json"):
                        continue
                    try:
                        advisory = json.loads(zf.read(name))
                    except (json.JSONDecodeError, OSError):
                        continue
                    if not isinstance(advisory, dict) or not advisory.get("id"):
                        continue
                    if _is_malicious_advisory(advisory):
                        touched += _upsert_ioc_rows(advisory, osv_eco, touched_purls)
                        continue
                    advisories_seen += 1
                    modified = _parse_iso_dt(advisory.get("modified"))
                    if modified is not None and known_modified.get(advisory["id"]) == modified:
                        skipped += 1
                        continue
                    batch.append((advisory, osv_eco))
                    if len(batch) >= _OSV_BATCH:
                        touched += _upsert_advisories(batch)
                        batch = []
            if batch:
                touched += _upsert_advisories(batch)
            # Only now is the zip known to be good and fully applied.
            _commit_fetch_state(f"osv:{osv_eco}", getattr(zip_path, "fetch_state", None))
            log.info(
                "enrichment.osv.applied eco=%s advisories=%d unchanged=%d",
                osv_eco, advisories_seen, skipped,
            )
        except zipfile.BadZipFile:
            log.warning("enrichment.osv.bad_zip eco=%s", osv_eco)
        finally:
            Path(zip_path).unlink(missing_ok=True)
            del known_modified

    if touched_purls:
        match_iocs_to_components(touched_purls=touched_purls)
    return touched


def refresh_osv() -> int:
    """The cron entry point: apply the feeds, then match every deployed
    component. The full match runs even when every zip came back 304 —
    a finding only stays visible while something bumps its `last_seen`
    past the cluster's latest complete inventory, so still-deployed
    matches must be re-asserted every tick, not only when their
    advisory changed."""
    from core.services.osv_vuln_matcher import match_osv_vulns

    touched = fetch_osv()
    match_osv_vulns()
    return touched


# Pre-vulnerability-lane name, kept for callers and operators' muscle memory.
fetch_osv_supply_chain = fetch_osv
