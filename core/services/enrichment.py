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
import socket
import tempfile
import time
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from django.db import transaction

from core.models import EpssScore, Finding, KevEntry
from core.urgency import recompute_batch

log = logging.getLogger("core.enrichment")


# ── HTTP fetch ────────────────────────────────────────────────────

EPSS_URL = "https://epss.cyentia.com/epss_scores-current.csv.gz"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

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
