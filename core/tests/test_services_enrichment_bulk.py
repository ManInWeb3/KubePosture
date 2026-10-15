"""Tests for the bulk Finding-cache refresh in core.services.enrichment.

Locks the behaviour after the per-CVE UPDATE loop in `load_epss_from_file`
deadlocked in production with the ingest queue worker. The replacement is
a single bulk SQL UPDATE (autocommit + deadlock retry) that propagates
EpssScore / KevEntry into the Finding cache columns.
"""
from __future__ import annotations

import contextlib
import gzip
import io
import json
import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest

from core.constants import Environment, Severity
from core.models import (
    Cluster,
    EpssScore,
    Finding,
    KevEntry,
    Namespace,
    Workload,
)
from core.services import enrichment

# ── Fixture builders ─────────────────────────────────────────────


def _cluster():
    return Cluster.objects.create(name="c-enr", environment=Environment.PROD.value)


def _ns(c):
    return Namespace.objects.create(cluster=c, name="default")


def _workload(c, ns):
    return Workload.objects.create(
        cluster=c, namespace=ns, kind="Deployment", name="api",
        deployed=True,
    )


def _finding(w, vuln_id, *, epss_score=None, epss_percentile=None, kev_listed=False, hash_code):
    return Finding.objects.create(
        cluster=w.cluster,
        workload=w,
        source="trivy",
        category="vulnerability",
        vuln_id=vuln_id,
        title=f"test {vuln_id}",
        severity=Severity.HIGH.value,
        epss_score=epss_score,
        epss_percentile=epss_percentile,
        kev_listed=kev_listed,
        hash_code=hash_code,
    )


def _write_csv(rows: list[tuple[str, float, float]]) -> str:
    """Write a FIRST.org-style EPSS CSV (1-line preamble + header + rows)
    to a temp file and return the path. Caller is responsible for cleanup.
    """
    out = io.StringIO()
    out.write("#model_version:v2024.05.18,score_date:2025-01-01T00:00:00+0000\n")
    out.write("cve,epss,percentile\n")
    for cve, score, pct in rows:
        out.write(f"{cve},{score},{pct}\n")
    fd = tempfile.NamedTemporaryFile("w", suffix=".csv", delete=False)
    fd.write(out.getvalue())
    fd.close()
    return fd.name


# ── EPSS bulk refresh ────────────────────────────────────────────


@pytest.mark.django_db
def test_epss_bulk_refresh_pushes_scores_into_finding_cache():
    c = _cluster()
    ns = _ns(c)
    w = _workload(c, ns)
    _finding(w, "CVE-2024-AAA", hash_code="ha")
    _finding(w, "CVE-2024-BBB", hash_code="hb")

    path = _write_csv([
        ("CVE-2024-AAA", 0.91, 0.99),
        ("CVE-2024-BBB", 0.10, 0.40),
        ("CVE-2024-CCC", 0.05, 0.20),  # no Finding row for this one
    ])
    try:
        n = enrichment.load_epss_from_file(path)
    finally:
        Path(path).unlink(missing_ok=True)

    assert n == 3
    a = Finding.objects.get(vuln_id="CVE-2024-AAA")
    b = Finding.objects.get(vuln_id="CVE-2024-BBB")
    assert a.epss_score == 0.91 and a.epss_percentile == 0.99
    assert b.epss_score == 0.10 and b.epss_percentile == 0.40


@pytest.mark.django_db
def test_epss_bulk_refresh_clears_stale_cache_when_cve_drops_from_dump():
    """A CVE present in the previous dump but absent from the new one must
    have its Finding cache cleared — otherwise priorities reflect
    long-stale EPSS values."""
    c = _cluster()
    ns = _ns(c)
    w = _workload(c, ns)
    _finding(w, "CVE-2024-AAA", epss_score=0.8, epss_percentile=0.9, hash_code="ha")
    EpssScore.objects.create(vuln_id="CVE-2024-AAA", score=0.8, percentile=0.9)

    # New dump omits CVE-2024-AAA entirely.
    path = _write_csv([("CVE-2024-BBB", 0.1, 0.2)])
    try:
        enrichment.load_epss_from_file(path)
    finally:
        Path(path).unlink(missing_ok=True)

    a = Finding.objects.get(vuln_id="CVE-2024-AAA")
    assert a.epss_score is None and a.epss_percentile is None


@pytest.mark.django_db
def test_epss_bulk_refresh_idempotent_when_values_unchanged():
    """Second run with identical input must not write to Finding rows
    (the `IS DISTINCT FROM` predicate keeps the UPDATE lock count down
    so re-runs don't deadlock with concurrent ingest)."""
    c = _cluster()
    ns = _ns(c)
    w = _workload(c, ns)
    _finding(w, "CVE-2024-AAA", hash_code="ha")
    csv_rows = [("CVE-2024-AAA", 0.5, 0.7)]

    path = _write_csv(csv_rows)
    try:
        enrichment.load_epss_from_file(path)
    finally:
        Path(path).unlink(missing_ok=True)

    # Second run — values match what's already in Finding row.
    path = _write_csv(csv_rows)
    try:
        # The bulk UPDATE must short-circuit; no exception raised.
        enrichment.load_epss_from_file(path)
    finally:
        Path(path).unlink(missing_ok=True)

    a = Finding.objects.get(vuln_id="CVE-2024-AAA")
    assert a.epss_score == 0.5 and a.epss_percentile == 0.7


@pytest.mark.django_db
def test_epss_bulk_refresh_does_not_touch_non_cve_findings():
    """Findings whose vuln_id is not a CVE (Trivy AVD-*, Kyverno policy
    names) must not be touched by the EPSS clear path."""
    c = _cluster()
    ns = _ns(c)
    w = _workload(c, ns)
    _finding(w, "AVD-KSV-0001", hash_code="hk")  # config-audit finding
    EpssScore.objects.create(vuln_id="CVE-OLD", score=0.5, percentile=0.7)

    path = _write_csv([("CVE-NEW", 0.1, 0.2)])
    try:
        enrichment.load_epss_from_file(path)
    finally:
        Path(path).unlink(missing_ok=True)

    avd = Finding.objects.get(vuln_id="AVD-KSV-0001")
    assert avd.epss_score is None  # untouched


# ── KEV bulk refresh ─────────────────────────────────────────────


def _write_kev(*cve_ids: str) -> str:
    payload = {
        "vulnerabilities": [
            {"cveID": cve, "dateAdded": "2025-01-01"} for cve in cve_ids
        ],
    }
    fd = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False)
    fd.write(json.dumps(payload))
    fd.close()
    return fd.name


@pytest.mark.django_db
def test_kev_bulk_refresh_flips_kev_flag_on_matching_findings():
    c = _cluster()
    ns = _ns(c)
    w = _workload(c, ns)
    _finding(w, "CVE-2024-AAA", hash_code="ha")  # not yet KEV
    _finding(w, "CVE-2024-BBB", hash_code="hb")

    path = _write_kev("CVE-2024-AAA")
    try:
        enrichment.load_kev_from_file(path)
    finally:
        Path(path).unlink(missing_ok=True)

    assert Finding.objects.get(vuln_id="CVE-2024-AAA").kev_listed is True
    assert Finding.objects.get(vuln_id="CVE-2024-BBB").kev_listed is False


@pytest.mark.django_db
def test_kev_bulk_refresh_clears_flag_when_cve_drops_from_kev():
    c = _cluster()
    ns = _ns(c)
    w = _workload(c, ns)
    _finding(w, "CVE-2024-AAA", kev_listed=True, hash_code="ha")
    KevEntry.objects.create(vuln_id="CVE-2024-AAA")

    # New KEV dump no longer lists CVE-2024-AAA.
    path = _write_kev("CVE-2024-BBB")
    try:
        enrichment.load_kev_from_file(path)
    finally:
        Path(path).unlink(missing_ok=True)

    assert Finding.objects.get(vuln_id="CVE-2024-AAA").kev_listed is False


# ── chunked priority recompute ────────────────────────────────────
#
# Regression coverage for the enrich-epss OOMs: `_recompute_affected_
# findings` used to be `list(Finding.objects.filter(vuln_id__in=seen_ids))`
# — one unbounded materialization scaling with total org-wide finding
# count (every Finding matching any EPSS-scored CVE), not with the feed's
# own size. Both load_epss_from_file and load_kev_from_file call the same
# shared, now-chunked helper.


@pytest.mark.django_db
def test_recompute_affected_findings_covers_every_match_across_chunks(monkeypatch):
    """More matches than one chunk — every one must still be recomputed,
    split across multiple bounded recompute_batch calls instead of one
    call over the whole match set."""
    monkeypatch.setattr(enrichment, "_RECOMPUTE_CHUNK_SIZE", 2)

    c = _cluster()
    ns = _ns(c)
    w = _workload(c, ns)
    matching = [_finding(w, "CVE-2024-CHUNK", hash_code=f"h{i}") for i in range(5)]
    unrelated = _finding(w, "CVE-2024-OTHER", hash_code="h-other")

    seen_pks: list[set[int]] = []
    real_recompute_batch = enrichment.recompute_batch

    def _spy(findings):
        findings = list(findings)
        seen_pks.append({f.pk for f in findings})
        return real_recompute_batch(findings)

    with patch.object(enrichment, "recompute_batch", side_effect=_spy):
        enrichment._recompute_affected_findings(["CVE-2024-CHUNK"])

    assert len(seen_pks) == 3, "5 matches at chunk size 2 must be 3 calls (2, 2, 1)"
    assert all(len(chunk) <= 2 for chunk in seen_pks), "no call may exceed the chunk size"
    covered = set().union(*seen_pks)
    assert covered == {f.pk for f in matching}, "every matching Finding must be covered once"
    assert unrelated.pk not in covered, "a Finding for an unrelated CVE must never be touched"


@pytest.mark.django_db
def test_recompute_affected_findings_handles_no_matches(monkeypatch):
    """No Finding matches the given CVEs — must return cleanly without
    calling recompute_batch at all (empty chunk must not be built)."""
    monkeypatch.setattr(enrichment, "_RECOMPUTE_CHUNK_SIZE", 2)

    with patch.object(enrichment, "recompute_batch") as mock_recompute:
        total = enrichment._recompute_affected_findings(["CVE-2024-NO-MATCH"])

    mock_recompute.assert_not_called()
    assert total == 0


@pytest.mark.django_db
def test_epss_bulk_refresh_recomputes_priority_for_affected_findings():
    """End-to-end: load_epss_from_file's priority recompute call still
    reaches the Finding it just refreshed the EPSS cache on (i.e. the
    chunking refactor didn't silently drop the recompute step)."""
    c = _cluster()
    ns = _ns(c)
    w = _workload(c, ns)
    _finding(w, "CVE-2024-AAA", hash_code="ha")

    with patch.object(
        enrichment, "recompute_batch", wraps=enrichment.recompute_batch,
    ) as mock_recompute:
        path = _write_csv([("CVE-2024-AAA", 0.91, 0.99)])
        try:
            enrichment.load_epss_from_file(path)
        finally:
            Path(path).unlink(missing_ok=True)

    mock_recompute.assert_called_once()
    recomputed_pks = {f.pk for f in mock_recompute.call_args.args[0]}
    assert recomputed_pks == {Finding.objects.get(vuln_id="CVE-2024-AAA").pk}


# ── streaming / chunked feed load ─────────────────────────────────
#
# The EPSS loader used to hold the ~330k-row feed in RAM several times
# over (gz bytes, decompressed str, temp-file copy, row list, model
# list) before a single bulk_create — the actual OOM of the enrich-epss
# job. It now streams: lines → csv.reader → chunks of _UPSERT_CHUNK_SIZE
# model instances → one upsert per chunk, and "rows the feed dropped"
# is a `fetched_at < run_started` delete instead of a 330k-id NOT IN.


def _gz_csv(rows: list[tuple[str, float, float]]) -> bytes:
    out = io.StringIO()
    out.write("#model_version:v2024.05.18,score_date:2025-01-01T00:00:00+0000\n")
    out.write("cve,epss,percentile\n")
    for cve, score, pct in rows:
        out.write(f"{cve},{score},{pct}\n")
    return gzip.compress(out.getvalue().encode())


@contextlib.contextmanager
def _fake_http_open(body: bytes | None):
    yield None if body is None else io.BytesIO(body)


@pytest.mark.django_db
def test_epss_loader_upserts_in_bounded_chunks_and_sweeps_stale_rows(monkeypatch):
    monkeypatch.setattr(enrichment, "_UPSERT_CHUNK_SIZE", 2)
    EpssScore.objects.create(vuln_id="CVE-STALE", score=0.1, percentile=0.1)
    EpssScore.objects.create(vuln_id="CVE-2024-0", score=0.0, percentile=0.0)  # re-listed, value changes

    rows = [(f"CVE-2024-{i}", i / 10, i / 10) for i in range(5)]
    batches: list[int] = []
    real_bulk_create = EpssScore.objects.bulk_create

    def _spy(objs, **kw):
        batches.append(len(objs))
        return real_bulk_create(objs, **kw)

    path = _write_csv(rows)
    try:
        with patch.object(EpssScore.objects, "bulk_create", side_effect=_spy):
            n = enrichment.load_epss_from_file(path)
    finally:
        Path(path).unlink(missing_ok=True)

    assert n == 5
    assert batches == [2, 2, 1], "5 rows at chunk size 2 must be 3 statements, never one list"
    assert set(EpssScore.objects.values_list("vuln_id", flat=True)) == {f"CVE-2024-{i}" for i in range(5)}
    assert EpssScore.objects.get(vuln_id="CVE-2024-0").score == 0.0
    assert EpssScore.objects.get(vuln_id="CVE-2024-3").score == 0.3


@pytest.mark.django_db
def test_epss_loader_zero_rows_leaves_table_intact():
    """Zero-input rule survives the rewrite: a feed that parses to no rows
    must not sweep the existing table."""
    EpssScore.objects.create(vuln_id="CVE-KEEP", score=0.5, percentile=0.5)
    fd = tempfile.NamedTemporaryFile("w", suffix=".csv", delete=False)
    fd.write("cve,epss,percentile\n#nothing,here\n")
    fd.close()
    try:
        assert enrichment.load_epss_from_file(fd.name) == 0
    finally:
        Path(fd.name).unlink(missing_ok=True)
    assert EpssScore.objects.filter(vuln_id="CVE-KEEP").exists()
    assert enrichment.load_epss_from_file("/nonexistent/epss.csv") == 0
    assert EpssScore.objects.filter(vuln_id="CVE-KEEP").exists()


@pytest.mark.django_db
def test_fetch_epss_streams_gzip_response_without_temp_file(monkeypatch, tmp_path):
    """The HTTP body is gunzipped and parsed as it arrives; no temp file
    is written and the stale-row sweep still runs."""
    monkeypatch.setenv("TMPDIR", str(tmp_path))
    tempfile.tempdir = None  # make tempfile re-read TMPDIR
    EpssScore.objects.create(vuln_id="CVE-STALE", score=0.1, percentile=0.1)
    body = _gz_csv([("CVE-2024-AAA", 0.91, 0.99), ("CVE-2024-BBB", 0.10, 0.40)])

    with patch.object(enrichment, "_http_open", return_value=_fake_http_open(body)):
        n = enrichment.fetch_epss()

    assert n == 2
    assert set(EpssScore.objects.values_list("vuln_id", flat=True)) == {"CVE-2024-AAA", "CVE-2024-BBB"}
    assert list(tmp_path.iterdir()) == [], "EPSS must stream, not spool to disk"
    tempfile.tempdir = None


@pytest.mark.django_db
def test_fetch_epss_failed_connection_is_zero_input():
    EpssScore.objects.create(vuln_id="CVE-KEEP", score=0.5, percentile=0.5)
    with patch.object(enrichment, "_http_open", return_value=_fake_http_open(None)):
        assert enrichment.fetch_epss() == 0
    assert EpssScore.objects.filter(vuln_id="CVE-KEEP").exists()


class _DiesMidStream(io.RawIOBase):
    """Delivers `good` bytes, then fails like a dropped connection."""

    def __init__(self, good: bytes):
        self._buf = io.BytesIO(good)

    def readable(self):
        return True

    def readinto(self, b):
        n = self._buf.readinto(b)
        if n == 0:
            raise ConnectionResetError("peer reset")
        return n


@pytest.mark.django_db
def test_fetch_epss_stream_dying_mid_body_does_not_sweep_table(monkeypatch):
    """A connection reset half-way through the body: rows that already
    arrived are upserted (idempotent), but the stale-row delete and the
    Finding-cache refresh must not run on a partial feed."""
    monkeypatch.setattr(enrichment, "_UPSERT_CHUNK_SIZE", 1)
    EpssScore.objects.create(vuln_id="CVE-STALE", score=0.1, percentile=0.1)
    body = _gz_csv([(f"CVE-2024-{i}", 0.5, 0.5) for i in range(50)])
    truncated = body[: len(body) // 2]

    @contextlib.contextmanager
    def _open(url):
        yield io.BufferedReader(_DiesMidStream(truncated))

    with patch.object(enrichment, "_http_open", _open), \
            patch.object(enrichment, "_refresh_finding_epss_cache") as refresh:
        assert enrichment.fetch_epss() == 0

    refresh.assert_not_called()
    assert EpssScore.objects.filter(vuln_id="CVE-STALE").exists(), "partial feed must not delete"


@pytest.mark.django_db
def test_fetch_kev_streams_response_to_disk_then_loads():
    KevEntry.objects.create(vuln_id="CVE-STALE")
    body = json.dumps({"vulnerabilities": [{"cveID": "CVE-2024-AAA", "dateAdded": "2025-01-01"}]}).encode()
    with patch.object(enrichment, "_http_open", return_value=_fake_http_open(body)):
        assert enrichment.fetch_kev() == 1
    assert set(KevEntry.objects.values_list("vuln_id", flat=True)) == {"CVE-2024-AAA"}
    with patch.object(enrichment, "_http_open", return_value=_fake_http_open(None)):
        assert enrichment.fetch_kev() == 0
    assert KevEntry.objects.filter(vuln_id="CVE-2024-AAA").exists()


@pytest.mark.django_db
def test_kev_loader_invalid_json_and_empty_catalog_change_nothing():
    KevEntry.objects.create(vuln_id="CVE-KEEP")
    for content in (b"{not json", json.dumps({"vulnerabilities": []}).encode()):
        fd = tempfile.NamedTemporaryFile("wb", suffix=".json", delete=False)
        fd.write(content)
        fd.close()
        try:
            assert enrichment.load_kev_from_file(fd.name) == 0
        finally:
            Path(fd.name).unlink(missing_ok=True)
        assert KevEntry.objects.filter(vuln_id="CVE-KEEP").exists()


@pytest.mark.django_db
def test_recompute_affected_findings_accepts_a_subquery():
    """The loaders hand over `EpssScore.objects.values("vuln_id")` so the
    catalog never round-trips through Python as an IN list."""
    c = _cluster()
    ns = _ns(c)
    w = _workload(c, ns)
    hit = _finding(w, "CVE-2024-HIT", hash_code="h1")
    miss = _finding(w, "CVE-2024-MISS", hash_code="h2")
    EpssScore.objects.create(vuln_id="CVE-2024-HIT", score=0.5, percentile=0.5)

    with patch.object(enrichment, "recompute_batch", wraps=enrichment.recompute_batch) as spy:
        enrichment._recompute_affected_findings(EpssScore.objects.values("vuln_id"))

    spy.assert_called_once()
    assert {f.pk for f in spy.call_args.args[0]} == {hit.pk}
    assert miss.pk not in {f.pk for f in spy.call_args.args[0]}
