"""Tests for the bulk Finding-cache refresh in core.services.enrichment.

Locks the behaviour after the per-CVE UPDATE loop in `load_epss_from_file`
deadlocked in production with the ingest queue worker. The replacement is
a single bulk SQL UPDATE (autocommit + deadlock retry) that propagates
EpssScore / KevEntry into the Finding cache columns.
"""
from __future__ import annotations

import io
import json
import tempfile
from pathlib import Path

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
