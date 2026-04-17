"""
Tests for EPSS and CISA KEV enrichment.

Uses mock data instead of real URLs. Tests cover:
- CSV/JSON parsing
- Bulk update logic (mark, clear, skip unchanged)
- Management commands
"""
import gzip
import json
from decimal import Decimal
from http.server import BaseHTTPRequestHandler, HTTPServer
from io import StringIO
from pathlib import Path
from threading import Thread
from unittest.mock import patch

import pytest

from core.constants import Category, Origin, Severity, Source, Status
from core.models import Cluster, Finding
from core.services.enrichment import (
    apply_epss_scores,
    apply_kev_flags,
    fetch_epss_scores,
    fetch_kev_cves,
    enrich_epss,
    enrich_kev,
)

# ── Sample data ────────────────────────────────────────────────

SAMPLE_EPSS_CSV = """\
#model_version:v2024.01.01,score_date:2026-04-15
cve,epss,percentile
CVE-2024-1234,0.85000,0.99000
CVE-2024-5678,0.00150,0.45000
CVE-2024-9999,0.50000,0.95000
"""

SAMPLE_KEV_JSON = json.dumps({
    "title": "CISA KEV",
    "catalogVersion": "2026.04.15",
    "vulnerabilities": [
        {"cveID": "CVE-2024-1234", "vendorProject": "OpenSSL"},
        {"cveID": "CVE-2024-9999", "vendorProject": "curl"},
    ],
})


def _create_cve_finding(cluster, vuln_id, **kwargs):
    defaults = {
        "origin": Origin.CLUSTER,
        "cluster": cluster,
        "title": f"Test {vuln_id}",
        "severity": Severity.HIGH,
        "vuln_id": vuln_id,
        "category": Category.VULNERABILITY,
        "source": Source.TRIVY,
        "status": Status.ACTIVE,
        "hash_code": f"hash_{vuln_id}",
        "namespace": "default",
        "resource_kind": "Deployment",
        "resource_name": "test",
    }
    defaults.update(kwargs)
    return Finding.objects.create(**defaults)


# ── EPSS parsing ───────────────────────────────────────────────


class TestFetchEpssScores:
    def test_parse_csv(self):
        with patch("core.services.enrichment.urlopen") as mock:
            mock.return_value.__enter__ = lambda s: s
            mock.return_value.__exit__ = lambda s, *a: None
            # Return plain text (not gzipped, for simplicity)
            mock.return_value.read.return_value = SAMPLE_EPSS_CSV.encode()

            scores = fetch_epss_scores("http://fake")

        assert len(scores) == 3
        assert scores["CVE-2024-1234"] == Decimal("0.85000")
        assert scores["CVE-2024-5678"] == Decimal("0.00150")

    def test_parse_gzipped(self):
        compressed = gzip.compress(SAMPLE_EPSS_CSV.encode())
        with patch("core.services.enrichment.urlopen") as mock:
            mock.return_value.__enter__ = lambda s: s
            mock.return_value.__exit__ = lambda s, *a: None
            mock.return_value.read.return_value = compressed

            scores = fetch_epss_scores("http://fake")

        assert len(scores) == 3

    def test_empty_response(self):
        with patch("core.services.enrichment.urlopen") as mock:
            mock.return_value.__enter__ = lambda s: s
            mock.return_value.__exit__ = lambda s, *a: None
            mock.return_value.read.return_value = b""

            scores = fetch_epss_scores("http://fake")

        assert scores == {}

    def test_network_error(self):
        from urllib.error import URLError

        with patch("core.services.enrichment.urlopen", side_effect=URLError("timeout")):
            scores = fetch_epss_scores("http://fake")

        assert scores == {}


# ── EPSS apply ─────────────────────────────────────────────────


@pytest.mark.django_db
class TestApplyEpssScores:
    def test_updates_matching_findings(self, cluster):
        f1 = _create_cve_finding(cluster, "CVE-2024-1234")
        f2 = _create_cve_finding(cluster, "CVE-2024-5678")

        scores = {
            "CVE-2024-1234": Decimal("0.85"),
            "CVE-2024-5678": Decimal("0.0015"),
        }
        updated = apply_epss_scores(scores)

        assert updated == 2
        f1.refresh_from_db()
        f2.refresh_from_db()
        assert f1.epss_score == Decimal("0.85")
        assert f2.epss_score == Decimal("0.0015")

    def test_skips_non_cve_findings(self, cluster):
        _create_cve_finding(cluster, "KSV001")  # not a CVE

        scores = {"KSV001": Decimal("0.5")}
        updated = apply_epss_scores(scores)
        assert updated == 0

    def test_skips_unchanged(self, cluster):
        f = _create_cve_finding(cluster, "CVE-2024-1234", epss_score=Decimal("0.85"))

        scores = {"CVE-2024-1234": Decimal("0.85")}
        updated = apply_epss_scores(scores)
        assert updated == 0

    def test_empty_scores(self):
        assert apply_epss_scores({}) == 0


# ── KEV parsing ────────────────────────────────────────────────


class TestFetchKevCves:
    def test_parse_json(self):
        with patch("core.services.enrichment.urlopen") as mock:
            mock.return_value.__enter__ = lambda s: s
            mock.return_value.__exit__ = lambda s, *a: None
            mock.return_value.read.return_value = SAMPLE_KEV_JSON.encode()

            cves = fetch_kev_cves("http://fake")

        assert cves == {"CVE-2024-1234", "CVE-2024-9999"}

    def test_network_error(self):
        from urllib.error import URLError

        with patch("core.services.enrichment.urlopen", side_effect=URLError("timeout")):
            cves = fetch_kev_cves("http://fake")

        assert cves == set()


# ── KEV apply ──────────────────────────────────────────────────


@pytest.mark.django_db
class TestApplyKevFlags:
    def test_marks_matching(self, cluster):
        f1 = _create_cve_finding(cluster, "CVE-2024-1234")
        f2 = _create_cve_finding(cluster, "CVE-2024-5678")

        result = apply_kev_flags({"CVE-2024-1234"})

        f1.refresh_from_db()
        f2.refresh_from_db()
        assert f1.kev_listed is True
        assert f2.kev_listed is None  # unchanged
        assert result["marked_kev"] == 1

    def test_clears_removed_from_kev(self, cluster):
        f = _create_cve_finding(cluster, "CVE-2024-1234", kev_listed=True)

        # CVE removed from KEV list
        result = apply_kev_flags({"CVE-2024-9999"})

        f.refresh_from_db()
        assert f.kev_listed is False
        assert result["cleared_kev"] == 1

    def test_skips_already_marked(self, cluster):
        _create_cve_finding(cluster, "CVE-2024-1234", kev_listed=True)

        result = apply_kev_flags({"CVE-2024-1234"})
        assert result["marked_kev"] == 0  # already True

    def test_empty_kev(self):
        result = apply_kev_flags(set())
        assert result["marked_kev"] == 0
        assert result["cleared_kev"] == 0


# ── End-to-end with mocked downloads ──────────────────────────


@pytest.mark.django_db
class TestEnrichEndToEnd:
    def test_enrich_epss(self, cluster):
        _create_cve_finding(cluster, "CVE-2024-1234")
        _create_cve_finding(cluster, "CVE-2024-5678")

        with patch("core.services.enrichment.urlopen") as mock:
            mock.return_value.__enter__ = lambda s: s
            mock.return_value.__exit__ = lambda s, *a: None
            mock.return_value.read.return_value = SAMPLE_EPSS_CSV.encode()

            result = enrich_epss("http://fake")

        assert result["scores_downloaded"] == 3
        assert result["findings_updated"] == 2

        f = Finding.objects.get(vuln_id="CVE-2024-1234")
        assert f.epss_score == Decimal("0.85000")

    def test_enrich_kev(self, cluster):
        _create_cve_finding(cluster, "CVE-2024-1234")
        _create_cve_finding(cluster, "CVE-2024-5678")

        with patch("core.services.enrichment.urlopen") as mock:
            mock.return_value.__enter__ = lambda s: s
            mock.return_value.__exit__ = lambda s, *a: None
            mock.return_value.read.return_value = SAMPLE_KEV_JSON.encode()

            result = enrich_kev("http://fake")

        assert result["kev_cves_downloaded"] == 2
        assert result["marked_kev"] == 1  # only CVE-2024-1234

        f = Finding.objects.get(vuln_id="CVE-2024-1234")
        assert f.kev_listed is True

        f2 = Finding.objects.get(vuln_id="CVE-2024-5678")
        assert f2.kev_listed is None  # not in KEV
