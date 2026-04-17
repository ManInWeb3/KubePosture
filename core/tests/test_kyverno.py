"""
Tests for Kyverno PolicyReport parser, model, and ingest integration.

Covers:
- parse_kyverno_policyreport parser output (findings + summary)
- PolicyComplianceSnapshot model
- End-to-end ingest of PolicyReport
- Dedup behavior for Kyverno findings
"""
import json
from pathlib import Path

import pytest

from core.constants import Category, Severity, Source
from core.models import Cluster, Finding
from core.models.kyverno import PolicyComplianceSnapshot
from core.parsers.kyverno import parse_kyverno_policyreport
from core.services.ingest import ingest_scan

FIXTURES = Path(__file__).parent / "fixtures"


def _load_fixture(name: str) -> dict:
    return json.loads((FIXTURES / name).read_text())


# ── Parser tests (no DB) ──────────────────────────────────────


class TestParseKyvernoPolicyReport:
    def test_returns_findings_and_summary(self):
        payload = _load_fixture("policy_report.json")
        result = parse_kyverno_policyreport("test-cluster", payload)

        # 2 fail results → 2 findings + 1 summary dict
        findings = [r for r in result if not r.get("_kyverno_summary")]
        summary = [r for r in result if r.get("_kyverno_summary")]
        assert len(findings) == 2
        assert len(summary) == 1

    def test_only_fail_and_error_become_findings(self):
        payload = _load_fixture("policy_report.json")
        result = parse_kyverno_policyreport("test-cluster", payload)
        findings = [r for r in result if not r.get("_kyverno_summary")]

        # pass and warn results are NOT findings
        for f in findings:
            assert f["details"]["result"] in ("fail", "error")

    def test_finding_fields(self):
        payload = _load_fixture("policy_report.json")
        result = parse_kyverno_policyreport("test-cluster", payload)
        findings = [r for r in result if not r.get("_kyverno_summary")]
        f = findings[0]

        assert f["title"] == "require-resource-limits/check-cpu-limits"
        assert f["severity"] == Severity.MEDIUM
        assert f["vuln_id"] == "require-resource-limits"
        assert f["category"] == Category.POLICY
        assert f["source"] == Source.KYVERNO
        assert f["namespace"] == "prod-app-backend"
        assert f["resource_kind"] == "Deployment"
        assert f["resource_name"] == "backend"

        assert f["details"]["policy"] == "require-resource-limits"
        assert f["details"]["rule"] == "check-cpu-limits"
        assert "CPU limits" in f["details"]["message"]

    def test_summary_counts(self):
        payload = _load_fixture("policy_report.json")
        result = parse_kyverno_policyreport("test-cluster", payload)
        summary = result[-1]

        assert summary["_kyverno_summary"] is True
        assert summary["total_pass"] == 2
        assert summary["total_fail"] == 2  # 2 fail + 0 error
        assert summary["total_warn"] == 1
        assert summary["total_skip"] == 0
        assert summary["pass_rate"] == 50.0

    def test_empty_report(self):
        payload = {
            "kind": "PolicyReport",
            "metadata": {"name": "empty"},
            "scope": {},
            "results": [],
            "summary": {},
        }
        result = parse_kyverno_policyreport("test-cluster", payload)
        # Only summary, no findings
        assert len(result) == 1
        assert result[0]["_kyverno_summary"] is True
        assert result[0]["total_pass"] == 0
        assert result[0]["pass_rate"] == 0

    def test_all_pass_no_findings(self):
        payload = {
            "kind": "PolicyReport",
            "metadata": {"name": "all-pass"},
            "scope": {"kind": "Deployment", "name": "web", "namespace": "default"},
            "results": [
                {"policy": "p1", "rule": "r1", "result": "pass", "severity": "high"},
                {"policy": "p2", "rule": "r2", "result": "pass", "severity": "medium"},
            ],
            "summary": {"pass": 2, "fail": 0, "warn": 0, "error": 0, "skip": 0},
        }
        result = parse_kyverno_policyreport("test-cluster", payload)
        findings = [r for r in result if not r.get("_kyverno_summary")]
        assert len(findings) == 0
        assert result[-1]["pass_rate"] == 100.0

    def test_error_results_become_findings(self):
        payload = {
            "kind": "PolicyReport",
            "metadata": {"name": "errors"},
            "scope": {"kind": "Pod", "name": "test", "namespace": "default"},
            "results": [
                {"policy": "p1", "rule": "r1", "result": "error", "severity": "high",
                 "message": "Policy evaluation error"},
            ],
            "summary": {"pass": 0, "fail": 0, "warn": 0, "error": 1, "skip": 0},
        }
        result = parse_kyverno_policyreport("test-cluster", payload)
        findings = [r for r in result if not r.get("_kyverno_summary")]
        assert len(findings) == 1
        assert findings[0]["details"]["result"] == "error"
        # error counts as fail in summary
        assert result[-1]["total_fail"] == 1

    def test_severity_mapping(self):
        payload = {
            "kind": "PolicyReport",
            "metadata": {"name": "sev"},
            "scope": {"kind": "Pod", "name": "x", "namespace": "ns"},
            "results": [
                {"policy": "p", "rule": "r", "result": "fail", "severity": "critical"},
            ],
            "summary": {"fail": 1},
        }
        result = parse_kyverno_policyreport("test-cluster", payload)
        assert result[0]["severity"] == Severity.CRITICAL


# ── Model tests ────────────────────────────────────────────────


@pytest.mark.django_db
class TestPolicyComplianceSnapshotModel:
    def test_create(self, cluster):
        from django.utils import timezone

        snap = PolicyComplianceSnapshot.objects.create(
            cluster=cluster,
            scanned_at=timezone.now(),
            total_pass=10,
            total_fail=3,
            total_warn=1,
            total_skip=0,
            pass_rate=76.92,
        )
        assert "test-cluster" in str(snap)
        assert "76.92" in str(snap)


# ── Ingest integration ─────────────────────────────────────────


@pytest.mark.django_db
class TestKyvernoIngestIntegration:
    def test_end_to_end(self):
        payload = _load_fixture("policy_report.json")
        result = ingest_scan(payload, cluster_name_header="test-cluster")

        assert result["status"] == "success"
        assert result["kind"] == "PolicyReport"
        assert result["source"] == Source.KYVERNO
        assert result["created"] == 2

        # Findings created with correct source
        assert Finding.objects.filter(source=Source.KYVERNO).count() == 2
        assert Finding.objects.filter(category=Category.POLICY).count() == 2

        # PolicyComplianceSnapshot created
        assert PolicyComplianceSnapshot.objects.count() == 1
        snap = PolicyComplianceSnapshot.objects.first()
        assert snap.total_pass == 2
        assert snap.total_fail == 2

        # Cluster auto-registered
        assert Cluster.objects.filter(name="test-cluster").exists()

    def test_dedup_on_rescan(self):
        payload = _load_fixture("policy_report.json")
        ingest_scan(payload, cluster_name_header="test-cluster")
        result = ingest_scan(payload, cluster_name_header="test-cluster")

        assert result["created"] == 0
        assert result["updated"] == 2
        assert Finding.objects.count() == 2

        # Each ingest creates a new snapshot (immutable)
        assert PolicyComplianceSnapshot.objects.count() == 2

    def test_no_stale_resolution_for_kyverno(self):
        """Kyverno findings should NOT be auto-resolved per-CRD
        since a PolicyReport spans multiple resources."""
        payload = _load_fixture("policy_report.json")
        ingest_scan(payload, cluster_name_header="test-cluster")
        assert Finding.objects.filter(status="active").count() == 2

        # Second ingest with different failures — original findings stay active
        payload2 = {
            "kind": "PolicyReport",
            "metadata": {"name": "other"},
            "scope": {"kind": "Deployment", "name": "other-app", "namespace": "default"},
            "results": [
                {"policy": "new-policy", "rule": "new-rule", "result": "fail",
                 "severity": "high", "message": "New failure"},
            ],
            "summary": {"pass": 0, "fail": 1},
        }
        result2 = ingest_scan(payload2, cluster_name_header="test-cluster")

        # All 3 findings should be active — no stale resolution
        assert Finding.objects.filter(status="active").count() == 3
        assert result2["resolved"] == 0

    def test_scan_status_updated(self):
        payload = _load_fixture("policy_report.json")
        ingest_scan(payload, cluster_name_header="test-cluster")

        from core.models import ScanStatus
        ss = ScanStatus.objects.get(cluster__name="test-cluster", source=Source.KYVERNO)
        assert ss.finding_count == 2

    def test_all_pass_report(self):
        """A report with no failures creates snapshot but no findings."""
        payload = {
            "kind": "PolicyReport",
            "metadata": {"name": "all-pass"},
            "scope": {"kind": "Deployment", "name": "web", "namespace": "default"},
            "results": [
                {"policy": "p1", "rule": "r1", "result": "pass", "severity": "high"},
            ],
            "summary": {"pass": 1, "fail": 0, "warn": 0, "error": 0, "skip": 0},
        }
        result = ingest_scan(payload, cluster_name_header="test-cluster")

        assert result["status"] == "success"
        assert result["created"] == 0
        assert Finding.objects.count() == 0
        assert PolicyComplianceSnapshot.objects.count() == 1
