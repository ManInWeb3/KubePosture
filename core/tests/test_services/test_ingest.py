import json
from pathlib import Path

import pytest

from core.models import Cluster, Finding, RawReport, ScanStatus
from core.services.ingest import IngestError, ingest_scan

FIXTURES = Path(__file__).parent.parent / "fixtures"


def _load_fixture(name: str) -> dict:
    return json.loads((FIXTURES / name).read_text())


@pytest.mark.django_db
class TestIngestScan:
    def test_vulnerability_report_end_to_end(self):
        payload = _load_fixture("vulnerability_report.json")
        result = ingest_scan(payload, cluster_name_header="test-cluster")

        assert result["status"] == "success"
        assert result["kind"] == "VulnerabilityReport"
        assert result["created"] == 2
        assert result["cluster"] == "test-cluster"

        # Cluster auto-registered
        assert Cluster.objects.filter(name="test-cluster").exists()

        # Findings created
        assert Finding.objects.count() == 2

        # ScanStatus updated
        ss = ScanStatus.objects.get(cluster__name="test-cluster", source="trivy")
        assert ss.finding_count == 2

    def test_configaudit_report(self):
        payload = _load_fixture("configaudit_report.json")
        result = ingest_scan(payload, cluster_name_header="test-cluster")

        assert result["status"] == "success"
        assert result["created"] == 2  # 2 failed checks out of 3

    def test_compliance_creates_snapshot(self):
        payload = {
            "kind": "ClusterComplianceReport",
            "metadata": {"name": "cis", "labels": {}},
            "spec": {
                "compliance": {
                    "id": "cis",
                    "title": "CIS Test",
                    "version": "1.0",
                    "controls": [
                        {"id": "1.1", "name": "Test", "severity": "HIGH", "checks": []}
                    ],
                }
            },
            "status": {
                "totalCounts": {"passCount": 50, "failCount": 10},
                "summaryReport": {
                    "controlCheck": [
                        {"id": "1.1", "name": "Test", "severity": "HIGH", "totalPass": 50, "totalFail": 10}
                    ]
                },
            },
        }
        result = ingest_scan(payload, cluster_name_header="test-cluster")

        assert result["status"] == "success"
        assert result["framework"] == "cis"
        assert RawReport.objects.count() == 0  # no longer stored as raw
        assert Finding.objects.count() == 0  # compliance doesn't create findings

    def test_sbom_creates_components(self):
        payload = _load_fixture("sbom_report.json")
        result = ingest_scan(payload, cluster_name_header="test-cluster")

        assert result["status"] == "success"
        assert result["kind"] == "SbomReport"
        assert result["components_created"] == 3
        assert RawReport.objects.count() == 0  # no longer stored as raw

        from core.models import Component
        assert Component.objects.filter(cluster__name="test-cluster").count() == 3

    def test_unknown_kind_raises(self):
        with pytest.raises(IngestError, match="Unknown CRD kind"):
            ingest_scan({"kind": "FakeReport"}, cluster_name_header="test-cluster")

    def test_missing_kind_raises(self):
        with pytest.raises(IngestError, match="Missing 'kind'"):
            ingest_scan({"data": "no kind"}, cluster_name_header="test-cluster")

    def test_missing_cluster_name_raises(self):
        payload = {"kind": "VulnerabilityReport", "metadata": {"labels": {}}, "report": {"vulnerabilities": []}}
        with pytest.raises(IngestError, match="Cluster name required"):
            ingest_scan(payload, cluster_name_header=None)

    def test_envelope_unwrap(self):
        inner = _load_fixture("vulnerability_report.json")
        envelope = {"verb": "update", "operatorObject": inner}
        result = ingest_scan(envelope, cluster_name_header="test-cluster")
        assert result["status"] == "success"
        assert result["created"] == 2

    def test_delete_verb_skipped(self):
        envelope = {"verb": "delete", "operatorObject": {"kind": "VulnerabilityReport"}}
        result = ingest_scan(envelope, cluster_name_header="test-cluster")
        assert result["status"] == "skipped"

    def test_cluster_auto_registration(self):
        payload = _load_fixture("vulnerability_report.json")
        ingest_scan(payload, cluster_name_header="cluster-name-1")

        cluster = Cluster.objects.get(name="cluster-name-1")
        # Auto-register seeds defaults; provider/region come from the
        # /cluster-metadata/sync/ endpoint (not ingest). Environment is
        # parsed from the cluster name — "cluster-name-1" has no keyword
        # so it stays "unknown" until the admin sets it or the sync
        # endpoint runs with a name containing prod/staging/dev.
        assert cluster.provider == "onprem"  # default
        assert cluster.environment == "unknown"

    def test_dedup_on_rescan(self):
        payload = _load_fixture("vulnerability_report.json")
        ingest_scan(payload, cluster_name_header="test-cluster")
        result = ingest_scan(payload, cluster_name_header="test-cluster")

        assert result["created"] == 0
        assert result["updated"] == 2
        assert Finding.objects.count() == 2
