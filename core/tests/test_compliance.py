"""
Tests for compliance models, parser, service, and management command.

Covers:
- Framework/Control/Snapshot/ControlResult model constraints
- parse_trivy_compliance parser output
- save_compliance_snapshot service
- End-to-end ingest of ClusterComplianceReport
- load_frameworks management command
- backfill_compliance from RawReport
"""
import json
from decimal import Decimal
from io import StringIO
from pathlib import Path

import pytest
from django.core.management import call_command

from core.constants import Source
from core.models import Cluster, RawReport
from core.models.compliance import (
    CheckType,
    Control,
    ControlResult,
    ControlStatus,
    Framework,
    Snapshot,
)
from core.parsers.trivy import parse_trivy_compliance
from core.services.compliance import backfill_raw_reports, save_compliance_snapshot
from core.services.ingest import ingest_scan

FIXTURES = Path(__file__).parent / "fixtures"


def _load_fixture(name: str) -> dict:
    return json.loads((FIXTURES / name).read_text())


# ── Parser tests (no DB needed) ───────────────────────────────


class TestParseTrivyCompliance:
    def test_returns_compliance_dict(self):
        payload = _load_fixture("cluster_compliance_report.json")
        result = parse_trivy_compliance("test-cluster", payload)

        assert len(result) == 1
        data = result[0]
        assert data["_compliance"] is True
        assert data["framework_id"] == "k8s-cis"
        assert data["framework_title"] == "CIS Kubernetes Benchmark v1.23"
        assert data["framework_version"] == "1.23"

    def test_total_counts(self):
        payload = _load_fixture("cluster_compliance_report.json")
        data = parse_trivy_compliance("test-cluster", payload)[0]

        assert data["total_pass"] == 13
        assert data["total_fail"] == 3
        assert data["pass_rate"] == 81.25  # 13/(13+3)*100

    def test_control_results(self):
        payload = _load_fixture("cluster_compliance_report.json")
        data = parse_trivy_compliance("test-cluster", payload)[0]

        controls = data["controls"]
        assert len(controls) == 2

        # First control: 0 fail → PASS
        assert controls[0]["control_id"] == "1.2.1"
        assert controls[0]["status"] == "PASS"
        assert controls[0]["total_pass"] == 1
        assert controls[0]["total_fail"] == 0

        # Second control: 3 fail → FAIL
        assert controls[1]["control_id"] == "4.1.1"
        assert controls[1]["status"] == "FAIL"
        assert controls[1]["total_fail"] == 3

    def test_spec_controls_extracted(self):
        payload = _load_fixture("cluster_compliance_report.json")
        data = parse_trivy_compliance("test-cluster", payload)[0]

        spec = data["spec_controls"]
        assert len(spec) == 2
        assert spec[0]["control_id"] == "1.2.1"
        assert spec[0]["check_ids"] == ["AVD-KCV-0001"]

    def test_fallback_to_metadata_name(self):
        payload = {
            "kind": "ClusterComplianceReport",
            "metadata": {"name": "k8s-nsa-1.0"},
            "spec": {"compliance": {}},
            "status": {"totalCounts": {}, "summaryReport": {"controlCheck": []}},
        }
        data = parse_trivy_compliance("test", payload)[0]
        assert data["framework_id"] == "k8s-nsa-1.0"

    def test_empty_status(self):
        payload = {
            "kind": "ClusterComplianceReport",
            "metadata": {"name": "empty"},
            "spec": {"compliance": {"id": "test"}},
            "status": {},
        }
        data = parse_trivy_compliance("test", payload)[0]
        assert data["total_pass"] == 0
        assert data["total_fail"] == 0
        assert data["pass_rate"] == 0
        assert data["controls"] == []

    def test_real_world_format_no_totalcounts_no_totalpass(self):
        """Real Trivy CRDs have empty totalCounts and no totalPass key in controlCheck.
        A control with totalFail=0 means PASS (it was evaluated, nothing failed)."""
        payload = {
            "kind": "ClusterComplianceReport",
            "metadata": {"name": "k8s-pss-baseline-0.1"},
            "spec": {"compliance": {"id": "k8s-pss-baseline"}},
            "status": {
                "totalCounts": {},
                "summaryReport": {
                    "controlCheck": [
                        {"id": "1", "name": "HostProcess", "severity": "HIGH", "totalFail": 0},
                        {"id": "2", "name": "Host Namespaces", "severity": "HIGH", "totalFail": 2},
                        {"id": "3", "name": "Privileged Containers", "severity": "HIGH", "totalFail": 14},
                    ]
                },
            },
        }
        data = parse_trivy_compliance("test", payload)[0]

        # Control 1: totalFail=0 → PASS (evaluated, nothing failed)
        # Control 2: totalFail=2 → FAIL
        # Control 3: totalFail=14 → FAIL
        assert data["controls"][0]["status"] == "PASS"
        assert data["controls"][1]["status"] == "FAIL"
        assert data["controls"][2]["status"] == "FAIL"

        # Aggregated: 1 PASS control, 2 FAIL controls
        assert data["total_pass"] == 1
        assert data["total_fail"] == 2
        assert data["pass_rate"] == 33.33  # 1/(1+2)*100


# ── Model tests ────────────────────────────────────────────────


@pytest.mark.django_db
class TestComplianceModels:
    def test_framework_creation(self):
        fw = Framework.objects.create(
            slug="k8s-cis-1.23",
            name="CIS Kubernetes Benchmark",
            version="1.23",
        )
        assert str(fw) == "CIS Kubernetes Benchmark v1.23"

    def test_framework_slug_unique(self):
        Framework.objects.create(slug="cis", name="CIS", version="1")
        with pytest.raises(Exception):
            Framework.objects.create(slug="cis", name="CIS dup", version="2")

    def test_control_creation(self):
        fw = Framework.objects.create(slug="cis", name="CIS", version="1")
        ctrl = Control.objects.create(
            framework=fw,
            control_id="1.2.1",
            title="Anonymous auth disabled",
            severity="Critical",
            check_type=CheckType.AUTOMATED,
            check_ids=["AVD-KCV-0001"],
        )
        assert "1.2.1" in str(ctrl)

    def test_control_unique_per_framework(self):
        fw = Framework.objects.create(slug="cis", name="CIS", version="1")
        Control.objects.create(framework=fw, control_id="1.1", title="A")
        with pytest.raises(Exception):
            Control.objects.create(framework=fw, control_id="1.1", title="B")

    def test_snapshot_creation(self, cluster):
        fw = Framework.objects.create(slug="cis", name="CIS", version="1")
        from django.utils import timezone

        snap = Snapshot.objects.create(
            cluster=cluster,
            framework=fw,
            scanned_at=timezone.now(),
            total_pass=10,
            total_fail=2,
            pass_rate=Decimal("83.33"),
        )
        assert "cis" in str(snap)
        assert "83.33" in str(snap)

    def test_control_result_creation(self, cluster):
        fw = Framework.objects.create(slug="cis", name="CIS", version="1")
        ctrl = Control.objects.create(framework=fw, control_id="1.1", title="A")
        from django.utils import timezone

        snap = Snapshot.objects.create(
            cluster=cluster,
            framework=fw,
            scanned_at=timezone.now(),
            total_pass=5,
            total_fail=1,
        )
        cr = ControlResult.objects.create(
            snapshot=snap,
            control=ctrl,
            status=ControlStatus.PASS,
            total_pass=5,
            total_fail=0,
        )
        assert cr.status == "PASS"

    def test_control_result_unique_per_snapshot(self, cluster):
        fw = Framework.objects.create(slug="cis", name="CIS", version="1")
        ctrl = Control.objects.create(framework=fw, control_id="1.1", title="A")
        from django.utils import timezone

        snap = Snapshot.objects.create(
            cluster=cluster,
            framework=fw,
            scanned_at=timezone.now(),
        )
        ControlResult.objects.create(snapshot=snap, control=ctrl, status="PASS")
        with pytest.raises(Exception):
            ControlResult.objects.create(snapshot=snap, control=ctrl, status="FAIL")


# ── Service tests ──────────────────────────────────────────────


@pytest.mark.django_db
class TestSaveComplianceSnapshot:
    def test_creates_framework_and_snapshot(self, cluster):
        payload = _load_fixture("cluster_compliance_report.json")
        data = parse_trivy_compliance("test-cluster", payload)[0]

        result = save_compliance_snapshot(cluster, data, payload)

        assert result["status"] == "success"
        assert result["framework"] == "k8s-cis"
        assert Framework.objects.count() == 1
        assert Snapshot.objects.count() == 1
        assert ControlResult.objects.count() == 2

    def test_snapshot_values(self, cluster):
        payload = _load_fixture("cluster_compliance_report.json")
        data = parse_trivy_compliance("test-cluster", payload)[0]
        save_compliance_snapshot(cluster, data, payload)

        snap = Snapshot.objects.first()
        assert snap.total_pass == 13
        assert snap.total_fail == 3
        assert snap.pass_rate == Decimal("81.25")
        assert snap.cluster == cluster

    def test_control_results_status(self, cluster):
        payload = _load_fixture("cluster_compliance_report.json")
        data = parse_trivy_compliance("test-cluster", payload)[0]
        save_compliance_snapshot(cluster, data, payload)

        results = {
            cr.control.control_id: cr
            for cr in ControlResult.objects.select_related("control")
        }
        assert results["1.2.1"].status == "PASS"
        assert results["4.1.1"].status == "FAIL"
        assert results["4.1.1"].total_fail == 3

    def test_creates_controls_from_spec(self, cluster):
        payload = _load_fixture("cluster_compliance_report.json")
        data = parse_trivy_compliance("test-cluster", payload)[0]
        save_compliance_snapshot(cluster, data, payload)

        fw = Framework.objects.get(slug="k8s-cis")
        assert fw.total_controls == 2
        assert Control.objects.filter(framework=fw).count() == 2
        ctrl = Control.objects.get(control_id="1.2.1")
        assert ctrl.check_ids == ["AVD-KCV-0001"]

    def test_multiple_snapshots_immutable(self, cluster):
        payload = _load_fixture("cluster_compliance_report.json")
        data = parse_trivy_compliance("test-cluster", payload)[0]

        save_compliance_snapshot(cluster, data, payload)
        save_compliance_snapshot(cluster, data, payload)

        assert Snapshot.objects.count() == 2  # each scan = new snapshot
        assert Framework.objects.count() == 1  # framework reused

    def test_raw_json_stored(self, cluster):
        payload = _load_fixture("cluster_compliance_report.json")
        data = parse_trivy_compliance("test-cluster", payload)[0]
        save_compliance_snapshot(cluster, data, payload)

        snap = Snapshot.objects.first()
        assert snap.raw_json["kind"] == "ClusterComplianceReport"


# ── Ingest integration test ────────────────────────────────────


@pytest.mark.django_db
class TestComplianceIngestIntegration:
    def test_end_to_end(self):
        payload = _load_fixture("cluster_compliance_report.json")
        result = ingest_scan(payload, cluster_name_header="test-cluster")

        assert result["status"] == "success"
        assert result["kind"] == "ClusterComplianceReport"
        assert result["framework"] == "k8s-cis"
        assert Snapshot.objects.count() == 1
        assert ControlResult.objects.count() == 2
        assert Cluster.objects.filter(name="test-cluster").exists()

    def test_no_longer_stored_as_raw(self):
        """Compliance reports should go to structured models, not RawReport."""
        payload = _load_fixture("cluster_compliance_report.json")
        ingest_scan(payload, cluster_name_header="test-cluster")

        assert RawReport.objects.count() == 0
        assert Snapshot.objects.count() == 1


# ── Backfill test ──────────────────────────────────────────────


@pytest.mark.django_db
class TestBackfillCompliance:
    def test_backfill_processes_raw_reports(self, cluster):
        payload = _load_fixture("cluster_compliance_report.json")
        RawReport.objects.create(
            cluster=cluster,
            kind="ClusterComplianceReport",
            source=Source.TRIVY,
            raw_json=payload,
        )

        result = backfill_raw_reports()
        assert result["processed"] == 1
        assert result["errors"] == 0
        assert Snapshot.objects.count() == 1

    def test_backfill_filter_by_cluster(self, cluster):
        payload = _load_fixture("cluster_compliance_report.json")
        other = Cluster.objects.create(name="other-cluster")
        RawReport.objects.create(
            cluster=cluster, kind="ClusterComplianceReport", raw_json=payload
        )
        RawReport.objects.create(
            cluster=other, kind="ClusterComplianceReport", raw_json=payload
        )

        result = backfill_raw_reports(cluster_name="test-cluster")
        assert result["processed"] == 1
        assert Snapshot.objects.filter(cluster=cluster).count() == 1
        assert Snapshot.objects.filter(cluster=other).count() == 0


# ── Management command test ────────────────────────────────────


@pytest.mark.django_db
class TestLoadFrameworksCommand:
    def test_load_sample_fixture(self):
        fixture_path = (
            Path(__file__).parent.parent.parent / "fixtures" / "k8s-cis-1.23-sample.yaml"
        )
        out = StringIO()
        call_command("load_frameworks", str(fixture_path), stdout=out)

        assert Framework.objects.count() == 1
        fw = Framework.objects.first()
        assert fw.slug == "k8s-cis-1.23"
        assert fw.total_controls == 5

        # Check control types
        auto = Control.objects.filter(check_type=CheckType.AUTOMATED).count()
        manual = Control.objects.filter(check_type=CheckType.MANUAL).count()
        assert auto == 4
        assert manual == 1

    def test_idempotent_reload(self):
        fixture_path = (
            Path(__file__).parent.parent.parent / "fixtures" / "k8s-cis-1.23-sample.yaml"
        )
        call_command("load_frameworks", str(fixture_path))
        call_command("load_frameworks", str(fixture_path))

        assert Framework.objects.count() == 1
        assert Control.objects.count() == 5  # no duplicates

    def test_kyverno_policies_loaded(self):
        fixture_path = (
            Path(__file__).parent.parent.parent / "fixtures" / "k8s-cis-1.23-sample.yaml"
        )
        call_command("load_frameworks", str(fixture_path))

        ctrl = Control.objects.get(control_id="4.1.1")
        assert ctrl.kyverno_policies == ["disallow-privileged-containers"]
