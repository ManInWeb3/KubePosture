import pytest
from django.db import IntegrityError

from core.constants import Category, Origin, Severity, Source, Status
from core.models import Cluster, Finding, RawReport, ScanStatus


@pytest.mark.django_db
class TestCluster:
    def test_create_cluster(self):
        cluster = Cluster.objects.create(
            name="test-cluster", provider="ovh", environment="dev"
        )
        assert cluster.name == "test-cluster"
        assert str(cluster) == "test-cluster"

    def test_unique_name(self):
        Cluster.objects.create(name="cluster-1")
        with pytest.raises(IntegrityError):
            Cluster.objects.create(name="cluster-1")

    def test_defaults(self):
        cluster = Cluster.objects.create(name="bare-cluster")
        assert cluster.provider == "onprem"
        assert cluster.environment == ""
        assert cluster.region == ""


@pytest.mark.django_db
class TestScanStatus:
    def test_create(self, cluster):
        ss = ScanStatus.objects.create(
            cluster=cluster,
            source=Source.TRIVY,
            last_ingest="2026-04-15T10:00:00Z",
            finding_count=42,
        )
        assert str(ss) == "test-cluster / trivy"

    def test_unique_per_cluster_source(self, cluster):
        ScanStatus.objects.create(
            cluster=cluster, source=Source.TRIVY, last_ingest="2026-04-15T10:00:00Z"
        )
        with pytest.raises(IntegrityError):
            ScanStatus.objects.create(
                cluster=cluster, source=Source.TRIVY, last_ingest="2026-04-15T11:00:00Z"
            )

    def test_different_sources_ok(self, cluster):
        ScanStatus.objects.create(
            cluster=cluster, source=Source.TRIVY, last_ingest="2026-04-15T10:00:00Z"
        )
        ScanStatus.objects.create(
            cluster=cluster, source=Source.KYVERNO, last_ingest="2026-04-15T10:00:00Z"
        )
        assert ScanStatus.objects.filter(cluster=cluster).count() == 2


@pytest.mark.django_db
class TestFinding:
    def _make_finding(self, cluster, **overrides):
        from core.models import Namespace
        ns, _ = Namespace.objects.get_or_create(cluster=cluster, name="prod-app")
        defaults = {
            "origin": Origin.CLUSTER,
            "cluster": cluster,
            "namespace": ns,
            "resource_kind": "Deployment",
            "resource_name": "backend",
            "title": "CVE-2024-1234 in openssl",
            "severity": Severity.CRITICAL,
            "vuln_id": "CVE-2024-1234",
            "category": Category.VULNERABILITY,
            "source": Source.TRIVY,
            "hash_code": "abc123",
            "details": {"component_name": "openssl", "score": 9.8},
        }
        defaults.update(overrides)
        return Finding.objects.create(**defaults)

    def test_create(self, cluster):
        f = self._make_finding(cluster)
        assert f.status == Status.ACTIVE
        assert f.first_seen is not None
        assert f.resolved_at is None
        assert "[Critical]" in str(f)

    def test_unique_constraint(self, cluster):
        self._make_finding(cluster, hash_code="same-hash")
        with pytest.raises(IntegrityError):
            self._make_finding(cluster, hash_code="same-hash")

    def test_different_clusters_same_hash_ok(self):
        c1 = Cluster.objects.create(name="cluster-1")
        c2 = Cluster.objects.create(name="cluster-2")
        self._make_finding(c1, hash_code="same-hash")
        self._make_finding(c2, hash_code="same-hash")
        assert Finding.objects.count() == 2

    def test_jsonb_details_queryable(self, cluster):
        self._make_finding(
            cluster,
            hash_code="h1",
            details={"component_name": "openssl", "score": 9.8},
        )
        self._make_finding(
            cluster,
            hash_code="h2",
            details={"component_name": "curl", "score": 7.5},
        )
        results = Finding.objects.filter(details__component_name="openssl")
        assert results.count() == 1
        assert results.first().vuln_id == "CVE-2024-1234"

    def test_default_status_is_active(self, cluster):
        f = self._make_finding(cluster)
        assert f.status == Status.ACTIVE

    def test_enrichment_fields_nullable(self, cluster):
        f = self._make_finding(cluster)
        assert f.epss_score is None
        assert f.kev_listed is None
        assert f.accepted_by is None


@pytest.mark.django_db
class TestRawReport:
    def test_create(self, cluster):
        rr = RawReport.objects.create(
            cluster=cluster,
            kind="ClusterComplianceReport",
            raw_json={"spec": {"compliance": {"id": "cis"}}},
        )
        assert "ClusterComplianceReport" in str(rr)
        assert rr.received_at is not None
