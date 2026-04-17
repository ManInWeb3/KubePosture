import pytest

from core.constants import Category, Origin, Severity, Source, Status
from core.models import Finding
from core.services.dedup import compute_hash, resolve_stale, upsert_findings


def _vuln_dict(**overrides):
    defaults = {
        "title": "CVE-2024-1234 in openssl",
        "severity": Severity.CRITICAL,
        "vuln_id": "CVE-2024-1234",
        "category": Category.VULNERABILITY,
        "source": Source.TRIVY,
        "namespace": "prod-app",
        "resource_kind": "Deployment",
        "resource_name": "backend",
        "details": {"component_name": "openssl"},
    }
    defaults.update(overrides)
    return defaults


class TestComputeHash:
    def test_deterministic(self):
        fd = _vuln_dict()
        assert compute_hash(fd) == compute_hash(fd)

    def test_different_vuln_id_different_hash(self):
        h1 = compute_hash(_vuln_dict(vuln_id="CVE-2024-1234"))
        h2 = compute_hash(_vuln_dict(vuln_id="CVE-2024-9999"))
        assert h1 != h2

    def test_different_resource_different_hash(self):
        h1 = compute_hash(_vuln_dict(resource_name="backend"))
        h2 = compute_hash(_vuln_dict(resource_name="frontend"))
        assert h1 != h2

    def test_hash_is_64_char_hex(self):
        h = compute_hash(_vuln_dict())
        assert len(h) == 64
        assert all(c in "0123456789abcdef" for c in h)


@pytest.mark.django_db
class TestUpsertFindings:
    def test_creates_new_finding(self, cluster):
        stats = upsert_findings(cluster, Source.TRIVY, [_vuln_dict()])
        assert stats["created"] == 1
        assert stats["updated"] == 0
        assert Finding.objects.count() == 1

        f = Finding.objects.first()
        assert f.status == Status.ACTIVE
        assert f.cluster == cluster
        assert f.details["component_name"] == "openssl"

    def test_updates_existing_on_rescan(self, cluster):
        upsert_findings(cluster, Source.TRIVY, [_vuln_dict()])
        stats = upsert_findings(cluster, Source.TRIVY, [_vuln_dict()])
        assert stats["created"] == 0
        assert stats["updated"] == 1
        assert Finding.objects.count() == 1

    def test_reactivates_resolved(self, cluster):
        upsert_findings(cluster, Source.TRIVY, [_vuln_dict()])
        # Manually resolve
        Finding.objects.update(status=Status.RESOLVED)

        stats = upsert_findings(cluster, Source.TRIVY, [_vuln_dict()])
        assert stats["reactivated"] == 1

        f = Finding.objects.first()
        assert f.status == Status.ACTIVE
        assert f.resolved_at is None

    def test_preserves_risk_accepted(self, cluster):
        upsert_findings(cluster, Source.TRIVY, [_vuln_dict()])
        Finding.objects.update(status=Status.RISK_ACCEPTED)

        stats = upsert_findings(cluster, Source.TRIVY, [_vuln_dict()])
        # Still updated (last_seen), but status preserved
        assert stats["updated"] == 1
        f = Finding.objects.first()
        assert f.status == Status.RISK_ACCEPTED

    def test_multiple_findings(self, cluster):
        dicts = [
            _vuln_dict(vuln_id="CVE-2024-0001", title="Vuln 1"),
            _vuln_dict(vuln_id="CVE-2024-0002", title="Vuln 2"),
            _vuln_dict(vuln_id="CVE-2024-0003", title="Vuln 3"),
        ]
        stats = upsert_findings(cluster, Source.TRIVY, dicts)
        assert stats["created"] == 3
        assert Finding.objects.count() == 3


@pytest.mark.django_db
class TestResolveStale:
    SCOPE = {
        "namespace": "prod-app",
        "resource_kind": "Deployment",
        "resource_name": "backend",
        "category": Category.VULNERABILITY,
    }

    def test_resolves_missing_findings(self, cluster):
        dicts = [
            _vuln_dict(vuln_id="CVE-0001", title="V1"),
            _vuln_dict(vuln_id="CVE-0002", title="V2"),
        ]
        upsert_findings(cluster, Source.TRIVY, dicts)

        # Second scan only has CVE-0001
        second = [_vuln_dict(vuln_id="CVE-0001", title="V1")]
        stats2 = upsert_findings(cluster, Source.TRIVY, second)
        resolved_count = resolve_stale(
            cluster, Source.TRIVY, stats2["hashes"], self.SCOPE
        )

        assert resolved_count == 1
        stale = Finding.objects.get(vuln_id="CVE-0002")
        assert stale.status == Status.RESOLVED
        assert stale.resolved_at is not None

    def test_does_not_resolve_risk_accepted(self, cluster):
        upsert_findings(
            cluster, Source.TRIVY, [_vuln_dict(vuln_id="CVE-0001", title="V1")]
        )
        Finding.objects.update(status=Status.RISK_ACCEPTED)

        resolved_count = resolve_stale(
            cluster, Source.TRIVY, set(), self.SCOPE
        )
        assert resolved_count == 0

    def test_scoped_to_resource(self, cluster):
        """Findings for different resources are NOT resolved by each other."""
        res_a = _vuln_dict(vuln_id="CVE-0001", title="V1", resource_name="backend")
        res_b = _vuln_dict(vuln_id="CVE-0002", title="V2", resource_name="frontend")
        upsert_findings(cluster, Source.TRIVY, [res_a])
        upsert_findings(cluster, Source.TRIVY, [res_b])

        # Resolve for backend scope with empty hashes — only backend resolved
        scope_a = {**self.SCOPE, "resource_name": "backend"}
        resolved = resolve_stale(cluster, Source.TRIVY, set(), scope_a)
        assert resolved == 1

        # Frontend finding untouched
        frontend = Finding.objects.get(vuln_id="CVE-0002")
        assert frontend.status == Status.ACTIVE

    def test_scoped_to_cluster(self):
        from core.models import Cluster

        c1 = Cluster.objects.create(name="cluster-1")
        c2 = Cluster.objects.create(name="cluster-2")

        upsert_findings(c1, Source.TRIVY, [_vuln_dict(vuln_id="CVE-0001", title="V1")])
        upsert_findings(c2, Source.TRIVY, [_vuln_dict(vuln_id="CVE-0002", title="V2")])

        resolved = resolve_stale(c1, Source.TRIVY, set(), self.SCOPE)
        assert resolved == 1
        assert Finding.objects.get(cluster=c2).status == Status.ACTIVE
