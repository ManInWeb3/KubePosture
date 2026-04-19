"""Tests for /api/v1/cluster-metadata/sync/."""
import pytest
from django.contrib.auth.models import User
from rest_framework.authtoken.models import Token
from rest_framework.test import APIClient

from core.constants import Category, Origin, Severity, Status
from core.models import Cluster, Finding, Namespace


@pytest.fixture
def service_account():
    user = User.objects.create_user(username="svc-test-import")
    token = Token.objects.create(user=user)
    return user, token


@pytest.fixture
def authed_client(service_account):
    user, token = service_account
    client = APIClient()
    client.credentials(HTTP_AUTHORIZATION=f"Token {token.key}")
    return client


@pytest.mark.django_db
class TestClusterMetadataSync:
    URL = "/api/v1/cluster-metadata/sync/"

    def test_requires_service_account_auth(self):
        """Non-service-account users get 403."""
        regular_user = User.objects.create_user(username="regular-user")
        token = Token.objects.create(user=regular_user)
        client = APIClient()
        client.credentials(HTTP_AUTHORIZATION=f"Token {token.key}")
        resp = client.post(self.URL, {"cluster_name": "c1"}, format="json")
        assert resp.status_code == 403

    def test_requires_cluster_name(self, authed_client):
        resp = authed_client.post(self.URL, {}, format="json")
        assert resp.status_code == 400
        assert "cluster_name" in resp.json()["error"]

    def test_auto_creates_cluster_on_first_sync(self, authed_client):
        resp = authed_client.post(
            self.URL,
            {"cluster_name": "fresh-cluster", "k8s_version": "v1.29.0", "provider": "aws"},
            format="json",
        )
        assert resp.status_code == 200
        c = Cluster.objects.get(name="fresh-cluster")
        assert c.k8s_version == "v1.29.0"
        assert c.provider == "aws"

    def test_populates_namespaces_and_exposure(self, authed_client):
        authed_client.post(
            self.URL,
            {
                "cluster_name": "c1",
                "namespaces": [
                    {"name": "frontend", "internet_exposed": True},
                    {"name": "workers", "internet_exposed": False},
                ],
            },
            format="json",
        )
        frontend = Namespace.objects.get(name="frontend", cluster__name="c1")
        workers = Namespace.objects.get(name="workers", cluster__name="c1")
        assert frontend.internet_exposed is True
        assert workers.internet_exposed is False
        assert frontend.exposure_is_manual is False

    def test_preserves_manual_exposure_override(self, authed_client):
        """Once exposure_is_manual=True, sync must not overwrite internet_exposed."""
        c = Cluster.objects.create(name="c-manual", environment="prod")
        ns = Namespace.objects.create(
            cluster=c, name="api", internet_exposed=False, exposure_is_manual=True
        )
        authed_client.post(
            self.URL,
            {
                "cluster_name": "c-manual",
                "namespaces": [{"name": "api", "internet_exposed": True}],
            },
            format="json",
        )
        ns.refresh_from_db()
        assert ns.internet_exposed is False  # auto-detect skipped
        assert ns.exposure_is_manual is True

    def test_preserves_manual_provider_override(self, authed_client):
        c = Cluster.objects.create(
            name="c-prov",
            environment="prod",
            provider="onprem",
            provider_is_manual=True,
        )
        authed_client.post(
            self.URL,
            {"cluster_name": "c-prov", "provider": "aws"},
            format="json",
        )
        c.refresh_from_db()
        assert c.provider == "onprem"  # not overwritten

    def test_updates_labels_and_annotations_always(self, authed_client):
        """Labels/annotations are always synced (not admin-owned)."""
        authed_client.post(
            self.URL,
            {
                "cluster_name": "c-labels",
                "namespaces": [
                    {
                        "name": "team-a",
                        "internet_exposed": False,
                        "labels": {"team": "alpha"},
                        "annotations": {"compliance.scope/pci": "true"},
                    }
                ],
            },
            format="json",
        )
        ns = Namespace.objects.get(name="team-a", cluster__name="c-labels")
        assert ns.labels == {"team": "alpha"}
        assert ns.annotations == {"compliance.scope/pci": "true"}

    def test_k8s_version_always_updates(self, authed_client):
        """k8s_version is ground truth — always updated (no manual flag)."""
        c = Cluster.objects.create(name="c-kv", environment="prod", k8s_version="v1.28.0")
        authed_client.post(
            self.URL,
            {"cluster_name": "c-kv", "k8s_version": "v1.29.0"},
            format="json",
        )
        c.refresh_from_db()
        assert c.k8s_version == "v1.29.0"


def _make_finding(cluster, ns, *, status=Status.ACTIVE, hash_code="h-placeholder"):
    return Finding.objects.create(
        origin=Origin.CLUSTER,
        cluster=cluster,
        namespace=ns,
        resource_kind="Deployment",
        resource_name="app",
        title="CVE-2024-0001",
        severity=Severity.HIGH,
        vuln_id="CVE-2024-0001",
        category=Category.VULNERABILITY,
        source="trivy",
        status=status,
        hash_code=hash_code,
    )


@pytest.mark.django_db
class TestNamespaceDeactivation:
    URL = "/api/v1/cluster-metadata/sync/"

    def test_missing_namespace_deactivated_on_complete_snapshot(self, authed_client):
        """Namespace absent from a complete_snapshot payload is flipped inactive."""
        c = Cluster.objects.create(name="c-dead", environment="prod")
        keep = Namespace.objects.create(cluster=c, name="keep")
        gone = Namespace.objects.create(cluster=c, name="gone")

        resp = authed_client.post(
            self.URL,
            {
                "cluster_name": "c-dead",
                "complete_snapshot": True,
                "namespaces": [{"name": "keep", "internet_exposed": False}],
            },
            format="json",
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["namespaces"]["deactivated"] == 1
        assert body["namespaces"]["complete_snapshot"] is True

        keep.refresh_from_db()
        gone.refresh_from_db()
        assert keep.active is True
        assert gone.active is False
        assert gone.deactivated_at is not None

    def test_partial_snapshot_does_not_deactivate(self, authed_client):
        """Without complete_snapshot=True, missing namespaces are not touched."""
        c = Cluster.objects.create(name="c-partial", environment="prod")
        Namespace.objects.create(cluster=c, name="survivor")

        resp = authed_client.post(
            self.URL,
            {
                "cluster_name": "c-partial",
                # No complete_snapshot, empty namespaces — could be a
                # failed kubectl call; must not trigger the sweep.
                "namespaces": [],
            },
            format="json",
        )
        assert resp.status_code == 200
        assert resp.json()["namespaces"]["deactivated"] == 0
        ns = Namespace.objects.get(cluster=c, name="survivor")
        assert ns.active is True

    def test_interrupted_import_with_partial_list_does_not_deactivate(self, authed_client):
        """Real interrupted-import scenario: import script got SOME namespaces
        before crashing, posts a partial list without complete_snapshot=True.

        The cluster actually has {prod, staging, workers}. The import script
        only managed to collect {prod}. Without the flag, staging/workers
        must NOT be deactivated, and findings in them must NOT cascade.
        """
        c = Cluster.objects.create(name="c-interrupted", environment="prod")
        prod = Namespace.objects.create(cluster=c, name="prod")
        staging = Namespace.objects.create(cluster=c, name="staging")
        workers = Namespace.objects.create(cluster=c, name="workers")
        _make_finding(c, staging, status=Status.ACTIVE, hash_code="h-staging")
        _make_finding(c, workers, status=Status.ACTIVE, hash_code="h-workers")

        resp = authed_client.post(
            self.URL,
            {
                "cluster_name": "c-interrupted",
                # complete_snapshot intentionally absent — partial payload.
                "namespaces": [{"name": "prod", "internet_exposed": False}],
            },
            format="json",
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["namespaces"]["deactivated"] == 0
        assert body["namespaces"]["cascaded_findings_resolved"] == 0
        assert body["namespaces"]["complete_snapshot"] is False

        for ns in (prod, staging, workers):
            ns.refresh_from_db()
            assert ns.active is True

        assert Finding.objects.filter(
            cluster=c, status=Status.ACTIVE
        ).count() == 2  # both survived

    def test_explicit_complete_snapshot_false_does_not_deactivate(self, authed_client):
        """Explicit complete_snapshot=false must also skip the sweep."""
        c = Cluster.objects.create(name="c-explicit-false", environment="prod")
        Namespace.objects.create(cluster=c, name="keep")
        gone = Namespace.objects.create(cluster=c, name="would-be-gone")

        resp = authed_client.post(
            self.URL,
            {
                "cluster_name": "c-explicit-false",
                "complete_snapshot": False,
                "namespaces": [{"name": "keep"}],
            },
            format="json",
        )
        assert resp.status_code == 200
        assert resp.json()["namespaces"]["deactivated"] == 0
        gone.refresh_from_db()
        assert gone.active is True

    def test_cascades_active_findings_to_resolved(self, authed_client):
        """On deactivation, active/acknowledged findings go to resolved; others stay."""
        c = Cluster.objects.create(name="c-cascade", environment="prod")
        ns = Namespace.objects.create(cluster=c, name="doomed")
        active_f = _make_finding(c, ns, status=Status.ACTIVE, hash_code="h-active")
        ack_f = _make_finding(c, ns, status=Status.ACKNOWLEDGED, hash_code="h-ack")
        accepted_f = _make_finding(c, ns, status=Status.RISK_ACCEPTED, hash_code="h-accepted")
        fp_f = _make_finding(c, ns, status=Status.FALSE_POSITIVE, hash_code="h-fp")

        resp = authed_client.post(
            self.URL,
            {
                "cluster_name": "c-cascade",
                "complete_snapshot": True,
                "namespaces": [],
            },
            format="json",
        )
        assert resp.status_code == 200
        assert resp.json()["namespaces"]["cascaded_findings_resolved"] == 2

        active_f.refresh_from_db()
        ack_f.refresh_from_db()
        accepted_f.refresh_from_db()
        fp_f.refresh_from_db()
        assert active_f.status == Status.RESOLVED
        assert active_f.resolved_at is not None
        assert ack_f.status == Status.RESOLVED
        assert accepted_f.status == Status.RISK_ACCEPTED
        assert fp_f.status == Status.FALSE_POSITIVE

    def test_reappearing_namespace_reactivates(self, authed_client):
        """Namespace coming back in payload flips active=True and clears deactivated_at."""
        c = Cluster.objects.create(name="c-return", environment="prod")
        ns = Namespace.objects.create(
            cluster=c, name="phoenix", active=False,
        )
        from django.utils import timezone
        ns.deactivated_at = timezone.now()
        ns.save(update_fields=["deactivated_at"])

        resp = authed_client.post(
            self.URL,
            {
                "cluster_name": "c-return",
                "complete_snapshot": True,
                "namespaces": [{"name": "phoenix", "internet_exposed": True}],
            },
            format="json",
        )
        assert resp.status_code == 200
        assert resp.json()["namespaces"]["reactivated"] == 1

        ns.refresh_from_db()
        assert ns.active is True
        assert ns.deactivated_at is None
        assert ns.internet_exposed is True

    def test_cluster_rollups_ignore_inactive(self, authed_client):
        """has_public_exposure must not count inactive namespaces."""
        c = Cluster.objects.create(name="c-rollup", environment="prod")
        Namespace.objects.create(
            cluster=c, name="ghost", internet_exposed=True, active=False,
        )
        assert c.has_public_exposure is False

        # Add an active exposed one and re-check (cached_property on a fresh instance)
        Namespace.objects.create(
            cluster=c, name="real", internet_exposed=True, active=True,
        )
        c2 = Cluster.objects.get(pk=c.pk)
        assert c2.has_public_exposure is True

    def test_full_lifecycle_delete_then_recreate_reactivates_finding(self, authed_client):
        """End-to-end: namespace present → deleted (cascade resolve) → recreated →
        scanner re-ingests same finding → dedup reactivates it in place.

        Verifies the hash is stable across the round-trip and first_seen is
        preserved while resolved_at is cleared.
        """
        from core.constants import Source
        from core.services.dedup import upsert_findings

        # --- Phase 1: namespace exists, ingest creates a finding ---------
        authed_client.post(
            self.URL,
            {
                "cluster_name": "c-cycle",
                "complete_snapshot": True,
                "namespaces": [{"name": "ephemeral", "internet_exposed": False}],
            },
            format="json",
        )
        cluster = Cluster.objects.get(name="c-cycle")
        finding_dict = {
            "title": "CVE-2024-9999 in libfoo",
            "severity": Severity.HIGH,
            "vuln_id": "CVE-2024-9999",
            "category": Category.VULNERABILITY,
            "source": Source.TRIVY,
            "namespace": "ephemeral",
            "resource_kind": "Deployment",
            "resource_name": "worker",
            "details": {"component_name": "libfoo"},
        }
        stats = upsert_findings(cluster, Source.TRIVY, [finding_dict])
        assert stats["created"] == 1
        finding = Finding.objects.get(cluster=cluster, vuln_id="CVE-2024-9999")
        assert finding.status == Status.ACTIVE
        original_first_seen = finding.first_seen
        original_hash = finding.hash_code

        # --- Phase 2: namespace deleted — complete snapshot without it ---
        authed_client.post(
            self.URL,
            {
                "cluster_name": "c-cycle",
                "complete_snapshot": True,
                "namespaces": [],
            },
            format="json",
        )
        ns = Namespace.objects.get(cluster=cluster, name="ephemeral")
        assert ns.active is False
        assert ns.deactivated_at is not None

        finding.refresh_from_db()
        assert finding.status == Status.RESOLVED
        assert finding.resolved_at is not None
        assert finding.first_seen == original_first_seen  # preserved

        # --- Phase 3: namespace recreated — sync brings it back ----------
        authed_client.post(
            self.URL,
            {
                "cluster_name": "c-cycle",
                "complete_snapshot": True,
                "namespaces": [{"name": "ephemeral", "internet_exposed": False}],
            },
            format="json",
        )
        ns.refresh_from_db()
        assert ns.active is True
        assert ns.deactivated_at is None
        # Finding stays resolved until the scanner re-ingests it (sync alone
        # doesn't know which findings still apply). It will reactivate on the
        # next upsert via hash match.
        finding.refresh_from_db()
        assert finding.status == Status.RESOLVED

        # --- Phase 4: scanner re-ingests same finding — dedup reactivates ---
        stats = upsert_findings(cluster, Source.TRIVY, [finding_dict])
        assert stats["reactivated"] == 1
        assert stats["created"] == 0

        finding.refresh_from_db()
        assert finding.status == Status.ACTIVE
        assert finding.resolved_at is None
        assert finding.hash_code == original_hash
        assert finding.first_seen == original_first_seen  # full history kept
        assert finding.namespace_id == ns.pk  # same namespace row, not a new one
