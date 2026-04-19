"""Tests for effective priority — decision tree, namespace exposure, recalculation.

After the Namespace-first refactor: per-namespace exposure/sensitivity flags
live on the Namespace model. Cluster-scoped findings (namespace=None) fall
back to the cluster rollup (`has_public_exposure` / `has_sensitive_data`).
"""
from decimal import Decimal

import pytest

from core.constants import Priority, Severity, Status
from core.models import Cluster, Finding, Namespace
from core.services.priority import (
    compute_priority,
    compute_priority_reason,
    recalculate_cluster_priorities,
)


# ── Helpers ─────────────────────────────────────────────────────


def _make_cluster(env="prod"):
    return Cluster.objects.create(name=f"test-{env}", environment=env)


def _make_namespace(cluster, name="default", exposed=False, sensitive=False):
    return Namespace.objects.create(
        cluster=cluster,
        name=name,
        internet_exposed=exposed,
        contains_sensitive_data=sensitive,
    )


def _make_finding(cluster, namespace=None, severity="Critical", epss=None, kev=False):
    return Finding.objects.create(
        cluster=cluster,
        namespace=namespace,
        severity=severity,
        epss_score=Decimal(str(epss)) if epss is not None else None,
        kev_listed=kev,
        title="Test finding",
        category="vulnerability",
        source="trivy",
        hash_code=f"h-{cluster.pk}-{namespace.pk if namespace else 'none'}-{severity}-{kev}",
        status=Status.ACTIVE,
    )


# ── Decision Tree Branch Tests ──────────────────────────────────


@pytest.mark.django_db
class TestComputePriority:
    def test_kev_always_immediate(self):
        """KEV-listed → IMMEDIATE regardless of environment or exposure."""
        c = _make_cluster(env="dev")
        ns = _make_namespace(c, exposed=False)
        f = _make_finding(c, namespace=ns, severity="Low", kev=True)
        assert compute_priority(f, c) == Priority.IMMEDIATE

    def test_high_epss_exposed_prod_immediate(self):
        c = _make_cluster(env="prod")
        ns = _make_namespace(c, exposed=True)
        f = _make_finding(c, namespace=ns, severity="Medium", epss=0.5)
        assert compute_priority(f, c) == Priority.IMMEDIATE

    def test_critical_exposed_prod_immediate(self):
        c = _make_cluster(env="prod")
        ns = _make_namespace(c, exposed=True)
        f = _make_finding(c, namespace=ns, severity="Critical")
        assert compute_priority(f, c) == Priority.IMMEDIATE

    def test_high_epss_prod_not_exposed_out_of_cycle(self):
        c = _make_cluster(env="prod")
        ns = _make_namespace(c, exposed=False)
        f = _make_finding(c, namespace=ns, severity="Medium", epss=0.5)
        assert compute_priority(f, c) == Priority.OUT_OF_CYCLE

    def test_critical_prod_not_exposed_out_of_cycle(self):
        c = _make_cluster(env="prod")
        ns = _make_namespace(c, exposed=False)
        f = _make_finding(c, namespace=ns, severity="Critical")
        assert compute_priority(f, c) == Priority.OUT_OF_CYCLE

    def test_high_exposed_prod_out_of_cycle(self):
        c = _make_cluster(env="prod")
        ns = _make_namespace(c, exposed=True)
        f = _make_finding(c, namespace=ns, severity="High")
        assert compute_priority(f, c) == Priority.OUT_OF_CYCLE

    def test_critical_dev_scheduled(self):
        c = _make_cluster(env="dev")
        ns = _make_namespace(c, exposed=False)
        f = _make_finding(c, namespace=ns, severity="Critical")
        assert compute_priority(f, c) == Priority.SCHEDULED

    def test_high_prod_not_exposed_scheduled(self):
        c = _make_cluster(env="prod")
        ns = _make_namespace(c, exposed=False)
        f = _make_finding(c, namespace=ns, severity="High")
        assert compute_priority(f, c) == Priority.SCHEDULED

    def test_medium_sensitive_scheduled(self):
        c = _make_cluster(env="dev")
        ns = _make_namespace(c, exposed=False, sensitive=True)
        f = _make_finding(c, namespace=ns, severity="Medium")
        assert compute_priority(f, c) == Priority.SCHEDULED

    def test_low_dev_defer(self):
        c = _make_cluster(env="dev")
        ns = _make_namespace(c, exposed=False)
        f = _make_finding(c, namespace=ns, severity="Low")
        assert compute_priority(f, c) == Priority.DEFER

    def test_medium_dev_not_sensitive_defer(self):
        c = _make_cluster(env="dev")
        ns = _make_namespace(c, exposed=False, sensitive=False)
        f = _make_finding(c, namespace=ns, severity="Medium")
        assert compute_priority(f, c) == Priority.DEFER

    def test_high_dev_not_sensitive_defer(self):
        c = _make_cluster(env="dev")
        ns = _make_namespace(c, exposed=False, sensitive=False)
        f = _make_finding(c, namespace=ns, severity="High")
        assert compute_priority(f, c) == Priority.DEFER

    def test_no_cluster_returns_scheduled(self):
        """Finding with no cluster → SCHEDULED (safe default)."""
        f = Finding(severity="Critical", kev_listed=False, epss_score=None)
        assert compute_priority(f, None) == Priority.SCHEDULED


# ── Per-namespace exposure (the old "overrides" equivalent) ─────


@pytest.mark.django_db
class TestPerNamespaceExposure:
    def test_exposed_namespace_immediate(self):
        """Exposed namespace on prod cluster gives Critical → IMMEDIATE."""
        c = _make_cluster(env="prod")
        _make_namespace(c, name="internal", exposed=False)
        exposed_ns = _make_namespace(c, name="public-frontend", exposed=True)
        f = _make_finding(c, namespace=exposed_ns, severity="Critical")
        assert compute_priority(f, c) == Priority.IMMEDIATE

    def test_non_exposed_namespace_out_of_cycle(self):
        """Non-exposed namespace on prod cluster gives Critical → OUT-OF-CYCLE."""
        c = _make_cluster(env="prod")
        _make_namespace(c, name="public-frontend", exposed=True)
        internal = _make_namespace(c, name="internal", exposed=False)
        f = _make_finding(c, namespace=internal, severity="Critical")
        assert compute_priority(f, c) == Priority.OUT_OF_CYCLE

    def test_sensitive_namespace_medium_scheduled(self):
        c = _make_cluster(env="dev")
        ns = _make_namespace(c, name="pii-handler", exposed=False, sensitive=True)
        f = _make_finding(c, namespace=ns, severity="Medium")
        assert compute_priority(f, c) == Priority.SCHEDULED


# ── Cluster-scoped findings (namespace=None) ────────────────────


@pytest.mark.django_db
class TestClusterScopedFindings:
    def test_cluster_scoped_uses_rollup_when_exposed_ns_present(self):
        """Cluster-scoped finding (namespace=None) → critical+prod+any-ns-exposed → IMMEDIATE."""
        c = _make_cluster(env="prod")
        _make_namespace(c, name="public", exposed=True)
        f = _make_finding(c, namespace=None, severity="Critical")
        assert compute_priority(f, c) == Priority.IMMEDIATE

    def test_cluster_scoped_no_exposed_namespaces_out_of_cycle(self):
        """Cluster-scoped finding on cluster with zero exposed namespaces → OUT-OF-CYCLE."""
        c = _make_cluster(env="prod")
        _make_namespace(c, name="internal", exposed=False)
        f = _make_finding(c, namespace=None, severity="Critical")
        assert compute_priority(f, c) == Priority.OUT_OF_CYCLE

    def test_cluster_scoped_sensitive_derived(self):
        """Cluster-scoped medium finding → SCHEDULED if any namespace sensitive."""
        c = _make_cluster(env="dev")
        _make_namespace(c, name="pii", exposed=False, sensitive=True)
        f = _make_finding(c, namespace=None, severity="Medium")
        assert compute_priority(f, c) == Priority.SCHEDULED


# ── Priority Reason Tests ───────────────────────────────────────


@pytest.mark.django_db
class TestComputePriorityReason:
    def test_kev_reason(self):
        c = _make_cluster(env="dev")
        ns = _make_namespace(c)
        f = _make_finding(c, namespace=ns, kev=True)
        assert "KEV" in compute_priority_reason(f, c)

    def test_exposed_prod_reason(self):
        c = _make_cluster(env="prod")
        ns = _make_namespace(c, exposed=True)
        f = _make_finding(c, namespace=ns, severity="Critical")
        assert "exposed production" in compute_priority_reason(f, c)

    def test_no_cluster_reason(self):
        f = Finding(severity="Critical", kev_listed=False, epss_score=None)
        assert "No cluster" in compute_priority_reason(f, None)


# ── Recalculation Tests ─────────────────────────────────────────


@pytest.mark.django_db
class TestRecalculateClusterPriorities:
    def test_recalculate_updates_changed_findings(self):
        cluster = _make_cluster(env="prod")
        ns = _make_namespace(cluster, name="default", exposed=False)
        finding = Finding.objects.create(
            cluster=cluster,
            namespace=ns,
            severity=Severity.CRITICAL,
            title="Test CVE",
            category="vulnerability",
            source="trivy",
            hash_code="recalc123",
            status=Status.ACTIVE,
            effective_priority=Priority.SCHEDULED,  # wrong — correct is OUT_OF_CYCLE
        )

        updated = recalculate_cluster_priorities(cluster)
        assert updated == 1

        finding.refresh_from_db()
        assert finding.effective_priority == Priority.OUT_OF_CYCLE

    def test_recalculate_skips_resolved(self):
        cluster = _make_cluster(env="prod")
        ns = _make_namespace(cluster, exposed=True)
        Finding.objects.create(
            cluster=cluster,
            namespace=ns,
            severity=Severity.CRITICAL,
            title="Resolved CVE",
            category="vulnerability",
            source="trivy",
            hash_code="resolved123",
            status=Status.RESOLVED,
            effective_priority=Priority.DEFER,
        )

        updated = recalculate_cluster_priorities(cluster)
        assert updated == 0

    def test_recalculate_no_change_returns_zero(self):
        cluster = _make_cluster(env="prod")
        ns = _make_namespace(cluster, exposed=True)
        Finding.objects.create(
            cluster=cluster,
            namespace=ns,
            severity=Severity.CRITICAL,
            title="Correct CVE",
            category="vulnerability",
            source="trivy",
            hash_code="correct123",
            status=Status.ACTIVE,
            effective_priority=Priority.IMMEDIATE,
        )

        updated = recalculate_cluster_priorities(cluster)
        assert updated == 0


@pytest.mark.django_db
class TestLoadContextIgnoresInactive:
    """load_context must treat inactive namespaces as absent — their stale
    exposure/sensitivity flags must not inflate cluster-scoped priority."""

    def test_inactive_namespace_excluded_from_rollup(self):
        from core.services.priority import load_context

        cluster = _make_cluster(env="prod")
        # An inactive namespace that was flagged exposed + sensitive
        Namespace.objects.create(
            cluster=cluster, name="ghost", active=False,
            internet_exposed=True, contains_sensitive_data=True,
        )
        ctx = load_context(cluster)
        assert ctx.cluster_has_exposure is False
        assert ctx.cluster_has_sensitive is False
        assert "ghost" not in ctx.exposure_map
        assert "ghost" not in ctx.sensitive_map

    def test_active_namespace_contributes_to_rollup(self):
        from core.services.priority import load_context

        cluster = _make_cluster(env="prod")
        Namespace.objects.create(
            cluster=cluster, name="ghost", active=False,
            internet_exposed=True,
        )
        Namespace.objects.create(
            cluster=cluster, name="real", active=True,
            internet_exposed=True,
        )
        ctx = load_context(cluster)
        assert ctx.cluster_has_exposure is True
        assert ctx.exposure_map == {"real": True}


# ── Template Tag Tests (unchanged) ──────────────────────────────


class TestBadgeTooltips:
    def test_severity_badge_has_title(self):
        from core.templatetags.findings_tags import severity_badge

        result = severity_badge("Critical")
        assert 'title="' in result
        assert "CVSS 9.0-10.0" in result

    def test_status_badge_has_title(self):
        from core.templatetags.findings_tags import status_badge

        result = status_badge("active")
        assert 'title="' in result
        assert "Open finding" in result

    def test_priority_badge_has_title(self):
        from core.templatetags.findings_tags import priority_badge

        result = priority_badge("immediate")
        assert 'title="' in result
        assert "Fix now" in result
        assert "bg-danger" in result

    def test_priority_badge_colors(self):
        from core.templatetags.findings_tags import priority_badge

        assert "bg-danger" in priority_badge("immediate")
        assert "bg-orange" in priority_badge("out_of_cycle")
        assert "bg-azure" in priority_badge("scheduled")
        assert "bg-secondary" in priority_badge("defer")

    def test_epss_badge_has_descriptive_title(self):
        from core.templatetags.findings_tags import epss_badge

        result = epss_badge(0.85)
        assert 'title="' in result
        assert "probability" in result
        assert "85.0%" in result

    def test_all_severities_have_descriptions(self):
        from core.templatetags.findings_tags import SEVERITY_DESCRIPTIONS

        for sev in ["Critical", "High", "Medium", "Low"]:
            assert sev in SEVERITY_DESCRIPTIONS

    def test_all_statuses_have_descriptions(self):
        from core.templatetags.findings_tags import STATUS_DESCRIPTIONS

        for status in ["active", "acknowledged", "risk_accepted", "false_positive", "resolved"]:
            assert status in STATUS_DESCRIPTIONS

    def test_all_priorities_have_descriptions(self):
        from core.templatetags.findings_tags import PRIORITY_DESCRIPTIONS

        for priority in ["immediate", "out_of_cycle", "scheduled", "defer"]:
            assert priority in PRIORITY_DESCRIPTIONS
