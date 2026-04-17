"""Tests for effective priority — decision tree, namespace overrides, recalculation."""
from decimal import Decimal
from unittest.mock import MagicMock

import pytest

from core.constants import Priority, Severity, Status
from core.models import Cluster, Finding
from core.services.priority import (
    compute_priority,
    compute_priority_reason,
    recalculate_cluster_priorities,
)


def _make_cluster(env="prod", exposed=True, sensitive=True, overrides=None):
    """Create a Cluster instance (unsaved) for testing."""
    c = Cluster(
        name=f"test-{env}",
        environment=env,
        internet_exposed=exposed,
        contains_sensitive_data=sensitive,
        namespace_overrides=overrides or {},
    )
    return c


def _make_finding(severity="Critical", epss=None, kev=False, namespace="default"):
    """Create a Finding instance (unsaved) for testing."""
    f = Finding(
        severity=severity,
        epss_score=Decimal(str(epss)) if epss is not None else None,
        kev_listed=kev,
        namespace=namespace,
        title="Test finding",
        category="vulnerability",
        source="trivy",
        hash_code="abc123",
    )
    return f


# ── Decision Tree Branch Tests ──────────────────────────────────


class TestComputePriority:
    def test_kev_always_immediate(self):
        """KEV-listed → IMMEDIATE regardless of environment or exposure."""
        f = _make_finding(severity="Low", kev=True)
        c = _make_cluster(env="dev", exposed=False, sensitive=False)
        assert compute_priority(f, c) == Priority.IMMEDIATE

    def test_high_epss_exposed_prod_immediate(self):
        """High EPSS + exposed production → IMMEDIATE."""
        f = _make_finding(severity="Medium", epss=0.5)
        c = _make_cluster(env="prod", exposed=True)
        assert compute_priority(f, c) == Priority.IMMEDIATE

    def test_critical_exposed_prod_immediate(self):
        """Critical + exposed production → IMMEDIATE."""
        f = _make_finding(severity="Critical")
        c = _make_cluster(env="prod", exposed=True)
        assert compute_priority(f, c) == Priority.IMMEDIATE

    def test_high_epss_prod_not_exposed_out_of_cycle(self):
        """High EPSS + production but not exposed → OUT-OF-CYCLE."""
        f = _make_finding(severity="Medium", epss=0.5)
        c = _make_cluster(env="prod", exposed=False)
        assert compute_priority(f, c) == Priority.OUT_OF_CYCLE

    def test_critical_prod_not_exposed_out_of_cycle(self):
        """Critical + production but not exposed → OUT-OF-CYCLE."""
        f = _make_finding(severity="Critical")
        c = _make_cluster(env="prod", exposed=False)
        assert compute_priority(f, c) == Priority.OUT_OF_CYCLE

    def test_high_exposed_prod_out_of_cycle(self):
        """High + exposed production → OUT-OF-CYCLE."""
        f = _make_finding(severity="High")
        c = _make_cluster(env="prod", exposed=True)
        assert compute_priority(f, c) == Priority.OUT_OF_CYCLE

    def test_critical_dev_scheduled(self):
        """Critical in dev/staging → SCHEDULED."""
        f = _make_finding(severity="Critical")
        c = _make_cluster(env="dev", exposed=False)
        assert compute_priority(f, c) == Priority.SCHEDULED

    def test_high_prod_not_exposed_scheduled(self):
        """High + production not exposed → SCHEDULED."""
        f = _make_finding(severity="High")
        c = _make_cluster(env="prod", exposed=False)
        assert compute_priority(f, c) == Priority.SCHEDULED

    def test_medium_sensitive_scheduled(self):
        """Medium + sensitive data → SCHEDULED."""
        f = _make_finding(severity="Medium")
        c = _make_cluster(env="dev", exposed=False, sensitive=True)
        assert compute_priority(f, c) == Priority.SCHEDULED

    def test_low_dev_defer(self):
        """Low in dev → DEFER."""
        f = _make_finding(severity="Low")
        c = _make_cluster(env="dev", exposed=False, sensitive=False)
        assert compute_priority(f, c) == Priority.DEFER

    def test_medium_dev_not_sensitive_defer(self):
        """Medium in dev, no sensitive data → DEFER."""
        f = _make_finding(severity="Medium")
        c = _make_cluster(env="dev", exposed=False, sensitive=False)
        assert compute_priority(f, c) == Priority.DEFER

    def test_high_dev_not_sensitive_defer(self):
        """High in dev, not sensitive → DEFER (below critical threshold for non-prod)."""
        f = _make_finding(severity="High")
        c = _make_cluster(env="dev", exposed=False, sensitive=False)
        assert compute_priority(f, c) == Priority.DEFER

    def test_no_cluster_returns_scheduled(self):
        """Finding with no cluster → SCHEDULED (safe default)."""
        f = _make_finding(severity="Critical")
        assert compute_priority(f, None) == Priority.SCHEDULED


# ── Namespace Override Tests ────────────────────────────────────


class TestNamespaceOverrides:
    def test_override_reduces_exposure(self):
        """Namespace override internet_exposed=false on exposed cluster."""
        f = _make_finding(severity="Critical", namespace="internal-workers")
        c = _make_cluster(
            env="prod",
            exposed=True,
            overrides={"internal-workers": {"internet_exposed": False}},
        )
        # Critical + prod + NOT exposed → OUT-OF-CYCLE (not IMMEDIATE)
        assert compute_priority(f, c) == Priority.OUT_OF_CYCLE

    def test_override_increases_exposure(self):
        """Namespace override internet_exposed=true on internal cluster."""
        f = _make_finding(severity="Critical", namespace="public-frontend")
        c = _make_cluster(
            env="prod",
            exposed=False,
            overrides={"public-frontend": {"internet_exposed": True}},
        )
        # Critical + prod + exposed → IMMEDIATE
        assert compute_priority(f, c) == Priority.IMMEDIATE

    def test_no_override_inherits_cluster(self):
        """Namespace without override inherits cluster defaults."""
        f = _make_finding(severity="Critical", namespace="other-ns")
        c = _make_cluster(
            env="prod",
            exposed=True,
            overrides={"internal-workers": {"internet_exposed": False}},
        )
        # other-ns not in overrides → inherits cluster exposed=True → IMMEDIATE
        assert compute_priority(f, c) == Priority.IMMEDIATE

    def test_empty_overrides_inherits(self):
        """Empty namespace_overrides dict inherits cluster defaults."""
        f = _make_finding(severity="Critical", namespace="any-ns")
        c = _make_cluster(env="prod", exposed=True, overrides={})
        assert compute_priority(f, c) == Priority.IMMEDIATE

    def test_sensitive_data_override(self):
        """Namespace override for contains_sensitive_data."""
        f = _make_finding(severity="Medium", namespace="pii-handler")
        c = _make_cluster(
            env="dev",
            exposed=False,
            sensitive=False,
            overrides={"pii-handler": {"contains_sensitive_data": True}},
        )
        # Medium + sensitive → SCHEDULED
        assert compute_priority(f, c) == Priority.SCHEDULED


# ── Priority Reason Tests ───────────────────────────────────────


class TestComputePriorityReason:
    def test_kev_reason(self):
        f = _make_finding(kev=True)
        c = _make_cluster()
        assert "KEV" in compute_priority_reason(f, c)

    def test_exposed_prod_reason(self):
        f = _make_finding(severity="Critical")
        c = _make_cluster(env="prod", exposed=True)
        assert "exposed production" in compute_priority_reason(f, c)

    def test_no_cluster_reason(self):
        f = _make_finding()
        assert "No cluster" in compute_priority_reason(f, None)


# ── Recalculation Tests ─────────────────────────────────────────


@pytest.mark.django_db
class TestRecalculateClusterPriorities:
    def test_recalculate_updates_changed_findings(self):
        """Recalculate updates findings whose priority changed."""
        cluster = Cluster.objects.create(
            name="recalc-test",
            environment="prod",
            internet_exposed=False,
        )
        # Create finding with default SCHEDULED priority
        finding = Finding.objects.create(
            cluster=cluster,
            severity=Severity.CRITICAL,
            title="Test CVE",
            category="vulnerability",
            source="trivy",
            hash_code="recalc123",
            status=Status.ACTIVE,
            effective_priority=Priority.SCHEDULED,
        )

        # Now expose the cluster — priority should change to OUT-OF-CYCLE
        # (critical + prod, not exposed → OUT-OF-CYCLE)
        # Actually it's already OUT-OF-CYCLE for critical+prod... let me check
        # critical + prod + not exposed → OUT_OF_CYCLE
        # So the default SCHEDULED is wrong, recalculate should fix it
        updated = recalculate_cluster_priorities(cluster)
        assert updated == 1

        finding.refresh_from_db()
        assert finding.effective_priority == Priority.OUT_OF_CYCLE

    def test_recalculate_skips_resolved(self):
        """Recalculate skips resolved/risk_accepted findings."""
        cluster = Cluster.objects.create(
            name="recalc-skip",
            environment="prod",
            internet_exposed=True,
        )
        Finding.objects.create(
            cluster=cluster,
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
        """Recalculate returns 0 if no priorities changed."""
        cluster = Cluster.objects.create(
            name="recalc-nochange",
            environment="prod",
            internet_exposed=True,
        )
        # Create finding with correct priority already
        Finding.objects.create(
            cluster=cluster,
            severity=Severity.CRITICAL,
            title="Correct CVE",
            category="vulnerability",
            source="trivy",
            hash_code="correct123",
            status=Status.ACTIVE,
            effective_priority=Priority.IMMEDIATE,  # Already correct
        )

        updated = recalculate_cluster_priorities(cluster)
        assert updated == 0


# ── Template Tag Tests ──────────────────────────────────────────


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
