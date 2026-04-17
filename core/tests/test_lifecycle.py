"""
Tests for finding lifecycle actions and audit trail.

Covers:
- FindingHistory model
- acknowledge, accept_risk, false_positive, reactivate service functions
- Status transition validation (invalid transitions raise LifecycleError)
- Audit trail creation on every status change
- expire_risk_acceptances daily cron
- API action endpoints with permission checks
"""
import datetime

import pytest
from django.contrib.auth.models import Group, User

from core.constants import Category, Origin, Severity, Source, Status
from core.models import Finding, FindingHistory
from core.services.lifecycle import (
    LifecycleError,
    accept_risk,
    acknowledge,
    expire_risk_acceptances,
    false_positive,
    reactivate,
)


@pytest.fixture
def active_finding(cluster, db):
    return Finding.objects.create(
        origin=Origin.CLUSTER,
        cluster=cluster,
        title="CVE-2024-1234 in openssl",
        severity=Severity.CRITICAL,
        vuln_id="CVE-2024-1234",
        category=Category.VULNERABILITY,
        source=Source.TRIVY,
        status=Status.ACTIVE,
        hash_code="testhash1234",
        namespace="default",
        resource_kind="Deployment",
        resource_name="backend",
    )


@pytest.fixture
def operator_user(db):
    user = User.objects.create_user(username="operator", password="test")
    group, _ = Group.objects.get_or_create(name="operator")
    user.groups.add(group)
    return user


@pytest.fixture
def admin_user(db):
    user = User.objects.create_user(username="admin-user", password="test")
    group, _ = Group.objects.get_or_create(name="admin")
    user.groups.add(group)
    return user


# ── FindingHistory model ───────────────────────────────────────


@pytest.mark.django_db
class TestFindingHistoryModel:
    def test_create(self, active_finding, operator_user):
        h = FindingHistory.objects.create(
            finding=active_finding,
            user=operator_user,
            old_status=Status.ACTIVE,
            new_status=Status.ACKNOWLEDGED,
            comment="Reviewed",
        )
        assert "active" in str(h)
        assert "acknowledged" in str(h)
        assert "operator" in str(h)

    def test_system_action_null_user(self, active_finding):
        h = FindingHistory.objects.create(
            finding=active_finding,
            user=None,
            old_status=Status.RISK_ACCEPTED,
            new_status=Status.ACTIVE,
            comment="Risk acceptance expired",
        )
        assert "system" in str(h)


# ── Acknowledge ────────────────────────────────────────────────


@pytest.mark.django_db
class TestAcknowledge:
    def test_success(self, active_finding, operator_user):
        result = acknowledge(active_finding.pk, operator_user)
        assert result.status == Status.ACKNOWLEDGED

        active_finding.refresh_from_db()
        assert active_finding.status == Status.ACKNOWLEDGED

    def test_creates_history(self, active_finding, operator_user):
        acknowledge(active_finding.pk, operator_user)
        h = FindingHistory.objects.get(finding=active_finding)
        assert h.old_status == Status.ACTIVE
        assert h.new_status == Status.ACKNOWLEDGED
        assert h.user == operator_user

    def test_invalid_from_resolved(self, active_finding, operator_user):
        active_finding.status = Status.RESOLVED
        active_finding.save()
        with pytest.raises(LifecycleError, match="must be 'active'"):
            acknowledge(active_finding.pk, operator_user)

    def test_invalid_from_risk_accepted(self, active_finding, operator_user):
        active_finding.status = Status.RISK_ACCEPTED
        active_finding.save()
        with pytest.raises(LifecycleError):
            acknowledge(active_finding.pk, operator_user)


# ── Accept Risk ────────────────────────────────────────────────


@pytest.mark.django_db
class TestAcceptRisk:
    def test_from_active(self, active_finding, admin_user):
        result = accept_risk(
            active_finding.pk, admin_user,
            reason="Mitigated by network policy",
            until=datetime.date(2026, 7, 14),
        )
        assert result.status == Status.RISK_ACCEPTED
        assert result.accepted_by == admin_user
        assert result.accepted_reason == "Mitigated by network policy"
        assert result.accepted_until == datetime.date(2026, 7, 14)

    def test_from_acknowledged(self, active_finding, admin_user):
        active_finding.status = Status.ACKNOWLEDGED
        active_finding.save()

        result = accept_risk(
            active_finding.pk, admin_user, reason="OK", until="2026-12-31"
        )
        assert result.status == Status.RISK_ACCEPTED

    def test_creates_history_with_comment(self, active_finding, admin_user):
        accept_risk(
            active_finding.pk, admin_user,
            reason="No fix available", until="2026-07-14"
        )
        h = FindingHistory.objects.get(finding=active_finding)
        assert "No fix available" in h.comment
        assert "2026-07-14" in h.comment

    def test_invalid_from_resolved(self, active_finding, admin_user):
        active_finding.status = Status.RESOLVED
        active_finding.save()
        with pytest.raises(LifecycleError, match="must be 'active' or 'acknowledged'"):
            accept_risk(active_finding.pk, admin_user, reason="x", until="2026-12-31")


# ── False Positive ─────────────────────────────────────────────


@pytest.mark.django_db
class TestFalsePositive:
    def test_success(self, active_finding, admin_user):
        result = false_positive(
            active_finding.pk, admin_user, reason="Not applicable"
        )
        assert result.status == Status.FALSE_POSITIVE

    def test_creates_history(self, active_finding, admin_user):
        false_positive(active_finding.pk, admin_user, reason="Not applicable")
        h = FindingHistory.objects.get(finding=active_finding)
        assert h.new_status == Status.FALSE_POSITIVE
        assert "Not applicable" in h.comment

    def test_invalid_from_resolved(self, active_finding, admin_user):
        active_finding.status = Status.RESOLVED
        active_finding.save()
        with pytest.raises(LifecycleError):
            false_positive(active_finding.pk, admin_user, reason="x")


# ── Reactivate ─────────────────────────────────────────────────


@pytest.mark.django_db
class TestReactivate:
    def test_from_acknowledged(self, active_finding, admin_user):
        active_finding.status = Status.ACKNOWLEDGED
        active_finding.save()

        result = reactivate(active_finding.pk, admin_user)
        assert result.status == Status.ACTIVE

    def test_from_risk_accepted_clears_fields(self, active_finding, admin_user):
        active_finding.status = Status.RISK_ACCEPTED
        active_finding.accepted_by = admin_user
        active_finding.accepted_reason = "was accepted"
        active_finding.accepted_until = datetime.date(2026, 12, 31)
        active_finding.save()

        result = reactivate(active_finding.pk, admin_user)
        assert result.status == Status.ACTIVE
        assert result.accepted_by is None
        assert result.accepted_reason == ""
        assert result.accepted_until is None

    def test_from_resolved(self, active_finding, admin_user):
        active_finding.status = Status.RESOLVED
        active_finding.save()
        result = reactivate(active_finding.pk, admin_user)
        assert result.status == Status.ACTIVE

    def test_invalid_already_active(self, active_finding, admin_user):
        with pytest.raises(LifecycleError, match="already active"):
            reactivate(active_finding.pk, admin_user)

    def test_creates_history(self, active_finding, admin_user):
        active_finding.status = Status.RISK_ACCEPTED
        active_finding.save()
        reactivate(active_finding.pk, admin_user)
        h = FindingHistory.objects.get(finding=active_finding)
        assert h.old_status == Status.RISK_ACCEPTED
        assert h.new_status == Status.ACTIVE


# ── Expire Risk Acceptances ────────────────────────────────────


@pytest.mark.django_db
class TestExpireRiskAcceptances:
    def test_expires_past_due(self, active_finding, admin_user):
        active_finding.status = Status.RISK_ACCEPTED
        active_finding.accepted_by = admin_user
        active_finding.accepted_reason = "temp"
        active_finding.accepted_until = datetime.date(2020, 1, 1)  # past
        active_finding.save()

        count = expire_risk_acceptances()
        assert count == 1

        active_finding.refresh_from_db()
        assert active_finding.status == Status.ACTIVE
        assert active_finding.accepted_by is None
        assert active_finding.accepted_until is None

        h = FindingHistory.objects.get(finding=active_finding)
        assert h.comment == "Risk acceptance expired"
        assert h.user is None  # system action

    def test_keeps_future_acceptances(self, active_finding, admin_user):
        active_finding.status = Status.RISK_ACCEPTED
        active_finding.accepted_until = datetime.date(2099, 12, 31)
        active_finding.save()

        count = expire_risk_acceptances()
        assert count == 0
        active_finding.refresh_from_db()
        assert active_finding.status == Status.RISK_ACCEPTED

    def test_skips_non_risk_accepted(self, active_finding):
        # Active finding with accepted_until should not be touched
        active_finding.accepted_until = datetime.date(2020, 1, 1)
        active_finding.save()

        count = expire_risk_acceptances()
        assert count == 0


# ── API endpoint tests ─────────────────────────────────────────


@pytest.mark.django_db
class TestLifecycleEndpoints:
    @pytest.fixture
    def operator_client(self, api_client, operator_user):
        from rest_framework.authtoken.models import Token

        token, _ = Token.objects.get_or_create(user=operator_user)
        api_client.credentials(HTTP_AUTHORIZATION=f"Token {token.key}")
        return api_client

    @pytest.fixture
    def admin_client(self, api_client, admin_user):
        from rest_framework.authtoken.models import Token

        token, _ = Token.objects.get_or_create(user=admin_user)
        api_client.credentials(HTTP_AUTHORIZATION=f"Token {token.key}")
        return api_client

    def test_acknowledge_as_operator(self, operator_client, active_finding):
        resp = operator_client.post(f"/api/v1/findings/{active_finding.pk}/acknowledge/")
        assert resp.status_code == 200
        assert resp.json()["status"] == "acknowledged"

    def test_acknowledge_as_service_token_forbidden(self, auth_client, active_finding):
        resp = auth_client.post(f"/api/v1/findings/{active_finding.pk}/acknowledge/")
        assert resp.status_code == 403

    def test_accept_risk_as_admin(self, admin_client, active_finding):
        resp = admin_client.post(
            f"/api/v1/findings/{active_finding.pk}/accept-risk/",
            data={"reason": "mitigated", "until": "2026-12-31"},
            format="json",
        )
        assert resp.status_code == 200
        assert resp.json()["status"] == "risk_accepted"

    def test_accept_risk_missing_reason(self, admin_client, active_finding):
        resp = admin_client.post(
            f"/api/v1/findings/{active_finding.pk}/accept-risk/",
            data={"until": "2026-12-31"},
            format="json",
        )
        assert resp.status_code == 400
        assert "reason" in resp.json()["error"]

    def test_accept_risk_as_operator_forbidden(self, operator_client, active_finding):
        resp = operator_client.post(
            f"/api/v1/findings/{active_finding.pk}/accept-risk/",
            data={"reason": "x", "until": "2026-12-31"},
            format="json",
        )
        assert resp.status_code == 403

    def test_false_positive_as_admin(self, admin_client, active_finding):
        resp = admin_client.post(
            f"/api/v1/findings/{active_finding.pk}/false-positive/",
            data={"reason": "not applicable"},
            format="json",
        )
        assert resp.status_code == 200
        assert resp.json()["status"] == "false_positive"

    def test_reactivate_as_admin(self, admin_client, active_finding):
        active_finding.status = Status.ACKNOWLEDGED
        active_finding.save()
        resp = admin_client.post(f"/api/v1/findings/{active_finding.pk}/reactivate/")
        assert resp.status_code == 200
        assert resp.json()["status"] == "active"

    def test_not_found(self, admin_client):
        resp = admin_client.post("/api/v1/findings/99999/reactivate/")
        assert resp.status_code == 404
