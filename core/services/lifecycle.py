"""
Finding lifecycle actions — acknowledge, accept risk, false positive, reactivate.

Each action: validates current status, updates finding, creates FindingHistory.
Exposed via explicit action endpoints (Convention A2 — not generic PATCH).

See: docs/architecture.md § F4, F22
"""
import logging

from django.utils import timezone

from core.constants import Status
from core.models.finding import Finding
from core.models.history import FindingHistory

logger = logging.getLogger(__name__)


class LifecycleError(Exception):
    """Raised when a lifecycle action is invalid for the current state."""


def _record_history(finding, user, old_status, new_status, comment=""):
    """Create an immutable FindingHistory record."""
    FindingHistory.objects.create(
        finding=finding,
        user=user,
        old_status=old_status,
        new_status=new_status,
        comment=comment,
    )


def acknowledge(finding_id: int, user) -> Finding:
    """Mark finding as acknowledged. Operator+ permission.

    Valid from: active
    """
    finding = Finding.objects.get(pk=finding_id)
    if finding.status != Status.ACTIVE:
        raise LifecycleError(
            f"Cannot acknowledge: finding is '{finding.status}', must be 'active'"
        )

    old_status = finding.status
    finding.status = Status.ACKNOWLEDGED
    finding.save(update_fields=["status"])

    _record_history(finding, user, old_status, Status.ACKNOWLEDGED)
    logger.info("Finding #%d acknowledged by %s", finding_id, user)
    return finding


def accept_risk(finding_id: int, user, reason: str, until) -> Finding:
    """Accept risk on finding. Admin-only. Requires reason + expiry.

    Valid from: active, acknowledged
    """
    finding = Finding.objects.get(pk=finding_id)
    if finding.status not in (Status.ACTIVE, Status.ACKNOWLEDGED):
        raise LifecycleError(
            f"Cannot accept risk: finding is '{finding.status}', "
            f"must be 'active' or 'acknowledged'"
        )

    old_status = finding.status
    finding.status = Status.RISK_ACCEPTED
    finding.accepted_by = user
    finding.accepted_reason = reason
    finding.accepted_until = until
    finding.save(update_fields=[
        "status", "accepted_by", "accepted_reason", "accepted_until"
    ])

    _record_history(
        finding, user, old_status, Status.RISK_ACCEPTED,
        comment=f"Reason: {reason}. Expires: {until}",
    )
    logger.info("Finding #%d risk accepted by %s until %s", finding_id, user, until)
    return finding


def false_positive(finding_id: int, user, reason: str) -> Finding:
    """Mark finding as false positive. Admin-only. Requires reason.

    Valid from: active, acknowledged
    """
    finding = Finding.objects.get(pk=finding_id)
    if finding.status not in (Status.ACTIVE, Status.ACKNOWLEDGED):
        raise LifecycleError(
            f"Cannot mark false positive: finding is '{finding.status}', "
            f"must be 'active' or 'acknowledged'"
        )

    old_status = finding.status
    finding.status = Status.FALSE_POSITIVE
    finding.save(update_fields=["status"])

    _record_history(
        finding, user, old_status, Status.FALSE_POSITIVE,
        comment=f"Reason: {reason}",
    )
    logger.info("Finding #%d marked false positive by %s", finding_id, user)
    return finding


def reactivate(finding_id: int, user) -> Finding:
    """Reactivate a finding. Admin-only.

    Valid from: acknowledged, risk_accepted, false_positive, resolved
    """
    finding = Finding.objects.get(pk=finding_id)
    if finding.status == Status.ACTIVE:
        raise LifecycleError("Finding is already active")

    old_status = finding.status
    finding.status = Status.ACTIVE
    finding.resolved_at = None
    finding.accepted_by = None
    finding.accepted_reason = ""
    finding.accepted_until = None
    finding.save(update_fields=[
        "status", "resolved_at", "accepted_by", "accepted_reason", "accepted_until"
    ])

    _record_history(finding, user, old_status, Status.ACTIVE)
    logger.info("Finding #%d reactivated by %s", finding_id, user)
    return finding


def expire_risk_acceptances() -> int:
    """Reactivate findings with expired risk acceptance. Daily cron.

    Finds all risk_accepted findings where accepted_until < today,
    sets them back to active, clears risk fields, creates history.
    """
    today = timezone.now().date()
    expired = Finding.objects.filter(
        status=Status.RISK_ACCEPTED,
        accepted_until__lt=today,
    )

    count = 0
    for finding in expired:
        old_status = finding.status
        finding.status = Status.ACTIVE
        finding.accepted_by = None
        finding.accepted_reason = ""
        finding.accepted_until = None
        finding.save(update_fields=[
            "status", "accepted_by", "accepted_reason", "accepted_until"
        ])
        _record_history(
            finding, None, old_status, Status.ACTIVE,
            comment="Risk acceptance expired",
        )
        count += 1

    if count:
        logger.info("Expired %d risk acceptances", count)
    return count
