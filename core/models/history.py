"""
FindingHistory — append-only audit trail for finding status changes.

Every status change (acknowledge, accept-risk, false-positive, reactivate,
auto-resolve, auto-reactivate) creates a record. Immutable — audit evidence.

See: docs/architecture.md § F22
"""
from django.conf import settings
from django.db import models


class FindingHistory(models.Model):
    """Immutable audit record for a finding status change."""

    finding = models.ForeignKey(
        "core.Finding",
        on_delete=models.CASCADE,
        related_name="history",
    )
    timestamp = models.DateTimeField(auto_now_add=True)
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        help_text="User who performed the action (null for system actions)",
    )
    old_status = models.CharField(max_length=20)
    new_status = models.CharField(max_length=20)
    comment = models.TextField(
        blank=True,
        help_text="Reason for risk acceptance, false positive justification, etc.",
    )

    class Meta:
        ordering = ["-timestamp"]
        indexes = [
            models.Index(fields=["finding", "-timestamp"], name="history_finding_ts"),
        ]

    def __str__(self):
        actor = self.user.username if self.user else "system"
        return f"{self.finding_id}: {self.old_status} → {self.new_status} by {actor}"
