"""FindingAction — the only place users drive finding state.

Replaces the legacy RiskAcceptance + ExceptionPolicy + lifecycle-status
machinery. One row per user-driven action — acknowledge, accept,
false_positive, scheduled. Append-only: revocation writes `revoked_at`,
re-applying creates a new row.

A finding has no status column; its effective state is computed at
query time as "the most specific active matching FindingAction row,
if any". Active = `revoked_at IS NULL AND (expires_at IS NULL OR
expires_at > now())`.

Scope:
  per-finding         → one Finding row.
  per-vuln-image      → every Finding with this (vuln_id, image.digest).
  per-vuln            → every Finding with this vuln_id (admin only in UI).
"""
from django.conf import settings
from django.db import models

from core.constants import FindingActionScope, FindingActionType


class FindingAction(models.Model):
    action_type = models.CharField(
        max_length=20,
        choices=FindingActionType.choices,
    )
    scope_kind = models.CharField(
        max_length=20,
        choices=FindingActionScope.choices,
        default=FindingActionScope.PER_FINDING,
    )

    finding = models.ForeignKey(
        "core.Finding",
        on_delete=models.CASCADE,
        related_name="actions",
        null=True,
        blank=True,
    )
    vuln_id = models.CharField(max_length=128, blank=True, db_index=True)
    image = models.ForeignKey(
        "core.Image",
        on_delete=models.CASCADE,
        related_name="finding_actions",
        null=True,
        blank=True,
    )

    reason = models.TextField()
    expires_at = models.DateTimeField(
        null=True,
        blank=True,
        help_text="Required for action_type=accept; optional otherwise.",
    )
    ticket_ref = models.CharField(max_length=128, blank=True)
    sla_due_at = models.DateTimeField(null=True, blank=True)

    actor = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="finding_actions",
    )

    created_at = models.DateTimeField(auto_now_add=True)
    revoked_at = models.DateTimeField(
        null=True,
        blank=True,
        help_text="Non-null = no longer in effect; append a new row to revive.",
    )

    class Meta:
        indexes = [
            models.Index(
                fields=["scope_kind", "vuln_id"],
                name="finding_action_vuln",
            ),
            models.Index(
                fields=["scope_kind", "image"],
                name="finding_action_image",
            ),
            models.Index(
                fields=["finding", "revoked_at"],
                name="finding_action_finding_revoked",
            ),
            models.Index(fields=["expires_at"], name="finding_action_expires"),
        ]
        ordering = ["-created_at"]

    def __str__(self) -> str:
        return f"{self.action_type} ({self.scope_kind}) by {self.actor or 'system'}"
