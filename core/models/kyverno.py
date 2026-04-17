"""
Kyverno compliance model — PolicyComplianceSnapshot.

Captures Kyverno PolicyReport summary counts (pass/fail/warn/skip)
per cluster. Not individual policy results — those go to Finding model.

See: docs/architecture.md § PolicyComplianceSnapshot
"""
from django.db import models


class PolicyComplianceSnapshot(models.Model):
    """Point-in-time Kyverno policy compliance summary per cluster.

    Created on each PolicyReport ingest. Stores aggregate pass/fail/warn/skip
    counts across all policies in the cluster.
    """

    cluster = models.ForeignKey(
        "core.Cluster",
        on_delete=models.CASCADE,
        related_name="policy_compliance_snapshots",
    )
    scanned_at = models.DateTimeField()
    total_pass = models.PositiveIntegerField(default=0)
    total_fail = models.PositiveIntegerField(default=0)
    total_warn = models.PositiveIntegerField(default=0)
    total_skip = models.PositiveIntegerField(default=0)
    pass_rate = models.DecimalField(
        max_digits=5,
        decimal_places=2,
        default=0,
        help_text="Pass percentage: total_pass / (total_pass + total_fail) * 100",
    )
    raw_json = models.JSONField(
        default=dict,
        blank=True,
        help_text="Summary of ingested PolicyReport data",
    )

    class Meta:
        ordering = ["-scanned_at"]
        indexes = [
            models.Index(
                fields=["cluster", "-scanned_at"],
                name="polsnap_cluster_date",
            ),
        ]

    def __str__(self):
        return f"{self.cluster.name} @ {self.scanned_at:%Y-%m-%d} ({self.pass_rate}%)"
