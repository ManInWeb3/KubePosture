"""ScanInconsistency — coverage-gap row from the inventory ↔ scan cross-check.

After each cycle the worker compares the live Pod set (from the
inventory payload's ground truth) with the (workload, image) pairs
referenced by scan reports. Mismatches in either direction are
recorded here for the Scan Health UI / log alerts.

Persistent gaps (≥ N consecutive cycles, default 3) escalate to a
high-severity log event. Rows older than 30 days are pruned by a
maintenance job.
"""
from django.db import models


class ScanInconsistency(models.Model):
    cluster = models.ForeignKey(
        "core.Cluster",
        on_delete=models.CASCADE,
        related_name="scan_inconsistencies",
    )
    kind = models.CharField(max_length=64)
    workload = models.ForeignKey(
        "core.Workload",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="scan_inconsistencies",
    )
    image_digest = models.CharField(max_length=80, blank=True)

    seen_in_inventory = models.BooleanField(default=False)
    seen_in_scans = models.BooleanField(default=False)

    first_observed_at = models.DateTimeField(auto_now_add=True)
    last_observed_at = models.DateTimeField(auto_now=True)
    consecutive_cycles = models.PositiveIntegerField(default=1)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["cluster", "kind", "workload", "image_digest"],
                name="unique_scan_inconsistency",
            ),
        ]
        indexes = [
            models.Index(fields=["cluster", "kind"], name="scan_inconsist_ck"),
            models.Index(fields=["last_observed_at"], name="scan_inconsist_age"),
        ]
        ordering = ["-last_observed_at"]

    def __str__(self) -> str:
        return f"{self.cluster.name}/{self.kind} {self.workload}/{self.image_digest[:20]}"
