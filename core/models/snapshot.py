"""Snapshot — point-in-time count rollups for trend charts.

Append-only. Two write paths combined:

1. Event-path (workload-scope only) — written inside the inventory
   reap when a workload's image-set differs from the previous
   snapshot. `change_kind != none` rows are real deploy / rollback /
   admission-rewrite events.

2. Daily-heartbeat path (all scopes) — `manage.py snapshot_capture`
   writes one global, one per cluster, one per active namespace, one
   per deployed workload. Workload heartbeat rows carry
   `change_kind=none` and serve as trend continuity.

Replaces the legacy FindingSnapshot and PolicyComplianceSnapshot
tables.
"""
from django.db import models

from core.constants import ImageSetChangeKind, SnapshotScope


class Snapshot(models.Model):
    scope_kind = models.CharField(max_length=20, choices=SnapshotScope.choices)
    cluster = models.ForeignKey(
        "core.Cluster",
        on_delete=models.CASCADE,
        related_name="snapshots",
        null=True,
        blank=True,
    )
    namespace = models.ForeignKey(
        "core.Namespace",
        on_delete=models.CASCADE,
        related_name="snapshots",
        null=True,
        blank=True,
    )
    workload = models.ForeignKey(
        "core.Workload",
        on_delete=models.CASCADE,
        related_name="snapshots",
        null=True,
        blank=True,
    )

    severity_counts = models.JSONField(
        default=dict,
        blank=True,
        help_text="{critical: N, high: N, medium: N, low: N, info: N, unknown: N}",
    )
    priority_counts = models.JSONField(
        default=dict,
        blank=True,
        help_text="{immediate: N, out_of_cycle: N, scheduled: N, defer: N}",
    )
    total_active = models.PositiveIntegerField(default=0)
    total_actioned = models.PositiveIntegerField(default=0)

    import_id = models.CharField(
        max_length=32,
        blank=True,
        help_text="Import that produced this snapshot. Empty for safety-net rows.",
    )

    # Workload-scope only:
    image_digest_set = models.JSONField(
        default=list,
        blank=True,
        help_text="Sorted array of digests across primary + init containers.",
    )
    image_set_changed_from_previous = models.BooleanField(default=False)
    change_kind = models.CharField(
        max_length=16,
        choices=ImageSetChangeKind.choices,
        default=ImageSetChangeKind.NONE,
    )

    captured_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        indexes = [
            models.Index(
                fields=["scope_kind", "captured_at"],
                name="snapshot_scope_captured",
            ),
            models.Index(
                fields=["workload", "captured_at"],
                name="snapshot_workload",
            ),
            models.Index(
                fields=["cluster", "captured_at"],
                name="snapshot_cluster",
            ),
        ]
        ordering = ["-captured_at"]

    def __str__(self) -> str:
        target = (
            self.workload or self.namespace or self.cluster or "global"
        )
        return f"Snapshot[{self.scope_kind}] {target} @ {self.captured_at.isoformat()}"
