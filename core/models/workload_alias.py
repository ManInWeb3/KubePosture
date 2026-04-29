"""WorkloadAlias — maps non-top-level controllers to their owner Workload.

Trivy emits VulnerabilityReports targeting ReplicaSets and Jobs;
findings need to attach to the parent Deployment / CronJob. The
importer walks ownerReferences and posts these rows so the central
worker can rewrite `(kind, name)` to the top-level controller before
attaching findings.

Stale aliases (resource no longer in the live snapshot) are deleted
in the inventory-sync worker transaction — no background cleanup
job. Aliases never persist beyond the resource they alias.
"""
from django.db import models

from core.constants import AliasKind


class WorkloadAlias(models.Model):
    cluster = models.ForeignKey(
        "core.Cluster",
        on_delete=models.CASCADE,
        related_name="workload_aliases",
    )
    namespace = models.ForeignKey(
        "core.Namespace",
        on_delete=models.CASCADE,
        related_name="workload_aliases",
    )
    alias_kind = models.CharField(max_length=32, choices=AliasKind.choices)
    alias_name = models.CharField(max_length=253)
    target_workload = models.ForeignKey(
        "core.Workload",
        on_delete=models.CASCADE,
        related_name="aliases",
    )
    last_seen_at = models.DateTimeField(auto_now=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["cluster", "namespace", "alias_kind", "alias_name"],
                name="unique_workload_alias",
            ),
        ]
        indexes = [
            models.Index(
                fields=["cluster", "alias_kind", "alias_name"],
                name="workload_alias_lookup",
            ),
        ]
        ordering = ["cluster_id", "namespace_id", "alias_kind", "alias_name"]

    def __str__(self) -> str:
        return f"{self.alias_kind}/{self.alias_name} → {self.target_workload}"
