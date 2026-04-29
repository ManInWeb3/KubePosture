"""Workload — top-level K8s controller (or naked Pod) seen in inventory.

Identity is `(cluster, namespace, kind, name)`. ReplicaSets and child
Jobs resolve to their parent via WorkloadAlias before any finding is
attached.

Exposure is collapsed to a single boolean `publicly_exposed`: true iff
the workload is backed by an external Ingress OR a non-internal
LoadBalancer Service. Other Pod-spec security facts (hostNetwork,
hostPID, privileged container, NodePort selection, etc.) are
WorkloadSignal rows, not columns. Adding new signals is a registry
edit, not a schema migration.

`deployed` and `last_inventory_at` are maintained by the inventory
reap; scan-kind handlers must NOT touch them — that's how a stale
Trivy CRD never re-animates a workload no longer in the live
inventory.
"""
from django.db import models

from core.constants import WorkloadKind


class Workload(models.Model):
    cluster = models.ForeignKey(
        "core.Cluster",
        on_delete=models.CASCADE,
        related_name="workloads",
    )
    namespace = models.ForeignKey(
        "core.Namespace",
        on_delete=models.CASCADE,
        related_name="workloads",
    )
    kind = models.CharField(max_length=32, choices=WorkloadKind.choices)
    name = models.CharField(max_length=253)

    service_account = models.CharField(max_length=253, blank=True, default="default")
    replicas = models.PositiveIntegerField(null=True, blank=True)

    labels = models.JSONField(
        default=dict,
        blank=True,
        help_text="Pod template labels — used for Service / Ingress selector matching.",
    )

    publicly_exposed = models.BooleanField(
        default=False,
        help_text=(
            "Auto-derived: true iff backed by an external Ingress OR a "
            "non-internal LoadBalancer Service. Admin override via "
            "publicly_exposed_is_manual."
        ),
    )
    publicly_exposed_is_manual = models.BooleanField(default=False)

    deployed = models.BooleanField(
        default=True,
        help_text="Maintained by the inventory reap.",
    )
    last_inventory_at = models.DateTimeField(
        null=True,
        blank=True,
        help_text=(
            "Bumped only by inventory-kind handlers. Drives the deployed-flag "
            "diff (`deployed = last_inventory_at >= mark.started_at`). Scan "
            "handlers must not touch this field."
        ),
    )

    first_seen_at = models.DateTimeField(auto_now_add=True)
    last_seen_at = models.DateTimeField(
        auto_now=True,
        help_text="Bumped on any touch (inventory or scan).",
    )

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["cluster", "namespace", "kind", "name"],
                name="unique_workload_identity",
            ),
        ]
        indexes = [
            models.Index(fields=["cluster", "deployed"], name="workload_cluster_deployed"),
            models.Index(fields=["cluster", "publicly_exposed"], name="workload_cluster_exposed"),
        ]
        ordering = ["cluster_id", "namespace_id", "kind", "name"]

    def __str__(self) -> str:
        return f"{self.cluster.name}/{self.namespace.name}/{self.kind}/{self.name}"
