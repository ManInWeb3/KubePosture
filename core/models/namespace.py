"""
First-class Namespace entity — per-cluster, auto-discovered, admin-overridable.

Source of truth for per-namespace exposure/sensitivity. Replaces the
earlier Cluster-level flags + JSON overrides.

Auto-detect (via import script `/cluster-metadata/sync/`) seeds:
  - internet_exposed  from Services (LoadBalancer/NodePort) + Ingresses
  - labels, annotations from K8s namespace metadata

Admin edits in the UI flip *_is_manual=True so future auto-detect runs
skip that field. Reset button clears the manual flag.
"""
from django.db import models


class Namespace(models.Model):
    cluster = models.ForeignKey(
        "core.Cluster",
        on_delete=models.CASCADE,
        related_name="namespaces",
    )
    name = models.CharField(max_length=253)

    internet_exposed = models.BooleanField(
        default=False,
        help_text="Namespace has externally-reachable workloads (Services LB/NodePort, Ingresses).",
    )
    exposure_is_manual = models.BooleanField(
        default=False,
        help_text="Admin manually set internet_exposed — auto-detect skips this record.",
    )

    contains_sensitive_data = models.BooleanField(
        default=False,
        help_text="Namespace processes PII, financial, or regulated data.",
    )
    sensitive_is_manual = models.BooleanField(
        default=False,
        help_text="Admin manually set contains_sensitive_data.",
    )

    labels = models.JSONField(
        default=dict,
        blank=True,
        help_text="Mirrored from K8s namespace.metadata.labels (future: ownership, scope).",
    )
    annotations = models.JSONField(
        default=dict,
        blank=True,
        help_text="Mirrored from K8s namespace.metadata.annotations.",
    )

    active = models.BooleanField(
        default=True,
        help_text=(
            "False when the namespace no longer appears in a complete cluster snapshot. "
            "Inactive namespaces are excluded from exposure rollups; their active/acknowledged "
            "findings are auto-resolved. Flipped back to True if the namespace reappears."
        ),
    )
    deactivated_at = models.DateTimeField(
        null=True,
        blank=True,
        help_text="Timestamp of most recent deactivation. Null while active.",
    )

    first_seen = models.DateTimeField(auto_now_add=True)
    last_seen = models.DateTimeField(auto_now=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["cluster", "name"],
                name="unique_namespace_per_cluster",
            ),
        ]
        indexes = [
            models.Index(
                fields=["cluster", "internet_exposed"],
                name="namespace_cluster_exposed",
            ),
            models.Index(
                fields=["cluster", "active"],
                name="namespace_cluster_active",
            ),
        ]
        ordering = ["cluster_id", "name"]

    def __str__(self):
        return f"{self.cluster.name}/{self.name}"
