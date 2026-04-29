"""Namespace — per-cluster, auto-discovered from inventory.

`internet_exposed` is a rollup over the namespace's Workloads — true
iff at least one Workload in the namespace has `publicly_exposed=true`.
The rollup is recomputed by the inventory parser; admin override flips
`exposure_is_manual=true` and the auto-rollup skips the namespace.

`contains_sensitive_data` has no reliable manifest signal in v1; admin
flips it via Cluster detail.

`active` flips false when the namespace disappears from a complete
inventory snapshot. Inactive namespaces stay queryable; their
workloads' findings stay on record.
"""
from django.db import models


class Namespace(models.Model):
    cluster = models.ForeignKey(
        "core.Cluster",
        on_delete=models.CASCADE,
        related_name="namespaces",
    )
    name = models.CharField(max_length=253)

    labels = models.JSONField(default=dict, blank=True)
    annotations = models.JSONField(default=dict, blank=True)

    internet_exposed = models.BooleanField(
        default=False,
        help_text="Rollup: any Workload in this namespace has publicly_exposed=true.",
    )
    exposure_is_manual = models.BooleanField(default=False)

    contains_sensitive_data = models.BooleanField(default=False)
    sensitive_is_manual = models.BooleanField(default=False)

    active = models.BooleanField(default=True)
    deactivated_at = models.DateTimeField(null=True, blank=True)

    first_seen_at = models.DateTimeField(auto_now_add=True)
    last_seen_at = models.DateTimeField(auto_now=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["cluster", "name"],
                name="unique_namespace_per_cluster",
            ),
        ]
        indexes = [
            models.Index(fields=["cluster", "active"], name="namespace_cluster_active"),
        ]
        ordering = ["cluster_id", "name"]

    def __str__(self) -> str:
        # Just the namespace name. Cluster is shown separately as its
        # own column in admin / UI; including it here would double up
        # whenever Workload.__str__ already prefixes the cluster, and
        # makes it harder to spot the same namespace name appearing
        # in two clusters at a glance.
        return self.name

    @property
    def pss_enforce(self) -> str:
        """Pod Security Standards `enforce` mode label, or "" if unset.

        Read from `labels["pod-security.kubernetes.io/enforce"]`. Missing
        label means PSS is not configured (semantically: privileged).
        """
        if not isinstance(self.labels, dict):
            return ""
        return self.labels.get("pod-security.kubernetes.io/enforce", "") or ""
