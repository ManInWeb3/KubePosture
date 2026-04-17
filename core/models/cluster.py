from django.db import models

from core.constants import Source


class Cluster(models.Model):
    """
    K8s cluster auto-registered on first ingest (Convention D2).

    Metadata (provider, environment, region) resolved from cluster name
    via parse_cluster_meta() — convention-based parsing with overrides dict.
    """

    name = models.CharField(max_length=253, unique=True)
    provider = models.CharField(
        max_length=20,
        default="unknown",
        help_text="eks, aks, ovh, do, unknown",
    )
    environment = models.CharField(
        max_length=20,
        default="unknown",
        help_text="dev, staging, prod, unknown",
    )
    region = models.CharField(max_length=50, blank=True)
    project = models.CharField(max_length=100, blank=True)
    k8s_version = models.CharField(max_length=30, blank=True)
    internet_exposed = models.BooleanField(
        default=False,
        help_text="Cluster has internet-facing services (ingress, LoadBalancer)",
    )
    contains_sensitive_data = models.BooleanField(
        default=False,
        help_text="Cluster processes PII, financial, or regulated data",
    )
    namespace_overrides = models.JSONField(
        default=dict,
        blank=True,
        help_text=(
            'Per-namespace exposure overrides. Inherits cluster defaults if not set. '
            'Format: {"namespace": {"internet_exposed": bool, "contains_sensitive_data": bool}}'
        ),
    )
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["name"]

    def __str__(self):
        return self.name


class ScanStatus(models.Model):
    """
    Tracks last ingest per cluster per source (F30).

    Updated on every ingest call. Dashboard shows scanner health matrix
    (cluster x source -> last ingest time). Alert if last_ingest > 24h ago.
    """

    cluster = models.ForeignKey(
        Cluster, on_delete=models.CASCADE, related_name="scan_statuses"
    )
    source = models.CharField(max_length=30, choices=Source.choices)
    last_ingest = models.DateTimeField()
    finding_count = models.IntegerField(default=0)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["cluster", "source"],
                name="unique_scan_status_per_cluster_source",
            ),
        ]
        verbose_name_plural = "scan statuses"

    def __str__(self):
        return f"{self.cluster.name} / {self.source}"
