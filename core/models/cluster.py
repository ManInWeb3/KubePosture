from django.db import models
from django.utils.functional import cached_property

from core.constants import Source


class Cluster(models.Model):
    """
    K8s cluster auto-registered on first ingest (Convention D2).

    Most metadata is auto-detected by the import script
    (`/api/v1/cluster-metadata/sync/`): k8s_version, provider, region,
    plus per-namespace exposure in the related Namespace model.

    The *_is_manual flags flip to True when an admin edits a field via
    the UI; subsequent auto-detect runs then skip that field.
    """

    name = models.CharField(max_length=253, unique=True)

    environment = models.CharField(
        max_length=20,
        blank=True,
        help_text="dev, staging, prod — parsed from cluster name on auto-register.",
    )
    environment_is_manual = models.BooleanField(default=False)

    provider = models.CharField(
        max_length=20,
        default="onprem",
        help_text="aws, eks, gcp, gke, azure, aks, onprem — auto-detected from node provider_id.",
    )
    provider_is_manual = models.BooleanField(default=False)

    region = models.CharField(
        max_length=50,
        blank=True,
        help_text="Auto-detected from node label topology.kubernetes.io/region.",
    )
    region_is_manual = models.BooleanField(default=False)

    project = models.CharField(max_length=100, blank=True)
    k8s_version = models.CharField(max_length=30, blank=True)

    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["name"]

    def __str__(self):
        return self.name

    @cached_property
    def has_public_exposure(self) -> bool:
        """True if ANY namespace in this cluster is marked exposed.

        Used for lateral-movement pressure and for cluster-scoped findings
        (namespace=NULL) where per-namespace context doesn't apply.
        """
        return self.namespaces.filter(
            active=True, internet_exposed=True
        ).exists()

    @cached_property
    def has_sensitive_data(self) -> bool:
        """True if ANY namespace in this cluster is marked sensitive.

        Same derivation as has_public_exposure — symmetric.
        """
        return self.namespaces.filter(
            active=True, contains_sensitive_data=True
        ).exists()


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
