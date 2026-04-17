from django.db import models


class RawReport(models.Model):
    """
    Temporary storage for CRDs that aren't fully parsed in Phase 1.

    Stores raw ClusterComplianceReport and SbomReport JSON so data is
    captured from day 1. Phase 2 backfills these into structured models
    (Snapshot/ControlResult for compliance, Component for SBOM).
    """

    cluster = models.ForeignKey(
        "core.Cluster", on_delete=models.CASCADE, related_name="raw_reports"
    )
    kind = models.CharField(
        max_length=100,
        help_text="CRD kind: ClusterComplianceReport, SbomReport",
    )
    source = models.CharField(max_length=30, default="trivy")
    received_at = models.DateTimeField(auto_now_add=True)
    raw_json = models.JSONField()

    class Meta:
        ordering = ["-received_at"]

    def __str__(self):
        return f"{self.cluster.name} / {self.kind} @ {self.received_at:%Y-%m-%d %H:%M}"
