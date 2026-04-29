"""Finding — one vuln / misconfig / policy violation per (workload, image).

Per-workload semantics: the same CVE on the same image running in two
workloads produces two Finding rows, each with its own
`effective_priority` and its own `FindingAction` overlays. Different
deployment contexts warrant different priorities.

`workload` is nullable for cluster-scoped findings (e.g. a Trivy
ClusterRbacAssessmentReport against a ClusterRole with no owning
workload). For those rows the dedup hash substitutes `cluster.name`
for `workload.id` and omits `image.digest`.

Finding has no status field. Workflow state — acknowledge, accept,
false-positive, scheduled — lives in `FindingAction`.
"""
from django.contrib.postgres.indexes import GinIndex
from django.db import models
from django.utils import timezone

from core.constants import Category, PriorityBand, Severity, Source


class Finding(models.Model):
    cluster = models.ForeignKey(
        "core.Cluster",
        on_delete=models.CASCADE,
        related_name="findings",
        help_text=(
            "Always set. For workload-scoped findings, redundant with "
            "workload.cluster — kept on the row for query convenience and "
            "for cluster-scoped findings (workload null)."
        ),
    )
    workload = models.ForeignKey(
        "core.Workload",
        on_delete=models.CASCADE,
        related_name="findings",
        null=True,
        blank=True,
    )
    image = models.ForeignKey(
        "core.Image",
        on_delete=models.CASCADE,
        related_name="findings",
        null=True,
        blank=True,
    )

    source = models.CharField(max_length=32, choices=Source.choices)
    category = models.CharField(max_length=32, choices=Category.choices)

    vuln_id = models.CharField(
        max_length=128,
        blank=True,
        db_index=True,
        help_text=(
            "Source-defined identifier as opaque string — CVE-*, GHSA-*, "
            "vendor IDs, AVD-* or Kyverno policy names. EPSS / KEV joins "
            "match on the CVE-* prefix only."
        ),
    )
    pkg_name = models.CharField(max_length=256, blank=True, db_index=True)
    installed_version = models.CharField(max_length=128, blank=True)
    fixed_version = models.CharField(max_length=128, blank=True)

    title = models.CharField(max_length=512)
    severity = models.CharField(max_length=16, choices=Severity.choices)
    cvss_score = models.FloatField(null=True, blank=True)
    cvss_vector = models.CharField(max_length=128, blank=True)

    details = models.JSONField(
        default=dict,
        blank=True,
        help_text="Source-specific fields not promoted to columns.",
    )

    effective_priority = models.CharField(
        max_length=20,
        choices=PriorityBand.choices,
        default=PriorityBand.SCHEDULED,
        db_index=True,
    )

    epss_score = models.FloatField(null=True, blank=True)
    epss_percentile = models.FloatField(null=True, blank=True)
    kev_listed = models.BooleanField(default=False)

    first_seen = models.DateTimeField(default=timezone.now)
    last_seen = models.DateTimeField(default=timezone.now)

    hash_code = models.CharField(
        max_length=64,
        help_text=(
            "sha256 of (source, category, vuln_id, workload.id or "
            "cluster.name, image.digest, pkg_name, installed_version)."
        ),
    )

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["source", "hash_code"],
                name="unique_finding_per_source_hash",
            ),
        ]
        indexes = [
            GinIndex(fields=["details"], name="finding_details_gin"),
            models.Index(
                fields=["workload", "effective_priority"],
                name="finding_workload_priority",
            ),
            models.Index(
                fields=["cluster", "effective_priority"],
                name="finding_cluster_priority",
            ),
            models.Index(fields=["last_seen"], name="finding_last_seen"),
            models.Index(fields=["image"], name="finding_image"),
        ]
        ordering = ["-last_seen"]

    def __str__(self) -> str:
        return f"[{self.severity}] {self.title[:80]}"
