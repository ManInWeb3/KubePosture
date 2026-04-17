"""
Compliance models — Framework, Control, Snapshot, ControlResult.

Frameworks are loaded from YAML fixtures via `manage.py load_frameworks`.
Snapshots are created on every ClusterComplianceReport ingest — immutable.
ControlResults are per-control pass/fail within a snapshot.

See: docs/architecture.md § Compliance Reporting
"""
from django.db import models

from core.constants import Severity


class CheckType(models.TextChoices):
    AUTOMATED = "automated", "Automated"
    MANUAL = "manual", "Manual"


class ControlStatus(models.TextChoices):
    PASS = "PASS", "Pass"
    FAIL = "FAIL", "Fail"
    MANUAL = "MANUAL", "Manual"


class Framework(models.Model):
    """Compliance framework definition (CIS K8s 1.23, NSA 1.0, etc.).

    Loaded from YAML fixtures via `manage.py load_frameworks`.
    Not editable in UI (Convention CF1).
    """

    slug = models.SlugField(max_length=100, unique=True)
    name = models.CharField(max_length=200)
    version = models.CharField(max_length=50)
    description = models.TextField(blank=True)
    total_controls = models.PositiveIntegerField(default=0)
    source = models.CharField(
        max_length=30,
        default="trivy",
        help_text="trivy (built-in spec) or custom (hand-authored YAML)",
    )

    class Meta:
        ordering = ["name"]

    def __str__(self):
        return f"{self.name} v{self.version}"


class Control(models.Model):
    """Individual control within a compliance framework.

    Controls map to Trivy AVD-* check IDs (automated) or require
    manual verification (manual). kyverno_policies lists Kyverno
    policies that enforce this control at admission.
    """

    framework = models.ForeignKey(
        Framework, on_delete=models.CASCADE, related_name="controls"
    )
    control_id = models.CharField(max_length=50)
    title = models.CharField(max_length=500)
    severity = models.CharField(
        max_length=20, choices=Severity.choices, default=Severity.MEDIUM
    )
    section = models.CharField(max_length=200, blank=True)
    description = models.TextField(blank=True)
    remediation = models.TextField(blank=True)
    check_type = models.CharField(
        max_length=20, choices=CheckType.choices, default=CheckType.AUTOMATED
    )
    check_ids = models.JSONField(
        default=list,
        blank=True,
        help_text="List of Trivy AVD-* check IDs mapped to this control",
    )
    kyverno_policies = models.JSONField(
        default=list,
        blank=True,
        help_text="List of Kyverno policy names that enforce this control",
    )

    class Meta:
        unique_together = ["framework", "control_id"]
        ordering = ["framework", "control_id"]

    def __str__(self):
        return f"{self.framework.slug} / {self.control_id}: {self.title[:60]}"


class Snapshot(models.Model):
    """Point-in-time compliance scan result per cluster per framework.

    Immutable — each scan creates a new snapshot (Convention C3).
    Query by date returns the nearest snapshot for audit evidence.
    """

    cluster = models.ForeignKey(
        "core.Cluster", on_delete=models.CASCADE, related_name="compliance_snapshots"
    )
    framework = models.ForeignKey(
        Framework, on_delete=models.CASCADE, related_name="snapshots"
    )
    scanned_at = models.DateTimeField()
    total_pass = models.PositiveIntegerField(default=0)
    total_fail = models.PositiveIntegerField(default=0)
    total_manual = models.PositiveIntegerField(default=0)
    pass_rate = models.DecimalField(
        max_digits=5, decimal_places=2, default=0,
        help_text="Pass percentage: total_pass / (total_pass + total_fail) * 100",
    )
    raw_json = models.JSONField(
        default=dict,
        blank=True,
        help_text="Original ClusterComplianceReport for audit reference",
    )

    class Meta:
        ordering = ["-scanned_at"]
        indexes = [
            models.Index(
                fields=["cluster", "framework", "-scanned_at"],
                name="snapshot_cluster_fw_date",
            ),
        ]

    def __str__(self):
        return (
            f"{self.cluster.name} / {self.framework.slug} "
            f"@ {self.scanned_at:%Y-%m-%d} ({self.pass_rate}%)"
        )


class ControlResult(models.Model):
    """Per-control pass/fail within a compliance snapshot."""

    snapshot = models.ForeignKey(
        Snapshot, on_delete=models.CASCADE, related_name="results"
    )
    control = models.ForeignKey(
        Control, on_delete=models.CASCADE, related_name="results"
    )
    status = models.CharField(max_length=10, choices=ControlStatus.choices)
    total_pass = models.PositiveIntegerField(default=0)
    total_fail = models.PositiveIntegerField(default=0)
    details = models.JSONField(default=dict, blank=True)

    class Meta:
        unique_together = ["snapshot", "control"]

    def __str__(self):
        return f"{self.control.control_id}: {self.status}"
