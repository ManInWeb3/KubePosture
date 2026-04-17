from django.conf import settings
from django.contrib.postgres.indexes import GinIndex
from django.db import models

from core.constants import Category, Origin, Priority, Severity, Source, Status


class Finding(models.Model):
    """
    Central security finding — JSONB hybrid model.

    Indexed columns for filtering/dedup/lifecycle + JSONB `details` (GIN indexed)
    for all CRD-type-specific data. Different CRD types (VulnerabilityReport,
    ConfigAuditReport, etc.) produce findings with different fields in `details`.
    No schema migration when CRDs change — new fields land in JSONB automatically.

    See: docs/architecture.md § JSONB Hybrid Approach
    """

    # ── Origin ──────────────────────────────────────────────────
    origin = models.CharField(
        max_length=10, choices=Origin.choices, default=Origin.CLUSTER
    )

    # ── K8s Identity (columns — used in hash + filtering) ───────
    cluster = models.ForeignKey(
        "core.Cluster",
        on_delete=models.CASCADE,
        related_name="findings",
        null=True,
        blank=True,
    )
    namespace = models.CharField(max_length=253, blank=True)
    resource_kind = models.CharField(max_length=100, blank=True)
    resource_name = models.CharField(max_length=253, blank=True)

    # ── Finding Core (columns — most displayed/searched) ────────
    title = models.CharField(max_length=500)
    severity = models.CharField(max_length=20, choices=Severity.choices)
    vuln_id = models.CharField(
        max_length=100,
        blank=True,
        db_index=True,
        help_text="CVE ID, check ID, or rule ID",
    )

    # ── Classification ──────────────────────────────────────────
    category = models.CharField(max_length=30, choices=Category.choices)
    source = models.CharField(max_length=30, choices=Source.choices)

    # ── Lifecycle ───────────────────────────────────────────────
    status = models.CharField(
        max_length=20, choices=Status.choices, default=Status.ACTIVE
    )
    first_seen = models.DateTimeField(auto_now_add=True)
    last_seen = models.DateTimeField(auto_now=True)
    resolved_at = models.DateTimeField(null=True, blank=True)

    # ── Dedup ───────────────────────────────────────────────────
    hash_code = models.CharField(max_length=64)

    # ── Effective Priority (SSVC-inspired decision tree) ─────────
    effective_priority = models.CharField(
        max_length=20,
        choices=Priority.choices,
        default=Priority.SCHEDULED,
        db_index=True,
        help_text="Contextual priority from severity + EPSS/KEV + cluster/namespace exposure",
    )

    # ── Enrichment (Phase 2 — columns for bulk updates) ────────
    epss_score = models.DecimalField(
        max_digits=5, decimal_places=4, null=True, blank=True
    )
    kev_listed = models.BooleanField(null=True, blank=True)

    # ── Risk Acceptance (Phase 2 — columns for lifecycle) ───────
    accepted_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="accepted_findings",
    )
    accepted_reason = models.TextField(blank=True)
    accepted_until = models.DateField(null=True, blank=True)

    # ── JSONB — all CRD-type-specific data (GIN indexed) ───────
    details = models.JSONField(
        default=dict,
        blank=True,
        help_text=(
            "CRD-type-specific fields: description, remediation, score, "
            "component_name, installed_version, fixed_version, image, "
            "container, advisory_url, check_id, messages, etc."
        ),
    )

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["origin", "cluster", "hash_code"],
                name="unique_finding_per_origin_cluster",
            ),
        ]
        indexes = [
            GinIndex(fields=["details"], name="finding_details_gin"),
            models.Index(
                fields=["cluster", "source", "status"],
                name="finding_cluster_source_status",
            ),
            models.Index(
                fields=["cluster", "status"],
                name="finding_cluster_status",
            ),
            models.Index(
                fields=["severity", "status"],
                name="finding_severity_status",
            ),
            models.Index(
                fields=["last_seen"],
                name="finding_last_seen",
            ),
        ]
        ordering = ["-first_seen"]

    def __str__(self):
        return f"[{self.severity}] {self.title[:80]}"
