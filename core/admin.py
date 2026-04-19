from django.contrib import admin

from core.models import (
    Cluster,
    Component,
    Control,
    ControlResult,
    Finding,
    FindingHistory,
    Framework,
    IngestQueue,
    Namespace,
    PolicyComplianceSnapshot,
    RawReport,
    ScanStatus,
    Snapshot,
)


class FindingHistoryInline(admin.TabularInline):
    model = FindingHistory
    extra = 0
    fields = ["timestamp", "user", "old_status", "new_status", "comment"]
    readonly_fields = fields
    ordering = ["-timestamp"]


@admin.register(FindingHistory)
class FindingHistoryAdmin(admin.ModelAdmin):
    list_display = ["finding", "timestamp", "user", "old_status", "new_status"]
    list_filter = ["new_status"]
    readonly_fields = ["finding", "timestamp", "user", "old_status", "new_status", "comment"]
    date_hierarchy = "timestamp"


@admin.register(Finding)
class FindingAdmin(admin.ModelAdmin):
    list_display = [
        "severity",
        "effective_priority",
        "vuln_id",
        "short_title",
        "get_component",
        "cluster",
        "namespace",
        "resource_name",
        "status",
        "first_seen",
        "kev_listed",
    ]
    list_display_links = ["vuln_id", "short_title"]
    list_filter = [
        "severity",
        "effective_priority",
        "status",
        "source",
        "category",
        "cluster",
        "kev_listed",
    ]
    search_fields = ["title", "vuln_id", "namespace__name", "resource_name"]
    readonly_fields = [
        "origin",
        "cluster",
        "namespace",
        "resource_kind",
        "resource_name",
        "title",
        "severity",
        "vuln_id",
        "category",
        "source",
        "hash_code",
        "first_seen",
        "last_seen",
        "resolved_at",
        "effective_priority",
        "epss_score",
        "kev_listed",
        "details",
    ]
    date_hierarchy = "first_seen"
    list_per_page = 50
    actions = ["mark_acknowledged", "mark_resolved"]
    inlines = [FindingHistoryInline]

    fieldsets = [
        (
            "K8s Identity",
            {
                "fields": [
                    "origin",
                    "cluster",
                    "namespace",
                    "resource_kind",
                    "resource_name",
                ]
            },
        ),
        (
            "Finding",
            {
                "fields": [
                    "title",
                    "severity",
                    "vuln_id",
                    "category",
                    "source",
                    "hash_code",
                ]
            },
        ),
        (
            "Lifecycle",
            {
                "fields": ["status", "effective_priority", "first_seen", "last_seen", "resolved_at"]
            },
        ),
        (
            "Enrichment",
            {
                "fields": ["epss_score", "kev_listed"],
                "classes": ["collapse"],
            },
        ),
        (
            "Risk Acceptance",
            {
                "fields": ["accepted_by", "accepted_reason", "accepted_until"],
                "classes": ["collapse"],
            },
        ),
        (
            "Details (JSONB)",
            {
                "fields": ["details"],
                "classes": ["collapse"],
            },
        ),
    ]

    @admin.display(description="Title")
    def short_title(self, obj):
        return obj.title[:60] + "..." if len(obj.title) > 60 else obj.title

    @admin.display(description="Component")
    def get_component(self, obj):
        return obj.details.get("component_name", "")

    @admin.action(description="Mark selected as acknowledged")
    def mark_acknowledged(self, request, queryset):
        updated = queryset.filter(status="active").update(status="acknowledged")
        self.message_user(request, f"{updated} findings acknowledged.")

    @admin.action(description="Mark selected as resolved")
    def mark_resolved(self, request, queryset):
        from django.utils import timezone

        updated = queryset.exclude(
            status__in=["resolved", "risk_accepted", "false_positive"]
        ).update(status="resolved", resolved_at=timezone.now())
        self.message_user(request, f"{updated} findings resolved.")

    def get_search_results(self, request, queryset, search_term):
        """Extend search to JSONB details.component_name."""
        queryset, use_distinct = super().get_search_results(
            request, queryset, search_term
        )
        if search_term:
            queryset |= self.model.objects.filter(
                details__component_name__icontains=search_term
            )
        return queryset, use_distinct


class NamespaceInline(admin.TabularInline):
    model = Namespace
    extra = 0
    fields = [
        "name",
        "active",
        "internet_exposed",
        "exposure_is_manual",
        "contains_sensitive_data",
        "sensitive_is_manual",
        "deactivated_at",
        "last_seen",
    ]
    # active / deactivated_at are owned by the sync endpoint — editing them
    # here would bypass the cascade (finding deactivation on flip-off).
    readonly_fields = ["active", "deactivated_at", "last_seen"]
    ordering = ["-active", "name"]


@admin.register(Cluster)
class ClusterAdmin(admin.ModelAdmin):
    list_display = [
        "name",
        "provider",
        "environment",
        "region",
        "k8s_version",
    ]
    list_filter = ["provider", "environment"]
    search_fields = ["name"]
    inlines = [NamespaceInline]
    fieldsets = [
        (None, {"fields": ["name", "provider", "environment", "region", "project", "k8s_version"]}),
        (
            "Manual overrides",
            {
                "fields": [
                    "provider_is_manual",
                    "environment_is_manual",
                    "region_is_manual",
                ],
                "description": (
                    "When True, the field was set manually in the UI or admin — "
                    "subsequent auto-detect runs from the import script will skip it."
                ),
            },
        ),
    ]
    actions = ["recalculate_priorities"]

    # Fields whose changes require a priority recalculation.
    _PRIORITY_FIELDS = {"environment"}

    def save_model(self, request, obj, form, change):
        super().save_model(request, obj, form, change)
        if change and self._PRIORITY_FIELDS & set(form.changed_data):
            from core.services.priority import recalculate_cluster_priorities

            count = recalculate_cluster_priorities(obj)
            self.message_user(
                request,
                f"Priorities recalculated: {count} finding(s) updated for cluster '{obj.name}'.",
            )

    @admin.action(description="Recalculate effective priorities for selected clusters")
    def recalculate_priorities(self, request, queryset):
        from core.services.priority import recalculate_cluster_priorities

        total = 0
        for cluster in queryset:
            total += recalculate_cluster_priorities(cluster)
        self.message_user(request, f"Recalculated priorities: {total} findings updated.")


@admin.register(Namespace)
class NamespaceAdmin(admin.ModelAdmin):
    list_display = [
        "cluster",
        "name",
        "active",
        "internet_exposed",
        "exposure_is_manual",
        "contains_sensitive_data",
        "sensitive_is_manual",
        "last_seen",
        "deactivated_at",
    ]
    list_filter = [
        "active",
        "cluster",
        "internet_exposed",
        "exposure_is_manual",
        "contains_sensitive_data",
    ]
    search_fields = ["name", "cluster__name"]
    readonly_fields = [
        "active",
        "first_seen", "last_seen", "deactivated_at", "labels", "annotations",
    ]

    def save_model(self, request, obj, form, change):
        # Admin edits to exposure/sensitivity flip the *_is_manual flags so
        # auto-detect doesn't stomp the admin's intent on next sync.
        if change and form.changed_data:
            if "internet_exposed" in form.changed_data:
                obj.exposure_is_manual = True
            if "contains_sensitive_data" in form.changed_data:
                obj.sensitive_is_manual = True
        super().save_model(request, obj, form, change)
        if change and set(form.changed_data) & {"internet_exposed", "contains_sensitive_data"}:
            from core.services.priority import recalculate_cluster_priorities

            count = recalculate_cluster_priorities(obj.cluster)
            self.message_user(
                request,
                f"Priorities recalculated: {count} finding(s) updated.",
            )


@admin.register(ScanStatus)
class ScanStatusAdmin(admin.ModelAdmin):
    list_display = ["cluster", "source", "last_ingest", "finding_count"]
    list_filter = ["source"]
    readonly_fields = ["cluster", "source", "last_ingest", "finding_count"]


@admin.register(RawReport)
class RawReportAdmin(admin.ModelAdmin):
    list_display = ["cluster", "kind", "source", "received_at"]
    list_filter = ["kind", "source"]
    readonly_fields = ["cluster", "kind", "source", "received_at", "raw_json"]


# ── Compliance ─────────────────────────────────────────────────


class ControlInline(admin.TabularInline):
    model = Control
    extra = 0
    fields = ["control_id", "title", "severity", "check_type", "check_ids"]
    readonly_fields = fields
    show_change_link = True


@admin.register(Framework)
class FrameworkAdmin(admin.ModelAdmin):
    list_display = ["slug", "name", "version", "total_controls", "source"]
    list_filter = ["source"]
    search_fields = ["slug", "name"]
    readonly_fields = ["total_controls"]
    inlines = [ControlInline]


@admin.register(Control)
class ControlAdmin(admin.ModelAdmin):
    list_display = [
        "control_id",
        "title_short",
        "framework",
        "severity",
        "section",
        "check_type",
    ]
    list_display_links = ["control_id", "title_short"]
    list_filter = ["framework", "severity", "check_type"]
    search_fields = ["control_id", "title", "section"]

    @admin.display(description="Title")
    def title_short(self, obj):
        return obj.title[:60] + "..." if len(obj.title) > 60 else obj.title


class ControlResultInline(admin.TabularInline):
    model = ControlResult
    extra = 0
    fields = ["control", "status", "total_pass", "total_fail"]
    readonly_fields = fields


@admin.register(Snapshot)
class SnapshotAdmin(admin.ModelAdmin):
    list_display = [
        "cluster",
        "framework",
        "scanned_at",
        "total_pass",
        "total_fail",
        "pass_rate",
    ]
    list_filter = ["framework", "cluster"]
    readonly_fields = [
        "cluster",
        "framework",
        "scanned_at",
        "total_pass",
        "total_fail",
        "total_manual",
        "pass_rate",
        "raw_json",
    ]
    date_hierarchy = "scanned_at"
    inlines = [ControlResultInline]


@admin.register(ControlResult)
class ControlResultAdmin(admin.ModelAdmin):
    list_display = ["snapshot", "control", "status", "total_pass", "total_fail"]
    list_filter = ["status", "snapshot__framework"]
    readonly_fields = [
        "snapshot",
        "control",
        "status",
        "total_pass",
        "total_fail",
        "details",
    ]


# ── SBOM ───────────────────────────────────────────────────────


@admin.register(Component)
class ComponentAdmin(admin.ModelAdmin):
    list_display = [
        "name",
        "version",
        "component_type",
        "cluster",
        "image_short",
        "get_licenses",
        "last_seen",
    ]
    list_display_links = ["name", "version"]
    list_filter = ["component_type", "cluster"]
    search_fields = ["name", "purl", "image"]
    list_per_page = 50

    @admin.display(description="Image")
    def image_short(self, obj):
        # Show last part of image ref
        parts = obj.image.rsplit("/", 1)
        return parts[-1] if parts else obj.image

    @admin.display(description="Licenses")
    def get_licenses(self, obj):
        return ", ".join(obj.licenses) if obj.licenses else ""


# ── Kyverno ────────────────────────────────────────────────────


@admin.register(PolicyComplianceSnapshot)
class PolicyComplianceSnapshotAdmin(admin.ModelAdmin):
    list_display = [
        "cluster",
        "scanned_at",
        "total_pass",
        "total_fail",
        "total_warn",
        "total_skip",
        "pass_rate",
    ]
    list_filter = ["cluster"]
    readonly_fields = [
        "cluster",
        "scanned_at",
        "total_pass",
        "total_fail",
        "total_warn",
        "total_skip",
        "pass_rate",
        "raw_json",
    ]
    date_hierarchy = "scanned_at"


# ── Ingest Queue ───────────────────────────────────────────────


@admin.register(IngestQueue)
class IngestQueueAdmin(admin.ModelAdmin):
    list_display = [
        "id",
        "cluster_name",
        "get_kind",
        "status",
        "attempts",
        "created_at",
        "processed_at",
    ]
    list_display_links = ["id", "cluster_name"]
    list_filter = ["status", "cluster_name"]
    readonly_fields = [
        "cluster_name",
        "raw_json",
        "status",
        "created_at",
        "processed_at",
        "error_message",
        "attempts",
    ]
    date_hierarchy = "created_at"
    actions = ["retry_failed"]

    @admin.display(description="Kind")
    def get_kind(self, obj):
        if isinstance(obj.raw_json, dict):
            kind = obj.raw_json.get("kind", "")
            if not kind:
                kind = obj.raw_json.get("operatorObject", {}).get("kind", "")
            return kind
        return ""

    @admin.action(description="Retry failed items (reset to pending)")
    def retry_failed(self, request, queryset):
        updated = queryset.filter(status="failed").update(
            status="pending", error_message=""
        )
        self.message_user(request, f"{updated} items reset to pending.")
