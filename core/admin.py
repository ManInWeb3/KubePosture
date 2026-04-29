"""Django admin registration for KubePostureNG models."""
from django.contrib import admin

from core.models import (
    Cluster,
    EpssScore,
    Finding,
    FindingAction,
    Image,
    ImportMark,
    IngestQueue,
    IngestToken,
    KevEntry,
    Namespace,
    ScanInconsistency,
    Snapshot,
    Workload,
    WorkloadAlias,
    WorkloadImageObservation,
    WorkloadSignal,
)


@admin.register(Workload)
class WorkloadAdmin(admin.ModelAdmin):
    list_display = ("name", "namespace", "kind", "cluster", "deployed", "publicly_exposed")
    list_filter = ("cluster", "kind", "deployed", "publicly_exposed")
    search_fields = ("name", "namespace__name", "cluster__name", "kind")
    list_select_related = ("cluster", "namespace")
    ordering = ("cluster", "namespace", "kind", "name")


@admin.register(WorkloadImageObservation)
class WorkloadImageObservationAdmin(admin.ModelAdmin):
    list_display = ("workload", "container_name", "image", "last_seen_at")
    list_filter = ("workload__cluster", "workload__kind")
    search_fields = (
        "workload__name",
        "workload__namespace__name",
        "workload__cluster__name",
        "container_name",
        "image__ref",
        "image__digest",
    )
    list_select_related = ("workload", "workload__cluster", "workload__namespace", "image")
    ordering = ("workload", "container_name")


@admin.register(Finding)
class FindingAdmin(admin.ModelAdmin):
    list_display = (
        "vuln_id",
        "severity",
        "effective_priority",
        "workload",
        "image",
        "cluster",
        "kev_listed",
        "last_seen",
    )
    list_filter = (
        "cluster",
        "severity",
        "effective_priority",
        "source",
        "category",
        "kev_listed",
    )
    search_fields = (
        "vuln_id",
        "pkg_name",
        "title",
        "workload__name",
        "workload__namespace__name",
        "cluster__name",
        "image__ref",
        "image__digest",
    )
    list_select_related = ("cluster", "workload", "workload__namespace", "image")
    ordering = ("-last_seen",)


@admin.register(IngestToken)
class IngestTokenAdmin(admin.ModelAdmin):
    list_display = ("name", "description", "created_at", "last_used_at", "revoked_at")
    list_filter = ("revoked_at",)
    search_fields = ("name", "description")
    readonly_fields = ("token_hash", "created_at", "last_used_at")
    ordering = ("-created_at",)


# Bulk-register the rest with default options.
for _model in (
    Cluster,
    EpssScore,
    FindingAction,
    Image,
    ImportMark,
    IngestQueue,
    KevEntry,
    Namespace,
    ScanInconsistency,
    Snapshot,
    WorkloadAlias,
    WorkloadSignal,
):
    admin.site.register(_model)
