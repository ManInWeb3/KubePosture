"""Django admin registration for KubePostureNG models."""
from django.contrib import admin
from django.db import transaction

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
from core.services.snapshot import (
    capture_cluster_snapshot,
    capture_namespace_snapshot,
)
from core.urgency import recompute_batch


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


@admin.register(Namespace)
class NamespaceAdmin(admin.ModelAdmin):
    list_display = (
        "name",
        "cluster",
        "active",
        "internet_exposed",
        "contains_sensitive_data",
    )
    list_filter = (
        "cluster",
        "active",
        "internet_exposed",
        "contains_sensitive_data",
    )
    search_fields = ("name", "cluster__name")
    list_select_related = ("cluster",)
    ordering = ("cluster", "name")

    def save_model(self, request, obj, form, change):
        # Bracket admin saves with pre/post cluster + namespace Snapshot
        # rows around a priority recompute, so flag flips land visibly
        # on the trend. Skip on initial create — no findings yet.
        if not change:
            super().save_model(request, obj, form, change)
            return

        with transaction.atomic():
            capture_cluster_snapshot(obj.cluster)
            capture_namespace_snapshot(obj)
            super().save_model(request, obj, form, change)
            recompute_batch(list(
                Finding.objects.filter(cluster=obj.cluster).only("id")
            ))
            capture_cluster_snapshot(obj.cluster)
            capture_namespace_snapshot(obj)


@admin.register(Cluster)
class ClusterAdmin(admin.ModelAdmin):
    list_display = ("name", "environment", "provider", "region", "k8s_version")
    list_filter = ("environment", "provider")
    search_fields = ("name",)
    ordering = ("name",)

    def save_model(self, request, obj, form, change):
        # Bracket admin saves with pre/post cluster-scope Snapshot rows
        # so environment / exposure edits land visibly on the trend
        # chart. Skip on initial create — no findings to count yet.
        if not change:
            super().save_model(request, obj, form, change)
            return

        with transaction.atomic():
            capture_cluster_snapshot(obj)
            super().save_model(request, obj, form, change)
            recompute_batch(list(obj.findings.all().only("id")))
            capture_cluster_snapshot(obj)


@admin.register(Snapshot)
class SnapshotAdmin(admin.ModelAdmin):
    list_display = (
        "captured_at",
        "scope_kind",
        "cluster",
        "namespace",
        "workload",
        "total_active",
        "severity_counts",
        "priority_counts",
        "change_kind",
    )
    list_filter = ("scope_kind", "cluster", "namespace", "change_kind")
    search_fields = (
        "cluster__name",
        "namespace__name",
        "workload__name",
        "import_id",
    )
    list_select_related = ("cluster", "namespace", "workload")
    ordering = ("-captured_at",)


# Bulk-register the rest with default options.
for _model in (
    EpssScore,
    FindingAction,
    Image,
    ImportMark,
    IngestQueue,
    KevEntry,
    ScanInconsistency,
    WorkloadAlias,
    WorkloadSignal,
):
    admin.site.register(_model)
