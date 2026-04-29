"""DRF serializers for the read API.

All serializers are read-only — POST/PATCH endpoints land in B1
(FindingAction CRUD) and D1 (settings overrides). For now we just
project model rows to JSON for the UI to consume.

Patterns used here:
  - Flatten FK names to top-level strings for the common case
    (e.g., `cluster_name` instead of nested `{cluster: {id, name}}`)
    so callers don't need a join. Detail responses can still expose
    related objects when useful.
  - `currently_deployed` on ImageSerializer comes from the
    `Image.objects.with_currently_deployed()` annotation. Views must
    apply that annotation to their queryset; otherwise the field
    is None.
"""
from __future__ import annotations

from rest_framework import serializers

from core.models import (
    Cluster,
    Finding,
    Image,
    Namespace,
    Workload,
)


# ── Cluster ──────────────────────────────────────────────────────


class ClusterSerializer(serializers.ModelSerializer):
    class Meta:
        model = Cluster
        fields = [
            "id",
            "name",
            "environment",
            "environment_is_manual",
            "provider",
            "provider_is_manual",
            "region",
            "region_is_manual",
            "k8s_version",
            "consecutive_incomplete_inventories",
            "last_complete_inventory_at",
            "created_at",
            "last_seen_at",
        ]
        read_only_fields = fields


# ── Namespace ────────────────────────────────────────────────────


class NamespaceSerializer(serializers.ModelSerializer):
    cluster_name = serializers.CharField(source="cluster.name", read_only=True)

    class Meta:
        model = Namespace
        fields = [
            "id",
            "cluster",
            "cluster_name",
            "name",
            "labels",
            "annotations",
            "internet_exposed",
            "exposure_is_manual",
            "contains_sensitive_data",
            "sensitive_is_manual",
            "active",
            "deactivated_at",
            "first_seen_at",
            "last_seen_at",
        ]
        read_only_fields = fields


# ── Workload ─────────────────────────────────────────────────────


class WorkloadSerializer(serializers.ModelSerializer):
    cluster_name = serializers.CharField(source="cluster.name", read_only=True)
    namespace_name = serializers.CharField(source="namespace.name", read_only=True)

    class Meta:
        model = Workload
        fields = [
            "id",
            "cluster",
            "cluster_name",
            "namespace",
            "namespace_name",
            "kind",
            "name",
            "service_account",
            "replicas",
            "labels",
            "publicly_exposed",
            "publicly_exposed_is_manual",
            "deployed",
            "last_inventory_at",
            "first_seen_at",
            "last_seen_at",
        ]
        read_only_fields = fields


# ── Image ────────────────────────────────────────────────────────


class ImageSerializer(serializers.ModelSerializer):
    """`currently_deployed` is sourced from the queryset annotation
    added by `Image.objects.with_currently_deployed(cluster=...)`.
    Views that don't apply the annotation will return None for this
    field — that's a programmer error, not a runtime one.
    """

    currently_deployed = serializers.BooleanField(read_only=True, default=None)

    class Meta:
        model = Image
        fields = [
            "id",
            "digest",
            "ref",
            "registry",
            "repository",
            "os_family",
            "os_version",
            "base_eosl",
            "currently_deployed",
            "first_seen_at",
            "last_seen_at",
        ]
        read_only_fields = fields


# ── Finding ──────────────────────────────────────────────────────


class FindingSerializer(serializers.ModelSerializer):
    cluster_name = serializers.CharField(source="cluster.name", read_only=True)
    workload_name = serializers.CharField(
        source="workload.name", read_only=True, allow_null=True
    )
    workload_namespace = serializers.CharField(
        source="workload.namespace.name", read_only=True, allow_null=True
    )
    workload_kind = serializers.CharField(
        source="workload.kind", read_only=True, allow_null=True
    )
    image_digest = serializers.CharField(
        source="image.digest", read_only=True, allow_null=True
    )
    image_ref = serializers.CharField(
        source="image.ref", read_only=True, allow_null=True
    )

    class Meta:
        model = Finding
        fields = [
            "id",
            "cluster",
            "cluster_name",
            "workload",
            "workload_name",
            "workload_namespace",
            "workload_kind",
            "image",
            "image_digest",
            "image_ref",
            "source",
            "category",
            "vuln_id",
            "pkg_name",
            "installed_version",
            "fixed_version",
            "title",
            "severity",
            "cvss_score",
            "effective_priority",
            "epss_score",
            "epss_percentile",
            "kev_listed",
            "first_seen",
            "last_seen",
            "details",
        ]
        read_only_fields = fields
