"""django-filter FilterSet classes for the read API.

Each FilterSet declares URL params for one resource. The DRF
default backend is already wired in settings.py:

    REST_FRAMEWORK = {
        "DEFAULT_FILTER_BACKENDS": [
            "django_filters.rest_framework.DjangoFilterBackend",
        ],
        ...
    }

Filters that require computed/annotated fields (e.g. an image's
`currently_deployed` flag, which depends on the cluster scope) are
handled in the view's `get_queryset`, not here.
"""
from __future__ import annotations

import django_filters

from core.models import Cluster, Finding, Image, Namespace, Workload


class ClusterFilter(django_filters.FilterSet):
    name = django_filters.CharFilter(lookup_expr="icontains")

    class Meta:
        model = Cluster
        fields = ["name", "environment", "provider", "region"]


class NamespaceFilter(django_filters.FilterSet):
    cluster = django_filters.CharFilter(field_name="cluster__name")
    name = django_filters.CharFilter(lookup_expr="icontains")

    class Meta:
        model = Namespace
        fields = [
            "cluster",
            "name",
            "active",
            "internet_exposed",
            "contains_sensitive_data",
        ]


class WorkloadFilter(django_filters.FilterSet):
    cluster = django_filters.CharFilter(field_name="cluster__name")
    namespace = django_filters.CharFilter(field_name="namespace__name")
    name = django_filters.CharFilter(lookup_expr="icontains")

    class Meta:
        model = Workload
        fields = [
            "cluster",
            "namespace",
            "kind",
            "name",
            "deployed",
            "publicly_exposed",
        ]


class FindingFilter(django_filters.FilterSet):
    cluster = django_filters.CharFilter(field_name="cluster__name")
    workload = django_filters.CharFilter(field_name="workload__name")
    namespace = django_filters.CharFilter(field_name="workload__namespace__name")
    image = django_filters.CharFilter(field_name="image__digest")
    vuln_id = django_filters.CharFilter(lookup_expr="icontains")
    pkg_name = django_filters.CharFilter(lookup_expr="icontains")

    class Meta:
        model = Finding
        fields = [
            "cluster",
            "workload",
            "namespace",
            "image",
            "vuln_id",
            "pkg_name",
            "severity",
            "effective_priority",
            "source",
            "category",
            "kev_listed",
        ]


class ImageFilter(django_filters.FilterSet):
    """`currently_deployed` is NOT here — see ImageListView.get_queryset
    which handles the cluster-scoped annotation."""

    repository = django_filters.CharFilter(lookup_expr="icontains")
    ref = django_filters.CharFilter(lookup_expr="icontains")

    class Meta:
        model = Image
        fields = ["repository", "ref", "registry", "os_family", "os_version"]
