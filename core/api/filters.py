import django_filters

from core.models import Finding


class FindingFilter(django_filters.FilterSet):
    vuln_id = django_filters.CharFilter(lookup_expr="icontains")
    namespace = django_filters.CharFilter(lookup_expr="icontains")
    cluster_name = django_filters.CharFilter(
        field_name="cluster__name", lookup_expr="exact"
    )

    class Meta:
        model = Finding
        fields = [
            "cluster",
            "cluster_name",
            "severity",
            "status",
            "source",
            "category",
            "vuln_id",
            "namespace",
            "kev_listed",
            "origin",
        ]
