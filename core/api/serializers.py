from rest_framework import serializers

from core.models import Finding


class FindingSerializer(serializers.ModelSerializer):
    cluster_name = serializers.CharField(source="cluster.name", read_only=True)
    # Preserve the external API shape — namespace remains a string, sourced
    # from the FK. Empty string for cluster-scoped findings (namespace=NULL).
    namespace = serializers.CharField(
        source="namespace.name", default="", read_only=True, allow_blank=True
    )

    class Meta:
        model = Finding
        fields = [
            "id",
            "origin",
            "cluster",
            "cluster_name",
            "namespace",
            "resource_kind",
            "resource_name",
            "title",
            "severity",
            "vuln_id",
            "category",
            "source",
            "status",
            "first_seen",
            "last_seen",
            "resolved_at",
            "hash_code",
            "epss_score",
            "kev_listed",
            "details",
        ]
        read_only_fields = fields
