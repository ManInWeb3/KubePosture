"""Read-only DRF views for the UI.

Auth is session-based — DRF's default `IsAuthenticated` (already set
globally in settings.py REST_FRAMEWORK) keeps anonymous users out.
RBAC tightening (operator-only, admin-only) lands in B1/D1 along
with the write endpoints.

URL surface (mounted at /api/v1/):
    /clusters/             ClusterListView
    /clusters/<id>/        ClusterDetailView
    /namespaces/           NamespaceListView
    /namespaces/<id>/      NamespaceDetailView
    /workloads/            WorkloadListView
    /workloads/<id>/       WorkloadDetailView
    /findings/             FindingListView
    /findings/<id>/        FindingDetailView
    /images/               ImageListView
    /images/<digest>/      ImageDetailView      ← lookup by digest, not pk
"""
from __future__ import annotations

from rest_framework import generics, status
from rest_framework.response import Response
from rest_framework.views import APIView

from core.api.filters import (
    ClusterFilter,
    FindingFilter,
    ImageFilter,
    NamespaceFilter,
    WorkloadFilter,
)
from core.api.serializers import (
    ClusterSerializer,
    FindingSerializer,
    ImageSerializer,
    NamespaceSerializer,
    WorkloadSerializer,
)
from core.models import Cluster, Finding, Image, Namespace, Workload
from core.services.components import search_by_purls


# ── Cluster ──────────────────────────────────────────────────────


class ClusterListView(generics.ListAPIView):
    serializer_class = ClusterSerializer
    filterset_class = ClusterFilter
    ordering_fields = ["name", "environment", "last_seen_at"]
    ordering = ["name"]

    def get_queryset(self):
        return Cluster.objects.all()


class ClusterDetailView(generics.RetrieveAPIView):
    serializer_class = ClusterSerializer
    queryset = Cluster.objects.all()


# ── Namespace ────────────────────────────────────────────────────


class NamespaceListView(generics.ListAPIView):
    serializer_class = NamespaceSerializer
    filterset_class = NamespaceFilter
    ordering_fields = ["name", "last_seen_at"]
    ordering = ["cluster__name", "name"]

    def get_queryset(self):
        return Namespace.objects.select_related("cluster")


class NamespaceDetailView(generics.RetrieveAPIView):
    serializer_class = NamespaceSerializer
    queryset = Namespace.objects.select_related("cluster")


# ── Workload ─────────────────────────────────────────────────────


class WorkloadListView(generics.ListAPIView):
    serializer_class = WorkloadSerializer
    filterset_class = WorkloadFilter
    ordering_fields = ["name", "kind", "last_inventory_at", "last_seen_at"]
    ordering = ["cluster__name", "namespace__name", "kind", "name"]

    def get_queryset(self):
        return Workload.objects.select_related("cluster", "namespace")


class WorkloadDetailView(generics.RetrieveAPIView):
    serializer_class = WorkloadSerializer
    queryset = Workload.objects.select_related("cluster", "namespace")


# ── Finding ──────────────────────────────────────────────────────


class FindingListView(generics.ListAPIView):
    serializer_class = FindingSerializer
    filterset_class = FindingFilter
    ordering_fields = [
        "severity",
        "effective_priority",
        "epss_score",
        "last_seen",
        "first_seen",
    ]
    ordering = ["-last_seen"]

    def get_queryset(self):
        return Finding.objects.select_related(
            "cluster",
            "workload",
            "workload__namespace",
            "image",
        )


class FindingDetailView(generics.RetrieveAPIView):
    serializer_class = FindingSerializer

    def get_queryset(self):
        return Finding.objects.select_related(
            "cluster",
            "workload",
            "workload__namespace",
            "image",
        )


# ── Image ────────────────────────────────────────────────────────


class ImageListView(generics.ListAPIView):
    """`?cluster=NAME` scopes the `currently_deployed` annotation
    to that cluster. `?currently_deployed=true|false` filters on
    the annotation. Both filters compose with the FilterSet.
    """

    serializer_class = ImageSerializer
    filterset_class = ImageFilter
    ordering_fields = ["ref", "first_seen_at", "last_seen_at"]
    ordering = ["ref"]

    def get_queryset(self):
        cluster_name = self.request.query_params.get("cluster")
        cluster = None
        if cluster_name:
            cluster = Cluster.objects.filter(name=cluster_name).first()
        qs = Image.objects.with_currently_deployed(cluster=cluster)
        cd = self.request.query_params.get("currently_deployed")
        if cd is not None:
            wanted = cd.lower() in ("1", "true", "yes")
            qs = qs.filter(currently_deployed=wanted)
        return qs


class ImageDetailView(generics.RetrieveAPIView):
    serializer_class = ImageSerializer
    lookup_field = "digest"

    def get_queryset(self):
        cluster_name = self.request.query_params.get("cluster")
        cluster = None
        if cluster_name:
            cluster = Cluster.objects.filter(name=cluster_name).first()
        return Image.objects.with_currently_deployed(cluster=cluster)


# ── SBOM search ──────────────────────────────────────────────────


class SbomSearchView(APIView):
    """`POST /api/v1/sbom/search/` — purl-keyed component lookup.

    Body:
        {
          "purls": ["pkg:npm/lodash@4.17.21", ...],
          "purl_prefixes": ["pkg:npm/eslint-config-prettier"],
          "cluster": "prod-east"      // optional, scopes both selection and counts
        }

    Query params:
        ?include_inactive=true        // include components from
                                      // currently-undeployed images.

    Returns a flat list, one row per (cluster, workload, purl).
    """

    def post(self, request):
        body = request.data or {}
        purls = body.get("purls") or []
        prefixes = body.get("purl_prefixes") or []
        if not isinstance(purls, list) or not isinstance(prefixes, list):
            return Response(
                {"error": "purls and purl_prefixes must be arrays"},
                status=status.HTTP_400_BAD_REQUEST,
            )
        if not purls and not prefixes:
            return Response(
                {"error": "supply at least one of purls / purl_prefixes"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        cluster = None
        cluster_name = (body.get("cluster") or "").strip()
        if cluster_name:
            cluster = Cluster.objects.filter(name=cluster_name).first()
            if cluster is None:
                return Response(
                    {"error": f"cluster {cluster_name!r} not found"},
                    status=status.HTTP_404_NOT_FOUND,
                )

        include_inactive = (
            request.query_params.get("include_inactive", "").lower()
            in ("1", "true", "yes")
        )

        rows = search_by_purls(
            purls=purls,
            purl_prefixes=prefixes,
            cluster=cluster,
            include_inactive=include_inactive,
        )
        return Response({"count": len(rows), "matches": rows})
