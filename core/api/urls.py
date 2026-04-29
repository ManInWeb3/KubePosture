"""KubePostureNG API URL routing."""
from django.conf import settings
from django.urls import path

from core.api import testing_views, views, views_read, views_snapshot

urlpatterns = [
    # Ingest (bearer-token auth)
    path("imports/start/", views.imports_start),
    path("imports/finish/", views.imports_finish),
    path("ingest/", views.ingest),
    path("cluster-metadata/sync/", views.cluster_metadata_sync),

    # Read API (session auth — IsAuthenticated default)
    path("clusters/", views_read.ClusterListView.as_view(), name="cluster-list"),
    path("clusters/<int:pk>/", views_read.ClusterDetailView.as_view(), name="cluster-detail"),
    path("namespaces/", views_read.NamespaceListView.as_view(), name="namespace-list"),
    path("namespaces/<int:pk>/", views_read.NamespaceDetailView.as_view(), name="namespace-detail"),
    path("workloads/", views_read.WorkloadListView.as_view(), name="workload-list"),
    path("workloads/<int:pk>/", views_read.WorkloadDetailView.as_view(), name="workload-detail"),
    path("findings/", views_read.FindingListView.as_view(), name="finding-list"),
    path("findings/<int:pk>/", views_read.FindingDetailView.as_view(), name="finding-detail"),
    path("images/", views_read.ImageListView.as_view(), name="image-list"),
    path("images/<str:digest>/", views_read.ImageDetailView.as_view(), name="image-detail"),

    # Snapshot trends (session auth — IsAuthenticated default)
    path("snapshots/series/", views_snapshot.SnapshotSeriesView.as_view(), name="snapshot-series"),
]

# Test harness endpoints — only routed when the flag is on. The view
# itself also checks the flag, so adding the route in production is
# safe; we still suppress the route here to keep the URL surface tight.
if getattr(settings, "TESTING_HARNESS_ENABLED", False):
    urlpatterns += [
        path("testing/reset/", testing_views.reset),
        path("testing/load_scenario/", testing_views.load_scenario),
        path("testing/run_snapshot/", testing_views.run_snapshot),
        path("testing/run_enrichment/", testing_views.run_enrichment),
        path("testing/advance_clock/", testing_views.advance_clock),
        path("testing/assert_batch/", testing_views.assert_batch),
    ]
