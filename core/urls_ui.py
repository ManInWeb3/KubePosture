"""UI URL routing.

`/` redirects to `/workloads/` — the Workloads list is the primary
landing per [Architecture/dev_docs/08-ui.md §1](Architecture/dev_docs/08-ui.md#L100).
A dashboard takes the root slot in a later slice.

Workload detail lives at `/workloads/<kind>/<name>/`, multi-cluster-
aggregating with optional `?cluster=<name>` narrowing.

Placeholders fill in for nav items not yet wired in this slice — they
keep `{% url %}` resolutions valid in `templates/base.html`.
"""
from __future__ import annotations

from django.urls import path

from core.views_ui import (
    ClusterDetailView,
    ClusterListView,
    FindingDetailPanelView,
    NamespaceResetAutoView,
    NamespaceToggleView,
    ProfileView,
    RootRedirectView,
    WorkloadDetailView,
    WorkloadsListView,
    make_placeholder,
)

urlpatterns = [
    path("", RootRedirectView.as_view(), name="root"),
    path("workloads/", WorkloadsListView.as_view(), name="workloads-list"),
    path(
        "workloads/<str:kind>/<str:name>/",
        WorkloadDetailView.as_view(),
        name="workloads-detail",
    ),

    # Placeholders for nav targets that other slices will fill in.
    path("findings/", make_placeholder("Findings", nav="findings").as_view(), name="findings-list"),
    path("findings/<int:pk>/", make_placeholder("Finding detail").as_view(), name="findings-detail"),
    path(
        "findings/<int:pk>/panel/",
        FindingDetailPanelView.as_view(),
        name="findings-detail-panel",
    ),
    path("clusters/", ClusterListView.as_view(), name="cluster-list"),
    path("clusters/<int:pk>/", ClusterDetailView.as_view(), name="cluster-detail"),
    path(
        "clusters/<int:cluster_pk>/namespaces/<int:ns_pk>/toggle/",
        NamespaceToggleView.as_view(),
        name="namespace-toggle",
    ),
    path(
        "clusters/<int:cluster_pk>/namespaces/<int:ns_pk>/reset-auto/",
        NamespaceResetAutoView.as_view(),
        name="namespace-reset-auto",
    ),
    path("profile/", ProfileView.as_view(), name="profile"),
]
