"""UI URL routing.

`/` redirects to `/workloads/` — the Workloads list is the primary
landing per [Architecture/dev_docs/08-ui.md §1](Architecture/dev_docs/08-ui.md#L100).
A dashboard takes the root slot in a later slice.

Workload detail lives at `/workloads/<kind>/<name>/`, multi-cluster-
aggregating with optional `?cluster=<name>` narrowing.
"""
from __future__ import annotations

from django.urls import path

from core.views_ui import (
    ClusterDetailView,
    ClusterListView,
    ClusterReimportView,
    FindingDetailPanelView,
    FindingsListView,
    NamespaceResetAutoView,
    NamespaceToggleView,
    ProfileView,
    RootRedirectView,
    TokenCreateView,
    TokenDeleteView,
    TokenListView,
    TokenRegenerateView,
    UserCreateView,
    UserEditView,
    UserListView,
    UserToggleActiveView,
    WorkloadDetailView,
    WorkloadsListView,
)

urlpatterns = [
    path("", RootRedirectView.as_view(), name="root"),
    path("workloads/", WorkloadsListView.as_view(), name="workloads-list"),
    path(
        "workloads/<str:kind>/<str:name>/",
        WorkloadDetailView.as_view(),
        name="workloads-detail",
    ),

    path("findings/", FindingsListView.as_view(), name="findings-list"),
    path(
        "findings/<int:pk>/panel/",
        FindingDetailPanelView.as_view(),
        name="findings-detail-panel",
    ),
    path("clusters/", ClusterListView.as_view(), name="cluster-list"),
    path("clusters/<int:pk>/", ClusterDetailView.as_view(), name="cluster-detail"),
    path(
        "clusters/<int:pk>/re-import/",
        ClusterReimportView.as_view(),
        name="cluster-reimport",
    ),
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

    # Access (admin-only) — users + ingest tokens.
    path("access/users/", UserListView.as_view(), name="user-list"),
    path("access/users/new/", UserCreateView.as_view(), name="user-create"),
    path("access/users/<int:pk>/edit/", UserEditView.as_view(), name="user-edit"),
    path(
        "access/users/<int:pk>/toggle-active/",
        UserToggleActiveView.as_view(),
        name="user-toggle-active",
    ),
    path("access/tokens/", TokenListView.as_view(), name="token-list"),
    path("access/tokens/create/", TokenCreateView.as_view(), name="token-create"),
    path(
        "access/tokens/<int:pk>/regenerate/",
        TokenRegenerateView.as_view(),
        name="token-regenerate",
    ),
    path(
        "access/tokens/<int:pk>/delete/",
        TokenDeleteView.as_view(),
        name="token-delete",
    ),
]
