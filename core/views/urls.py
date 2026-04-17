from django.urls import path

from core.views.compliance import compliance_matrix, compliance_overview, kyverno_overview
from core.views.components import component_detail, components_list, license_overview
from core.views.findings import (
    finding_accept_risk,
    finding_acknowledge,
    finding_bulk_action,
    finding_detail,
    finding_list,
)
from core.views.dashboard import dashboard
from core.views.images import image_detail, image_list
from core.views.settings import cluster_edit, cluster_list
from core.views.users import user_create, user_edit, user_list, user_toggle_active

urlpatterns = [
    path("", dashboard, name="dashboard"),
    # Findings
    path("findings/", finding_list, name="findings-list"),
    path("findings/<int:pk>/", finding_detail, name="findings-detail"),
    path("findings/<int:pk>/acknowledge/", finding_acknowledge, name="findings-acknowledge"),
    path("findings/<int:pk>/accept-risk/", finding_accept_risk, name="findings-accept-risk"),
    path("findings/bulk/", finding_bulk_action, name="findings-bulk-action"),
    # Compliance
    path("compliance/", compliance_overview, name="compliance-overview"),
    path("compliance/kyverno/", kyverno_overview, name="kyverno-overview"),
    path("compliance/<str:slug>/", compliance_matrix, name="compliance-matrix"),
    # Images — CVE rollup per image
    path("images/", image_list, name="image-list"),
    path("images/detail/<path:image_ref>", image_detail, name="image-detail"),
    # Components + SBOM
    path("components/", components_list, name="components-list"),
    path("components/licenses/", license_overview, name="license-overview"),
    path("components/<path:name>/", component_detail, name="component-detail"),
    # Settings — admin-only (Users + Clusters + Base Images tabs)
    path("settings/users/", user_list, name="user-list"),
    path("settings/users/new/", user_create, name="user-create"),
    path("settings/users/<int:pk>/edit/", user_edit, name="user-edit"),
    path("settings/users/<int:pk>/toggle-active/", user_toggle_active, name="user-toggle-active"),
    path("settings/clusters/", cluster_list, name="settings-clusters"),
    path("settings/clusters/<int:pk>/", cluster_edit, name="settings-cluster-edit"),
]
