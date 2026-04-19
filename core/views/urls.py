from django.urls import path

from core.views.clusters import (
    cluster_detail,
    cluster_list,
    namespace_reset_auto,
    namespace_toggle,
)
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
from core.views.tokens import token_create, token_delete, token_list, token_regenerate
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
    # Clusters — read-only for viewer/operator, edit for admin
    path("clusters/", cluster_list, name="cluster-list"),
    path("clusters/<int:pk>/", cluster_detail, name="cluster-detail"),
    path(
        "clusters/<int:pk>/namespaces/<int:ns_pk>/toggle/",
        namespace_toggle,
        name="namespace-toggle",
    ),
    path(
        "clusters/<int:pk>/namespaces/<int:ns_pk>/reset/",
        namespace_reset_auto,
        name="namespace-reset-auto",
    ),
    # Access — admin-only (Users + Tokens)
    path("settings/users/", user_list, name="user-list"),
    path("settings/users/new/", user_create, name="user-create"),
    path("settings/users/<int:pk>/edit/", user_edit, name="user-edit"),
    path("settings/users/<int:pk>/toggle-active/", user_toggle_active, name="user-toggle-active"),
    path("settings/tokens/", token_list, name="token-list"),
    path("settings/tokens/create/", token_create, name="token-create"),
    path("settings/tokens/<str:username>/regenerate/", token_regenerate, name="token-regenerate"),
    path("settings/tokens/<str:username>/delete/", token_delete, name="token-delete"),
]
