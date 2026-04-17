from django.urls import path

from core.api.views import (
    AcceptRiskView,
    AcknowledgeView,
    FalsePositiveView,
    FindingDetailView,
    FindingListView,
    IngestView,
    ReactivateView,
)

urlpatterns = [
    path("ingest/", IngestView.as_view(), name="ingest"),
    path("findings/", FindingListView.as_view(), name="finding-list"),
    path("findings/<int:pk>/", FindingDetailView.as_view(), name="finding-detail"),
    # Lifecycle actions (Convention A2: explicit endpoints, not generic PATCH)
    path("findings/<int:pk>/acknowledge/", AcknowledgeView.as_view(), name="finding-acknowledge"),
    path("findings/<int:pk>/accept-risk/", AcceptRiskView.as_view(), name="finding-accept-risk"),
    path("findings/<int:pk>/false-positive/", FalsePositiveView.as_view(), name="finding-false-positive"),
    path("findings/<int:pk>/reactivate/", ReactivateView.as_view(), name="finding-reactivate"),
]
