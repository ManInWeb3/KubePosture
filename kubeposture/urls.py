from django.contrib import admin
from django.db import connection
from django.http import JsonResponse
from django.urls import include, path


def healthz(request):
    """Liveness/readiness probe for K8s."""
    try:
        connection.ensure_connection()
        return JsonResponse({"status": "ok"})
    except Exception as e:
        return JsonResponse({"status": "error", "detail": str(e)}, status=503)


urlpatterns = [
    path("admin/", admin.site.urls),
    path("api/v1/", include("core.api.urls")),
    path("healthz/", healthz),
    path("accounts/", include("core.views.auth_urls")),
    path("", include("core.views.urls")),
]

# Admin site customization
admin.site.site_header = "KubePosture Admin"
admin.site.site_title = "KubePosture"
admin.site.index_title = "Security Platform"
