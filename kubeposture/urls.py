"""Top-level URL routing."""
from django.contrib import admin
from django.contrib.auth import views as auth_views
from django.db import connection
from django.http import JsonResponse
from django.urls import include, path


def healthz(request):
    """Liveness probe — process is up."""
    return JsonResponse({"status": "ok"})


def readyz(request):
    """Readiness probe — DB reachable."""
    try:
        connection.ensure_connection()
        return JsonResponse({"status": "ok"})
    except Exception as exc:  # pragma: no cover — DB rarely down in dev
        return JsonResponse({"status": "error", "detail": str(exc)}, status=503)


urlpatterns = [
    # Auth flow — uses the existing templates/auth/login.html
    path(
        "accounts/login/",
        auth_views.LoginView.as_view(template_name="auth/login.html"),
        name="login",
    ),
    path("accounts/logout/", auth_views.LogoutView.as_view(), name="logout"),
    path(
        "accounts/password_change/",
        auth_views.PasswordChangeView.as_view(
            template_name="auth/password_change.html",
            success_url="/profile/",
        ),
        name="password-change",
    ),

    path("admin/", admin.site.urls),
    path("api/v1/", include("core.api.urls")),
    path("healthz", healthz),
    path("readyz", readyz),

    # UI (must come last — root path lives here)
    path("", include("core.urls_ui")),
]

admin.site.site_header = "KubePostureNG Admin"
admin.site.site_title = "KubePostureNG"
admin.site.index_title = "Security Posture"
