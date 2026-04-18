"""
Settings views — admin-only tabbed page for Users, Clusters, and Base Images.

The Settings page combines user management, cluster exposure configuration
(for effective priority), and base image catalog under one nav item with tabs.
"""
import json

from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.http import HttpResponseBadRequest, HttpResponseForbidden
from django.shortcuts import get_object_or_404, redirect, render

from core.api.permissions import has_role
from core.models import Cluster


def admin_required(view_func):
    """Decorator: login + admin role required."""

    @login_required
    def wrapper(request, *args, **kwargs):
        if not has_role(request.user, "admin"):
            return HttpResponseForbidden("Admin role required")
        return view_func(request, *args, **kwargs)

    wrapper.__name__ = view_func.__name__
    wrapper.__doc__ = view_func.__doc__
    return wrapper


@admin_required
def cluster_list(request):
    """Cluster list with exposure flags — embedded in settings page."""
    clusters = Cluster.objects.order_by("name")
    context = {
        "clusters": clusters,
        "nav": "settings",
        "settings_tab": "clusters",
    }
    # HTMX partial: return just the cluster table
    if request.headers.get("HX-Request"):
        return render(request, "settings/_clusters.html", context)
    return render(request, "settings/index.html", context)


@admin_required
def cluster_edit(request, pk):
    """Edit cluster exposure flags and namespace overrides."""
    cluster = get_object_or_404(Cluster, pk=pk)

    if request.method == "POST":
        cluster.internet_exposed = request.POST.get("internet_exposed") == "on"
        cluster.contains_sensitive_data = request.POST.get("contains_sensitive_data") == "on"
        env = request.POST.get("environment", "").strip()
        if env not in ("prod", "staging", "dev"):
            messages.error(request, "Environment must be prod, staging, or dev.")
            return _render_cluster_form(request, cluster)
        cluster.environment = env
        cluster.provider = request.POST.get("provider", "unknown").strip() or "unknown"
        cluster.region = request.POST.get("region", "").strip()

        # Parse namespace overrides JSON
        overrides_raw = request.POST.get("namespace_overrides", "").strip()
        if overrides_raw:
            try:
                overrides = json.loads(overrides_raw)
                if not isinstance(overrides, dict):
                    messages.error(request, "Namespace overrides must be a JSON object.")
                    return _render_cluster_form(request, cluster)
                cluster.namespace_overrides = overrides
            except json.JSONDecodeError as e:
                messages.error(request, f"Invalid JSON in namespace overrides: {e}")
                return _render_cluster_form(request, cluster)
        else:
            cluster.namespace_overrides = {}

        cluster.save(update_fields=[
            "internet_exposed", "contains_sensitive_data", "namespace_overrides",
            "environment", "provider", "region",
        ])

        # Recalculate priorities for this cluster
        from core.services.priority import recalculate_cluster_priorities

        updated = recalculate_cluster_priorities(cluster)
        messages.success(
            request,
            f"Cluster '{cluster.name}' updated. {updated} finding priorities recalculated.",
        )
        return redirect("settings-clusters")

    return _render_cluster_form(request, cluster)


def _render_cluster_form(request, cluster):
    overrides_json = json.dumps(cluster.namespace_overrides, indent=2) if cluster.namespace_overrides else ""
    context = {
        "cluster": cluster,
        "overrides_json": overrides_json,
        "nav": "settings",
        "settings_tab": "clusters",
    }
    return render(request, "settings/cluster_edit.html", context)
