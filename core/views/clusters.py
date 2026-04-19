"""
Clusters UI — first-class section viewable by every authenticated user.

List + detail are read-only for viewer/operator; admins see the edit form
and HTMX toggle controls for per-namespace exposure/sensitivity.

Role enforcement stays at the view level (admin-only actions return 403);
templates branch on `is_admin` to render badges vs interactive controls,
matching the pattern used for finding lifecycle actions.
"""
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.db.models import Count, Q
from django.http import HttpResponseForbidden
from django.shortcuts import get_object_or_404, redirect, render

from core.api.permissions import has_role
from core.models import Cluster, Namespace


def _is_admin(user) -> bool:
    return has_role(user, "admin")


@login_required
def cluster_list(request):
    """Read-only for everyone; admin sees a Configure button on each row."""
    clusters = Cluster.objects.prefetch_related("namespaces").annotate(
        exposed_count=Count(
            "namespaces",
            filter=Q(namespaces__active=True, namespaces__internet_exposed=True),
        ),
        namespace_count=Count("namespaces", filter=Q(namespaces__active=True)),
    ).order_by("name")
    context = {
        "clusters": clusters,
        "nav": "clusters",
        "is_admin": _is_admin(request.user),
    }
    return render(request, "clusters/list.html", context)


@login_required
def cluster_detail(request, pk):
    """Show cluster metadata + namespace table.

    Non-admins: read-only badges.
    Admins: POST updates cluster metadata, HTMX toggles per-namespace flags.
    """
    cluster = get_object_or_404(Cluster, pk=pk)
    is_admin = _is_admin(request.user)

    if request.method == "POST":
        if not is_admin:
            return HttpResponseForbidden("Admin role required")

        env = request.POST.get("environment", "").strip()
        if env not in ("prod", "staging", "dev"):
            messages.error(request, "Environment must be prod, staging, or dev.")
            return _render(request, cluster, is_admin)

        old_env = cluster.environment
        cluster.environment = env
        cluster.provider = request.POST.get("provider", "onprem").strip() or "onprem"
        cluster.region = request.POST.get("region", "").strip()

        if env != old_env:
            cluster.environment_is_manual = True
        cluster.provider_is_manual = True
        cluster.region_is_manual = True

        cluster.save(update_fields=[
            "environment", "provider", "region",
            "environment_is_manual", "provider_is_manual", "region_is_manual",
        ])

        from core.services.priority import recalculate_cluster_priorities
        updated = recalculate_cluster_priorities(cluster)
        messages.success(
            request,
            f"Cluster '{cluster.name}' updated. {updated} finding priorities recalculated.",
        )
        return redirect("cluster-detail", pk=cluster.pk)

    return _render(request, cluster, is_admin)


def _render(request, cluster, is_admin: bool):
    return render(request, "clusters/detail.html", {
        "cluster": cluster,
        "namespaces": _load_namespaces(cluster),
        "nav": "clusters",
        "is_admin": is_admin,
    })


def _load_namespaces(cluster):
    """Active first, inactive (deleted) last. Inactive rows still render
    so users can audit historical state; edit controls are disabled."""
    return cluster.namespaces.annotate(
        finding_count=Count(
            "findings",
            filter=Q(findings__status__in=["active", "acknowledged"]),
        ),
    ).order_by("-active", "name")


def _admin_required(view_func):
    @login_required
    def wrapper(request, *args, **kwargs):
        if not _is_admin(request.user):
            return HttpResponseForbidden("Admin role required")
        return view_func(request, *args, **kwargs)

    wrapper.__name__ = view_func.__name__
    wrapper.__doc__ = view_func.__doc__
    return wrapper


@_admin_required
def namespace_toggle(request, pk, ns_pk):
    """HTMX: toggle internet_exposed or contains_sensitive_data. Admin-only."""
    if request.method != "POST":
        return redirect("cluster-detail", pk=pk)

    cluster = get_object_or_404(Cluster, pk=pk)
    ns = get_object_or_404(Namespace, pk=ns_pk, cluster=cluster)
    if not ns.active:
        return HttpResponseForbidden("Namespace is inactive")

    field = request.POST.get("field")
    if field == "internet_exposed":
        ns.internet_exposed = not ns.internet_exposed
        ns.exposure_is_manual = True
        ns.save(update_fields=["internet_exposed", "exposure_is_manual"])
    elif field == "contains_sensitive_data":
        ns.contains_sensitive_data = not ns.contains_sensitive_data
        ns.sensitive_is_manual = True
        ns.save(update_fields=["contains_sensitive_data", "sensitive_is_manual"])
    else:
        return HttpResponseForbidden("Unknown field")

    from core.services.priority import recalculate_cluster_priorities
    recalculate_cluster_priorities(cluster)

    ns = _load_namespaces(cluster).get(pk=ns.pk)
    return render(request, "clusters/_namespace_row.html", {
        "cluster": cluster,
        "ns": ns,
        "is_admin": True,
    })


@_admin_required
def namespace_reset_auto(request, pk, ns_pk):
    """HTMX: clear the manual flag. Admin-only."""
    if request.method != "POST":
        return redirect("cluster-detail", pk=pk)

    cluster = get_object_or_404(Cluster, pk=pk)
    ns = get_object_or_404(Namespace, pk=ns_pk, cluster=cluster)
    if not ns.active:
        return HttpResponseForbidden("Namespace is inactive")

    field = request.POST.get("field", "exposure")
    if field == "exposure":
        ns.exposure_is_manual = False
        ns.save(update_fields=["exposure_is_manual"])
    elif field == "sensitive":
        ns.sensitive_is_manual = False
        ns.save(update_fields=["sensitive_is_manual"])

    ns = _load_namespaces(cluster).get(pk=ns.pk)
    return render(request, "clusters/_namespace_row.html", {
        "cluster": cluster,
        "ns": ns,
        "is_admin": True,
    })
