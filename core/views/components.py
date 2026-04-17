"""
Tabler UI views for SBOM components — search, detail, licenses.

Convention U1: Read-only.
Convention U3: URL-driven filters.
"""
from collections import Counter

from django.contrib.auth.decorators import login_required
from django.core.paginator import Paginator
from django.db.models import Count, Q
from django.shortcuts import render

from core.models import Cluster, Component

# Licenses considered restrictive for production use
RESTRICTIVE_LICENSES = {
    "GPL-2.0-only", "GPL-2.0-or-later", "GPL-3.0-only", "GPL-3.0-or-later",
    "AGPL-1.0-only", "AGPL-1.0-or-later", "AGPL-3.0-only", "AGPL-3.0-or-later",
    "SSPL-1.0", "EUPL-1.1", "EUPL-1.2",
}


@login_required
def components_list(request):
    """Component search with HTMX instant search + license overview."""
    search = request.GET.get("search", "").strip()
    cluster_id = request.GET.get("cluster", "")
    license_filter = request.GET.get("license", "")
    restrictive_only = request.GET.get("restrictive") == "true"

    qs = Component.objects.select_related("cluster").all()

    if search:
        qs = qs.filter(Q(name__icontains=search) | Q(purl__icontains=search))
    if cluster_id:
        qs = qs.filter(cluster_id=cluster_id)
    if license_filter:
        qs = qs.filter(licenses__contains=[license_filter])
    if restrictive_only:
        q = Q()
        for lic in RESTRICTIVE_LICENSES:
            q |= Q(licenses__contains=[lic])
        qs = qs.filter(q)

    paginator = Paginator(qs, 50)
    page_obj = paginator.get_page(request.GET.get("page", 1))

    filter_params = request.GET.copy()
    filter_params.pop("page", None)
    filter_querystring = filter_params.urlencode()

    context = {
        "components": page_obj,
        "page_obj": page_obj,
        "clusters": Cluster.objects.order_by("name"),
        "filter_querystring": filter_querystring,
        "nav": "components",
        "restrictive_licenses": RESTRICTIVE_LICENSES,
    }

    if request.headers.get("HX-Request"):
        return render(request, "components/_table.html", context)
    return render(request, "components/list.html", context)


@login_required
def component_detail(request, name):
    """Show all versions/clusters/images for a component name."""
    instances = (
        Component.objects.filter(name=name)
        .select_related("cluster")
        .order_by("version", "cluster__name")
    )

    # Group by version
    versions = {}
    for c in instances:
        versions.setdefault(c.version, []).append(c)

    # Aggregate licenses across all instances
    all_licenses = Counter()
    sample_purl = ""
    for c in instances:
        for lic in c.licenses:
            all_licenses[lic] += 1
        if not sample_purl and c.purl:
            sample_purl = c.purl

    context = {
        "component_name": name,
        "versions": versions,
        "total_instances": instances.count(),
        "cluster_count": instances.values("cluster").distinct().count(),
        "all_licenses": all_licenses.most_common(),
        "sample_purl": sample_purl,
        "restrictive_licenses": RESTRICTIVE_LICENSES,
        "nav": "components",
    }
    return render(request, "components/detail.html", context)


@login_required
def license_overview(request):
    """License distribution with restrictive license flagging."""
    # Aggregate all licenses
    license_counts = Counter()
    restrictive_counts = Counter()
    prod_restrictive = Counter()

    for comp in Component.objects.select_related("cluster").only(
        "licenses", "cluster__environment"
    ).iterator(chunk_size=5000):
        for lic in comp.licenses:
            license_counts[lic] += 1
            if lic in RESTRICTIVE_LICENSES:
                restrictive_counts[lic] += 1
                if comp.cluster.environment == "prod":
                    prod_restrictive[lic] += 1

    context = {
        "license_counts": license_counts.most_common(50),
        "restrictive_counts": restrictive_counts.most_common(),
        "prod_restrictive": prod_restrictive.most_common(),
        "total_components": Component.objects.count(),
        "nav": "components",
    }
    return render(request, "components/licenses.html", context)
