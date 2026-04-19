"""
Image views — rollup of findings by image.

Shows which container images carry the most CVEs, how many are fixable,
and links to the individual findings for each image.
"""
from django.contrib.auth.decorators import login_required
from django.db.models import Count, Max, Q
from django.shortcuts import render

from core.constants import Category, Severity, Status
from core.models import Cluster, Finding


@login_required
def image_list(request):
    """Image rollup — findings grouped by image + cluster + namespace."""
    qs = Finding.objects.filter(
        category=Category.VULNERABILITY,
        status__in=[Status.ACTIVE, Status.ACKNOWLEDGED],
    )

    # Filters
    cluster_id = request.GET.get("cluster")
    namespace = request.GET.get("namespace", "").strip()
    search = request.GET.get("search", "").strip()

    if cluster_id:
        qs = qs.filter(cluster_id=cluster_id)
    if namespace:
        qs = qs.filter(namespace__name__icontains=namespace)
    if search:
        qs = qs.filter(details__image__icontains=search)

    # Aggregate by cluster + namespace + image
    image_stats = (
        qs.values("cluster__name", "namespace__name", "details__image")
        .annotate(
            total_cves=Count("id"),
            critical=Count("id", filter=Q(severity=Severity.CRITICAL)),
            high=Count("id", filter=Q(severity=Severity.HIGH)),
            fixable=Count(
                "id",
                filter=~Q(details__fixed_version="") & Q(details__fixed_version__isnull=False),
            ),
            kev_count=Count("id", filter=Q(kev_listed=True)),
            max_epss=Max("epss_score"),
        )
        .order_by("-total_cves")
    )

    # Filter out entries with no image, add short name
    image_stats = [s for s in image_stats if s["details__image"]]
    for stat in image_stats:
        stat["image"] = stat["details__image"]
        stat["short_image"] = _short_image(stat["details__image"])
        # Keep the old key name for template compatibility
        stat["namespace"] = stat.pop("namespace__name") or ""

    # Collect unique namespaces for filter dropdown
    namespaces = sorted(set(s["namespace"] for s in image_stats if s["namespace"]))

    context = {
        "image_stats": image_stats,
        "clusters": Cluster.objects.order_by("name"),
        "namespaces": namespaces,
        "total_images": len(image_stats),
        "nav": "images",
    }
    return render(request, "images/list.html", context)


@login_required
def image_detail(request, image_ref):
    """Detail view for one image — all CVEs in that image."""
    findings = Finding.objects.filter(
        category=Category.VULNERABILITY,
        status__in=[Status.ACTIVE, Status.ACKNOWLEDGED],
        details__image=image_ref,
    ).select_related("cluster").order_by("-severity", "-epss_score")

    stats = findings.aggregate(
        total=Count("pk"),
        critical=Count("pk", filter=Q(severity=Severity.CRITICAL)),
        high=Count("pk", filter=Q(severity=Severity.HIGH)),
        fixable=Count(
            "pk",
            filter=~Q(details__fixed_version="") & Q(details__fixed_version__isnull=False),
        ),
    )

    context = {
        "image_ref": image_ref,
        "short_image": _short_image(image_ref),
        "findings": findings[:200],
        "total": stats["total"],
        "critical": stats["critical"],
        "high": stats["high"],
        "fixable": stats["fixable"],
        "nav": "images",
    }
    return render(request, "images/detail.html", context)


def _short_image(ref):
    """Shorten image ref for display: drop registry prefix, keep repo:tag."""
    parts = ref.rsplit("/", 1)
    return parts[-1] if parts else ref
