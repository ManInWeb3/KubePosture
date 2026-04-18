"""
Tabler UI views for compliance — tabbed overview (Trivy / Kyverno), matrix.

Convention U1: Read-only. No create/edit forms.
Convention U3: URL-driven filters.
"""
from django.contrib.auth.decorators import login_required
from django.db.models import Max
from django.shortcuts import get_object_or_404, render

from core.models import Cluster
from core.models.compliance import (
    Framework,
    Snapshot,
)
from core.models.kyverno import PolicyComplianceSnapshot


@login_required
def compliance_overview(request):
    """Trivy compliance tab — framework cards with pass rates."""
    frameworks = Framework.objects.all()

    # Batch-fetch latest snapshot IDs per framework+cluster (single query)
    latest_ids = (
        Snapshot.objects.values("framework", "cluster")
        .annotate(latest_id=Max("id"))
        .values_list("latest_id", flat=True)
    )
    # Fetch all latest snapshots in one query
    all_snapshots = (
        Snapshot.objects.filter(id__in=latest_ids)
        .select_related("cluster", "framework")
    )
    # Group by framework
    snapshots_by_fw = {}
    for snap in all_snapshots:
        snapshots_by_fw.setdefault(snap.framework_id, []).append(snap)

    cards = []
    for fw in frameworks:
        snapshots = snapshots_by_fw.get(fw.pk, [])

        if snapshots:
            total_p = sum(s.total_pass for s in snapshots)
            total_f = sum(s.total_fail for s in snapshots)
            total = total_p + total_f
            avg_rate = round(total_p / total * 100, 1) if total else 0
        else:
            avg_rate = 0

        cards.append({
            "framework": fw,
            "snapshots": snapshots,
            "avg_pass_rate": avg_rate,
            "cluster_count": len(snapshots),
        })

    has_kyverno = PolicyComplianceSnapshot.objects.exists()

    context = {
        "cards": cards,
        "has_kyverno": has_kyverno,
        "compliance_tab": "trivy",
        "nav": "compliance",
    }
    return render(request, "compliance/overview.html", context)


@login_required
def kyverno_overview(request):
    """Kyverno compliance tab — all policy results as a table with filters."""
    status_filter = request.GET.get("result", "")
    cluster_ids = request.GET.getlist("clusters")

    # Get latest scan time per cluster
    latest_times = dict(
        PolicyComplianceSnapshot.objects.values("cluster")
        .annotate(latest=Max("scanned_at"))
        .values_list("cluster", "latest")
    )

    # All clusters with Kyverno data (for filter)
    all_cluster_ids = list(latest_times.keys())
    all_clusters = Cluster.objects.filter(pk__in=all_cluster_ids).order_by("name")

    # Filter clusters if selected
    cluster_ids = [c for c in cluster_ids if c]  # filter out empty strings
    if cluster_ids:
        selected_ids = [int(c) for c in cluster_ids]
        active_clusters = {cid: t for cid, t in latest_times.items() if cid in selected_ids}
    else:
        selected_ids = []
        active_clusters = latest_times

    # Collect all results from same-day snapshots for each cluster
    all_results = []
    for cluster_id, latest_time in active_clusters.items():
        day_start = latest_time.replace(hour=0, minute=0, second=0, microsecond=0)
        snapshots = PolicyComplianceSnapshot.objects.filter(
            cluster_id=cluster_id,
            scanned_at__gte=day_start,
        ).select_related("cluster")

        for snap in snapshots:
            for r in snap.raw_json.get("results", []):
                all_results.append({
                    **r,
                    "cluster_name": snap.cluster.name,
                    "cluster_id": cluster_id,
                })

    # Count totals before filtering (for badge counts)
    total_pass = sum(1 for r in all_results if r.get("result") == "pass")
    total_fail = sum(1 for r in all_results if r.get("result") in ("fail", "error"))
    total_warn = sum(1 for r in all_results if r.get("result") == "warn")

    # Apply status filter
    if status_filter:
        if status_filter == "fail":
            all_results = [r for r in all_results if r.get("result") in ("fail", "error")]
        else:
            all_results = [r for r in all_results if r.get("result") == status_filter]

    # Sort: fail first, then warn, then pass
    result_order = {"fail": 0, "error": 0, "warn": 1, "skip": 2, "pass": 3}
    all_results.sort(key=lambda r: (
        result_order.get(r.get("result", ""), 9),
        r.get("cluster_name", ""),
        r.get("policy", ""),
    ))

    has_trivy = Framework.objects.exists()

    context = {
        "results": all_results,
        "total_pass": total_pass,
        "total_fail": total_fail,
        "total_warn": total_warn,
        "total_results": len(all_results),
        "all_clusters": all_clusters,
        "selected_cluster_ids": selected_ids,
        "status_filter": status_filter,
        "has_trivy": has_trivy,
        "compliance_tab": "kyverno",
        "nav": "compliance",
    }
    return render(request, "compliance/kyverno.html", context)


@login_required
def compliance_matrix(request, slug):
    """Compliance matrix: controls (rows) x clusters (columns), PASS/FAIL color-coded."""
    framework = get_object_or_404(Framework, slug=slug)
    section_filter = request.GET.get("section", "")
    cluster_ids = request.GET.getlist("clusters")

    snap_qs = Snapshot.objects.filter(framework=framework)
    if cluster_ids:
        snap_qs = snap_qs.filter(cluster_id__in=cluster_ids)

    latest_ids = (
        snap_qs.values("cluster")
        .annotate(latest_id=Max("id"))
        .values_list("latest_id", flat=True)
    )
    snapshots = (
        Snapshot.objects.filter(id__in=latest_ids)
        .select_related("cluster")
        .order_by("cluster__name")
    )

    clusters = [s.cluster for s in snapshots]
    snapshot_by_cluster = {s.cluster_id: s for s in snapshots}

    all_cluster_ids = (
        Snapshot.objects.filter(framework=framework)
        .values_list("cluster_id", flat=True)
        .distinct()
    )
    all_clusters = Cluster.objects.filter(id__in=all_cluster_ids).order_by("name")

    controls = framework.controls.all()
    if section_filter:
        controls = controls.filter(section__startswith=section_filter)

    sections = (
        framework.controls.values_list("section", flat=True)
        .distinct()
        .order_by("section")
    )

    results_map = {}
    for snap in snapshots:
        for cr in snap.results.select_related("control").all():
            results_map.setdefault(cr.control_id, {})[snap.cluster_id] = cr

    matrix_rows = []
    for ctrl in controls:
        row = {"control": ctrl, "cells": []}
        for cluster in clusters:
            cr = results_map.get(ctrl.pk, {}).get(cluster.pk)
            row["cells"].append({
                "cluster": cluster,
                "result": cr,
                "status": cr.status if cr else "MISSING",
            })
        matrix_rows.append(row)

    context = {
        "framework": framework,
        "clusters": clusters,
        "all_clusters": all_clusters,
        "selected_cluster_ids": [int(c) for c in cluster_ids] if cluster_ids else [],
        "matrix_rows": matrix_rows,
        "snapshots": snapshot_by_cluster,
        "sections": sections,
        "section_filter": section_filter,
        "nav": "compliance",
    }
    return render(request, "compliance/matrix.html", context)
