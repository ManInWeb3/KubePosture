"""
Security dashboard — landing page with at-a-glance posture overview.

Convention U5: One good dashboard, not a configurable one.
Everyone sees the same view. No widget builder.
"""
import datetime

from django.contrib.auth.decorators import login_required
from django.db.models import Count, Max, Q
from django.shortcuts import render
from django.utils import timezone

from core.constants import Priority, Severity, Status
from core.models import Cluster, Finding, ScanStatus
from core.models.compliance import Framework, Snapshot
from core.models.kyverno import PolicyComplianceSnapshot


@login_required
def dashboard(request):
    now = timezone.now()
    week_ago = now - datetime.timedelta(days=7)
    thirty_days = now.date() + datetime.timedelta(days=30)

    # ── Active findings by severity (with week-over-week delta) ──
    severity_cards = []
    for sev_value, sev_label in Severity.choices:
        current = Finding.objects.filter(severity=sev_value, status=Status.ACTIVE).count()
        week_ago_new = Finding.objects.filter(
            severity=sev_value, status=Status.ACTIVE, first_seen__gte=week_ago
        ).count()
        severity_cards.append({
            "severity": sev_value,
            "label": sev_label,
            "count": current,
            "new_this_week": week_ago_new,
        })

    # ── KEV findings ──
    kev_count = Finding.objects.filter(kev_listed=True, status=Status.ACTIVE).count()

    # ── High risk: KEV or (Critical + EPSS > 0.1) ──
    high_risk_count = Finding.objects.filter(
        Q(kev_listed=True) | Q(severity=Severity.CRITICAL, epss_score__gt=0.1),
        status=Status.ACTIVE,
    ).count()

    # ── Effective priority counts ──
    immediate_count = Finding.objects.filter(
        effective_priority=Priority.IMMEDIATE, status=Status.ACTIVE
    ).count()
    needs_attention_count = Finding.objects.filter(
        effective_priority__in=[Priority.IMMEDIATE, Priority.OUT_OF_CYCLE],
        status=Status.ACTIVE,
    ).count()

    # ── Top CVEs by EPSS ──
    top_epss = (
        Finding.objects.filter(epss_score__isnull=False, status=Status.ACTIVE)
        .order_by("-epss_score")[:5]
    )

    # ── Risk acceptances expiring within 30 days ──
    expiring_acceptances = Finding.objects.filter(
        status=Status.RISK_ACCEPTED,
        accepted_until__lte=thirty_days,
    ).order_by("accepted_until")[:10]

    # ── Compliance pass rates (latest per framework) — batch query ──
    latest_snap_ids = (
        Snapshot.objects.values("framework", "cluster")
        .annotate(latest_id=Max("id"))
        .values_list("latest_id", flat=True)
    )
    all_snaps = (
        Snapshot.objects.filter(id__in=latest_snap_ids)
        .select_related("cluster", "framework")
    )
    snaps_by_fw = {}
    for s in all_snaps:
        snaps_by_fw.setdefault(s.framework_id, []).append(s)

    compliance_cards = []
    for fw in Framework.objects.all():
        snaps = snaps_by_fw.get(fw.pk, [])
        if snaps:
            total_p = sum(s.total_pass for s in snaps)
            total_f = sum(s.total_fail for s in snaps)
            total = total_p + total_f
            avg_rate = round(total_p / total * 100, 1) if total else 0
            compliance_cards.append({
                "framework": fw,
                "pass_rate": avg_rate,
                "cluster_count": len(snaps),
            })

    # ── Kyverno compliance (latest per cluster) ──
    kyverno_latest = (
        PolicyComplianceSnapshot.objects.values("cluster")
        .annotate(latest_id=Max("id"))
        .values_list("latest_id", flat=True)
    )
    kyverno_snaps = PolicyComplianceSnapshot.objects.filter(
        id__in=kyverno_latest
    ).select_related("cluster")

    # ── Scan health matrix ──
    scan_statuses = ScanStatus.objects.select_related("cluster").order_by("cluster__name")
    stale_threshold = now - datetime.timedelta(hours=24)

    # ── Totals ──
    total_findings = Finding.objects.filter(status=Status.ACTIVE).count()
    total_resolved_week = Finding.objects.filter(resolved_at__gte=week_ago).count()
    cluster_count = Cluster.objects.count()

    context = {
        "nav": "dashboard",
        "severity_cards": severity_cards,
        "kev_count": kev_count,
        "high_risk_count": high_risk_count,
        "immediate_count": immediate_count,
        "needs_attention_count": needs_attention_count,
        "top_epss": top_epss,
        "expiring_acceptances": expiring_acceptances,
        "compliance_cards": compliance_cards,
        "kyverno_snaps": kyverno_snaps,
        "scan_statuses": scan_statuses,
        "stale_threshold": stale_threshold,
        "total_findings": total_findings,
        "total_resolved_week": total_resolved_week,
        "cluster_count": cluster_count,
    }
    return render(request, "dashboard/index.html", context)
