"""
Tabler UI views for findings — list, detail, actions, bulk actions.

Convention U1: Read + Act, not CRUD. No create/edit forms.
Convention U2: Server-side rendering + HTMX.
Convention U3: URL-driven filters — every filter state in URL.
"""
import datetime

from django.contrib.auth.decorators import login_required
from django.core.paginator import Paginator
from django.db.models import Q
from django.http import HttpResponseBadRequest, HttpResponseForbidden
from django.shortcuts import get_object_or_404, redirect, render

from core.api.permissions import has_role
from core.constants import Category, Priority, Severity, Source, Status
from core.models import Cluster, Finding, FindingHistory


@login_required
def finding_list(request):
    """Finding list with filters, search, pagination. HTMX partial support."""
    qs = Finding.objects.select_related("cluster").all()

    # Filters
    cluster = request.GET.get("cluster")
    severity = request.GET.get("severity")
    priority_filter = request.GET.get("priority")
    status_filter = request.GET.get("status")
    category = request.GET.get("category")
    kev_listed = request.GET.get("kev_listed")
    search = request.GET.get("search", "").strip()

    if cluster:
        qs = qs.filter(cluster_id=cluster)
    if severity:
        qs = qs.filter(severity=severity)
    if priority_filter:
        qs = qs.filter(effective_priority=priority_filter)
    if status_filter:
        qs = qs.filter(status=status_filter)
    if category:
        qs = qs.filter(category=category)
    if kev_listed == "true":
        qs = qs.filter(kev_listed=True)
    image_filter = request.GET.get("image", "").strip()
    if image_filter:
        qs = qs.filter(details__image=image_filter)
    if search:
        qs = qs.filter(
            Q(title__icontains=search)
            | Q(vuln_id__icontains=search)
            | Q(namespace__icontains=search)
            | Q(resource_name__icontains=search)
            | Q(details__component_name__icontains=search)
            | Q(details__image__icontains=search)
        )

    paginator = Paginator(qs, 25)
    page = request.GET.get("page", 1)
    page_obj = paginator.get_page(page)

    # Build filter querystring for pagination links (exclude 'page')
    filter_params = request.GET.copy()
    filter_params.pop("page", None)
    filter_querystring = filter_params.urlencode()

    context = {
        "findings": page_obj,
        "page_obj": page_obj,
        "nav": "findings",
        "clusters": Cluster.objects.order_by("name"),
        "severity_choices": Severity.choices,
        "priority_choices": Priority.choices,
        "status_choices": Status.choices,
        "category_choices": Category.choices,
        "filter_querystring": filter_querystring,
    }

    # HTMX partial: return just the table
    if request.headers.get("HX-Request"):
        return render(request, "findings/_table.html", context)

    return render(request, "findings/list.html", context)


@login_required
def finding_detail(request, pk):
    """Finding detail with resource context, JSONB details, audit trail."""
    finding = get_object_or_404(
        Finding.objects.select_related("cluster", "accepted_by"), pk=pk
    )
    history = FindingHistory.objects.filter(finding=finding).select_related("user")

    today = datetime.date.today()
    default_expiry = today + datetime.timedelta(days=90)

    # Compute priority reason for display
    priority_reason = ""
    if finding.cluster:
        from core.services.priority import compute_priority_reason

        priority_reason = compute_priority_reason(finding, finding.cluster)

    context = {
        "finding": finding,
        "history": history,
        "nav": "findings",
        "today": today,
        "default_expiry": default_expiry,
        "priority_reason": priority_reason,
    }
    return render(request, "findings/detail.html", context)


@login_required
def finding_acknowledge(request, pk):
    """POST: acknowledge a finding. Operator+."""
    if request.method != "POST":
        return HttpResponseBadRequest("POST required")
    if not has_role(request.user, "operator"):
        return HttpResponseForbidden("Operator role required")

    from core.services.lifecycle import LifecycleError, acknowledge

    try:
        acknowledge(pk, request.user)
    except LifecycleError:
        pass  # Already not active — just redirect back

    return redirect("findings-detail", pk=pk)


@login_required
def finding_accept_risk(request, pk):
    """POST: accept risk on a finding. Admin-only. Requires reason + until."""
    if request.method != "POST":
        return HttpResponseBadRequest("POST required")
    if not has_role(request.user, "admin"):
        return HttpResponseForbidden("Admin role required")

    reason = request.POST.get("reason", "")
    until = request.POST.get("until", "")
    if not reason or not until:
        return HttpResponseBadRequest("reason and until are required")

    from core.services.lifecycle import LifecycleError, accept_risk

    try:
        accept_risk(pk, request.user, reason, until)
    except LifecycleError:
        pass

    return redirect("findings-detail", pk=pk)


@login_required
def finding_bulk_action(request):
    """POST: bulk action on selected findings."""
    if request.method != "POST":
        return HttpResponseBadRequest("POST required")

    action = request.POST.get("action", "")
    finding_ids = request.POST.getlist("finding_ids")

    if not action or not finding_ids:
        return redirect("findings-list")

    if action == "acknowledge" and has_role(request.user, "operator"):
        updated = Finding.objects.filter(
            pk__in=finding_ids, status=Status.ACTIVE
        ).update(status=Status.ACKNOWLEDGED)
        # Create history only for findings that were actually updated
        actual_ids = Finding.objects.filter(
            pk__in=finding_ids, status=Status.ACKNOWLEDGED
        ).values_list("pk", flat=True)
        for fid in actual_ids:
            FindingHistory.objects.create(
                finding_id=fid,
                user=request.user,
                old_status=Status.ACTIVE,
                new_status=Status.ACKNOWLEDGED,
                comment="Bulk acknowledge",
            )

    elif action == "resolve" and has_role(request.user, "operator"):
        from django.utils import timezone

        Finding.objects.filter(
            pk__in=finding_ids,
            status__in=[Status.ACTIVE, Status.ACKNOWLEDGED],
        ).update(status=Status.RESOLVED, resolved_at=timezone.now())

    return redirect("findings-list")
