"""
Tabler UI views for findings — list, detail, actions, bulk actions.

Convention U1: Read + Act, not CRUD. No create/edit forms.
Convention U2: Server-side rendering + HTMX.
Convention U3: URL-driven filters — every filter state in URL.
"""
import datetime

from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.core.paginator import Paginator
from django.db import transaction
from django.db.models import Q
from django.http import HttpResponseBadRequest, HttpResponseForbidden
from django.shortcuts import get_object_or_404, redirect, render
from django.utils import timezone

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

    try:
        until_date = datetime.date.fromisoformat(until)
    except ValueError:
        return HttpResponseBadRequest("until must be a valid date (YYYY-MM-DD)")
    if until_date <= datetime.date.today():
        return HttpResponseBadRequest("until must be in the future")

    from core.services.lifecycle import LifecycleError, accept_risk

    try:
        accept_risk(pk, request.user, reason, until_date)
    except LifecycleError:
        pass

    return redirect("findings-detail", pk=pk)


BULK_ACTIONS = {
    "acknowledge": {
        "from_statuses": [Status.ACTIVE],
        "to_status": Status.ACKNOWLEDGED,
        "comment": "Bulk acknowledge",
    },
    "resolve": {
        "from_statuses": [Status.ACTIVE, Status.ACKNOWLEDGED],
        "to_status": Status.RESOLVED,
        "comment": "Bulk resolve",
    },
}


@login_required
def finding_bulk_action(request):
    """POST: bulk action on selected findings. Operator+."""
    if request.method != "POST":
        return HttpResponseBadRequest("POST required")
    if not has_role(request.user, "operator"):
        return HttpResponseForbidden("Operator role required")

    action = request.POST.get("action", "")
    finding_ids = request.POST.getlist("finding_ids")

    if not action or not finding_ids:
        return redirect("findings-list")

    cfg = BULK_ACTIONS.get(action)
    if cfg is None:
        messages.error(request, f"Unknown action: {action}")
        return redirect("findings-list")

    with transaction.atomic():
        matched = Finding.objects.select_for_update().filter(
            pk__in=finding_ids,
            status__in=cfg["from_statuses"],
        )
        rows = list(matched.values("pk", "status"))

        if not rows:
            messages.warning(request, "No eligible findings in the selection.")
            return redirect("findings-list")

        update_kwargs = {"status": cfg["to_status"]}
        if cfg["to_status"] == Status.RESOLVED:
            update_kwargs["resolved_at"] = timezone.now()
        matched.update(**update_kwargs)

        FindingHistory.objects.bulk_create([
            FindingHistory(
                finding_id=row["pk"],
                user=request.user,
                old_status=row["status"],
                new_status=cfg["to_status"],
                comment=cfg["comment"],
            )
            for row in rows
        ])

    messages.success(request, f"{len(rows)} finding(s) {action}d.")
    return redirect("findings-list")
