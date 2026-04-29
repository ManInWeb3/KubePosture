"""Server-rendered UI views.

Workloads is the primary landing per
[Architecture/dev_docs/08-ui.md §1](Architecture/dev_docs/08-ui.md#L100).
`/` redirects to `/workloads/`; the dashboard at `/` lands in a later
slice.
"""
from __future__ import annotations

from django.contrib.auth.mixins import LoginRequiredMixin
from django.db.models import Count, Q
from django.http import Http404, HttpResponse, HttpResponseForbidden
from django.shortcuts import render
from django.urls import reverse
from django.views import View
from django.views.generic import RedirectView

from django.contrib import messages
from django.shortcuts import get_object_or_404, redirect

from core.constants import WorkloadKind
from core.models import Cluster, Finding, Namespace, UserPreference
from core.services.inventory import (
    findings_for_workload_image,
    list_workload_images,
    list_workloads,
    workloads_for_kind_name,
)
from core.urgency import recompute_batch


def _is_admin(user) -> bool:
    """Admin if superuser or in the seeded `admin` group."""
    if not getattr(user, "is_authenticated", False):
        return False
    if user.is_superuser:
        return True
    return user.groups.filter(name="admin").exists()


def _recompute_cluster(cluster: Cluster) -> int:
    """Recompute effective_priority for every Finding in `cluster`.

    Wraps the same `recompute_batch` the management command uses.
    """
    findings = list(Finding.objects.filter(cluster=cluster).only("id"))
    return recompute_batch(findings)


def _is_htmx(request) -> bool:
    return request.headers.get("HX-Request") == "true"


# ── Root redirect ────────────────────────────────────────────────


class RootRedirectView(RedirectView):
    """`/` → `/workloads/`. Dashboard takes this slot in a later slice."""

    pattern_name = "workloads-list"
    permanent = False


# ── Workloads (primary landing) ──────────────────────────────────


class WorkloadsListView(LoginRequiredMixin, View):
    """`/workloads/` — one row per (cluster, namespace, kind, name),
    ranked by urgency. Filter changes swap `#workload-rows` via HTMX.
    """

    template_name = "workloads/list.html"

    def get(self, request):
        params = request.GET
        cluster = params.get("cluster") or None
        namespace = params.get("namespace") or None
        name_contains = params.get("name") or None
        deployed_only = params.get("deployed_only", "true").lower() != "false"
        include_muted = params.get("include_muted") == "true"
        has_immediate = params.get("has_immediate") == "true"
        has_out_of_cycle = params.get("has_out_of_cycle") == "true"
        sort = params.get("sort") or None
        sort_dir = params.get("dir") or "desc"

        rows = list_workloads(
            cluster=cluster,
            namespace=namespace,
            name_contains=name_contains,
            has_immediate=has_immediate,
            has_out_of_cycle=has_out_of_cycle,
            include_muted=include_muted,
            deployed_only=deployed_only,
            sort=sort,
            sort_dir=sort_dir,
        )

        if _is_htmx(request) and (request.headers.get("HX-Target") == "workload-rows"):
            return render(request, "workloads/_rows.html", {"rows": rows})

        clusters = Cluster.objects.order_by("name")
        ns_qs = Namespace.objects.filter(workloads__deployed=True)
        if cluster:
            ns_qs = ns_qs.filter(cluster__name=cluster)
        namespace_names = list(
            ns_qs.values_list("name", flat=True).distinct().order_by("name")
        )

        return render(request, self.template_name, {
            "nav": "workloads",
            "rows": rows,
            "clusters": clusters,
            "namespace_names": namespace_names,
            "filters": {
                "cluster": cluster or "",
                "namespace": namespace or "",
                "name": name_contains or "",
                "deployed_only": deployed_only,
                "include_muted": include_muted,
                "has_immediate": has_immediate,
                "has_out_of_cycle": has_out_of_cycle,
                "sort": sort or "",
                "dir": sort_dir,
            },
        })


# ── Workload detail ──────────────────────────────────────────────


class WorkloadDetailView(LoginRequiredMixin, View):
    """`/workloads/<kind>/<name>/` — multi-cluster aggregate; cluster
    selector narrows via `?cluster=<name>`.
    """

    template_name = "workloads/detail.html"

    def get(self, request, kind, name):
        if kind not in WorkloadKind.values:
            raise Http404("unknown workload kind")
        cluster_name = request.GET.get("cluster") or None
        namespace_name = request.GET.get("namespace") or None
        all_workloads = list(workloads_for_kind_name(kind, name))
        if not all_workloads:
            raise Http404("workload not found")

        clusters_with_workload = sorted(
            {w.cluster.name for w in all_workloads}
        )
        if cluster_name and cluster_name not in clusters_with_workload:
            raise Http404("workload not deployed in that cluster")

        # Namespace list is scoped to the selected cluster (if any) so users
        # only see namespaces that actually contain this workload there.
        namespaces_with_workload = sorted({
            w.namespace.name for w in all_workloads
            if cluster_name is None or w.cluster.name == cluster_name
        })
        if namespace_name and namespace_name not in namespaces_with_workload:
            raise Http404("workload not deployed in that namespace")

        scoped = [w for w in all_workloads if (
            (cluster_name is None or w.cluster.name == cluster_name)
            and (namespace_name is None or w.namespace.name == namespace_name)
        )]

        include_history = request.GET.get("include_history") == "1"
        image_rows = list_workload_images(scoped, include_history=include_history)

        # Active-row pick: ?image=<digest> if it matches a row in scope,
        # else first row in the urgency-sorted list.
        selected_digest = request.GET.get("image") or None
        active_row = None
        if selected_digest:
            active_row = next(
                (r for r in image_rows if r["image"].digest == selected_digest),
                None,
            )
        if active_row is None and image_rows:
            active_row = image_rows[0]

        findings = (
            findings_for_workload_image(active_row["workload"], active_row["image"])
            if active_row else []
        )

        if _is_htmx(request) and request.headers.get("HX-Target") == "findings-panel":
            return render(request, "workloads/_findings_panel.html", {
                "active_row": active_row,
                "findings": findings,
            })

        signal_chips = []
        for w in scoped:
            for s in w.signals.all():
                if s.currently_active:
                    signal_chips.append({
                        "signal_id": s.signal_id,
                        "cluster": w.cluster.name,
                    })

        return render(request, self.template_name, {
            "nav": "workloads",
            "kind": kind,
            "name": name,
            "selected_cluster": cluster_name,
            "clusters_with_workload": clusters_with_workload,
            "selected_namespace": namespace_name,
            "namespaces_with_workload": namespaces_with_workload,
            "scoped_workloads": scoped,
            "all_workloads": all_workloads,
            "signal_chips": signal_chips,
            "image_rows": image_rows,
            "active_row": active_row,
            "findings": findings,
            "include_history": include_history,
        })


# ── Finding detail (HTMX fragment for workload-page offcanvas) ────


class FindingDetailPanelView(LoginRequiredMixin, View):
    """`/findings/<pk>/panel/` — HTMX fragment with full Finding metadata.

    Loaded into the offcanvas on the workload detail page so users can
    inspect a finding without leaving the workload context.
    """

    template_name = "findings/_detail_panel.html"

    def get(self, request, pk):
        f = (
            Finding.objects
            .select_related("cluster", "workload", "workload__namespace", "image")
            .filter(pk=pk)
            .first()
        )
        if f is None:
            raise Http404("finding not found")

        details = f.details if isinstance(f.details, dict) else {}
        # Pull common rich fields out for first-class rendering; the rest
        # is shown as raw key/value at the bottom of the panel.
        promoted_keys = {
            "description", "remediation", "messages",
            "primary_link", "links",
            "publishedDate", "lastModifiedDate",
            "resource_kind", "resource_name",
            "scope", "score", "target",
        }
        extra_details = {
            k: v for k, v in details.items() if k not in promoted_keys
        }

        return render(request, self.template_name, {
            "f": f,
            "description": details.get("description") or "",
            "remediation": details.get("remediation") or "",
            "messages": details.get("messages") or [],
            "primary_link": details.get("primary_link") or "",
            "links": details.get("links") or [],
            "published_date": details.get("publishedDate") or "",
            "last_modified_date": details.get("lastModifiedDate") or "",
            "resource_kind": details.get("resource_kind") or "",
            "resource_name": details.get("resource_name") or "",
            "extra_details": extra_details,
        })


# ── Clusters (read for everyone, edit for admin) ──────────────────


class ClusterListView(LoginRequiredMixin, View):
    """`/clusters/` — read-only list. Counts active namespaces and
    exposed-active namespaces per cluster for the badge column.
    """

    template_name = "clusters/list.html"

    def get(self, request):
        clusters = (
            Cluster.objects
            .annotate(
                namespace_count=Count(
                    "namespaces",
                    filter=Q(namespaces__active=True),
                    distinct=True,
                ),
                exposed_count=Count(
                    "namespaces",
                    filter=Q(namespaces__active=True, namespaces__internet_exposed=True),
                    distinct=True,
                ),
            )
            .order_by("name")
        )
        return render(request, self.template_name, {
            "nav": "clusters",
            "clusters": clusters,
            "is_admin": _is_admin(request.user),
        })


class ClusterDetailView(LoginRequiredMixin, View):
    """`/clusters/<pk>/` — cluster info + namespaces.

    GET renders read-only datagrid for non-admins, editable form for
    admins. POST is admin-gated: persists `environment` / `provider` /
    `region`, sets the matching `*_is_manual` flags, recomputes
    finding priorities, and redirects back.
    """

    template_name = "clusters/detail.html"

    def _context(self, request, cluster):
        # Active namespaces first, then inactive; both alphabetical.
        # Annotate with finding counts so the row shows useful info.
        namespaces = (
            Namespace.objects
            .filter(cluster=cluster)
            .annotate(
                finding_count=Count(
                    "workloads__findings",
                    filter=Q(workloads__deployed=True),
                    distinct=True,
                ),
            )
            .order_by("-active", "name")
        )
        return {
            "nav": "clusters",
            "cluster": cluster,
            "namespaces": namespaces,
            "is_admin": _is_admin(request.user),
        }

    def get(self, request, pk):
        cluster = get_object_or_404(Cluster, pk=pk)
        return render(request, self.template_name, self._context(request, cluster))

    def post(self, request, pk):
        if not _is_admin(request.user):
            return HttpResponseForbidden("admin only")
        cluster = get_object_or_404(Cluster, pk=pk)

        changed = []
        env = (request.POST.get("environment") or "").strip()
        if env and env != cluster.environment:
            cluster.environment = env
            cluster.environment_is_manual = True
            changed += ["environment", "environment_is_manual"]

        provider = (request.POST.get("provider") or "").strip()
        if provider and provider != cluster.provider:
            cluster.provider = provider
            cluster.provider_is_manual = True
            changed += ["provider", "provider_is_manual"]

        region = (request.POST.get("region") or "").strip()
        if region != cluster.region:
            cluster.region = region
            cluster.region_is_manual = True
            changed += ["region", "region_is_manual"]

        if changed:
            cluster.save(update_fields=changed)
            updated = _recompute_cluster(cluster)
            messages.success(
                request,
                f"Saved {', '.join(c for c in changed if not c.endswith('_is_manual'))}; "
                f"recomputed priority on {updated} findings.",
            )
        else:
            messages.info(request, "No changes to save.")

        return redirect("cluster-detail", pk=cluster.pk)


class NamespaceToggleView(LoginRequiredMixin, View):
    """HTMX endpoint that flips `internet_exposed` or
    `contains_sensitive_data` on a namespace and returns the re-rendered
    row partial. Admin only.
    """

    ALLOWED_FIELDS = {
        "internet_exposed": "exposure_is_manual",
        "contains_sensitive_data": "sensitive_is_manual",
    }
    template_name = "clusters/_namespace_row.html"

    def post(self, request, cluster_pk, ns_pk):
        if not _is_admin(request.user):
            return HttpResponseForbidden("admin only")
        ns = get_object_or_404(
            Namespace.objects.select_related("cluster"),
            pk=ns_pk,
            cluster_id=cluster_pk,
        )
        if not ns.active:
            return HttpResponse("namespace inactive", status=409)

        field = (request.POST.get("field") or "").strip()
        manual_field = self.ALLOWED_FIELDS.get(field)
        if manual_field is None:
            return HttpResponse(f"unknown field: {field}", status=400)

        setattr(ns, field, not getattr(ns, field))
        setattr(ns, manual_field, True)
        ns.save(update_fields=[field, manual_field])
        _recompute_cluster(ns.cluster)

        # Re-annotate finding_count so the row's count cell stays accurate.
        ns.finding_count = (
            ns.workloads.filter(deployed=True)
            .aggregate(n=Count("findings", distinct=True))["n"] or 0
        )
        return render(request, self.template_name, {
            "ns": ns,
            "cluster": ns.cluster,
            "is_admin": True,
        })


class NamespaceResetAutoView(LoginRequiredMixin, View):
    """HTMX endpoint that clears the `*_is_manual` flags on a namespace
    so the next inventory sync re-applies auto-detection. Admin only.
    """

    template_name = "clusters/_namespace_row.html"

    def post(self, request, cluster_pk, ns_pk):
        if not _is_admin(request.user):
            return HttpResponseForbidden("admin only")
        ns = get_object_or_404(
            Namespace.objects.select_related("cluster"),
            pk=ns_pk,
            cluster_id=cluster_pk,
        )
        ns.exposure_is_manual = False
        ns.sensitive_is_manual = False
        ns.save(update_fields=["exposure_is_manual", "sensitive_is_manual"])
        _recompute_cluster(ns.cluster)

        ns.finding_count = (
            ns.workloads.filter(deployed=True)
            .aggregate(n=Count("findings", distinct=True))["n"] or 0
        )
        return render(request, self.template_name, {
            "ns": ns,
            "cluster": ns.cluster,
            "is_admin": True,
        })


# ── Profile (per-user UI preferences) ────────────────────────────


class _PrefView:
    """Lightweight wrapper exposing `show_help` for the template, since the
    storage side uses inverted `hide_help` semantics."""

    def __init__(self, pref):
        self._pref = pref

    @property
    def show_help(self) -> bool:
        return not self._pref.hide_help


class ProfileView(LoginRequiredMixin, View):
    """`/profile/` — per-user account info + UI preferences.

    The template carries two forms:
    - User info (first_name, last_name, email)
    - Preferences (`form=preferences`, currently a single `show_help` toggle)

    Persisted on `auth.User` and `core.UserPreference` respectively.
    """

    template_name = "auth/profile.html"

    def _context(self, request):
        pref, _ = UserPreference.objects.get_or_create(user=request.user)
        return {
            "nav": "profile",
            "groups": list(request.user.groups.values_list("name", flat=True)),
            "preference": _PrefView(pref),
        }

    def get(self, request):
        return render(request, self.template_name, self._context(request))

    def post(self, request):
        if request.POST.get("form") == "preferences":
            pref, _ = UserPreference.objects.get_or_create(user=request.user)
            pref.hide_help = request.POST.get("show_help") != "on"
            pref.save(update_fields=["hide_help"])
            messages.success(request, "Preferences saved.")
        else:
            u = request.user
            u.first_name = request.POST.get("first_name", "").strip()
            u.last_name = request.POST.get("last_name", "").strip()
            u.email = request.POST.get("email", "").strip()
            u.save(update_fields=["first_name", "last_name", "email"])
            messages.success(request, "Profile updated.")
        return redirect("profile")


# ── Placeholder for nav items that aren't wired yet ──────────────


class PlaceholderView(LoginRequiredMixin, View):
    """Renders a small "Not yet wired" page so existing `{% url %}`
    calls in the navbar resolve. Replaced as each Phase C/D/F slice
    lands.
    """

    template_name = "_placeholder.html"
    label = "This page"

    def get(self, request, *args, **kwargs):
        return render(request, self.template_name, {
            "label": self.label,
            "nav": getattr(self, "nav_id", ""),
        })


def make_placeholder(label: str, nav: str = "") -> type[PlaceholderView]:
    return type(
        f"Placeholder_{label}",
        (PlaceholderView,),
        {"label": label, "nav_id": nav},
    )
