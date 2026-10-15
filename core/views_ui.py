"""Server-rendered UI views.

Workloads is the primary landing per
[Architecture/dev_docs/08-ui.md §1](Architecture/dev_docs/08-ui.md#L100).
`/` redirects to `/workloads/`; the dashboard at `/` lands in a later
slice.
"""
from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass
from datetime import timedelta
from types import SimpleNamespace

from django.contrib import messages
from django.contrib.auth import update_session_auth_hash
from django.contrib.auth.mixins import LoginRequiredMixin
from django.contrib.auth.models import Group, User
from django.core.paginator import Paginator
from django.db.models import Count, Q
from django.http import Http404, HttpResponse, HttpResponseForbidden
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse
from django.utils import timezone
from django.views import View
from django.views.generic import RedirectView

from core.api.auth import generate_token
from core.constants import Environment, PriorityBand, Source, WorkloadKind
from core.models import Cluster, Finding, Image, IngestToken, Namespace, UserPreference, Workload
from core.services import hardening_preview
from core.services.cluster_removal import remove_cluster
from core.services.components import (
    component_detail,
    list_components,
    list_ecosystems,
    summary_counts,
)
from core.services.images import (
    get_image_detail,
    is_valid_digest,
    list_images,
)
from core.services.inventory import (
    default_finding_qs,
    findings_for_workload_image,
    list_findings,
    list_workload_images,
    list_workloads,
    restrict_to_currently_deployed_images,
    workloads_for_kind_name,
)
from core.services.snapshot import bracketed_recompute
from core.templatetags.access_tags import is_admin


def _is_admin(user) -> bool:
    """Admin if superuser or in the seeded `admin` group. Delegates to the
    templatetag filter so the view and the navbar share one cached query."""
    return is_admin(user)


def _active_findings_by_namespace(cluster: Cluster) -> dict[int, int]:
    """Namespace id → active-finding count, using the same definition as
    the workloads / findings pages (default filter + currently deployed
    image). A raw `Count("workloads__findings")` counted stale, muted and
    rolled-out findings, so the cluster page disagreed with every other
    page for the same namespace."""
    rows = (
        restrict_to_currently_deployed_images(default_finding_qs(cluster=cluster))
        .order_by()
        .values("workload__namespace_id")
        .annotate(n=Count("id"))
    )
    return {r["workload__namespace_id"]: r["n"] for r in rows if r["workload__namespace_id"]}


def _bracketed_namespace_mutation(ns: Namespace, mutate) -> None:
    """Namespace-flag edit bracketed by pre/post snapshots — see
    `core.services.snapshot.bracketed_recompute`."""
    bracketed_recompute(ns.cluster, mutate, namespace=ns)


def _is_htmx(request) -> bool:
    return request.headers.get("HX-Request") == "true"


def _render_list(request, *, target: str, partial: str, page: str, context: dict,
                 page_context: Callable[[], dict]):
    """The fork every list / detail page has: an HTMX request whose
    `HX-Target` is the rows container gets the `partial` with `context`;
    anything else gets the full `page` with `context` plus
    `page_context()` — a callable so the dropdown / tile queries only
    run when the chrome is actually rendered."""
    if _is_htmx(request) and request.headers.get("HX-Target") == target:
        return render(request, partial, context)
    return render(request, page, {**context, **page_context()})


def _cluster_and_namespace_choices(cluster_name: str | None) -> tuple:
    """`(clusters, namespace_names)` for the list-page filter dropdowns:
    every cluster, and the names of namespaces with at least one deployed
    workload — in the selected cluster when one is."""
    ns_qs = Namespace.objects.filter(workloads__deployed=True)
    if cluster_name:
        ns_qs = ns_qs.filter(cluster__name=cluster_name)
    namespace_names = list(ns_qs.values_list("name", flat=True).distinct().order_by("name"))
    return Cluster.objects.order_by("name"), namespace_names


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
        sort = params.get("sort") or None
        sort_dir = params.get("dir") or "desc"

        rows = list_workloads(
            cluster=cluster,
            namespace=namespace,
            name_contains=name_contains,
            sort=sort,
            sort_dir=sort_dir,
        )
        # Rows are cheap dicts (band counts are one GROUP BY), but the
        # table itself was unbounded — a fleet-wide list rendered every
        # deployed workload on each HTMX keystroke.
        page = Paginator(rows, 50).get_page(params.get("page") or 1)

        def page_context():
            clusters, namespace_names = _cluster_and_namespace_choices(cluster)
            return {
                "nav": "workloads",
                "clusters": clusters,
                "namespace_names": namespace_names,
                "filters": {
                    "cluster": cluster or "",
                    "namespace": namespace or "",
                    "name": name_contains or "",
                    "sort": sort or "",
                    "dir": sort_dir,
                },
            }

        return _render_list(
            request, target="workload-rows", partial="workloads/_rows.html", page=self.template_name,
            context={"page_obj": page, "rows": page.object_list, "request_qs": _qs_without_page(request.GET)},
            page_context=page_context,
        )


# ── Workload detail ──────────────────────────────────────────────


_HARDENING_PREVIEW_MAX_BYTES = 10 * 1024 * 1024


def _candidate_image_row(workload, preview) -> dict:
    """Synthetic image row built from a stashed `PreviewResult`.

    Shape matches `list_workload_images()` rows so the existing template can
    render it without branching, except for the `is_candidate` flag which
    drives the "PREVIEW" badge.
    """
    img = SimpleNamespace(
        digest=preview.digest,
        ref=preview.image_ref,
        repository=preview.image_ref,
        registry="",
    )
    return {
        "observation": None,
        "image": img,
        "workload": workload,
        "cluster": workload.cluster,
        "namespace": workload.namespace,
        "container_name": "(candidate)",
        "init_container": False,
        "currently_deployed": True,
        "first_seen_at": None,
        "last_seen_at": None,
        "n_immediate": preview.counts.get(PriorityBand.IMMEDIATE.value, 0),
        "n_out_of_band": preview.counts.get(PriorityBand.OUT_OF_BAND.value, 0),
        "n_scheduled": preview.counts.get(PriorityBand.SCHEDULED.value, 0),
        "n_defer": preview.counts.get(PriorityBand.DEFER.value, 0),
        "n_total": preview.total,
        "is_candidate": True,
    }


@dataclass(frozen=True)
class _WorkloadScope:
    """What `/workloads/<kind>/<name>/?cluster=&namespace=` resolves to."""

    cluster_name: str | None
    namespace_name: str | None
    clusters_with_workload: list[str]
    namespaces_with_workload: list[str]
    scoped: list[Workload]


def _resolve_workload_scope(request, kind: str, name: str) -> _WorkloadScope:
    """Deployed `(kind, name)` instances across the fleet, narrowed by
    `?cluster=` and `?namespace=`. 404 when nothing is deployed under
    that identity, or when a selector names a cluster / namespace it
    isn't deployed in. The namespace list is scoped to the selected
    cluster so users only see namespaces that hold the workload there."""
    if kind not in WorkloadKind.values:
        raise Http404("unknown workload kind")
    cluster_name = request.GET.get("cluster") or None
    namespace_name = request.GET.get("namespace") or None
    all_workloads = [w for w in workloads_for_kind_name(kind, name) if w.deployed]
    if not all_workloads:
        raise Http404("workload not found")

    clusters_with_workload = sorted({w.cluster.name for w in all_workloads})
    if cluster_name and cluster_name not in clusters_with_workload:
        raise Http404("workload not deployed in that cluster")
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
    return _WorkloadScope(cluster_name, namespace_name, clusters_with_workload, namespaces_with_workload, scoped)


def _image_rows_with_preview(request, scoped: list[Workload], *, include_history: bool):
    """`(image_rows, preview)`: the per-(workload, image) rows for the
    scope, with a stashed hardening-preview candidate row prepended when
    `?image=` names one. The candidate only renders when the URL has
    narrowed to a single (cluster, namespace) — the preview is scored
    against one workload, not an aggregate, so showing it under a
    multi-cluster header would be misleading."""
    image_rows = list_workload_images(scoped, include_history=include_history)
    selected_digest = request.GET.get("image") or None
    preview = None
    if len(scoped) == 1 and hardening_preview.is_candidate_digest(selected_digest):
        cid = hardening_preview.candidate_id_from_digest(selected_digest)
        preview = hardening_preview.load(request, scoped[0].pk, cid)
    if preview is not None:
        image_rows = [_candidate_image_row(scoped[0], preview)] + image_rows
    return image_rows, preview


def _active_row_and_findings(request, image_rows: list[dict], preview) -> tuple[dict | None, list, bool]:
    """`(active_row, findings, is_preview)`. The active row is the
    `?image=<digest>` match if it is in scope, else the first row of the
    urgency-sorted list; its findings come from the preview stash when
    the candidate row is active, from the DB otherwise."""
    selected_digest = request.GET.get("image") or None
    active_row = None
    if selected_digest:
        active_row = next((r for r in image_rows if r["image"].digest == selected_digest), None)
    if active_row is None and image_rows:
        active_row = image_rows[0]

    is_preview = bool(active_row and active_row.get("is_candidate"))
    if is_preview and preview is not None:
        findings = preview.findings
    elif active_row:
        findings = findings_for_workload_image(active_row["workload"], active_row["image"])
    else:
        findings = []
    return active_row, findings, is_preview


def _signal_chips(scoped: list[Workload]) -> list[dict]:
    return [
        {"signal_id": s.signal_id, "cluster": w.cluster.name}
        for w in scoped for s in w.signals.all() if s.currently_active
    ]


def _cluster_import_rows(scoped: list[Workload]) -> list[dict]:
    """One entry per cluster in scope, with the most recent
    `last_seen_at` across that cluster's workloads in scope (a workload
    can sit in multiple namespaces). The template renders one Re-import
    button per row."""
    seen: dict[int, dict] = {}
    for w in scoped:
        row = seen.get(w.cluster_id)
        if row is None:
            seen[w.cluster_id] = {"cluster": w.cluster, "last_seen_at": w.last_seen_at}
        elif w.last_seen_at and (row["last_seen_at"] is None or w.last_seen_at > row["last_seen_at"]):
            row["last_seen_at"] = w.last_seen_at
    return sorted(seen.values(), key=lambda r: r["cluster"].name)


def _preview_target_choices(scoped: list[Workload]) -> list[dict]:
    """The hardening form renders whenever there's at least one workload
    in scope. With a single workload it binds via a hidden input; with
    multiple (multi-cluster / multi-namespace aggregate) it adds a picker
    so the user can choose which workload's context to score against."""
    return [
        {"pk": w.pk, "label": f"{w.cluster.name} / {w.namespace.name}"}
        for w in sorted(scoped, key=lambda w: (w.cluster.name, w.namespace.name))
    ]


class WorkloadDetailView(LoginRequiredMixin, View):
    """`/workloads/<kind>/<name>/` — multi-cluster aggregate; cluster
    selector narrows via `?cluster=<name>`.
    """

    template_name = "workloads/detail.html"

    def get(self, request, kind, name):
        scope = _resolve_workload_scope(request, kind, name)
        include_history = request.GET.get("include_history") == "1"
        image_rows, preview = _image_rows_with_preview(request, scope.scoped, include_history=include_history)
        active_row, findings, is_preview = _active_row_and_findings(request, image_rows, preview)

        def page_context():
            return {
                "nav": "workloads",
                "kind": kind,
                "name": name,
                "selected_cluster": scope.cluster_name,
                "clusters_with_workload": scope.clusters_with_workload,
                "selected_namespace": scope.namespace_name,
                "namespaces_with_workload": scope.namespaces_with_workload,
                "scoped_workloads": scope.scoped,
                "signal_chips": _signal_chips(scope.scoped),
                "image_rows": image_rows,
                "include_history": include_history,
                "cluster_imports": _cluster_import_rows(scope.scoped),
                "is_admin": _is_admin(request.user),
                "preview_target_choices": _preview_target_choices(scope.scoped),
            }

        return _render_list(
            request, target="findings-panel", partial="workloads/_findings_panel.html",
            page=self.template_name,
            context={"active_row": active_row, "findings": findings, "is_preview": is_preview, "preview": preview},
            page_context=page_context,
        )

    def post(self, request, kind, name):
        """Hardening-preview upload + clear actions.

        The form binds to the workload pk directly (single hidden input) —
        validated here against (kind, name) from the URL so a forged pk
        can't target a different workload.
        """
        if kind not in WorkloadKind.values:
            raise Http404("unknown workload kind")
        workload_id = request.POST.get("workload_id") or ""
        if not workload_id.isdigit():
            raise Http404("missing or invalid workload id")
        workload = (
            Workload.objects
            .select_related("cluster", "namespace")
            .prefetch_related("signals")
            .filter(pk=int(workload_id), kind=kind, name=name, deployed=True)
            .first()
        )
        if workload is None:
            raise Http404("workload not found")

        base_url = reverse("workloads-detail", kwargs={"kind": kind, "name": name})
        base_qs = f"?cluster={workload.cluster.name}&namespace={workload.namespace.name}"

        action = request.POST.get("action") or "preview"
        if action == "clear":
            cid = request.POST.get("candidate_id") or ""
            if cid:
                hardening_preview.clear(request, workload.pk, cid)
            return redirect(base_url + base_qs)

        upload = request.FILES.get("scan")
        pasted = (request.POST.get("scan_text") or "").strip()
        if upload is None and not pasted:
            messages.error(request, "Attach a Trivy JSON file or paste its contents.")
            return redirect(base_url + base_qs)

        if upload is not None and upload.size > _HARDENING_PREVIEW_MAX_BYTES:
            messages.error(request, "Scan file too large (10 MB max).")
            return redirect(base_url + base_qs)

        try:
            raw = upload.read() if upload is not None else pasted.encode("utf-8")
            cli_json = json.loads(raw)
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            messages.error(request, f"Could not parse JSON: {exc}")
            return redirect(base_url + base_qs)

        if not hardening_preview.is_trivy_cli_json(cli_json):
            messages.error(
                request,
                "Not a Trivy CLI scan JSON — expected a top-level `Results` array. "
                "Produce one with `trivy image --format json <image>`.",
            )
            return redirect(base_url + base_qs)

        result = hardening_preview.preview_trivy_cli_scan(workload, cli_json)
        hardening_preview.stash(request, workload.pk, result)
        return redirect(f"{base_url}{base_qs}&image={result.digest}")


# ── Images (image-centric triage) ────────────────────────────────


class ImagesListView(LoginRequiredMixin, View):
    """`/images/` — one row per container image, ranked by blast-radius
    impact (workloads × Σ weight·CVEs). Click a row to see workloads
    running it, what other CVEs exist on it, and the SBOM count.
    """

    template_name = "images/list.html"

    def get(self, request):
        params = request.GET
        filters = {
            "cluster":              params.get("cluster", ""),
            "namespace":            params.get("namespace", ""),
            "registry":             params.get("registry", ""),
            "repository":           params.get("repository", ""),
            "include_undeployed":   "1" if params.get("include_undeployed") == "1" else "",
            "sort":                 params.get("sort", ""),
            "dir":                  params.get("dir") or "desc",
        }

        rows = list_images(
            cluster=filters["cluster"] or None,
            namespace=filters["namespace"] or None,
            registry_contains=filters["registry"] or None,
            repository_contains=filters["repository"] or None,
            currently_deployed_only=not filters["include_undeployed"],
            sort=filters["sort"] or None,
            sort_dir=filters["dir"],
        )

        page = Paginator(rows, 50).get_page(params.get("page") or 1)

        def page_context():
            clusters, namespace_names = _cluster_and_namespace_choices(filters["cluster"])
            return {"nav": "images", "clusters": clusters, "namespace_names": namespace_names}

        return _render_list(
            request, target="image-rows", partial="images/_rows.html", page=self.template_name,
            context={
                "page_obj": page,
                "rows": page.object_list,
                "filters": filters,
                "request_qs": _qs_without_page(request.GET),
            },
            page_context=page_context,
        )


class ImageDetailView(LoginRequiredMixin, View):
    """`/images/<digest>/` — image header + workloads using it +
    findings on it + SBOM count. Findings are paginated 50/page (popular
    base images can carry 200+ CVEs). HTMX swaps #finding-rows on
    pagination so the rest of the detail page stays put.
    """

    template_name = "images/detail.html"

    def get(self, request, digest):
        if not is_valid_digest(digest):
            raise Http404("invalid image digest")
        detail = get_image_detail(digest)
        if detail is None:
            raise Http404("image not found")

        page = Paginator(detail["findings_qs"], 50).get_page(
            request.GET.get("page") or 1,
        )
        return _render_list(
            request, target="finding-rows", partial="findings/_rows.html", page=self.template_name,
            context={
                "page_obj": page,
                "findings": page.object_list,
                "filters": {},
                "request_qs": _qs_without_page(request.GET),
            },
            page_context=lambda: {
                "nav": "images",
                "image": detail["image"],
                "workload_rows": detail["workload_rows"],
                "sbom_count": detail["sbom_count"],
            },
        )


# ── Findings list (fleet-wide triage) ────────────────────────────


_EPSS_THRESHOLDS = {"10": 0.10, "50": 0.50}
_AGE_DAYS = {"1": 1, "7": 7, "30": 30}

_PRESETS = {
    "today":      {"priority": "immediate", "internet": "1"},
    "kev":        {"kev": "1"},
    "high_epss":  {"epss": "50"},
    "new_week":   {"age": "7"},
    "policy":     {"source": "kyverno", "priority": "immediate"},
}


def _exposure_arg(internet: bool, sensitive: bool) -> str | None:
    """Combine the two exposure checkboxes into the service-layer
    `exposure` enum: 'internet', 'sensitive', 'either', or None."""
    if internet and sensitive:
        return "either"
    if internet:
        return "internet"
    if sensitive:
        return "sensitive"
    return None


def _active_preset(filters: dict) -> str:
    """Return the preset key whose dimensions exactly match the active
    filters, or "" for no match. Best-effort string compare."""
    for name, expected in _PRESETS.items():
        if all(str(filters.get(k, "")) == v for k, v in expected.items()):
            non_preset = {k: v for k, v in filters.items()
                          if k not in expected and k not in {"sort", "dir", "page"}}
            if not any(non_preset.values()):
                return name
    return ""


class FindingsListView(LoginRequiredMixin, View):
    """`/findings/` — fleet-wide triage list.

    Filters slice by triage signals (priority, source, exposure, KEV,
    EPSS, name) — not topology. For "findings on cluster X / workload Y"
    use `/workloads/`. Click a row to open the existing
    `#finding-detail-offcanvas`.
    """

    template_name = "findings/list.html"

    def get(self, request):
        params = request.GET
        filters = {
            "name":      params.get("name", ""),
            "priority":  params.get("priority", ""),
            "source":    params.get("source", ""),
            "internet":  "1" if params.get("internet") == "1" else "",
            "sensitive": "1" if params.get("sensitive") == "1" else "",
            "kev":       "1" if params.get("kev") == "1" else "",
            "epss":      params.get("epss", ""),
            "age":       params.get("age", ""),
            "sort":      params.get("sort", ""),
            "dir":       params.get("dir") or "desc",
        }
        if filters["epss"] not in {"", *_EPSS_THRESHOLDS}:
            filters["epss"] = ""
        if filters["age"] not in {"", *_AGE_DAYS}:
            filters["age"] = ""

        common = dict(
            name_contains=filters["name"] or None,
            priority=filters["priority"] or None,
            source=filters["source"] or None,
            exposure=_exposure_arg(bool(filters["internet"]), bool(filters["sensitive"])),
            kev=bool(filters["kev"]),
            epss_min=_EPSS_THRESHOLDS.get(filters["epss"]),
            age_days=_AGE_DAYS.get(filters["age"]),
            sort=filters["sort"] or None,
            sort_dir=filters["dir"],
        )

        qs = list_findings(**common)
        page = Paginator(qs, 50).get_page(params.get("page") or 1)

        def page_context():
            # Tile counts respect the current filter scope MINUS the
            # dimension each tile reflects, so they update as you narrow
            # but don't zero themselves out.
            tiles = {
                "immediate": list_findings(**{**common, "priority": None}).filter(
                    effective_priority=PriorityBand.IMMEDIATE).count(),
                "kev": list_findings(**{**common, "kev": False}).filter(
                    kev_listed=True).count(),
                # Tile drops the two exposure checkboxes from the count so
                # ?priority=defer still shows non-zero exposed-namespace findings.
                "exposed": list_findings(
                    **{**common, "exposure": None}
                ).filter(
                    Q(workload__namespace__internet_exposed=True)
                    | Q(workload__namespace__contains_sensitive_data=True)
                ).count(),
                "new_week": list_findings(**{**common, "age_days": None}).filter(
                    first_seen__gte=timezone.now() - timedelta(days=7)).count(),
            }
            return {
                "nav": "findings",
                "tiles": tiles,
                "active_preset": _active_preset(filters),
                "priority_choices": PriorityBand.choices,
                "source_choices": Source.choices,
            }

        return _render_list(
            request, target="finding-rows", partial="findings/_rows.html", page=self.template_name,
            context={
                "page_obj": page,
                "findings": page.object_list,
                "filters": filters,
                "request_qs": _qs_without_page(request.GET),
            },
            page_context=page_context,
        )


def _qs_without_page(get_params) -> str:
    """Return URL-encoded querystring excluding the `page` key — used
    so pagination links can append `?<other_filters>&page=N`. Values are
    re-encoded: a filter containing `+ & = # %` must survive the round
    trip into the page-2 link."""
    qd = get_params.copy()
    qd.pop("page", None)
    for key in [k for k, v in qd.items() if v == ""]:
        qd.pop(key)
    return qd.urlencode()


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


class PreviewFindingDetailPanelView(LoginRequiredMixin, View):
    """`/workloads/.../preview/<candidate_id>/finding/<idx>/panel/`.

    HTMX offcanvas fragment for a hardening-preview finding. The preview is
    never persisted, so there's no DB row to hit — details come from the
    per-user session stash keyed by (workload, candidate). `idx` identifies
    the finding within the stash (stable across the urgency re-sort).
    """

    template_name = "findings/_preview_detail_panel.html"

    def get(self, request, workload_id, candidate_id, idx):
        result = hardening_preview.load(request, workload_id, candidate_id)
        if result is None:
            raise Http404("preview expired or not found")
        f = hardening_preview.find_finding(result, idx)
        if f is None:
            raise Http404("preview finding not found")
        return render(request, self.template_name, {
            "f": f,
            "image_ref": result.image_ref,
        })


# ── Components (SBOM browser) ─────────────────────────────────────


class ComponentsListView(LoginRequiredMixin, View):
    """`/components/` — fleet-wide SBOM browser.

    Rows are grouped by `purl` (so two different versions of the same
    name show as separate rows). Counts reflect currently-deployed
    images only unless `?include_inactive=1`. Cluster filter scopes
    both the component selection AND the count joins.
    """

    template_name = "components/list.html"

    def get(self, request):
        params = request.GET
        filters = {
            "name":      params.get("name", ""),
            "ecosystem": params.get("ecosystem", ""),
            "cluster":   params.get("cluster", ""),
            "image":     params.get("image", ""),
            "sort":      params.get("sort", ""),
            "dir":       params.get("dir") or "asc",
            "include_inactive": "1" if params.get("include_inactive") == "1" else "",
        }

        cluster = None
        if filters["cluster"]:
            cluster = Cluster.objects.filter(name=filters["cluster"]).first()
            if cluster is None:
                filters["cluster"] = ""

        image = None
        if filters["image"]:
            image = Image.objects.filter(digest=filters["image"]).first()
            if image is None:
                filters["image"] = ""

        rows = list_components(
            name_contains=filters["name"] or None,
            ecosystem=filters["ecosystem"] or None,
            cluster=cluster,
            image_digest=filters["image"] or None,
            include_inactive=bool(filters["include_inactive"]),
            sort=filters["sort"] or None,
            sort_dir=filters["dir"],
        )

        page = Paginator(rows, 50).get_page(params.get("page") or 1)
        return _render_list(
            request, target="component-rows", partial="components/_rows.html", page=self.template_name,
            context={
                "page_obj": page,
                "components": page.object_list,
                "filters": filters,
                "request_qs": _qs_without_page(request.GET),
            },
            page_context=lambda: {
                "nav": "components",
                "image": image,
                "ecosystems": list_ecosystems(cluster=cluster),
                "clusters": list(Cluster.objects.order_by("name").values_list("name", flat=True)),
                "summary": summary_counts(cluster=cluster),
            },
        )


class ComponentDetailPanelView(LoginRequiredMixin, View):
    """`/components/detail/?purl=<urlencoded>` — HTMX offcanvas fragment.

    Shows affected images (with per-cluster workload lists) and other
    versions of the same name observed in the fleet.
    """

    template_name = "components/_detail_panel.html"

    def get(self, request):
        purl = request.GET.get("purl") or ""
        if not purl:
            raise Http404("purl is required")

        cluster_name = request.GET.get("cluster") or ""
        cluster = None
        if cluster_name:
            cluster = Cluster.objects.filter(name=cluster_name).first()
            if cluster is None:
                raise Http404("unknown cluster")  # not a silent fleet-wide view
        include_inactive = request.GET.get("include_inactive") == "1"

        detail = component_detail(
            purl, cluster=cluster, include_inactive=include_inactive,
        )
        if detail is None:
            raise Http404("component not found")

        return render(request, self.template_name, {
            "c": detail,
            "selected_cluster": cluster_name,
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
        # Active namespaces first, then inactive; both alphabetical, each
        # carrying its active-finding count for the row.
        namespaces = list(Namespace.objects.filter(cluster=cluster).order_by("-active", "name"))
        counts = _active_findings_by_namespace(cluster)
        for ns in namespaces:
            ns.finding_count = counts.get(ns.pk, 0)
        active = Namespace.objects.filter(cluster=cluster, active=True)
        return {
            "nav": "clusters",
            "cluster": cluster,
            "namespaces": namespaces,
            "has_public_exposure": active.filter(internet_exposed=True).exists(),
            "has_sensitive_data": active.filter(contains_sensitive_data=True).exists(),
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
        if env and env not in Environment.values:
            messages.error(request, f"Unknown environment '{env}'.")
            return redirect("cluster-detail", pk=cluster.pk)
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
            # Same snapshot bracketing as the admin's ClusterAdmin.save_model,
            # so a UI environment flip shows as a step on the trend chart.
            updated = bracketed_recompute(
                cluster, lambda: cluster.save(update_fields=changed),
            )
            messages.success(
                request,
                f"Saved {', '.join(c for c in changed if not c.endswith('_is_manual'))}; "
                f"recomputed priority on {updated} findings.",
            )
        else:
            messages.info(request, "No changes to save.")

        return redirect("cluster-detail", pk=cluster.pk)


class ClusterReimportView(LoginRequiredMixin, View):
    """HTMX endpoint that flags a cluster for an on-demand re-import.

    Sets `Cluster.reimport_requested_at = now()` and records the actor.
    The workload-cluster trigger CronJob polls /api/v1/imports/pending/
    every minute and runs a full import the next tick. Admin only.
    """

    template_name = "clusters/_reimport_button.html"

    def post(self, request, pk):
        if not _is_admin(request.user):
            return HttpResponseForbidden("admin only")
        cluster = get_object_or_404(Cluster, pk=pk)
        cluster.reimport_requested_at = timezone.now()
        cluster.reimport_requested_by = request.user
        cluster.save(update_fields=["reimport_requested_at", "reimport_requested_by"])
        return render(request, self.template_name, {
            "cluster": cluster,
            "is_admin": True,
        })


class ClusterDeleteView(LoginRequiredMixin, View):
    """`POST /clusters/<pk>/delete/` — completely remove a cluster.

    Destructive and irreversible: drops the cluster and every row tied
    to it (namespaces, workloads, findings, history, snapshots, import
    marks, queued scan payloads). Admin only, and gated on the admin
    re-typing the cluster name so a stray click can't wipe a cluster.
    Delegates the deletion + cascade handling to
    `core.services.cluster_removal.remove_cluster`.
    """

    def post(self, request, pk):
        if not _is_admin(request.user):
            return HttpResponseForbidden("admin only")
        cluster = get_object_or_404(Cluster, pk=pk)

        typed = (request.POST.get("confirm_name") or "").strip()
        if typed != cluster.name:
            messages.error(
                request,
                "Cluster not deleted — the name you typed did not match.",
            )
            return redirect("cluster-detail", pk=cluster.pk)

        result = remove_cluster(cluster)
        messages.success(
            request,
            f"Removed cluster '{result.cluster_name}' and {result.total} "
            "related rows.",
        )
        return redirect("cluster-list")


class _NamespaceRowMutationView(LoginRequiredMixin, View):
    """Base for the admin-only HTMX endpoints on the cluster page's
    namespace rows: run a flag edit bracketed by pre/post snapshots
    (`bracketed_recompute`) and return the re-rendered row partial with
    a fresh active-finding count. Subclasses implement `mutation`."""

    template_name = "clusters/_namespace_row.html"

    def mutation(self, request, ns: Namespace) -> HttpResponse | Callable[[], None]:
        """Either an error response, or the zero-arg callable that
        performs the edit (run inside the snapshot bracket)."""
        raise NotImplementedError

    def post(self, request, cluster_pk, ns_pk):
        if not _is_admin(request.user):
            return HttpResponseForbidden("admin only")
        ns = get_object_or_404(
            Namespace.objects.select_related("cluster"),
            pk=ns_pk,
            cluster_id=cluster_pk,
        )
        mutate = self.mutation(request, ns)
        if isinstance(mutate, HttpResponse):
            return mutate
        _bracketed_namespace_mutation(ns, mutate)
        # Re-annotate finding_count so the row's count cell stays accurate.
        ns.finding_count = _active_findings_by_namespace(ns.cluster).get(ns.pk, 0)
        return render(request, self.template_name, {
            "ns": ns,
            "cluster": ns.cluster,
            "is_admin": True,
        })


class NamespaceToggleView(_NamespaceRowMutationView):
    """Flips `internet_exposed` or `contains_sensitive_data` on a
    namespace and pins the matching `*_is_manual` flag."""

    ALLOWED_FIELDS = {
        "internet_exposed": "exposure_is_manual",
        "contains_sensitive_data": "sensitive_is_manual",
    }

    def mutation(self, request, ns):
        if not ns.active:
            return HttpResponse("namespace inactive", status=409)
        field = (request.POST.get("field") or "").strip()
        manual_field = self.ALLOWED_FIELDS.get(field)
        if manual_field is None:
            return HttpResponse(f"unknown field: {field}", status=400)

        def _flip():
            setattr(ns, field, not getattr(ns, field))
            setattr(ns, manual_field, True)
            ns.save(update_fields=[field, manual_field])
        return _flip


class NamespaceResetAutoView(_NamespaceRowMutationView):
    """Clears the `*_is_manual` flags on a namespace so the next
    inventory sync re-applies auto-detection."""

    def mutation(self, request, ns):
        def _reset():
            ns.exposure_is_manual = False
            ns.sensitive_is_manual = False
            ns.save(update_fields=["exposure_is_manual", "sensitive_is_manual"])
        return _reset


# ── Profile (per-user UI preferences) ────────────────────────────


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
            # Storage uses inverted `hide_help` semantics.
            "show_help": not pref.hide_help,
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


# ── Access (admin-only): users + ingest tokens ───────────────────


ROLE_GROUPS = ("viewer", "SecEngineer", "admin")


class AdminRequiredMixin(LoginRequiredMixin):
    """Login + `admin` role required. Returns 403 for non-admins."""

    def dispatch(self, request, *args, **kwargs):
        if not request.user.is_authenticated:
            return self.handle_no_permission()
        if not _is_admin(request.user):
            return HttpResponseForbidden("Admin role required")
        return super().dispatch(request, *args, **kwargs)


def _role_groups_qs():
    return Group.objects.filter(name__in=ROLE_GROUPS).order_by("name")


class UserListView(AdminRequiredMixin, View):
    """`/access/users/` — list all human users with role + status."""

    template_name = "users/list.html"

    def get(self, request):
        search = (request.GET.get("search") or "").strip()
        role = (request.GET.get("role") or "").strip()

        qs = User.objects.prefetch_related("groups").order_by("username")
        if search:
            qs = qs.filter(
                Q(username__icontains=search)
                | Q(email__icontains=search)
                | Q(first_name__icontains=search)
                | Q(last_name__icontains=search)
            )
        if role:
            qs = qs.filter(groups__name=role)

        page = Paginator(qs, 25).get_page(request.GET.get("page", 1))
        return render(request, self.template_name, {
            "users": page,
            "page_obj": page,
            "groups": _role_groups_qs(),
            "nav": "access",
            "settings_tab": "users",
        })


class UserCreateView(AdminRequiredMixin, View):
    """`/access/users/new/` — create a Django user, assign one role group."""

    template_name = "users/form.html"

    def _ctx(self, selected_role):
        return {
            "edit_user": None,
            "groups": _role_groups_qs(),
            "selected_role": selected_role,
            "nav": "access",
            "settings_tab": "users",
        }

    def get(self, request):
        return render(request, self.template_name, self._ctx("viewer"))

    def post(self, request):
        username = (request.POST.get("username") or "").strip()
        email = (request.POST.get("email") or "").strip()
        password = request.POST.get("password") or ""
        first_name = (request.POST.get("first_name") or "").strip()
        last_name = (request.POST.get("last_name") or "").strip()
        is_active = request.POST.get("is_active") == "on"
        role = (request.POST.get("role") or "").strip()

        if not username:
            messages.error(request, "Username is required.")
        elif User.objects.filter(username=username).exists():
            messages.error(request, f"Username '{username}' already exists.")
        elif role not in ROLE_GROUPS:
            messages.error(request, "Pick a role: viewer, SecEngineer, or admin.")
        elif not password:
            messages.error(request, "Password is required for new users.")
        else:
            user = User.objects.create_user(
                username=username,
                email=email,
                password=password,
                first_name=first_name,
                last_name=last_name,
            )
            user.is_active = is_active
            user.save(update_fields=["is_active"])
            user.groups.set(Group.objects.filter(name=role))
            messages.success(request, f"User '{username}' created.")
            return redirect("user-list")

        return render(request, self.template_name, self._ctx(role or "viewer"))


class UserEditView(AdminRequiredMixin, View):
    """`/access/users/<pk>/edit/` — edit profile, role, optional password."""

    template_name = "users/form.html"

    def _ctx(self, user_obj, selected_role):
        return {
            "edit_user": user_obj,
            "groups": _role_groups_qs(),
            "selected_role": selected_role,
            "nav": "access",
            "settings_tab": "users",
        }

    def get(self, request, pk):
        user_obj = get_object_or_404(User, pk=pk)
        current = user_obj.groups.filter(name__in=ROLE_GROUPS).first()
        return render(request, self.template_name,
                      self._ctx(user_obj, current.name if current else ""))

    def post(self, request, pk):
        user_obj = get_object_or_404(User, pk=pk)
        # A group-`admin` (non-superuser) must not be able to take over a
        # superuser — resetting its password is a path into the Django
        # admin — nor lock themselves out by demoting / deactivating
        # their own account (mirrors UserToggleActiveView's self guard).
        if user_obj.is_superuser and not request.user.is_superuser:
            return HttpResponseForbidden("Only a superuser can edit a superuser")
        is_self = user_obj == request.user

        user_obj.first_name = (request.POST.get("first_name") or "").strip()
        user_obj.last_name = (request.POST.get("last_name") or "").strip()
        user_obj.email = (request.POST.get("email") or "").strip()
        update_fields = ["first_name", "last_name", "email"]
        if not is_self:
            user_obj.is_active = request.POST.get("is_active") == "on"
            update_fields.append("is_active")
        user_obj.save(update_fields=update_fields)

        role = (request.POST.get("role") or "").strip()
        if role in ROLE_GROUPS and not is_self:
            user_obj.groups.set(Group.objects.filter(name=role))

        new_password = request.POST.get("new_password") or ""
        if new_password:
            user_obj.set_password(new_password)
            user_obj.save(update_fields=["password"])
            if is_self:
                update_session_auth_hash(request, user_obj)

        messages.success(request, f"User '{user_obj.username}' updated.")
        return redirect("user-list")


class UserToggleActiveView(AdminRequiredMixin, View):
    """`POST /access/users/<pk>/toggle-active/` — flip `is_active`."""

    def post(self, request, pk):
        user_obj = get_object_or_404(User, pk=pk)
        if user_obj == request.user:
            messages.error(request, "Cannot deactivate your own account.")
            return redirect("user-list")
        user_obj.is_active = not user_obj.is_active
        user_obj.save(update_fields=["is_active"])
        verb = "activated" if user_obj.is_active else "deactivated"
        messages.success(request, f"User '{user_obj.username}' {verb}.")
        return redirect("user-list")


# ── Ingest tokens ────────────────────────────────────────────────


def _session_key(token_id: int) -> str:
    return f"new_ingest_token:{token_id}"


class TokenListView(AdminRequiredMixin, View):
    """`/access/tokens/` — list ingest tokens.

    A freshly-created or freshly-regenerated token's plain value is shown
    once via the session, then popped on next render (one-shot reveal).
    """

    template_name = "settings/tokens.html"

    def get(self, request):
        rows = []
        for tok in IngestToken.objects.order_by("-created_at"):
            rows.append({
                "obj": tok,
                "new_key": request.session.pop(_session_key(tok.id), None),
            })
        return render(request, self.template_name, {
            "tokens": rows,
            "nav": "access",
            "settings_tab": "tokens",
        })


class TokenCreateView(AdminRequiredMixin, View):
    """`POST /access/tokens/create/` — create token, stash plain in session."""

    def post(self, request):
        name = (request.POST.get("name") or "").strip()
        description = (request.POST.get("description") or "").strip()

        if not name:
            messages.error(request, "Name is required.")
            return redirect("token-list")
        if IngestToken.objects.filter(name=name).exists():
            messages.error(request, f"Token '{name}' already exists.")
            return redirect("token-list")

        plain, hashed = generate_token()
        tok = IngestToken.objects.create(
            name=name,
            description=description,
            token_hash=hashed,
        )
        request.session[_session_key(tok.id)] = plain
        messages.success(
            request,
            f"Token '{name}' created. Copy it now — it won't be shown again.",
        )
        return redirect("token-list")


class TokenRegenerateView(AdminRequiredMixin, View):
    """`POST /access/tokens/<pk>/regenerate/` — rotate the secret in place.

    Overwrites `token_hash` with a fresh value and resets `last_used_at`.
    The old token stops working immediately. `created_at` is preserved
    (it tracks the row, not the current secret).
    """

    def post(self, request, pk):
        tok = get_object_or_404(IngestToken, pk=pk, revoked_at__isnull=True)
        plain, hashed = generate_token()
        tok.token_hash = hashed
        tok.last_used_at = None
        tok.save(update_fields=["token_hash", "last_used_at"])
        request.session[_session_key(tok.id)] = plain
        messages.success(
            request,
            f"Token '{tok.name}' regenerated. Old token is now invalid.",
        )
        return redirect("token-list")


class TokenDeleteView(AdminRequiredMixin, View):
    """`POST /access/tokens/<pk>/delete/` — hard delete the row.

    Allowed regardless of revoked state — the row carries no secret value
    that can be replayed (only a hash), so deletion is purely cosmetic.
    """

    def post(self, request, pk):
        tok = get_object_or_404(IngestToken, pk=pk)
        name = tok.name
        tok.delete()
        messages.success(request, f"Token '{name}' deleted.")
        return redirect("token-list")


