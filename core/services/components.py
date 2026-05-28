"""Components service — queries backing the `/components/` SBOM browser.

`/components/` shows one row per unique `purl` (grouped across all images
that contain it), with image / workload / cluster counts. The per-row
SbomComponent model carries `(image, purl)`; aggregation to display rows
happens here, not in queryset annotations.

Stage 1 (this module): browse + search. Stage 2 will add an `is_flagged`
annotation and a `flagged_only` filter once `SupplyChainIoc` exists.
"""
from __future__ import annotations

from typing import Iterable

from django.db.models import Count, Q

from core.models import (
    Cluster,
    SbomComponent,
    WorkloadImageObservation,
)
from core.purl import normalize_purl


# ── List view (grouped by purl) -----------------------------------

_LIST_SORTS = {
    "name": "name",
    "version": "version",
    "ecosystem": "ecosystem",
    "image_count": "image_count",
    "workload_count": "workload_count",
    "cluster_count": "cluster_count",
}


def list_components(
    *,
    name_contains: str | None = None,
    ecosystem: str | None = None,
    cluster: Cluster | None = None,
    include_inactive: bool = False,
    sort: str | None = None,
    sort_dir: str = "asc",
):
    """Return a values-queryset grouped by `purl` for the components list.

    Each row carries: purl, name, version, ecosystem, image_count,
    workload_count, cluster_count. Cluster filter scopes both which
    components are considered AND the count joins, so the counts
    reflect the displayed scope.
    """
    qs = SbomComponent.objects.all()

    if not include_inactive:
        qs = qs.active(cluster=cluster)
    elif cluster is not None:
        qs = qs.filter(
            image__observations__workload__cluster=cluster,
        ).distinct()

    if name_contains:
        # Search across name + purl + version so the bar accepts any of:
        #   "lodash"  ·  "lodash@4.17.21"  ·  "pkg:npm/lodash@4.17.21"
        # The same `%40 -> @` normalisation we do on stored purls is
        # applied to the query so users can paste either encoding.
        needle = normalize_purl(name_contains)
        qs = qs.filter(
            Q(name__icontains=needle)
            | Q(purl__icontains=needle)
            | Q(version__icontains=needle)
        )
    if ecosystem:
        qs = qs.filter(ecosystem=ecosystem)

    obs_filter = Q(image__observations__currently_deployed=True)
    if cluster is not None:
        obs_filter &= Q(image__observations__workload__cluster=cluster)

    rows = qs.values("purl", "name", "version", "ecosystem").annotate(
        image_count=Count("image", distinct=True),
        workload_count=Count(
            "image__observations__workload",
            filter=obs_filter,
            distinct=True,
        ),
        cluster_count=Count(
            "image__observations__workload__cluster",
            filter=obs_filter,
            distinct=True,
        ),
    )

    sort_field = _LIST_SORTS.get(sort or "", "name")
    prefix = "" if sort_dir == "asc" else "-"
    # Secondary sort by name+version for stable pagination.
    if sort_field == "name":
        rows = rows.order_by(f"{prefix}name", f"{prefix}version")
    else:
        rows = rows.order_by(f"{prefix}{sort_field}", "name", "version")

    return rows


def list_ecosystems(*, cluster: Cluster | None = None) -> list[str]:
    """Distinct ecosystem values currently active, for the filter dropdown."""
    qs = SbomComponent.objects.active(cluster=cluster)
    values = (
        qs.exclude(ecosystem="")
          .order_by("ecosystem")
          .values_list("ecosystem", flat=True)
          .distinct()
    )
    return list(values)


def summary_counts(*, cluster: Cluster | None = None) -> dict:
    """Counts for the `_summary_tiles.html` partial.

    Stage 1 returns total + per-ecosystem buckets. Stage 2 will add a
    `flagged` count.
    """
    qs = SbomComponent.objects.active(cluster=cluster)
    total = qs.values("purl").distinct().count()
    per_ecosystem = (
        qs.values("ecosystem")
          .annotate(n=Count("purl", distinct=True))
          .order_by("-n")
    )
    return {
        "total": total,
        "per_ecosystem": list(per_ecosystem),
    }


# ── Detail panel --------------------------------------------------


def component_detail(
    purl: str,
    *,
    cluster: Cluster | None = None,
    include_inactive: bool = False,
) -> dict | None:
    purl = normalize_purl(purl)
    """Return the detail-panel payload for one purl, or None if absent.

    Shape:
        {
          "purl", "name", "version", "ecosystem", "component_type",
          "license", "supplier",
          "images": [
              {"image": Image,
               "workloads": [{"workload": Workload, "container_name": str}, ...]},
              ...
          ],
          "other_versions": [
              {"purl", "version", "image_count", "workload_count"},
              ...
          ],
        }
    """
    base_qs = SbomComponent.objects.filter(purl=purl)
    if not include_inactive:
        base_qs = base_qs.active(cluster=cluster)
    elif cluster is not None:
        base_qs = base_qs.filter(
            image__observations__workload__cluster=cluster,
        ).distinct()

    rows = list(base_qs.select_related("image"))
    if not rows:
        return None

    first = rows[0]

    obs_filter = Q(currently_deployed=True)
    if cluster is not None:
        obs_filter &= Q(workload__cluster=cluster)

    images_payload: list[dict] = []
    for row in rows:
        observations = (
            WorkloadImageObservation.objects
            .filter(image=row.image)
            .filter(obs_filter)
            .select_related("workload", "workload__cluster", "workload__namespace")
            .order_by(
                "workload__cluster__name",
                "workload__namespace__name",
                "workload__name",
                "container_name",
            )
        )
        wl_payload = [
            {"workload": o.workload, "container_name": o.container_name}
            for o in observations
        ]
        images_payload.append({"image": row.image, "workloads": wl_payload})

    # Other versions of the same name (different purls).
    other_qs = SbomComponent.objects.filter(name=first.name).exclude(purl=purl)
    if not include_inactive:
        other_qs = other_qs.active(cluster=cluster)
    elif cluster is not None:
        other_qs = other_qs.filter(
            image__observations__workload__cluster=cluster,
        ).distinct()

    other_obs_filter = Q(image__observations__currently_deployed=True)
    if cluster is not None:
        other_obs_filter &= Q(image__observations__workload__cluster=cluster)

    other_versions = list(
        other_qs.values("purl", "version", "ecosystem").annotate(
            image_count=Count("image", distinct=True),
            workload_count=Count(
                "image__observations__workload",
                filter=other_obs_filter,
                distinct=True,
            ),
        ).order_by("version")
    )

    return {
        "purl": first.purl,
        "name": first.name,
        "version": first.version,
        "ecosystem": first.ecosystem,
        "component_type": first.component_type,
        "license": first.license,
        "supplier": first.supplier,
        "images": images_payload,
        "other_versions": other_versions,
    }


# ── Search API + CLI ----------------------------------------------


def search_by_purls(
    *,
    purls: Iterable[str] | None = None,
    purl_prefixes: Iterable[str] | None = None,
    cluster: Cluster | None = None,
    include_inactive: bool = False,
) -> list[dict]:
    """Backs `POST /api/v1/sbom/search/` and `manage.py search_sbom`.

    Returns one row per (cluster, workload, purl), with image and
    component metadata. Pass either exact purls or prefixes (e.g.
    `pkg:npm/lodash` matches every version).
    """
    purls = [normalize_purl(p) for p in (purls or []) if p]
    purl_prefixes = [normalize_purl(p) for p in (purl_prefixes or []) if p]
    if not purls and not purl_prefixes:
        return []

    qs = SbomComponent.objects.all()
    if not include_inactive:
        qs = qs.active(cluster=cluster)
    elif cluster is not None:
        qs = qs.filter(
            image__observations__workload__cluster=cluster,
        ).distinct()

    purl_q = Q()
    if purls:
        purl_q |= Q(purl__in=purls)
    for prefix in purl_prefixes:
        purl_q |= Q(purl__startswith=prefix)
    qs = qs.filter(purl_q)

    rows = qs.select_related("image").prefetch_related(
        "image__observations__workload__cluster",
        "image__observations__workload__namespace",
    )

    obs_filter = Q()
    if not include_inactive:
        obs_filter &= Q(currently_deployed=True)
    if cluster is not None:
        obs_filter &= Q(workload__cluster=cluster)

    out: list[dict] = []
    for comp in rows:
        observations = (
            comp.image.observations.filter(obs_filter)
            .select_related("workload", "workload__cluster", "workload__namespace")
        )
        for obs in observations:
            w = obs.workload
            out.append({
                "cluster": w.cluster.name,
                "namespace": w.namespace.name if w.namespace else "",
                "workload_kind": w.kind,
                "workload_name": w.name,
                "container_name": obs.container_name,
                "image_ref": comp.image.ref,
                "image_digest": comp.image.digest,
                "purl": comp.purl,
                "name": comp.name,
                "version": comp.version,
                "ecosystem": comp.ecosystem,
            })

    out.sort(key=lambda r: (
        r["cluster"], r["namespace"], r["workload_name"], r["purl"],
    ))
    return out
