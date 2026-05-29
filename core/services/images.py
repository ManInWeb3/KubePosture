"""Images service — queries backing the `/images/` page.

`/images/` ranks container images by blast-radius impact, so users
patching an image can find the highest-leverage target fast:

    impact = workloads_using_image × Σ(weight[band] × cve_count_in_band)

Powers-of-10 weights guarantee a single IMMEDIATE always outranks any
pile of lower-band findings, matching `docs/urgency-decision-tree.md`.
A secondary `impact_per_cve` sort exposes "quick wins" — few CVEs
across many workloads, one patch unblocks many findings.

Band counts always reflect findings on (workload, image) pairs that
are currently deployed (see `restrict_to_currently_deployed_images`).
The `currently_deployed_only` toggle controls which images appear in
the list, not the finding scope — so historical-only images surface
with zero counts rather than misleading stale ones.
"""
from __future__ import annotations

import re
from typing import Optional

from django.db.models import Count, Exists, OuterRef

from core.constants import PriorityBand
from core.models import (
    Cluster,
    Image,
    SbomComponent,
    WorkloadImageObservation,
)
from core.services.inventory import (
    _band_counts_by,
    _empty_band_counts,
    _priority_rank_annotation,
    _severity_rank_annotation,
    default_finding_qs,
    restrict_to_currently_deployed_images,
)


# Powers of 10 — a single IMMEDIATE outranks any pile of lower bands.
IMPACT_WEIGHTS = {
    PriorityBand.IMMEDIATE.value:   1000,
    PriorityBand.OUT_OF_BAND.value:  100,
    PriorityBand.SCHEDULED.value:     10,
    PriorityBand.DEFER.value:          1,
}


_ALLOWED_SORTS = {
    "impact",
    "impact_per_cve",
    "workload_count",
    "n_immediate", "n_out_of_band", "n_scheduled", "n_defer",
    "n_total",
    "repository",
    "last_seen_at",
}


# sha256:<hex>. Validate before any lookup to avoid surface for
# pathological inputs in path-routed views.
_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{32,128}$")


def _resolve_cluster(cluster):
    if cluster is None or isinstance(cluster, Cluster):
        return cluster
    return Cluster.objects.filter(name=cluster).first()


def list_images(
    *,
    cluster: str | Cluster | None = None,
    namespace: str | None = None,
    registry_contains: str | None = None,
    repository_contains: str | None = None,
    currently_deployed_only: bool = True,
    sort: str | None = None,
    sort_dir: str = "desc",
):
    """Return display rows for the `/images/` landing.

    One dict per Image: registry / repository / ref / digest, workload
    count (currently-deployed observations, optionally cluster- or
    namespace-scoped), four priority-band CVE counts, total CVEs,
    computed `impact` and `impact_per_cve`, `last_seen_at`.

    Filters:
      - cluster: name or Cluster; scopes the observation join, the
        finding queryset, and the workload count.
      - namespace: name; image must have ≥1 currently_deployed
        observation in this namespace (intersected with `cluster` when
        present). Band counts stay fleet-wide so a high-impact image
        deployed in one namespace doesn't lose its full CVE picture.
      - registry_contains / repository_contains: case-insensitive
        substring on the Image columns.
      - currently_deployed_only: True (default) drops images with no
        live observation in scope; False also surfaces historical
        images (their band counts will be zero — band counts always
        reflect currently-deployed pairs).

    Sort: default `impact` desc. Whitelisted columns in `_ALLOWED_SORTS`.
    """
    cluster_obj = _resolve_cluster(cluster)

    images = Image.objects.with_currently_deployed(cluster=cluster_obj)
    if currently_deployed_only:
        images = images.filter(currently_deployed=True)
    if registry_contains:
        images = images.filter(registry__icontains=registry_contains)
    if repository_contains:
        images = images.filter(repository__icontains=repository_contains)
    if namespace:
        ns_obs = WorkloadImageObservation.objects.filter(
            image=OuterRef("pk"),
            currently_deployed=True,
            workload__namespace__name=namespace,
        )
        if cluster_obj is not None:
            ns_obs = ns_obs.filter(workload__cluster=cluster_obj)
        images = images.annotate(_ns_match=Exists(ns_obs)).filter(_ns_match=True)

    image_ids = list(images.values_list("pk", flat=True))
    if not image_ids:
        return []

    finding_qs = restrict_to_currently_deployed_images(
        default_finding_qs(cluster=cluster_obj).filter(image_id__in=image_ids)
    )
    band_counts = _band_counts_by(finding_qs, "image_id")

    wl_obs_qs = WorkloadImageObservation.objects.filter(
        image_id__in=image_ids, currently_deployed=True,
    )
    if cluster_obj is not None:
        wl_obs_qs = wl_obs_qs.filter(workload__cluster=cluster_obj)
    if namespace:
        wl_obs_qs = wl_obs_qs.filter(workload__namespace__name=namespace)
    wl_counts = dict(
        wl_obs_qs.values("image_id")
        .annotate(n=Count("workload_id", distinct=True))
        .values_list("image_id", "n")
    )

    rows: list[dict] = []
    for img in images:
        c = band_counts.get(img.pk, _empty_band_counts())
        wl = wl_counts.get(img.pk, 0)
        weighted = sum(IMPACT_WEIGHTS[b] * n for b, n in c.items())
        total_cves = sum(c.values())
        impact = wl * weighted
        rows.append(
            {
                "image": img,
                "digest": img.digest,
                "ref": img.ref,
                "registry": img.registry,
                "repository": img.repository,
                "workload_count": wl,
                "n_immediate": c[PriorityBand.IMMEDIATE.value],
                "n_out_of_band": c[PriorityBand.OUT_OF_BAND.value],
                "n_scheduled": c[PriorityBand.SCHEDULED.value],
                "n_defer": c[PriorityBand.DEFER.value],
                "n_total": total_cves,
                "impact": impact,
                "impact_per_cve": (impact / total_cves) if total_cves else 0,
                "last_seen_at": img.last_seen_at,
                "currently_deployed": getattr(img, "currently_deployed", False),
            }
        )

    sort_key = sort if sort in _ALLOWED_SORTS else "impact"
    reverse = sort_dir != "asc"

    def _label(r) -> str:
        return (r["repository"] or r["ref"] or r["digest"] or "").lower()

    if sort_key == "last_seen_at":
        rows.sort(
            key=lambda r: (r["last_seen_at"] or 0, _label(r)),
            reverse=reverse,
        )
    elif sort_key == "repository":
        rows.sort(key=_label, reverse=reverse)
    else:
        rows.sort(
            key=lambda r: (r[sort_key] or 0, _label(r)),
            reverse=reverse,
        )
    return rows


def is_valid_digest(digest: str) -> bool:
    """sha256:<hex>. Cheap guard before any DB lookup in path-routed views."""
    return bool(digest) and bool(_DIGEST_RE.match(digest))


def get_image_detail(digest: str) -> Optional[dict]:
    """Return the image-detail payload, or None if digest is unknown.

    Shape:
        {
          "image": Image,
          "workload_rows": [
              {"observation", "workload", "cluster", "namespace",
               "container_name", "init_container",
               "first_seen_at", "last_seen_at"}, ...
          ],
          "findings_qs": Finding queryset, urgency-ordered (SQL),
                         scoped to currently-deployed (workload, image)
                         pairs to match the workloads table.
          "sbom_count": int — distinct SbomComponent rows for this image.
        }
    """
    img = Image.objects.filter(digest=digest).first()
    if img is None:
        return None

    observations = (
        WorkloadImageObservation.objects.filter(image=img, currently_deployed=True)
        .select_related("workload", "workload__cluster", "workload__namespace")
        .order_by(
            "workload__cluster__name",
            "workload__namespace__name",
            "workload__kind",
            "workload__name",
            "container_name",
        )
    )
    workload_rows = [
        {
            "observation": o,
            "workload": o.workload,
            "cluster": o.workload.cluster,
            "namespace": o.workload.namespace,
            "container_name": o.container_name,
            "init_container": o.init_container,
            "first_seen_at": o.first_seen_at,
            "last_seen_at": o.last_seen_at,
        }
        for o in observations
    ]

    findings_qs = (
        restrict_to_currently_deployed_images(
            default_finding_qs().filter(image=img)
        )
        .annotate(
            _priority_rank=_priority_rank_annotation(),
            _severity_rank=_severity_rank_annotation(),
        )
        .order_by("-_priority_rank", "-_severity_rank", "-last_seen")
    )

    sbom_count = SbomComponent.objects.filter(image=img).count()

    return {
        "image": img,
        "workload_rows": workload_rows,
        "findings_qs": findings_qs,
        "sbom_count": sbom_count,
    }
