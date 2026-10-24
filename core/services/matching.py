"""The step every matcher shares: finding dicts → findings.

A matcher (`supply_chain_matcher`, `osv_vuln_matcher`) joins a feed against
`SbomComponent` rows and decides which components are affected. What is
common to all of them happens here: a component belongs to an *image*, an
image runs in *workloads*, and a finding is per (workload, image, package,
vuln) — so the finding dicts of one image are upserted once for every
workload the image is currently deployed in, stamped with the same
observation time. `core.services.dedup.upsert_findings` does the rest
(hash, enrichment, scoring, create / bump `last_seen`).

A matcher that bumps `last_seen` is what keeps its findings in the default
views: they hide once `last_seen` falls behind the cluster's latest
complete inventory (`core.services.inventory.base_finding_filter`), so
every matcher also has to run per image at SBOM ingest —
`core.services.ingest` calls each image-scoped matcher with
`matcher(image=image)`.
"""
from __future__ import annotations

from collections.abc import Callable, Sequence

from core.models import Image, Workload, WorkloadImageObservation
from core.services.dedup import upsert_findings

# Narrows / rewrites the finding dicts for one workload; may return [].
WorkloadFilter = Callable[[Workload, Sequence[dict]], Sequence[dict]]


def emit_for_image(
    image: Image,
    findings: Sequence[dict],
    now,
    *,
    for_workload: WorkloadFilter | None = None,
) -> int:
    """Upsert `findings` for every workload `image` is currently deployed
    in. `for_workload` lets a matcher drop or reshape the dicts per
    workload (the OSV lane skips what Trivy already reports for that
    workload); without it every workload gets all of them.

    Returns the number of findings created + updated; 0 when the image is
    not deployed anywhere or nothing is left to upsert.
    """
    if not findings:
        return 0
    observations = (
        WorkloadImageObservation.objects
        .filter(image=image, currently_deployed=True)
        .select_related("workload", "workload__cluster")
    )
    total = 0
    for obs in observations:
        workload = obs.workload
        dicts = for_workload(workload, findings) if for_workload else findings
        if not dicts:
            continue
        created, updated = upsert_findings(
            cluster=workload.cluster, workload=workload, image=image,
            findings=dicts, observation_time=now,
        )
        total += created + updated
    return total
