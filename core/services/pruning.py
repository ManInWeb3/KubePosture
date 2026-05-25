"""DB hygiene — prune stale rows from operational tables.

One function per target. Each is pure-ORM, returns a `PruneResult`, and
honours `dry_run` (count without delete).

Targets and rationale:

- **IngestQueue** — DONE/FAILED items are never re-read; default 14 days.
- **ImportMark** — REAPED state is audit-only; default 90 days.
- **ScanInconsistency** — per the model's docstring, "rows older than
  30 days are pruned by a maintenance job"; default 30 days.
- **Finding** — soft-resolved findings (workload undeployed or NULL,
  not observed for a long window); default 180 days.
- **SbomComponent** — components on images that haven't been observed
  recently AND aren't currently deployed anywhere; default 90 days.

`Image` is intentionally NOT pruned (append-only by design per
[image.py](../models/image.py)). `FindingAction` and `WorkloadSignal`
are also out of scope — see plan.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import timedelta

from django.db.models import Exists, OuterRef, Q
from django.utils import timezone

from core.constants import ImportMarkState, IngestQueueStatus
from core.models import (
    Finding,
    Image,
    ImportMark,
    IngestQueue,
    SbomComponent,
    ScanInconsistency,
    WorkloadImageObservation,
)


@dataclass(frozen=True)
class PruneResult:
    target: str
    scanned: int          # rows matching the predicate
    deleted: int          # rows actually deleted (== scanned, or 0 in dry-run)


def _cutoff(days: int):
    return timezone.now() - timedelta(days=days)


def prune_ingest_queue(*, days: int = 14, dry_run: bool = False) -> PruneResult:
    """DONE/FAILED queue items older than `days` are safe to delete —
    the worker never re-reads them, and the audit value beyond two
    weeks is low.
    """
    qs = IngestQueue.objects.filter(
        status__in=[IngestQueueStatus.DONE.value, IngestQueueStatus.FAILED.value],
        processed_at__isnull=False,
        processed_at__lt=_cutoff(days),
    )
    n = qs.count()
    if not dry_run and n:
        qs.delete()
    return PruneResult("ingest_queue", n, 0 if dry_run else n)


def prune_import_marks(*, days: int = 90, dry_run: bool = False) -> PruneResult:
    """REAPED marks are an audit log of completed imports. No
    operational code paths read them after reap.
    """
    qs = ImportMark.objects.filter(
        state=ImportMarkState.REAPED.value,
        completed_at__isnull=False,
        completed_at__lt=_cutoff(days),
    )
    n = qs.count()
    if not dry_run and n:
        qs.delete()
    return PruneResult("import_marks", n, 0 if dry_run else n)


def prune_scan_inconsistencies(*, days: int = 30, dry_run: bool = False) -> PruneResult:
    """Per the model docstring at scan_inconsistency.py:9 — "rows older
    than 30 days are pruned by a maintenance job". This is that job.
    """
    qs = ScanInconsistency.objects.filter(last_observed_at__lt=_cutoff(days))
    n = qs.count()
    if not dry_run and n:
        qs.delete()
    return PruneResult("scan_inconsistencies", n, 0 if dry_run else n)


def prune_stale_findings(*, days: int = 180, dry_run: bool = False) -> PruneResult:
    """Hard-delete Findings that have:
      - `last_seen` older than `days`, AND
      - their workload undeployed (or no workload — cluster-scoped).

    Findings on currently-deployed workloads are protected (every
    inventory cycle bumps `last_seen`, so they can't naturally drift
    past the cutoff).

    Cluster-scoped findings (`workload IS NULL`) are pruned on the same
    rule via the OR branch — for those the `last_seen` cutoff is the
    only safeguard.
    """
    qs = Finding.objects.filter(
        last_seen__lt=_cutoff(days),
    ).filter(Q(workload__deployed=False) | Q(workload__isnull=True))
    n = qs.count()
    if not dry_run and n:
        qs.delete()
    return PruneResult("findings", n, 0 if dry_run else n)


def prune_stale_sbom_components(*, days: int = 90, dry_run: bool = False) -> PruneResult:
    """Delete SbomComponent rows attached to images that:
      - haven't been observed (`Image.last_seen_at`) in `days`, AND
      - have **no** WorkloadImageObservation with `currently_deployed=True`.

    Image rows themselves are NOT deleted (append-only by model
    contract). Components on images that come back online later will
    be re-created by the next Trivy SbomReport ingest.
    """
    cutoff = _cutoff(days)
    stale_images = Image.objects.filter(last_seen_at__lt=cutoff).annotate(
        has_current=Exists(
            WorkloadImageObservation.objects.filter(
                image=OuterRef("pk"), currently_deployed=True,
            )
        ),
    ).filter(has_current=False)
    qs = SbomComponent.objects.filter(image__in=stale_images)
    n = qs.count()
    if not dry_run and n:
        qs.delete()
    return PruneResult("sbom_components", n, 0 if dry_run else n)
