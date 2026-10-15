"""Daily DB hygiene — prune stale rows across operational tables.

Usage:
  manage.py prune_stale_data                                    # default retention, real delete
  manage.py prune_stale_data --dry-run                          # show counts only
  manage.py prune_stale_data --ingest-queue-days 7              # custom retention
  manage.py prune_stale_data --skip-findings                    # disable one target

Targets, defaults, and rationale live in `core/services/pruning.py`.
This command is a thin wrapper that delegates to those functions.
"""
from __future__ import annotations

import inspect

from core.management.base import KubePostureCommand
from core.services.pruning import (
    prune_import_marks,
    prune_ingest_queue,
    prune_scan_inconsistencies,
    prune_stale_findings,
    prune_stale_sbom_components,
)

# (option_name, fetcher, days_kwarg); the retention defaults are the
# pruners' own keyword defaults in core/services/pruning.py.
_TARGETS = [
    ("ingest_queue",        prune_ingest_queue,           "ingest_queue_days"),
    ("import_marks",        prune_import_marks,           "import_marks_days"),
    ("scan_inconsistencies", prune_scan_inconsistencies,  "scan_inconsistencies_days"),
    ("findings",            prune_stale_findings,         "findings_days"),
    ("sbom_components",     prune_stale_sbom_components,  "sbom_components_days"),
]


def _default_days(fn) -> int:
    return inspect.signature(fn).parameters["days"].default


class Command(KubePostureCommand):
    help = "Daily DB hygiene — prune stale rows across operational tables."

    def add_arguments(self, parser):
        parser.add_argument(
            "--dry-run", action="store_true",
            help="Count rows that would be deleted without deleting.",
        )
        for name, fn, _days_kw in _TARGETS:
            parser.add_argument(
                f"--{name.replace('_', '-')}-days",
                type=int, default=None,
                help=f"Retention window for the {name} target (days). "
                     f"Default: {_default_days(fn)}.",
            )
            parser.add_argument(
                f"--skip-{name.replace('_', '-')}",
                action="store_true",
                help=f"Skip the {name} target entirely.",
            )

    def handle(self, *args, **options):
        results = []
        for name, fn, days_kw in _TARGETS:
            if options[f"skip_{name}"]:
                self.stdout.write(f"  {name}: skipped")
                continue
            kwargs = {"dry_run": options["dry_run"]}
            if options[days_kw] is not None:
                kwargs["days"] = options[days_kw]
            res = fn(**kwargs)
            results.append(res)
            self.stdout.write(
                f"  {res.target}: scanned={res.scanned} deleted={res.deleted}"
            )

        total_scanned = sum(r.scanned for r in results)
        total_deleted = sum(r.deleted for r in results)
        verb = "would delete" if options["dry_run"] else "deleted"
        self.stdout.write(self.style.SUCCESS(
            f"prune_stale_data: {verb} {total_deleted} of {total_scanned} scanned"
        ))
