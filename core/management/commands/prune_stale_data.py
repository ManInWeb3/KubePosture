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

from django.core.management.base import BaseCommand

from core.services.pruning import (
    prune_import_marks,
    prune_ingest_queue,
    prune_scan_inconsistencies,
    prune_stale_findings,
    prune_stale_sbom_components,
)


# (option_name, fetcher, days_kwarg, days_default)
_TARGETS = [
    ("ingest_queue",        prune_ingest_queue,           "ingest_queue_days",         14),
    ("import_marks",        prune_import_marks,           "import_marks_days",         90),
    ("scan_inconsistencies",prune_scan_inconsistencies,   "scan_inconsistencies_days", 30),
    ("findings",            prune_stale_findings,         "findings_days",            180),
    ("sbom_components",     prune_stale_sbom_components,  "sbom_components_days",      90),
]


class Command(BaseCommand):
    help = "Daily DB hygiene — prune stale rows across operational tables."

    def add_arguments(self, parser):
        parser.add_argument(
            "--dry-run", action="store_true",
            help="Count rows that would be deleted without deleting.",
        )
        for name, _, days_kw, days_default in _TARGETS:
            parser.add_argument(
                f"--{name.replace('_', '-')}-days",
                type=int, default=days_default,
                help=f"Retention window for the {name} target (days). Default: {days_default}.",
            )
            parser.add_argument(
                f"--skip-{name.replace('_', '-')}",
                action="store_true",
                help=f"Skip the {name} target entirely.",
            )

    def handle(self, *args, **options):
        results = []
        for name, fn, days_kw, _ in _TARGETS:
            if options[f"skip_{name}"]:
                self.stdout.write(f"  {name}: skipped")
                continue
            res = fn(days=options[days_kw], dry_run=options["dry_run"])
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
