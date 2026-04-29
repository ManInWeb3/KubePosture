"""Wipe runtime tables (workloads, findings, queue, marks, …) but
preserve enrichment data, clusters, tokens, and Django auth.

Use this between dev-import attempts when you want a clean slate
WITHOUT re-fetching EPSS / KEV (which are slow) and WITHOUT
re-creating the Cluster + IngestToken (which would invalidate the
token your importer script is using).

Usage:
    python manage.py reset_runtime_data --yes

What gets TRUNCATEd:
  Finding, FindingAction
  Workload, WorkloadAlias, WorkloadImageObservation, WorkloadSignal
  Image
  Namespace
  ImportMark, IngestQueue
  ScanInconsistency
  Snapshot

What is PRESERVED:
  Cluster (incl. manual flags) — `consecutive_incomplete_inventories`
    is reset to 0
  IngestToken
  EpssScore, KevEntry
  auth_user, django_session, …
"""
from django.core.management.base import BaseCommand
from django.db import connection, transaction

from core.models import (
    Cluster,
    Finding,
    FindingAction,
    Image,
    ImportMark,
    IngestQueue,
    Namespace,
    ScanInconsistency,
    Snapshot,
    Workload,
    WorkloadAlias,
    WorkloadImageObservation,
    WorkloadSignal,
)


_RUNTIME_TABLES = [
    Finding,
    FindingAction,
    Snapshot,
    ScanInconsistency,
    WorkloadSignal,
    WorkloadAlias,
    WorkloadImageObservation,
    IngestQueue,
    ImportMark,
    Workload,
    Image,
    Namespace,
]


class Command(BaseCommand):
    help = "Wipe runtime data; preserve EPSS/KEV, Cluster, IngestToken."

    def add_arguments(self, parser):
        parser.add_argument(
            "--yes",
            action="store_true",
            help="Skip the interactive confirmation prompt.",
        )

    def handle(self, *args, **opts):
        if not opts["yes"]:
            confirm = input(
                "TRUNCATE Finding / Workload / Image / IngestQueue / "
                "ImportMark / … (preserves EPSS/KEV, Cluster, "
                "IngestToken). Continue? [y/N] "
            ).strip().lower()
            if confirm not in ("y", "yes"):
                self.stdout.write("Aborted.")
                return

        before = {m._meta.db_table: m.objects.count() for m in _RUNTIME_TABLES}

        table_names = [m._meta.db_table for m in _RUNTIME_TABLES]
        quoted = ", ".join(f'"{t}"' for t in table_names)
        with transaction.atomic():
            with connection.cursor() as cur:
                cur.execute(f"TRUNCATE {quoted} RESTART IDENTITY CASCADE")
            # Reset per-cluster counter so the next import lands on
            # a clean baseline.
            Cluster.objects.update(consecutive_incomplete_inventories=0)

        self.stdout.write(self.style.SUCCESS(
            f"Truncated {len(table_names)} tables. Row counts before:"
        ))
        for t, n in before.items():
            self.stdout.write(f"  {t:50s} {n:>8d}")

        self.stdout.write("")
        self.stdout.write(
            f"Preserved: Cluster ({Cluster.objects.count()}), "
            "IngestToken, EpssScore, KevEntry, auth_*."
        )
