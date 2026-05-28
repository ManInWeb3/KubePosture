"""Completely remove a cluster and every row tied to it.

Drops the Cluster row — cascading to all its namespaces, workloads,
findings, finding history, snapshots, import marks, scan
inconsistencies, … — plus the IngestQueue rows that reference it by
name. Global / shared data (container images, ingest tokens, EPSS/KEV
enrichment, SBOM inventory, IoC feeds) is preserved. The full rationale
and the cascade map live in `core/services/cluster_removal.py`.

Usage:
  manage.py remove_cluster --cluster some-cluster --dry-run   # preview counts
  manage.py remove_cluster --cluster some-cluster             # prompt, then delete
  manage.py remove_cluster --cluster some-cluster --yes       # no prompt (scripts)
"""
from __future__ import annotations

from django.core.management.base import BaseCommand, CommandError

from core.models import Cluster
from core.services.cluster_removal import remove_cluster


class Command(BaseCommand):
    help = "Completely remove a cluster and all data tied to it."

    def add_arguments(self, parser):
        parser.add_argument(
            "--cluster", required=True,
            help="Name of the cluster to remove.",
        )
        parser.add_argument(
            "--dry-run", action="store_true",
            help="Show what would be deleted without deleting.",
        )
        parser.add_argument(
            "--yes", action="store_true",
            help="Skip the interactive confirmation prompt.",
        )

    def handle(self, *args, **opts):
        name = opts["cluster"]
        try:
            cluster = Cluster.objects.get(name=name)
        except Cluster.DoesNotExist:
            raise CommandError(f"No cluster named {name!r}.")

        # Always show a preview before touching anything.
        preview = remove_cluster(cluster, dry_run=True)
        if not preview.deleted:
            self.stdout.write(f"Cluster {name!r} has no related rows.")
        else:
            self.stdout.write(f"Rows tied to cluster {name!r}:")
            for label, n in sorted(preview.deleted.items()):
                self.stdout.write(f"  {label:32s} {n:>8d}")

        if opts["dry_run"]:
            self.stdout.write(self.style.WARNING(
                f"Dry run — nothing deleted. {preview.total} related rows "
                "(plus the cluster row) would go."
            ))
            return

        if not opts["yes"]:
            confirm = input(
                f"\nPermanently delete cluster {name!r} and everything above? "
                "This cannot be undone. [y/N] "
            ).strip().lower()
            if confirm not in ("y", "yes"):
                self.stdout.write("Aborted.")
                return

        result = remove_cluster(cluster)
        self.stdout.write(self.style.SUCCESS(
            f"Removed cluster {name!r} — deleted {result.total} rows across "
            f"{len(result.deleted)} tables."
        ))
