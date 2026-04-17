"""
Re-applies cluster name parsing to already-registered clusters.

Use this after updating CLUSTER_NAME_PARSING_OVERRIDES_JSON (via Helm
clusterNameParsingOverrides) to push the corrected metadata into the DB
without waiting for the next ingest.

Only the parser-derived fields are touched: provider, environment, region,
project. Human-set fields (internet_exposed, contains_sensitive_data,
namespace_overrides, k8s_version) are never modified.

Usage:
  manage.py sync_cluster_meta              # all clusters
  manage.py sync_cluster_meta --cluster central-cluster legacy-payments
  manage.py sync_cluster_meta --dry-run    # preview changes, no writes
"""

from django.core.management.base import BaseCommand

from core.models import Cluster
from core.parsers.metadata import parse_cluster_meta

PARSER_FIELDS = ("provider", "environment", "region", "project")


class Command(BaseCommand):
    help = "Re-apply cluster name parsing to already-registered clusters."

    def add_arguments(self, parser):
        parser.add_argument(
            "--cluster",
            nargs="+",
            metavar="NAME",
            help="Limit to these cluster names (default: all clusters).",
        )
        parser.add_argument(
            "--dry-run",
            action="store_true",
            help="Print proposed changes without writing to the database.",
        )

    def handle(self, *args, **options):
        dry_run = options["dry_run"]
        cluster_filter = options["cluster"]

        qs = Cluster.objects.all()
        if cluster_filter:
            qs = qs.filter(name__in=cluster_filter)
            found = set(qs.values_list("name", flat=True))
            missing = set(cluster_filter) - found
            for name in sorted(missing):
                self.stderr.write(self.style.WARNING(f"  cluster not found: {name}"))

        updated = 0
        unchanged = 0

        for cluster in qs.order_by("name"):
            meta = parse_cluster_meta(cluster.name)
            changes = {
                field: meta[field]
                for field in PARSER_FIELDS
                if getattr(cluster, field) != meta[field]
            }

            if not changes:
                unchanged += 1
                self.stdout.write(f"  {cluster.name}: no change")
                continue

            old = {f: getattr(cluster, f) for f in changes}
            diff = "  ".join(f"{f}: {old[f]!r} → {changes[f]!r}" for f in changes)

            if dry_run:
                self.stdout.write(f"  {cluster.name} [DRY RUN]  {diff}")
            else:
                for field, value in changes.items():
                    setattr(cluster, field, value)
                cluster.save(update_fields=list(changes.keys()))
                self.stdout.write(
                    self.style.SUCCESS(f"  {cluster.name}  {diff}")
                )
            updated += 1

        mode = " (dry run)" if dry_run else ""
        self.stdout.write(
            f"\n{updated} cluster(s) updated{mode}, {unchanged} unchanged."
        )
