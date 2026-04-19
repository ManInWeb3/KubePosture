"""
Recalculate effective_priority for findings.

Usage:
  manage.py recalculate_priorities                  # all clusters
  manage.py recalculate_priorities --cluster cluster-name-1  # single cluster
  manage.py recalculate_priorities --dry-run        # show what would change
"""
from django.core.management.base import BaseCommand, CommandError

from core.constants import Status
from core.models import Cluster, Finding
from core.services.priority import compute_priority, recalculate_cluster_priorities


class Command(BaseCommand):
    help = "Recalculate effective_priority for active findings based on current cluster flags and enrichment data."

    def add_arguments(self, parser):
        parser.add_argument(
            "--cluster",
            type=str,
            help="Recalculate for a specific cluster only (by name)",
        )
        parser.add_argument(
            "--dry-run",
            action="store_true",
            help="Show what would change without saving",
        )

    def handle(self, *args, **options):
        cluster_name = options["cluster"]
        dry_run = options["dry_run"]

        if cluster_name:
            try:
                clusters = [Cluster.objects.get(name=cluster_name)]
            except Cluster.DoesNotExist:
                raise CommandError(f"Cluster '{cluster_name}' not found")
        else:
            clusters = list(Cluster.objects.all())

        if not clusters:
            self.stdout.write("No clusters found.")
            return

        total_updated = 0
        for cluster in clusters:
            if dry_run:
                updated = self._dry_run_cluster(cluster)
            else:
                updated = recalculate_cluster_priorities(cluster)

            self.stdout.write(
                f"  {cluster.name}: {updated} findings "
                f"{'would be ' if dry_run else ''}updated"
                f" (env={cluster.environment}, exposed={cluster.has_public_exposure},"
                f" sensitive={cluster.has_sensitive_data})"
            )
            total_updated += updated

        prefix = "Would update" if dry_run else "Updated"
        self.stdout.write(
            self.style.SUCCESS(
                f"\n{prefix} {total_updated} findings across {len(clusters)} clusters."
            )
        )

    def _dry_run_cluster(self, cluster):
        """Count how many findings would change without saving."""
        findings = Finding.objects.filter(
            cluster=cluster,
            status__in=[Status.ACTIVE, Status.ACKNOWLEDGED],
        ).select_related("cluster")

        would_change = 0
        for finding in findings.iterator(chunk_size=1000):
            new_priority = compute_priority(finding, cluster)
            if finding.effective_priority != new_priority:
                would_change += 1

        return would_change
