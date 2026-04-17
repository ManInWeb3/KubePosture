"""
Backfill Phase 1 raw compliance reports into structured models.

Usage:
  python manage.py backfill_compliance
  python manage.py backfill_compliance --cluster cluster-name-1

Processes RawReport entries with kind=ClusterComplianceReport,
creating Snapshot + ControlResult records from the stored JSON.
"""
from django.core.management.base import BaseCommand

from core.services.compliance import backfill_raw_reports


class Command(BaseCommand):
    help = "Backfill Phase 1 raw compliance reports into structured models"

    def add_arguments(self, parser):
        parser.add_argument(
            "--cluster",
            type=str,
            default=None,
            help="Only backfill reports for this cluster name",
        )

    def handle(self, *args, **options):
        cluster_name = options["cluster"]
        if cluster_name:
            self.stdout.write(f"Backfilling compliance for cluster: {cluster_name}")
        else:
            self.stdout.write("Backfilling all raw compliance reports...")

        result = backfill_raw_reports(cluster_name=cluster_name)

        self.stdout.write(
            self.style.SUCCESS(
                f"Done: {result['processed']} processed, {result['errors']} errors"
            )
        )
