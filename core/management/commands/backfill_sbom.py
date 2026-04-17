"""
Backfill Phase 1 raw SBOM reports into Component model.

Usage:
  python manage.py backfill_sbom
  python manage.py backfill_sbom --cluster cluster-name-1
"""
from django.core.management.base import BaseCommand

from core.services.sbom import backfill_raw_sbom


class Command(BaseCommand):
    help = "Backfill Phase 1 raw SBOM reports into Component model"

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
            self.stdout.write(f"Backfilling SBOM for cluster: {cluster_name}")
        else:
            self.stdout.write("Backfilling all raw SBOM reports...")

        result = backfill_raw_sbom(cluster_name=cluster_name)

        self.stdout.write(
            self.style.SUCCESS(
                f"Done: {result['processed']} processed, {result['errors']} errors"
            )
        )
