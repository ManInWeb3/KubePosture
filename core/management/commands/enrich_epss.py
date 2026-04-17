"""
Download EPSS scores and update findings.

Usage:
  python manage.py enrich_epss
  python manage.py enrich_epss --url https://custom-mirror/epss.csv.gz

Run as daily K8s CronJob.
See: docs/architecture.md § F6
"""
from django.core.management.base import BaseCommand

from core.services.enrichment import EPSS_URL, enrich_epss


class Command(BaseCommand):
    help = "Download EPSS exploit probability scores and update CVE findings"

    def add_arguments(self, parser):
        parser.add_argument(
            "--url",
            type=str,
            default=EPSS_URL,
            help=f"EPSS CSV URL (default: {EPSS_URL})",
        )

    def handle(self, *args, **options):
        self.stdout.write("Downloading EPSS scores...")
        result = enrich_epss(url=options["url"])
        self.stdout.write(
            self.style.SUCCESS(
                f"EPSS: {result['scores_downloaded']} scores downloaded, "
                f"{result['findings_updated']} findings updated"
            )
        )
