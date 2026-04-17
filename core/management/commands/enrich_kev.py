"""
Download CISA KEV list and update findings.

Usage:
  python manage.py enrich_kev
  python manage.py enrich_kev --url https://custom-mirror/kev.json

Run as daily K8s CronJob.
See: docs/architecture.md § F31
"""
from django.core.management.base import BaseCommand

from core.services.enrichment import KEV_URL, enrich_kev


class Command(BaseCommand):
    help = "Download CISA Known Exploited Vulnerabilities and flag matching findings"

    def add_arguments(self, parser):
        parser.add_argument(
            "--url",
            type=str,
            default=KEV_URL,
            help=f"KEV JSON URL (default: {KEV_URL})",
        )

    def handle(self, *args, **options):
        self.stdout.write("Downloading CISA KEV list...")
        result = enrich_kev(url=options["url"])
        self.stdout.write(
            self.style.SUCCESS(
                f"KEV: {result['kev_cves_downloaded']} CVEs downloaded, "
                f"{result['marked_kev']} findings marked, "
                f"{result['cleared_kev']} findings cleared"
            )
        )
