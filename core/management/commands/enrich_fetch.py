"""Fetch EPSS or KEV from the public feed + apply.

Usage:
  manage.py enrich_fetch --source {epss|kev}

Network failures are non-fatal: the underlying loaders honour the
zero-input rule and leave existing rows intact.
"""
from django.core.management.base import BaseCommand

from core.services.enrichment import fetch_epss, fetch_kev


class Command(BaseCommand):
    help = "Fetch the latest EPSS or KEV feed over HTTP and apply it."

    def add_arguments(self, parser):
        parser.add_argument("--source", choices=["epss", "kev"], required=True)

    def handle(self, *args, **options):
        source = options["source"]
        fetcher = {"epss": fetch_epss, "kev": fetch_kev}[source]
        n = fetcher()
        if n == 0:
            self.stdout.write(self.style.WARNING(
                f"{source}: 0 rows applied (fetch failed or empty — existing rows preserved)"
            ))
        else:
            self.stdout.write(self.style.SUCCESS(f"{source}: {n} rows applied"))
