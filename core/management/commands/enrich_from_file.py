"""Load EPSS / KEV from a local file.

Usage:
  manage.py enrich_from_file --source {epss|kev} <path>
"""
from django.core.management.base import BaseCommand

from core.services.enrichment import (
    load_epss_from_file,
    load_kev_from_file,
)


class Command(BaseCommand):
    help = "Load enrichment data from a local file."

    def add_arguments(self, parser):
        parser.add_argument("--source", choices=["epss", "kev"], required=True)
        parser.add_argument("path")

    def handle(self, *args, **options):
        loaders = {
            "epss": load_epss_from_file,
            "kev": load_kev_from_file,
        }
        n = loaders[options["source"]](options["path"])
        self.stdout.write(self.style.SUCCESS(
            f"{options['source']}: {n} rows loaded from {options['path']}"
        ))
