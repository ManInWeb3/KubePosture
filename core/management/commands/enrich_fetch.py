"""Fetch enrichment feeds + apply.

Usage:
  manage.py enrich_fetch --source {epss|kev|osv-supply-chain|aikido}

Network failures are non-fatal: the underlying loaders honour the
zero-input rule and leave existing rows intact.
"""
from django.core.management.base import BaseCommand

from core.services.enrichment import (
    fetch_aikido_iocs,
    fetch_epss,
    fetch_kev,
    fetch_osv_supply_chain,
)


_FETCHERS = {
    "epss": fetch_epss,
    "kev": fetch_kev,
    "osv-supply-chain": fetch_osv_supply_chain,
    "aikido": fetch_aikido_iocs,
}


class Command(BaseCommand):
    help = "Fetch the latest enrichment feed over HTTP and apply it."

    def add_arguments(self, parser):
        parser.add_argument(
            "--source",
            choices=sorted(_FETCHERS),
            required=True,
        )

    def handle(self, *args, **options):
        source = options["source"]
        fetcher = _FETCHERS[source]
        n = fetcher()
        if n == 0:
            self.stdout.write(self.style.WARNING(
                f"{source}: 0 rows applied (fetch failed or empty — existing rows preserved)"
            ))
        else:
            self.stdout.write(self.style.SUCCESS(f"{source}: {n} rows applied"))
