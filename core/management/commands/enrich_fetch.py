"""Fetch enrichment feeds + apply.

Usage:
  manage.py enrich_fetch --source {epss|kev|osv}

`osv` applies the OSV.dev bulk zips (malicious-package IoCs and
vulnerability advisories) and then runs the vulnerability matcher over
every deployed SBOM component. `osv-supply-chain` is the pre-lane name
of the same thing.

Network failures are non-fatal: the underlying loaders honour the
zero-input rule and leave existing rows intact.
"""

from core.management.base import KubePostureCommand
from core.services.enrichment import (
    fetch_epss,
    fetch_kev,
    refresh_osv,
)

_FETCHERS = {
    "epss": fetch_epss,
    "kev": fetch_kev,
    "osv": refresh_osv,
    "osv-supply-chain": refresh_osv,
}


class Command(KubePostureCommand):
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
