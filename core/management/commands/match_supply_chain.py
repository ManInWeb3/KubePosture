"""Run the supply-chain matcher against the IoC + SBOM tables.

Usage:
  manage.py match_supply_chain                       # full re-scan
  manage.py match_supply_chain --purl pkg:npm/lodash@4.17.21
  manage.py match_supply_chain --purl pkg:npm/x@1 --purl pkg:npm/y@2

Normally the matcher runs automatically inside the feed fetchers
(`enrich_fetch --source osv-supply-chain`). This command is for:

  - manual testing after seeding IoCs by hand
  - re-running the match if matching logic changed
  - one-off catch-up when an SBOM lands between cron ticks

Returns the number of findings created or updated.
"""
from __future__ import annotations

from django.core.management.base import BaseCommand

from core.services.supply_chain_matcher import match_iocs_to_components


class Command(BaseCommand):
    help = "Match the SupplyChainIoc table against deployed SbomComponents."

    def add_arguments(self, parser):
        parser.add_argument(
            "--purl",
            action="append",
            default=[],
            help=(
                "Scope the join to these purls (incremental mode). "
                "Repeatable. Omit for a full re-scan."
            ),
        )

    def handle(self, *args, **options):
        purls = options["purl"] or None
        n = match_iocs_to_components(touched_purls=purls)
        scope = f"{len(purls)} purl(s)" if purls else "all IoCs"
        self.stdout.write(self.style.SUCCESS(
            f"match_supply_chain: scope={scope} findings_touched={n}"
        ))
