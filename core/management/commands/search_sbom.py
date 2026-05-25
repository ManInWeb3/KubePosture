"""CLI: find which clusters/workloads have a given purl deployed.

Usage:
    manage.py search_sbom --purl pkg:npm/lodash@4.17.21
    manage.py search_sbom --prefix pkg:npm/eslint-config-prettier
    manage.py search_sbom --purl ... --prefix ... --cluster prod-east
    manage.py search_sbom --purls-file iocs.txt          # one purl/prefix per line

Output is a tab-separated table on stdout. Exit code is 1 if no matches.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

from django.core.management.base import BaseCommand

from core.models import Cluster
from core.purl import normalize_purl
from core.services.components import search_by_purls


class Command(BaseCommand):
    help = "Search the SBOM inventory for purls / purl prefixes."

    def add_arguments(self, parser):
        parser.add_argument("--purl", action="append", default=[])
        parser.add_argument("--prefix", action="append", default=[])
        parser.add_argument(
            "--purls-file",
            default=None,
            help=(
                "Path to a file with one purl/prefix per line. "
                "Lines ending in '*' are treated as prefixes."
            ),
        )
        parser.add_argument("--cluster", default=None)
        parser.add_argument(
            "--include-inactive",
            action="store_true",
            help="Include components from currently-undeployed images.",
        )
        parser.add_argument(
            "--json",
            action="store_true",
            help="Emit JSON instead of TSV.",
        )

    def handle(self, *args, **options):
        purls: list[str] = [normalize_purl(p) for p in (options["purl"] or [])]
        prefixes: list[str] = [normalize_purl(p) for p in (options["prefix"] or [])]

        if options["purls_file"]:
            path = Path(options["purls_file"])
            for raw in path.read_text().splitlines():
                line = raw.strip()
                if not line or line.startswith("#"):
                    continue
                if line.endswith("*"):
                    prefixes.append(normalize_purl(line.rstrip("*")))
                else:
                    purls.append(normalize_purl(line))

        if not purls and not prefixes:
            self.stderr.write("supply at least one of --purl / --prefix / --purls-file")
            sys.exit(2)

        cluster = None
        if options["cluster"]:
            cluster = Cluster.objects.filter(name=options["cluster"]).first()
            if cluster is None:
                self.stderr.write(f"cluster {options['cluster']!r} not found")
                sys.exit(2)

        rows = search_by_purls(
            purls=purls,
            purl_prefixes=prefixes,
            cluster=cluster,
            include_inactive=options["include_inactive"],
        )

        if options["json"]:
            self.stdout.write(json.dumps({"count": len(rows), "matches": rows}, indent=2))
        else:
            if not rows:
                self.stderr.write("no matches")
            else:
                self.stdout.write(
                    "cluster\tnamespace\tworkload\tcontainer\tpurl\timage"
                )
                for r in rows:
                    self.stdout.write(
                        "\t".join([
                            r["cluster"],
                            r["namespace"],
                            f"{r['workload_kind']}/{r['workload_name']}",
                            r["container_name"],
                            r["purl"],
                            r["image_ref"] or r["image_digest"][:20],
                        ])
                    )

        sys.exit(0 if rows else 1)
