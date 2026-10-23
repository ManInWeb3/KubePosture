"""Run the OSV vulnerability matcher against the advisory + SBOM tables.

Usage:
  manage.py match_osv                    # every deployed component
  manage.py match_osv --image sha256:…   # one image

Normally the matcher runs by itself: per image at SBOM ingest and
fleet-wide at the end of `enrich_fetch --source osv`. This command is
for re-running it after a matching-logic change or for a one-off check
of one image.

Returns the number of findings created or updated.
"""
from __future__ import annotations

from core.management.base import KubePostureCommand
from core.models import Image
from core.services.osv_vuln_matcher import match_osv_vulns


class Command(KubePostureCommand):
    help = "Match deployed SbomComponents against the OSV advisory tables."

    def add_arguments(self, parser):
        parser.add_argument("--image", help="Image digest (sha256:…) to restrict the run to.")

    def handle(self, *args, **options):
        image = None
        if options["image"]:
            image = Image.objects.filter(digest=options["image"]).first()
            if image is None:
                self.stderr.write(f"no image with digest {options['image']}")
                return
        n = match_osv_vulns(image=image)
        scope = options["image"] or "all deployed components"
        self.stdout.write(self.style.SUCCESS(f"match_osv: scope={scope} findings_touched={n}"))
