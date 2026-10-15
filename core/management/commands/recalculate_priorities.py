"""Force a bulk recompute of Finding.effective_priority.

Useful after a tweak to `core/urgency.py` or when a settings flip
should fan out across existing data.
"""

from core.management.base import KubePostureCommand
from core.models import Finding
from core.urgency import finding_ids, recompute_ids


class Command(KubePostureCommand):
    help = "Recompute effective_priority for every Finding (or a cluster's worth)."

    def add_arguments(self, parser):
        parser.add_argument("--cluster", default=None)

    def handle(self, *args, **options):
        qs = Finding.objects.all()
        if options["cluster"]:
            qs = qs.filter(cluster__name=options["cluster"])
        # Streamed + chunked: memory stays flat however big the table is
        # (an unbounded load OOMKilled the CronJob).
        scanned, updated = recompute_ids(finding_ids(qs))
        self.stdout.write(self.style.SUCCESS(
            f"recomputed: scanned={scanned} updated={updated}"
        ))
