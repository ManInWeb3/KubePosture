"""Force a bulk recompute of Finding.effective_priority.

Useful after a tweak to `core/urgency.py` or when a settings flip
should fan out across existing data.
"""

from core.management.base import KubePostureCommand
from core.models import Finding
from core.urgency import RECOMPUTE_CHUNK_SIZE, recompute_ids


class Command(KubePostureCommand):
    help = "Recompute effective_priority for every Finding (or a cluster's worth)."

    def add_arguments(self, parser):
        parser.add_argument("--cluster", default=None)

    def handle(self, *args, **options):
        qs = Finding.objects.all()
        if options["cluster"]:
            qs = qs.filter(cluster__name=options["cluster"])
        scanned = 0

        def _ids():
            # Streamed + chunked by recompute_ids: memory stays flat however
            # big the table is (an unbounded load OOMKilled the CronJob).
            nonlocal scanned
            for pk in qs.order_by().values_list("id", flat=True).iterator(chunk_size=RECOMPUTE_CHUNK_SIZE):
                scanned += 1
                yield pk

        updated = recompute_ids(_ids())
        self.stdout.write(self.style.SUCCESS(
            f"recomputed: scanned={scanned} updated={updated}"
        ))
