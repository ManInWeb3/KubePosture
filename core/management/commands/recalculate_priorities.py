"""Force a bulk recompute of Finding.effective_priority.

Useful after a tweak to `core/urgency.py` or when a settings flip
should fan out across existing data.
"""

from core.management.base import KubePostureCommand
from core.models import Finding
from core.urgency import recompute_batch

# Same bound as enrichment's _RECOMPUTE_CHUNK_SIZE: recompute_batch loads each
# chunk with its relations + workload signals, so memory stays flat instead of
# growing with the whole Finding table (OOMKilled at 4Gi before chunking).
_CHUNK_SIZE = 5000


class Command(KubePostureCommand):
    help = "Recompute effective_priority for every Finding (or a cluster's worth)."

    def add_arguments(self, parser):
        parser.add_argument("--cluster", default=None)

    def handle(self, *args, **options):
        qs = Finding.objects.all()
        if options["cluster"]:
            qs = qs.filter(cluster__name=options["cluster"])
        ids = qs.order_by().values_list("id", flat=True).iterator(chunk_size=_CHUNK_SIZE)

        scanned = updated = 0
        chunk: list[int] = []
        for fid in ids:
            chunk.append(fid)
            if len(chunk) >= _CHUNK_SIZE:
                updated += recompute_batch(Finding.objects.filter(pk__in=chunk).only("id"))
                scanned += len(chunk)
                chunk = []
        if chunk:
            updated += recompute_batch(Finding.objects.filter(pk__in=chunk).only("id"))
            scanned += len(chunk)

        self.stdout.write(self.style.SUCCESS(
            f"recomputed: scanned={scanned} updated={updated}"
        ))
