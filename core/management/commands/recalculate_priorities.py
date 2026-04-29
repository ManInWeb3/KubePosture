"""Force a bulk recompute of Finding.effective_priority.

Useful after a tweak to `core/urgency.py` or when a settings flip
should fan out across existing data.
"""
from django.core.management.base import BaseCommand

from core.models import Finding
from core.urgency import recompute_batch


class Command(BaseCommand):
    help = "Recompute effective_priority for every Finding (or a cluster's worth)."

    def add_arguments(self, parser):
        parser.add_argument("--cluster", default=None)

    def handle(self, *args, **options):
        qs = Finding.objects.all()
        if options["cluster"]:
            qs = qs.filter(cluster__name=options["cluster"])
        findings = list(qs.only("id"))
        updated = recompute_batch(findings)
        self.stdout.write(self.style.SUCCESS(
            f"recomputed: scanned={len(findings)} updated={updated}"
        ))
