"""Delete Snapshot rows older than SNAPSHOT_RETENTION_DAYS.

Per Architecture/dev_docs/03-data-model.md §Snapshot — Retention.
"""
from datetime import timedelta

from django.conf import settings
from django.core.management.base import BaseCommand
from django.utils import timezone

from core.models import Snapshot


class Command(BaseCommand):
    help = "Delete Snapshot rows older than SNAPSHOT_RETENTION_DAYS."

    def add_arguments(self, parser):
        parser.add_argument(
            "--dry-run",
            action="store_true",
            help="Count rows that would be deleted without deleting.",
        )

    def handle(self, *args, **options):
        cutoff = timezone.now() - timedelta(days=settings.SNAPSHOT_RETENTION_DAYS)
        qs = Snapshot.objects.filter(captured_at__lt=cutoff)
        n = qs.count()
        if options["dry_run"]:
            self.stdout.write(f"would delete {n} snapshots older than {cutoff.isoformat()}")
            return
        qs.delete()
        self.stdout.write(self.style.SUCCESS(
            f"deleted {n} snapshots older than {cutoff.isoformat()}"
        ))
