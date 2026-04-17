"""
Clean up completed ingest queue items.

Usage:
  python manage.py cleanup_ingest_queue             # delete done items > 7 days
  python manage.py cleanup_ingest_queue --days 3    # delete done items > 3 days

Production: Daily K8s CronJob.
"""
from django.core.management.base import BaseCommand

from core.services.queue import cleanup_done


class Command(BaseCommand):
    help = "Delete completed ingest queue items older than N days"

    def add_arguments(self, parser):
        parser.add_argument(
            "--days",
            type=int,
            default=7,
            help="Delete done items older than this many days (default: 7)",
        )

    def handle(self, *args, **options):
        days = options["days"]
        count = cleanup_done(days=days)
        self.stdout.write(
            self.style.SUCCESS(f"Cleaned up {count} done items older than {days} days")
        )
