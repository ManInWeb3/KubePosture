"""One-shot drain of IngestQueue. Helm CronJob entry point."""
from django.core.management.base import BaseCommand

from core.services import worker


class Command(BaseCommand):
    help = "Drain pending IngestQueue items and fire reaps."

    def add_arguments(self, parser):
        parser.add_argument("--limit", type=int, default=100)
        parser.add_argument(
            "--once", action="store_true",
            help="Run a single drain_once batch (default: loop until empty).",
        )

    def handle(self, *args, **options):
        if options["once"]:
            totals = worker.drain_once(limit=options["limit"])
        else:
            totals = worker.drain_until_empty(limit=options["limit"])
        self.stdout.write(self.style.SUCCESS(str(totals)))
