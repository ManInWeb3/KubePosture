"""One-shot drain of IngestQueue. Helm CronJob entry point."""

from core.management.base import KubePostureCommand
from core.services import worker


class Command(KubePostureCommand):
    help = "Drain pending IngestQueue items and fire reaps."

    def add_arguments(self, parser):
        parser.add_argument(
            "--limit", type=int, default=1,
            help="Rows claimed per pass. 1 = claim one, process it, claim the next — "
                 "parallel pods then share an import row by row.",
        )
        parser.add_argument(
            "--max-iterations", type=int, default=0,
            help="Cap on passes per run; 0 = run until nothing is claimable.",
        )
        parser.add_argument(
            "--max-seconds", type=float, default=0,
            help="Wall-clock budget; no new pass starts (and the final reap sweep is "
                 "skipped) once spent. 0 = no budget. Keep below activeDeadlineSeconds.",
        )
        parser.add_argument(
            "--once", action="store_true",
            help="Run a single drain_once batch (default: loop until empty).",
        )

    def handle(self, *args, **options):
        if options["once"]:
            totals = worker.drain_once(limit=options["limit"])
        else:
            totals = worker.drain_until_empty(
                limit=options["limit"], max_iterations=options["max_iterations"],
                max_seconds=options["max_seconds"],
            )
        self.stdout.write(self.style.SUCCESS(str(totals)))
