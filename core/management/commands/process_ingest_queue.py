"""
Process the ingest queue.

Usage:
  python manage.py process_ingest_queue                       # drain queue and exit
  python manage.py process_ingest_queue --continuous          # loop forever (K8s Deployment)
  python manage.py process_ingest_queue --batch-size 5        # claim 5 items per cycle
  python manage.py process_ingest_queue --continuous --sleep 2  # sleep 2s when queue empty

Production (Deployment): ["python", "manage.py", "process_ingest_queue", "--continuous"]
CronJob: ["python", "manage.py", "process_ingest_queue", "--batch-size", "10"]
"""
import signal
import time

from django.core.management.base import BaseCommand

from core.services.queue import get_queue_stats, process_batch, recover_stuck


class Command(BaseCommand):
    help = "Process the ingest queue (drain and exit, or continuous loop with --continuous)"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._shutdown = False

    def add_arguments(self, parser):
        parser.add_argument(
            "--batch-size",
            type=int,
            default=1,
            help="Number of items to claim per cycle (default: 1)",
        )
        parser.add_argument(
            "--continuous",
            action="store_true",
            help="Keep running when queue is empty instead of exiting",
        )
        parser.add_argument(
            "--sleep",
            type=float,
            default=1.0,
            help="Seconds to sleep when queue is empty in --continuous mode (default: 1.0)",
        )

    def handle(self, *args, **options):
        batch_size = options["batch_size"]
        continuous = options["continuous"]
        sleep_seconds = options["sleep"]

        signal.signal(signal.SIGTERM, self._handle_signal)
        signal.signal(signal.SIGINT, self._handle_signal)

        self.stdout.write(
            f"Queue processor started (batch_size={batch_size}, "
            f"continuous={continuous}, sleep={sleep_seconds}s)"
        )

        while not self._shutdown:
            recovered = recover_stuck()
            if recovered:
                self.stdout.write(f"Recovered {recovered} stuck items")

            result = process_batch(batch_size)

            if result["claimed"] > 0:
                self.stdout.write(
                    f"Processed {result['succeeded']}/{result['claimed']} "
                    f"({result['failed']} failed)"
                )
            else:
                if not continuous:
                    break
                time.sleep(sleep_seconds)

        stats = get_queue_stats()
        self.stdout.write(
            self.style.SUCCESS(
                f"Done. Queue: {stats['pending']} pending, "
                f"{stats['processing']} processing, {stats['failed']} failed"
            )
        )

    def _handle_signal(self, signum, frame):
        self.stdout.write("Received shutdown signal, finishing current batch...")
        self._shutdown = True
