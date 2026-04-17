"""
Process the ingest queue — continuous worker loop.

Usage:
  python manage.py process_ingest_queue                  # continuous loop
  python manage.py process_ingest_queue --once            # single batch, then exit
  python manage.py process_ingest_queue --batch-size 5    # claim 5 items per cycle
  python manage.py process_ingest_queue --sleep 2         # sleep 2s when queue empty

Production: K8s Deployment with replicas: 2
  command: ["python", "manage.py", "process_ingest_queue", "--batch-size", "5"]
"""
import signal
import time

from django.core.management.base import BaseCommand

from core.services.queue import get_queue_stats, process_batch, recover_stuck


class Command(BaseCommand):
    help = "Process the ingest queue (continuous worker loop)"

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
            "--once",
            action="store_true",
            help="Process one batch and exit (for testing)",
        )
        parser.add_argument(
            "--sleep",
            type=float,
            default=1.0,
            help="Seconds to sleep when queue is empty (default: 1.0)",
        )

    def handle(self, *args, **options):
        batch_size = options["batch_size"]
        once = options["once"]
        sleep_seconds = options["sleep"]

        # Graceful shutdown on SIGTERM/SIGINT
        signal.signal(signal.SIGTERM, self._handle_signal)
        signal.signal(signal.SIGINT, self._handle_signal)

        self.stdout.write(
            f"Queue processor started (batch_size={batch_size}, "
            f"sleep={sleep_seconds}s, once={once})"
        )

        while not self._shutdown:
            # Recover stuck items first
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
                # Queue empty — sleep before next check
                time.sleep(sleep_seconds)

            if once:
                break

        stats = get_queue_stats()
        self.stdout.write(
            self.style.SUCCESS(
                f"Shutting down. Queue: {stats['pending']} pending, "
                f"{stats['processing']} processing, {stats['failed']} failed"
            )
        )

    def _handle_signal(self, signum, frame):
        self.stdout.write("Received shutdown signal, finishing current batch...")
        self._shutdown = True
