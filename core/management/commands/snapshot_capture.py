"""Daily heartbeat — write Snapshot rows for all scopes."""

from core.management.base import KubePostureCommand
from core.services.snapshot import capture_daily_heartbeat


class Command(KubePostureCommand):
    help = "Write today's Snapshot heartbeat rows."

    def handle(self, *args, **options):
        n = capture_daily_heartbeat()
        self.stdout.write(self.style.SUCCESS(f"snapshot rows written: {n}"))
