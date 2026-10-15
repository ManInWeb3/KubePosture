"""Safety-net reaper: discards imports that can never complete (marks
stuck `open` past their TTL, imports whose inventory payload failed),
then fires reaps for any draining mark whose queue is empty."""

from core.management.base import KubePostureCommand
from core.services.reaper import (
    discard_inventory_failed_imports,
    reap_all_drainable,
    reap_stuck_open,
)


class Command(KubePostureCommand):
    help = (
        "Discard stuck-open / inventory-failed imports, then sweep draining "
        "marks and fire eligible reaps."
    )

    def handle(self, *args, **options):
        stuck = reap_stuck_open()
        inventory_failed = discard_inventory_failed_imports()
        reaped = reap_all_drainable()
        self.stdout.write(self.style.SUCCESS(
            f"discarded_stuck_open: {stuck}, "
            f"discarded_inventory_failed: {inventory_failed}, "
            f"reaped: {reaped}"
        ))
