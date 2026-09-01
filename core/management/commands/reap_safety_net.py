"""Safety-net reaper: promotes stuck open marks, then fires reaps for
any draining mark whose queue is empty."""
from django.core.management.base import BaseCommand

from core.services.reaper import reap_all_drainable, reap_stuck_open


class Command(BaseCommand):
    help = "Promote stuck open ImportMarks, then sweep draining marks and fire eligible reaps."

    def handle(self, *args, **options):
        promoted = reap_stuck_open()
        n = reap_all_drainable()
        self.stdout.write(self.style.SUCCESS(f"promoted: {promoted}, reaped: {n}"))
