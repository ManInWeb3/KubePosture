"""Safety-net reaper: fire reaps for any draining mark whose queue is empty."""
from django.core.management.base import BaseCommand

from core.services.reaper import reap_all_drainable


class Command(BaseCommand):
    help = "Sweep draining ImportMarks and fire eligible reaps."

    def handle(self, *args, **options):
        n = reap_all_drainable()
        self.stdout.write(self.style.SUCCESS(f"reaped: {n}"))
