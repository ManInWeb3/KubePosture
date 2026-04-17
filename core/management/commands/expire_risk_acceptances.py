"""
Expire risk acceptances — reactivates findings past their expiry date.

Usage: python manage.py expire_risk_acceptances

Run as daily K8s CronJob.
See: docs/architecture.md § F4
"""
from django.core.management.base import BaseCommand

from core.services.lifecycle import expire_risk_acceptances


class Command(BaseCommand):
    help = "Reactivate findings with expired risk acceptances"

    def handle(self, *args, **options):
        count = expire_risk_acceptances()
        self.stdout.write(
            self.style.SUCCESS(f"Expired {count} risk acceptances")
        )
