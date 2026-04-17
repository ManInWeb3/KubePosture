"""
Create a DRF auth token for service accounts (scanner ingest).

Usage: python manage.py create_service_token <name>
Example: python manage.py create_service_token cluster-name-1

Creates user 'svc-<name>' with a token. Prints the token to stdout.
"""
from django.contrib.auth.models import User
from django.core.management.base import BaseCommand, CommandError
from rest_framework.authtoken.models import Token


class Command(BaseCommand):
    help = "Create a service account with DRF auth token for ingest API"

    def add_arguments(self, parser):
        parser.add_argument(
            "name",
            type=str,
            help="Service account name (will be prefixed with 'svc-')",
        )

    def handle(self, *args, **options):
        name = options["name"]
        username = f"svc-{name}"

        user, created = User.objects.get_or_create(
            username=username,
            defaults={
                "is_active": True,
                "is_staff": False,
            },
        )

        if not created:
            # User exists — get or recreate token
            token, token_created = Token.objects.get_or_create(user=user)
            if not token_created:
                raise CommandError(
                    f"Service account '{username}' already exists. "
                    f"Token: {token.key}"
                )
        else:
            token = Token.objects.create(user=user)

        self.stdout.write(
            self.style.SUCCESS(f"Service account: {username}")
        )
        self.stdout.write(
            self.style.SUCCESS(f"Token: {token.key}")
        )
        self.stdout.write(
            "\nUsage:\n"
            f'  curl -X POST http://localhost:8000/api/v1/ingest/ \\\n'
            f'    -H "Authorization: Token {token.key}" \\\n'
            f'    -H "Content-Type: application/json" \\\n'
            f'    -H "X-Cluster-Name: {name}" \\\n'
            f'    -d @vulnerability_report.json'
        )
