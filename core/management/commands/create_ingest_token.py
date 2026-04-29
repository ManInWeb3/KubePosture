"""Generate a named bearer token for the ingest API.

Tokens are NOT cluster-bound — one token can write into any cluster.
The cluster identity comes from each ingest payload's `cluster`
field and is auto-registered on first observation.

Prints the plain token once; only its hash is persisted.

Usage:
  manage.py create_ingest_token <name> [--description "..."]
"""
from __future__ import annotations

from django.core.management.base import BaseCommand

from core.api.auth import generate_token
from core.models import IngestToken


class Command(BaseCommand):
    help = "Generate a named ingest bearer token (cluster-less)."

    def add_arguments(self, parser):
        parser.add_argument(
            "name",
            help="Human-readable token name (unique). Examples: 'my-laptop', 'ci-bot'.",
        )
        parser.add_argument("--description", default="")

    def handle(self, *args, **options):
        name = options["name"]
        if IngestToken.objects.filter(name=name).exists():
            self.stderr.write(self.style.ERROR(
                f"Token name '{name}' already exists. Pick another name "
                f"or revoke the existing one first."
            ))
            return
        plain, hashed = generate_token()
        IngestToken.objects.create(
            name=name,
            token_hash=hashed,
            description=options["description"],
        )
        self.stdout.write(self.style.SUCCESS(
            f"Token '{name}' (shown once):"
        ))
        self.stdout.write(plain)
