"""IngestToken — named bearer secret for the central ingest API.

A token authenticates the importer. It is **not** bound to a cluster:
the cluster identity comes from the request payload's `cluster` field
and is auto-registered on first observation (per CLAUDE.md D2). One
token can write into any cluster.

The plain token is shown once at creation; only its sha256 hash is
stored. Importer sends `Authorization: Bearer <plain>`. Token rotation
= create new + revoke old. See dev_docs/02-architecture.md
*Importer authentication*.
"""
from django.db import models


class IngestToken(models.Model):
    name = models.CharField(
        max_length=120,
        unique=True,
        help_text="Human-readable identifier (e.g., 'my-laptop', 'ci-bot').",
    )
    token_hash = models.CharField(max_length=128, unique=True)
    description = models.CharField(max_length=200, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    last_used_at = models.DateTimeField(null=True, blank=True)
    revoked_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        indexes = [
            models.Index(fields=["revoked_at"], name="ingest_token_active"),
        ]

    def __str__(self) -> str:
        return self.name
