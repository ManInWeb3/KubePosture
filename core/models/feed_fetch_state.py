"""FeedFetchState — per-feed conditional-GET state (Last-Modified / ETag).

Used by `core.services.enrichment._http_download_conditional` to skip
re-downloading large feed files (OSV per-ecosystem zips, hundreds of MB)
when the upstream hasn't changed since the last successful fetch.

Keyed on an opaque `state_key` so callers compose their own (e.g.
"osv:npm", "osv:PyPI"). The row is upserted after a successful 200;
a 304 response leaves the row unchanged.
"""
from __future__ import annotations

from django.db import models


class FeedFetchState(models.Model):
    state_key = models.CharField(max_length=128, unique=True)
    etag = models.CharField(max_length=256, blank=True)
    last_modified = models.CharField(
        max_length=64,
        blank=True,
        help_text="HTTP Last-Modified header value (RFC 7231 date string).",
    )
    last_success_at = models.DateTimeField(null=True, blank=True)

    def __str__(self) -> str:
        return self.state_key
