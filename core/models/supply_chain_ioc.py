"""SupplyChainIoc — one purl flagged as malicious by an external feed.

Populated by feed fetchers (`core.services.enrichment.fetch_aikido_iocs`,
`core.services.enrichment.fetch_osv_supply_chain`). One row per
(feed_source, advisory_id, purl) — the same advisory affecting multiple
purls produces multiple rows; the same purl flagged by two feeds
produces two rows. Both intentional — the matcher emits one Finding
per row (so users see "Aikido says malicious" and "OSV says malicious"
as distinct evidence).

Matched against `SbomComponent.purl` by `core.services.supply_chain_matcher`.
"""
from __future__ import annotations

from django.db import models


class SupplyChainIoc(models.Model):
    purl = models.CharField(max_length=512, db_index=True)
    feed_source = models.CharField(
        max_length=32,
        help_text='Feed identifier — currently "osv" or "aikido".',
    )
    advisory_id = models.CharField(
        max_length=128,
        help_text="Feed-native ID: GHSA-xxxx, MAL-xxxx, AIKIDO-xxxx, etc.",
    )
    severity = models.CharField(max_length=16, blank=True)
    title = models.CharField(max_length=512, blank=True)
    summary = models.TextField(blank=True)
    advisory_url = models.URLField(max_length=512, blank=True)
    published_at = models.DateTimeField(null=True, blank=True)

    first_seen_at = models.DateTimeField(auto_now_add=True)
    last_seen_at = models.DateTimeField(auto_now=True)

    raw = models.JSONField(default=dict, blank=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["feed_source", "advisory_id", "purl"],
                name="unique_feed_advisory_purl",
            ),
        ]
        indexes = [
            models.Index(fields=["purl"], name="scioc_purl"),
            models.Index(fields=["feed_source"], name="scioc_feed_source"),
        ]
        ordering = ["-last_seen_at"]

    def __str__(self) -> str:
        return f"{self.feed_source}:{self.advisory_id} → {self.purl}"
