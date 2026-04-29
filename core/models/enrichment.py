"""Enrichment tables — EPSS, KEV.

Both feeds are fetched daily from public sources (FIRST.org / CISA).
Each row carries `fetched_at` so the UI can surface staleness.

The zero-input no-op rule applies on refresh: removal phase only
runs when a fetch returned non-empty. A previously-flagged CVE stays
flagged across an empty/failing refresh.
"""
from django.db import models


class EpssScore(models.Model):
    vuln_id = models.CharField(max_length=128, primary_key=True)
    score = models.FloatField()
    percentile = models.FloatField()
    fetched_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["-score", "vuln_id"]

    def __str__(self) -> str:
        return f"{self.vuln_id}: {self.score:.4f}"


class KevEntry(models.Model):
    vuln_id = models.CharField(max_length=128, primary_key=True)
    added_at = models.DateField(null=True, blank=True)
    short_description = models.TextField(blank=True)
    required_action = models.TextField(blank=True)
    due_date = models.DateField(null=True, blank=True)
    fetched_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["-added_at", "vuln_id"]

    def __str__(self) -> str:
        return self.vuln_id
