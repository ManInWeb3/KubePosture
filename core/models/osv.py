"""OSV vulnerability advisories — the non-malicious half of the OSV.dev
bulk zips (malicious-package entries go to `SupplyChainIoc`).

`OsvAdvisory` is one advisory (GHSA-/GO-/PYSEC-/RUSTSEC-…), slimmed to
what the matcher and the finding need; the full record is not kept (npm
alone is 230k advisories). `OsvAffected` is one `affected[]` block —
one package name in one ecosystem with its `versions[]` and `ranges[]`
as OSV published them — and is what the matcher joins against
`SbomComponent` on `(purl_type, name)`. Evaluation of a component's
version against a block is `core.osv_ranges.evaluate`.

Withdrawn advisories stay in the table with `withdrawn_at` set so the
matcher stops emitting them; nothing is deleted on withdrawal.
"""
from __future__ import annotations

from django.db import models


class OsvAdvisory(models.Model):
    osv_id = models.CharField(max_length=128, primary_key=True)
    ecosystem = models.CharField(
        max_length=32, db_index=True,
        help_text="OSV ecosystem of the bulk zip it came from (npm, Go, Maven, PyPI, crates.io…).",
    )
    aliases = models.JSONField(
        default=list, blank=True, help_text="CVE-/GHSA-/GO-… ids of the same vuln.",
    )
    severity = models.CharField(
        max_length=16, blank=True, help_text="Mapped Severity, or blank when the feed has none.",
    )
    cvss_vector = models.CharField(max_length=128, blank=True)
    summary = models.CharField(max_length=512, blank=True)
    references = models.JSONField(default=list, blank=True, help_text="Up to 10 reference URLs.")
    published_at = models.DateTimeField(null=True, blank=True)
    modified_at = models.DateTimeField(
        null=True, blank=True,
        help_text="OSV `modified` — unchanged entries are skipped on refresh.",
    )
    withdrawn_at = models.DateTimeField(null=True, blank=True)
    fetched_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["osv_id"]

    def __str__(self) -> str:
        return self.osv_id

    @property
    def ids(self) -> set[str]:
        """The advisory id plus its aliases — one vuln under all its names."""
        return {self.osv_id, *(self.aliases or [])}


class OsvAffected(models.Model):
    advisory = models.ForeignKey(OsvAdvisory, on_delete=models.CASCADE, related_name="affected")
    purl_type = models.CharField(
        max_length=16,
        help_text="purl type as on SbomComponent.ecosystem: npm, golang, pypi, maven, cargo…",
    )
    name = models.CharField(
        max_length=255,
        help_text="Package name in OSV convention: maven `group:artifact`, PyPI normalised, Go lower-cased.",  # noqa: E501
    )
    versions = models.JSONField(
        default=list, blank=True,
        help_text="OSV `versions[]` — enumerated affected versions, may be empty.",
    )
    ranges = models.JSONField(
        default=list, blank=True, help_text="OSV `ranges[]` — `[{type, events}]`.",
    )

    class Meta:
        indexes = [models.Index(fields=["purl_type", "name"], name="osvaffected_type_name")]

    def __str__(self) -> str:
        return f"{self.advisory_id} → pkg:{self.purl_type}/{self.name}"
