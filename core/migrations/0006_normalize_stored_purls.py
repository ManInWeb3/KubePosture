"""Data migration — replace `%40` with `@` in stored purls.

Some scanners URL-encode the `@` version separator as `%40` when
emitting purls in CycloneDX SbomReports. Our IoC feeds (OSV, Aikido)
use literal `@`, so mismatched encoding silently breaks matching.

This migration normalises every existing row in `SbomComponent` and
`SupplyChainIoc`. Going forward, `core.purl.normalize_purl` is applied
at write time so the issue won't recur.

Idempotent: rows already using `@` are no-ops.
"""
from __future__ import annotations

from django.db import migrations


def _forwards(apps, schema_editor):
    SbomComponent = apps.get_model("core", "SbomComponent")
    SupplyChainIoc = apps.get_model("core", "SupplyChainIoc")

    # SbomComponent: unique on (image, purl).
    for row in SbomComponent.objects.filter(purl__contains="%40").iterator(chunk_size=500):
        new_purl = row.purl.replace("%40", "@")
        existing = SbomComponent.objects.filter(
            image_id=row.image_id, purl=new_purl,
        ).exclude(pk=row.pk).first()
        if existing:
            # Both encodings coexist — drop the broken row, keep the
            # normalised one. (Should be rare; defensive.)
            row.delete()
            continue
        row.purl = new_purl
        row.save(update_fields=["purl"])

    # SupplyChainIoc: unique on (feed_source, advisory_id, purl).
    for row in SupplyChainIoc.objects.filter(purl__contains="%40").iterator(chunk_size=500):
        new_purl = row.purl.replace("%40", "@")
        existing = SupplyChainIoc.objects.filter(
            feed_source=row.feed_source,
            advisory_id=row.advisory_id,
            purl=new_purl,
        ).exclude(pk=row.pk).first()
        if existing:
            row.delete()
            continue
        row.purl = new_purl
        row.save(update_fields=["purl"])


def _backwards(apps, schema_editor):
    # No reverse — re-encoding `@` to `%40` would re-introduce the bug.
    pass


class Migration(migrations.Migration):
    dependencies = [
        ("core", "0005_supply_chain_ioc"),
    ]

    operations = [
        migrations.RunPython(_forwards, _backwards),
    ]
