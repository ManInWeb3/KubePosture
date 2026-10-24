"""Data migration — rebuild the IoC rows the loader stored wrongly for
scoped npm packages.

OSV publishes the package of a scoped advisory as
`pkg:npm/%40tanstack/router-devtools-core`. The loader tested "does this
purl carry a version" with `"@" in purl` — true for the scope's own `@` —
and so stored that name-only purl for advisories that enumerate their
compromised versions (`versions: [1.167.6, 1.167.9]`). A name-only IoC
means "every version", so every deployed version of the package was
flagged.

For each `osv` row whose purl is a name-only scoped purl
(`pkg:<type>/@scope/name`), this re-derives the purls from the advisory
JSON kept in `raw` — one exact purl per enumerated version, or the same
name-only purl when the advisory only has ranges (the matcher checks those
against the ranges) — and replaces the row. Rows without a usable `raw`
are left alone. The loader writes the corrected rows from now on; findings
already raised from the wrong rows are no longer bumped and age out of the
default views with the next complete inventory.

Idempotent: a row that already equals its derivation is a no-op. The
derivation below is a frozen copy of `core.osv_ranges.ioc_purls`.
"""
from __future__ import annotations

from django.db import migrations

_SCOPED_NAME_ONLY = r"^pkg:[^/]+/@[^@]+$"


def _normalize(purl: str) -> str:
    return purl.replace("%40", "@").replace("%2B", "+").replace("%2b", "+")


def _strip_version(purl: str) -> str:
    # A version never contains "/", the scope's own "@" is always followed
    # by "scope/name".
    head, sep, tail = purl.rpartition("@")
    return head if sep and head and "/" not in tail else purl


def _block_purls(block: dict, purl_type: str) -> list[str]:
    pkg = block.get("package") or {}
    name = pkg.get("name") or ""
    explicit = _normalize(pkg.get("purl") or "")
    if explicit and _strip_version(explicit) != explicit:
        return [explicit]
    if not name:
        return []
    versions = [v for v in block.get("versions") or [] if isinstance(v, str) and v]
    if versions:
        return [_normalize(f"pkg:{purl_type}/{name}@{v}") for v in dict.fromkeys(versions)]
    return [_normalize(f"pkg:{purl_type}/{name}")]


def _is_block_of(block: dict, purl_type: str, purl: str) -> bool:
    pkg = block.get("package") or {}
    names = {_strip_version(_normalize(pkg.get("purl") or ""))}
    if pkg.get("name"):
        names.add(_normalize(f"pkg:{purl_type}/{pkg['name']}"))
    return purl in names


def _forwards(apps, schema_editor):
    SupplyChainIoc = apps.get_model("core", "SupplyChainIoc")

    rows = SupplyChainIoc.objects.filter(feed_source="osv", purl__regex=_SCOPED_NAME_ONLY)
    for row in rows.iterator(chunk_size=200):
        raw = row.raw if isinstance(row.raw, dict) else {}
        purl_type = row.purl[len("pkg:"):].split("/", 1)[0]
        derived: list[str] = []
        for block in raw.get("affected") or []:
            if isinstance(block, dict) and _is_block_of(block, purl_type, row.purl):
                derived += _block_purls(block, purl_type)
        derived = list(dict.fromkeys(derived))
        if not derived or derived == [row.purl]:
            continue
        for purl in derived:
            SupplyChainIoc.objects.update_or_create(
                feed_source=row.feed_source,
                advisory_id=row.advisory_id,
                purl=purl,
                defaults={
                    "severity": row.severity,
                    "title": row.title,
                    "summary": row.summary,
                    "advisory_url": row.advisory_url,
                    "published_at": row.published_at,
                    "raw": raw,
                },
            )
        if row.purl not in derived:
            row.delete()


def _backwards(apps, schema_editor):
    # No reverse — the old rows were wrong.
    pass


class Migration(migrations.Migration):
    dependencies = [
        ("core", "0015_osv_advisories"),
    ]

    operations = [
        migrations.RunPython(_forwards, _backwards),
    ]
