"""Tests for migration 0016_repair_scoped_malicious_iocs.

Starts from the rows the old loader wrote for real advisories
(`fixtures/supply_chain`) — a name-only purl for every scoped npm package
— and runs the migration function the way Django does. Verifies:
  - an advisory that enumerates versions gets one exact row per version
    and the name-only row is gone;
  - a ranges-only advisory keeps its name-only row (the matcher checks the
    range);
  - unscoped rows, rows without usable `raw`, and other packages of a
    multi-package advisory are left alone;
  - it is idempotent.
"""
from __future__ import annotations

import importlib
import json
from pathlib import Path

import pytest
from django.apps import apps as django_apps

migration = importlib.import_module("core.migrations.0016_repair_scoped_malicious_iocs")

FIXTURES = Path(__file__).resolve().parents[2] / "fixtures" / "supply_chain"
ADVISORIES = FIXTURES / "advisories" / "npm"


def _advisory(advisory_id: str) -> dict:
    return json.loads((ADVISORIES / f"{advisory_id}.json").read_text())


@pytest.fixture
def Ioc(db):
    return django_apps.get_model("core", "SupplyChainIoc")


def _old_row(Ioc, purl: str, advisory_id: str, raw: dict, **kw):
    return Ioc.objects.create(
        feed_source="osv", advisory_id=advisory_id, purl=purl, raw=raw,
        severity="CRITICAL", title=f"Malicious {purl}", advisory_url="https://example.test/adv",
        **kw,
    )


def _purls(Ioc, advisory_id: str) -> set[str]:
    return set(Ioc.objects.filter(advisory_id=advisory_id).values_list("purl", flat=True))


def test_name_only_row_becomes_one_row_per_compromised_version(Ioc):
    _old_row(Ioc, "pkg:npm/@tanstack/router-devtools-core", "MAL-2026-3475",
             _advisory("MAL-2026-3475"))

    migration._forwards(django_apps, None)

    assert _purls(Ioc, "MAL-2026-3475") == {
        "pkg:npm/@tanstack/router-devtools-core@1.167.6",
        "pkg:npm/@tanstack/router-devtools-core@1.167.9",
    }
    row = Ioc.objects.get(purl="pkg:npm/@tanstack/router-devtools-core@1.167.6")
    assert (row.severity, row.advisory_url) == ("CRITICAL", "https://example.test/adv")
    assert row.raw["id"] == "MAL-2026-3475"


def test_ranges_only_row_keeps_its_name_only_purl(Ioc):
    _old_row(Ioc, "pkg:npm/@solana/web3.js", "MAL-2024-11183", _advisory("MAL-2024-11183"))

    migration._forwards(django_apps, None)

    assert _purls(Ioc, "MAL-2024-11183") == {"pkg:npm/@solana/web3.js"}


def test_unscoped_and_unreadable_rows_are_left_alone(Ioc):
    _old_row(Ioc, "pkg:npm/evil-pkg", "MAL-2026-0042",
             {"id": "MAL-2026-0042", "affected": [{"package": {"name": "evil-pkg"},
                                                   "versions": ["1.0.0"]}]})
    _old_row(Ioc, "pkg:npm/@scope/no-raw", "MAL-2026-0043", {})
    _old_row(Ioc, "pkg:npm/@scope/other", "MAL-2026-0044",
             {"id": "MAL-2026-0044", "affected": [{"package": {"name": "@scope/different"},
                                                   "versions": ["1.0.0"]}]})

    migration._forwards(django_apps, None)

    assert _purls(Ioc, "MAL-2026-0042") == {"pkg:npm/evil-pkg"}
    assert _purls(Ioc, "MAL-2026-0043") == {"pkg:npm/@scope/no-raw"}
    assert _purls(Ioc, "MAL-2026-0044") == {"pkg:npm/@scope/other"}


def test_only_the_package_of_each_row_is_rebuilt(Ioc):
    """One advisory, two scoped packages: one lists versions, one only has
    a range. Each old name-only row is rebuilt from its own block."""
    raw = {"id": "MAL-2026-0050", "affected": [
        {"package": {"name": "@s/listed", "purl": "pkg:npm/%40s/listed"},
         "versions": ["2.0.0", "2.0.1"]},
        {"package": {"name": "@s/ranged", "purl": "pkg:npm/%40s/ranged"},
         "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}]}]},
    ]}
    _old_row(Ioc, "pkg:npm/@s/listed", "MAL-2026-0050", raw)
    _old_row(Ioc, "pkg:npm/@s/ranged", "MAL-2026-0050", raw)

    migration._forwards(django_apps, None)

    assert _purls(Ioc, "MAL-2026-0050") == {
        "pkg:npm/@s/listed@2.0.0", "pkg:npm/@s/listed@2.0.1", "pkg:npm/@s/ranged",
    }


def test_migration_is_idempotent(Ioc):
    _old_row(Ioc, "pkg:npm/@tanstack/router-devtools-core", "MAL-2026-3475",
             _advisory("MAL-2026-3475"))
    _old_row(Ioc, "pkg:npm/@solana/web3.js", "MAL-2024-11183", _advisory("MAL-2024-11183"))

    migration._forwards(django_apps, None)
    first = set(Ioc.objects.values_list("advisory_id", "purl"))
    migration._forwards(django_apps, None)

    assert set(Ioc.objects.values_list("advisory_id", "purl")) == first
    assert Ioc.objects.count() == 3
