"""Tests for migration 0006_normalize_stored_purls.

Exercises the data-migration function directly (using `apps.get_model`
the way Django runs it). Verifies:
  - rows with `%40` are rewritten to `@`
  - already-clean rows are left alone
  - collision case: when both encodings already exist for the same
    uniqueness key, the broken row is dropped and the clean one kept.
"""
from __future__ import annotations

import importlib

import pytest
from django.apps import apps as django_apps

from core.constants import Environment


# Load the migration module so we can call _forwards directly.
migration = importlib.import_module("core.migrations.0006_normalize_stored_purls")


@pytest.fixture
def app_models(db):
    """Yield the model classes as the migration sees them
    (historical models from apps.get_model)."""
    SbomComponent = django_apps.get_model("core", "SbomComponent")
    SupplyChainIoc = django_apps.get_model("core", "SupplyChainIoc")
    Image = django_apps.get_model("core", "Image")
    return SbomComponent, SupplyChainIoc, Image


def test_migration_rewrites_percent_40_in_sbom_components(app_models):
    SbomComponent, _, Image = app_models
    img = Image.objects.create(digest="sha256:" + "a" * 64, ref="r:1")
    SbomComponent.objects.create(
        image=img, purl="pkg:npm/lodash%404.17.21",
        name="lodash", version="4.17.21", ecosystem="npm",
    )

    migration._forwards(django_apps, None)

    purls = list(SbomComponent.objects.values_list("purl", flat=True))
    assert purls == ["pkg:npm/lodash@4.17.21"]


def test_migration_rewrites_percent_40_in_supply_chain_ioc(app_models):
    _, SupplyChainIoc, _ = app_models
    SupplyChainIoc.objects.create(
        purl="pkg:npm/lodash%404.17.21",
        feed_source="osv",
        advisory_id="MAL-1",
        severity="critical",
        title="x",
    )

    migration._forwards(django_apps, None)

    purls = list(SupplyChainIoc.objects.values_list("purl", flat=True))
    assert purls == ["pkg:npm/lodash@4.17.21"]


def test_migration_leaves_clean_rows_alone(app_models):
    SbomComponent, _, Image = app_models
    img = Image.objects.create(digest="sha256:" + "a" * 64, ref="r:1")
    SbomComponent.objects.create(
        image=img, purl="pkg:npm/lodash@4.17.21",
        name="lodash", version="4.17.21", ecosystem="npm",
    )

    migration._forwards(django_apps, None)

    purls = list(SbomComponent.objects.values_list("purl", flat=True))
    assert purls == ["pkg:npm/lodash@4.17.21"]


def test_migration_drops_broken_row_when_clean_row_already_exists(app_models):
    """If both encodings happen to coexist for the same image, the
    migration keeps the clean row and deletes the broken one.
    """
    SbomComponent, _, Image = app_models
    img = Image.objects.create(digest="sha256:" + "a" * 64, ref="r:1")
    SbomComponent.objects.create(
        image=img, purl="pkg:npm/lodash@4.17.21",   # already clean
        name="lodash", version="4.17.21", ecosystem="npm",
    )
    SbomComponent.objects.create(
        image=img, purl="pkg:npm/lodash%404.17.21",  # broken
        name="lodash", version="4.17.21", ecosystem="npm",
    )

    migration._forwards(django_apps, None)

    purls = list(SbomComponent.objects.values_list("purl", flat=True))
    assert purls == ["pkg:npm/lodash@4.17.21"]   # only the clean row remains


def test_migration_drops_broken_ioc_row_when_clean_exists(app_models):
    _, SupplyChainIoc, _ = app_models
    SupplyChainIoc.objects.create(
        purl="pkg:npm/lodash@4.17.21",
        feed_source="osv", advisory_id="MAL-1", severity="critical", title="x",
    )
    SupplyChainIoc.objects.create(
        purl="pkg:npm/lodash%404.17.21",
        feed_source="osv", advisory_id="MAL-1", severity="critical", title="x",
    )

    migration._forwards(django_apps, None)

    purls = list(SupplyChainIoc.objects.values_list("purl", flat=True))
    assert purls == ["pkg:npm/lodash@4.17.21"]


def test_migration_is_idempotent(app_models):
    SbomComponent, _, Image = app_models
    img = Image.objects.create(digest="sha256:" + "a" * 64, ref="r:1")
    SbomComponent.objects.create(
        image=img, purl="pkg:npm/lodash%404.17.21",
        name="lodash", version="4.17.21", ecosystem="npm",
    )

    migration._forwards(django_apps, None)
    migration._forwards(django_apps, None)   # second run

    purls = list(SbomComponent.objects.values_list("purl", flat=True))
    assert purls == ["pkg:npm/lodash@4.17.21"]
