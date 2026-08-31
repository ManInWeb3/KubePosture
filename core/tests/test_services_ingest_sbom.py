"""Tests for core.services.ingest._process_sbom.

Covers the deterministic lock-ordering fix: two workers concurrently
upserting SbomComponent rows for the *same* image (e.g. two different
IngestQueue items both carrying a scan of that image) can deadlock,
because Django's `update_or_create()` uses `select_for_update()`
internally, and two transactions locking the same set of rows in
different orders is exactly what produces a deadlock. Sorting components
by purl before the upsert loop means every worker touching that image
acquires locks in the same relative order, so two concurrent transactions
can only ever queue behind each other, never form a lock cycle.

This can't prove a deadlock won't happen under real concurrency in a
single-threaded unit test (see core/tests/test_concurrency.py for that
style of test) — what it proves is that the ordering mechanism is
actually in place and doesn't change correctness.
"""
from __future__ import annotations

from unittest.mock import patch

import pytest
from django.utils import timezone

from core.constants import ImportMarkState
from core.models import Cluster, ImportMark, IngestQueue, SbomComponent
from core.services.ingest import _process_sbom


@pytest.fixture
def cluster(db):
    return Cluster.objects.create(name="c-sbom")


def _sbom_item(cluster, *, import_id: str = "imp-sbom") -> IngestQueue:
    ImportMark.objects.update_or_create(
        cluster=cluster, kind="trivy.SbomReport", import_id=import_id,
        defaults={"state": ImportMarkState.DRAINING.value, "started_at": timezone.now()},
    )
    return IngestQueue.objects.create(
        cluster_name=cluster.name, kind="trivy.SbomReport", import_id=import_id,
        raw_json={},
    )


def _component(purl: str) -> dict:
    return {
        "purl": purl,
        "name": purl,
        "version": "1.0",
        "ecosystem": "pypi",
        "component_type": "library",
        "supplier": "",
        "license": "",
        "layer_digest": "",
        "raw": {},
    }


@pytest.mark.django_db
def test_process_sbom_upserts_components_in_purl_sorted_order(cluster):
    """Components arrive in whatever order the CycloneDX BOM had them in
    — the upsert loop must process them purl-sorted regardless, so
    concurrent workers touching the same image's overlapping components
    always acquire row locks in the same relative order."""
    item = _sbom_item(cluster)
    unsorted_purls = ["pkg:pypi/zeta@1", "pkg:pypi/alpha@1", "pkg:pypi/mu@1"]
    parsed = {
        "image_ref": "example/app:1",
        "image_digest": "sha256:" + "a" * 64,
        "namespace": "",
        "resource_kind": "",
        "resource_name": "",
        "container_name": "",
        "components": [_component(p) for p in unsorted_purls],
    }

    seen_order: list[str] = []
    real_update_or_create = SbomComponent.objects.update_or_create

    def _spy(*, image, purl, defaults):
        seen_order.append(purl)
        return real_update_or_create(image=image, purl=purl, defaults=defaults)

    with patch.object(SbomComponent.objects, "update_or_create", side_effect=_spy):
        result = _process_sbom(item, lambda _raw: parsed)

    assert seen_order == sorted(unsorted_purls), (
        "components must be upserted in purl-sorted order for consistent "
        "lock acquisition order across concurrent workers"
    )
    assert result == {"components": 3, "created": 3, "updated": 0}
    assert SbomComponent.objects.filter(image__digest=parsed["image_digest"]).count() == 3


@pytest.mark.django_db
def test_process_sbom_reupsert_still_sorted_and_updates_not_creates(cluster):
    """A second SBOM for the same image (re-scan) re-sorts and updates
    the existing rows rather than duplicating them — the sort must not
    interfere with update_or_create's existing dedup key (image, purl)."""
    item = _sbom_item(cluster, import_id="imp-sbom-2")
    digest = "sha256:" + "b" * 64
    first_pass = {
        "image_ref": "example/app:2",
        "image_digest": digest,
        "namespace": "", "resource_kind": "", "resource_name": "", "container_name": "",
        "components": [_component("pkg:pypi/beta@1"), _component("pkg:pypi/gamma@1")],
    }
    _process_sbom(item, lambda _raw: first_pass)
    assert SbomComponent.objects.filter(image__digest=digest).count() == 2

    second_pass = dict(first_pass)
    second_pass["components"] = [_component("pkg:pypi/gamma@1"), _component("pkg:pypi/beta@1")]
    result = _process_sbom(item, lambda _raw: second_pass)

    assert result == {"components": 2, "created": 0, "updated": 2}
    assert SbomComponent.objects.filter(image__digest=digest).count() == 2
