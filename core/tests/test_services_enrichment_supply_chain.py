"""Tests for the OSV supply-chain feed fetcher in core.services.enrichment."""
from __future__ import annotations

import io
import json
import os
import tempfile
import zipfile
from unittest.mock import patch

import pytest

from core.constants import Environment, Severity
from core.models import (
    Cluster,
    Finding,
    Image,
    Namespace,
    SbomComponent,
    SupplyChainIoc,
    Workload,
    WorkloadImageObservation,
)
from core.services import enrichment


# ── Fixture helpers ─────────────────────────────────────────────


def _seed_deployed(purl: str, *, ecosystem: str, name: str | None = None, version: str = "4.17.21"):
    c = Cluster.objects.create(name="c1", environment=Environment.PROD.value)
    ns = Namespace.objects.create(cluster=c, name="payments")
    w = Workload.objects.create(
        cluster=c, namespace=ns, kind="Deployment", name="api", deployed=True,
    )
    img = Image.objects.create(digest="sha256:" + "a" * 64, ref="reg/api:v1")
    WorkloadImageObservation.objects.create(
        workload=w, image=img, container_name="app", currently_deployed=True,
    )
    SbomComponent.objects.create(
        image=img, purl=purl,
        name=name or purl.split("/")[-1].split("@")[0],
        version=version, ecosystem=ecosystem,
    )
    return c, w, img


def _make_zip(advisories: list[dict]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for adv in advisories:
            zf.writestr(f"{adv['id']}.json", json.dumps(adv))
    return buf.getvalue()


def _bytes_path(data: bytes, *, suffix: str = ".zip") -> str:
    """Write `data` to a temp file and return its path. Mirrors what
    `_http_download_conditional` hands back — the fetcher unlinks it.
    """
    fd, path = tempfile.mkstemp(suffix=suffix)
    with os.fdopen(fd, "wb") as f:
        f.write(data)
    return path


def _zip_path(advisories: list[dict]) -> str:
    return _bytes_path(_make_zip(advisories))


# ── OSV fetcher ─────────────────────────────────────────────────


@pytest.mark.django_db
def test_osv_ecosystem_discovery_skips_unmapped_and_undeployed():
    # Two deployed ecosystems: npm (mapped) and rkt (unmapped).
    _seed_deployed("pkg:npm/lodash@1.0", ecosystem="npm")
    # Add a second component in an unknown ecosystem on the same image.
    img = Image.objects.first()
    SbomComponent.objects.create(
        image=img, purl="pkg:rkt/weird@1.0", name="weird",
        version="1.0", ecosystem="rkt",
    )

    called_for: list[str] = []

    def fake_download(url, *, state_key, suffix=".zip"):
        called_for.append(state_key)
        return None   # short-circuit — we only care about which feeds got called

    with patch.object(enrichment, "_http_download_conditional", side_effect=fake_download):
        enrichment.fetch_osv_supply_chain()

    # Only "osv:npm" should be requested. "rkt" isn't in PURL_TO_OSV.
    assert called_for == ["osv:npm"]


@pytest.mark.django_db
def test_osv_filters_to_malicious_only():
    _seed_deployed("pkg:npm/lodash@4.17.21", ecosystem="npm")

    advisories = [
        # 1. Regular CVE — must be skipped.
        {
            "id": "GHSA-1234-aaaa-bbbb",
            "summary": "Regular CVE",
            "affected": [{
                "package": {"name": "lodash", "purl": "pkg:npm/lodash@4.17.21"},
                "versions": ["4.17.21"],
            }],
        },
        # 2. MAL- prefix — malicious-publish.
        {
            "id": "MAL-2026-9999",
            "summary": "Malicious lodash variant",
            "published": "2026-04-25T08:00:00Z",
            "affected": [{
                "package": {"name": "lodash", "purl": "pkg:npm/lodash@4.17.21"},
                "versions": ["4.17.21"],
            }],
        },
        # 3. database_specific.malicious=true — also malicious.
        {
            "id": "GHSA-mmmm-nnnn-oooo",
            "summary": "GHSA malicious",
            "database_specific": {"malicious": True, "severity": "HIGH"},
            "affected": [{
                "package": {"name": "lodash", "purl": "pkg:npm/lodash@4.17.21"},
                "versions": ["4.17.21"],
            }],
        },
    ]

    with patch.object(enrichment, "_http_download_conditional", return_value=_zip_path(advisories)):
        n = enrichment.fetch_osv_supply_chain()

    iocs = list(SupplyChainIoc.objects.order_by("advisory_id"))
    advisory_ids = [i.advisory_id for i in iocs]
    assert "MAL-2026-9999" in advisory_ids
    assert "GHSA-mmmm-nnnn-oooo" in advisory_ids
    assert "GHSA-1234-aaaa-bbbb" not in advisory_ids
    # Severity propagated from database_specific where present.
    ghsa_malicious = next(i for i in iocs if i.advisory_id == "GHSA-mmmm-nnnn-oooo")
    assert ghsa_malicious.severity == Severity.HIGH.value
    # MAL- defaults to critical when no severity given.
    mal = next(i for i in iocs if i.advisory_id == "MAL-2026-9999")
    assert mal.severity == Severity.CRITICAL.value
    # Two upserts; both kicked off matcher → one Finding per matching IoC.
    assert n == 2
    assert Finding.objects.count() == 2


@pytest.mark.django_db
def test_osv_handles_304_not_modified():
    _seed_deployed("pkg:npm/lodash@4.17.21", ecosystem="npm")

    # 304 → the download helper returns None.
    with patch.object(enrichment, "_http_download_conditional", return_value=None):
        n = enrichment.fetch_osv_supply_chain()
    assert n == 0
    assert SupplyChainIoc.objects.count() == 0


@pytest.mark.django_db
def test_osv_no_deployed_ecosystems_short_circuits():
    # No components at all.
    called = []

    def fake_download(url, *, state_key, suffix=".zip"):
        called.append(state_key)
        return None

    with patch.object(enrichment, "_http_download_conditional", side_effect=fake_download):
        n = enrichment.fetch_osv_supply_chain()
    assert n == 0
    assert called == []


# ── OSV robustness ──────────────────────────────────────────────


@pytest.mark.django_db
def test_osv_picks_up_advisory_with_mal_alias():
    """GHSA-* whose `aliases` contains a MAL-* counts as malicious."""
    _seed_deployed("pkg:npm/lodash@4.17.21", ecosystem="npm")

    advisories = [
        {
            "id": "GHSA-aaaa-bbbb-cccc",
            "summary": "GHSA with MAL alias",
            "aliases": ["CVE-2099-9999", "MAL-2026-7777"],
            "affected": [{
                "package": {"name": "lodash", "purl": "pkg:npm/lodash@4.17.21"},
                "versions": ["4.17.21"],
            }],
        },
    ]
    with patch.object(enrichment, "_http_download_conditional", return_value=_zip_path(advisories)):
        enrichment.fetch_osv_supply_chain()

    assert SupplyChainIoc.objects.filter(advisory_id="GHSA-aaaa-bbbb-cccc").exists()


@pytest.mark.django_db
def test_osv_multi_purl_in_one_affected_block():
    """A single advisory listing multiple versions yields one IoC row
    per version (purl).
    """
    _seed_deployed("pkg:npm/lodash@4.17.21", ecosystem="npm")
    SbomComponent.objects.create(
        image=Image.objects.first(), purl="pkg:npm/lodash@4.17.20",
        name="lodash", version="4.17.20", ecosystem="npm",
    )

    advisories = [
        {
            "id": "MAL-2026-multi",
            "summary": "Multiple bad versions",
            "affected": [{
                "package": {"name": "lodash"},
                "versions": ["4.17.20", "4.17.21"],
            }],
        },
    ]
    with patch.object(enrichment, "_http_download_conditional", return_value=_zip_path(advisories)):
        enrichment.fetch_osv_supply_chain()

    iocs = SupplyChainIoc.objects.filter(advisory_id="MAL-2026-multi").order_by("purl")
    assert list(iocs.values_list("purl", flat=True)) == [
        "pkg:npm/lodash@4.17.20",
        "pkg:npm/lodash@4.17.21",
    ]


@pytest.mark.django_db
def test_osv_handles_malformed_json_in_zip():
    """A corrupted entry doesn't abort processing of the rest."""
    _seed_deployed("pkg:npm/lodash@4.17.21", ecosystem="npm")

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("garbage.json", "{not valid json")
        zf.writestr("MAL-good.json", json.dumps({
            "id": "MAL-good",
            "summary": "ok",
            "affected": [{
                "package": {"name": "lodash", "purl": "pkg:npm/lodash@4.17.21"},
                "versions": ["4.17.21"],
            }],
        }))

    with patch.object(enrichment, "_http_download_conditional", return_value=_bytes_path(buf.getvalue())):
        enrichment.fetch_osv_supply_chain()

    assert SupplyChainIoc.objects.filter(advisory_id="MAL-good").exists()


@pytest.mark.django_db
def test_osv_skips_non_json_entries():
    """Random files in the zip (README, manifest) are skipped silently."""
    _seed_deployed("pkg:npm/lodash@4.17.21", ecosystem="npm")

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("README.md", "# OSV bulk")
        zf.writestr("manifest.txt", "MAL-1\nMAL-2")
        zf.writestr("MAL-ok.json", json.dumps({
            "id": "MAL-ok",
            "affected": [{
                "package": {"name": "lodash", "purl": "pkg:npm/lodash@4.17.21"},
                "versions": ["4.17.21"],
            }],
        }))

    with patch.object(enrichment, "_http_download_conditional", return_value=_bytes_path(buf.getvalue())):
        n = enrichment.fetch_osv_supply_chain()
    assert n == 1


@pytest.mark.django_db
def test_osv_handles_empty_zip():
    _seed_deployed("pkg:npm/lodash@4.17.21", ecosystem="npm")
    with patch.object(enrichment, "_http_download_conditional", return_value=_zip_path([])):
        n = enrichment.fetch_osv_supply_chain()
    assert n == 0
    assert SupplyChainIoc.objects.count() == 0


@pytest.mark.django_db
def test_osv_handles_bad_zip_gracefully():
    """Garbage bytes that aren't a zip file shouldn't crash."""
    _seed_deployed("pkg:npm/lodash@4.17.21", ecosystem="npm")
    with patch.object(enrichment, "_http_download_conditional", return_value=_bytes_path(b"not a zip")):
        n = enrichment.fetch_osv_supply_chain()
    assert n == 0
