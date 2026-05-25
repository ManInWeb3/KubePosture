"""Tests for OSV + Aikido feed fetchers in core.services.enrichment."""
from __future__ import annotations

import io
import json
import zipfile
from unittest.mock import patch
from urllib.error import HTTPError

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

    def fake_get(url, *, state_key):
        called_for.append(state_key)
        return None   # short-circuit — we only care about which feeds got called

    with patch.object(enrichment, "_http_get_conditional", side_effect=fake_get):
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
    body = _make_zip(advisories)

    with patch.object(enrichment, "_http_get_conditional", return_value=body):
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

    # Mock the underlying urlopen to raise 304.
    with patch.object(enrichment, "_http_get_conditional", return_value=None):
        n = enrichment.fetch_osv_supply_chain()
    assert n == 0
    assert SupplyChainIoc.objects.count() == 0


@pytest.mark.django_db
def test_osv_no_deployed_ecosystems_short_circuits():
    # No components at all.
    called = []

    def fake_get(url, *, state_key):
        called.append(state_key)
        return None

    with patch.object(enrichment, "_http_get_conditional", side_effect=fake_get):
        n = enrichment.fetch_osv_supply_chain()
    assert n == 0
    assert called == []


# ── Aikido fetcher ──────────────────────────────────────────────


@pytest.mark.django_db
def test_aikido_returns_zero_when_url_empty(monkeypatch):
    monkeypatch.setenv("AIKIDO_INTEL_URL", "")
    n = enrichment.fetch_aikido_iocs()
    assert n == 0
    assert SupplyChainIoc.objects.count() == 0


@pytest.mark.django_db
def test_aikido_upserts_entries_with_purl(monkeypatch):
    _seed_deployed("pkg:npm/bad-pkg@1.2.3", ecosystem="npm", name="bad-pkg")
    monkeypatch.setenv("AIKIDO_INTEL_URL", "https://intel.example.test/feed.json")

    body = json.dumps({
        "entries": [
            {
                "id": "AIKIDO-2026-1",
                "purl": "pkg:npm/bad-pkg@1.2.3",
                "severity": "critical",
                "title": "Malicious bad-pkg",
                "summary": "Exfils tokens.",
                "url": "https://intel.example.test/AIKIDO-2026-1",
                "published_at": "2026-04-25T08:00:00Z",
            },
        ],
    }).encode("utf-8")

    with patch.object(enrichment, "_http_get", return_value=body):
        n = enrichment.fetch_aikido_iocs()
    assert n == 1
    ioc = SupplyChainIoc.objects.get(feed_source="aikido")
    assert ioc.advisory_id == "AIKIDO-2026-1"
    assert ioc.purl == "pkg:npm/bad-pkg@1.2.3"
    assert ioc.severity == Severity.CRITICAL.value
    # And the matcher ran → a Finding exists.
    assert Finding.objects.count() == 1


@pytest.mark.django_db
def test_aikido_reconstructs_purl_from_fields(monkeypatch):
    _seed_deployed("pkg:npm/ctx@0.1.2", ecosystem="npm", name="ctx", version="0.1.2")
    monkeypatch.setenv("AIKIDO_INTEL_URL", "https://intel.example.test/feed.json")

    body = json.dumps({
        "entries": [
            {
                "id": "AIKIDO-99",
                "package_name": "ctx",
                "package_version": "0.1.2",
                "ecosystem": "npm",
                "severity": "critical",
            },
        ],
    }).encode("utf-8")

    with patch.object(enrichment, "_http_get", return_value=body):
        enrichment.fetch_aikido_iocs()

    ioc = SupplyChainIoc.objects.get()
    assert ioc.purl == "pkg:npm/ctx@0.1.2"


@pytest.mark.django_db
def test_aikido_handles_top_level_list(monkeypatch):
    _seed_deployed("pkg:npm/x@1.0", ecosystem="npm")
    monkeypatch.setenv("AIKIDO_INTEL_URL", "https://intel.example.test/feed.json")

    body = json.dumps([
        {"id": "AIKIDO-a", "purl": "pkg:npm/x@1.0"},
    ]).encode("utf-8")

    with patch.object(enrichment, "_http_get", return_value=body):
        n = enrichment.fetch_aikido_iocs()
    assert n == 1


@pytest.mark.django_db
def test_aikido_skips_entries_without_id_or_purl(monkeypatch):
    _seed_deployed("pkg:npm/x@1.0", ecosystem="npm")
    monkeypatch.setenv("AIKIDO_INTEL_URL", "https://intel.example.test/feed.json")

    body = json.dumps({
        "entries": [
            {"purl": "pkg:npm/x@1.0"},                     # no id → skip
            {"id": "AIKIDO-x"},                            # no purl → skip
            {"id": "AIKIDO-ok", "purl": "pkg:npm/x@1.0"},  # valid
        ],
    }).encode("utf-8")

    with patch.object(enrichment, "_http_get", return_value=body):
        enrichment.fetch_aikido_iocs()
    assert list(SupplyChainIoc.objects.values_list("advisory_id", flat=True)) == ["AIKIDO-ok"]


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
    with patch.object(enrichment, "_http_get_conditional", return_value=_make_zip(advisories)):
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
    with patch.object(enrichment, "_http_get_conditional", return_value=_make_zip(advisories)):
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

    with patch.object(enrichment, "_http_get_conditional", return_value=buf.getvalue()):
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

    with patch.object(enrichment, "_http_get_conditional", return_value=buf.getvalue()):
        n = enrichment.fetch_osv_supply_chain()
    assert n == 1


@pytest.mark.django_db
def test_osv_handles_empty_zip():
    _seed_deployed("pkg:npm/lodash@4.17.21", ecosystem="npm")
    empty = _make_zip([])
    with patch.object(enrichment, "_http_get_conditional", return_value=empty):
        n = enrichment.fetch_osv_supply_chain()
    assert n == 0
    assert SupplyChainIoc.objects.count() == 0


@pytest.mark.django_db
def test_osv_handles_bad_zip_gracefully():
    """Garbage bytes that aren't a zip file shouldn't crash."""
    _seed_deployed("pkg:npm/lodash@4.17.21", ecosystem="npm")
    with patch.object(enrichment, "_http_get_conditional", return_value=b"not a zip"):
        n = enrichment.fetch_osv_supply_chain()
    assert n == 0


# ── Aikido robustness ───────────────────────────────────────────


@pytest.mark.django_db
@pytest.mark.parametrize("input_eco,expected_purl_prefix", [
    ("npm", "pkg:npm/"),
    ("pypi", "pkg:pypi/"),
    ("rubygems", "pkg:gem/"),
    ("gem", "pkg:gem/"),
    ("go", "pkg:golang/"),
    ("golang", "pkg:golang/"),
    ("cargo", "pkg:cargo/"),
    ("maven", "pkg:maven/"),
    ("nuget", "pkg:nuget/"),
])
def test_aikido_ecosystem_reconstruction_table(monkeypatch, input_eco, expected_purl_prefix):
    _seed_deployed(f"{expected_purl_prefix}testpkg@1.0", ecosystem=input_eco.lower())
    monkeypatch.setenv("AIKIDO_INTEL_URL", "https://intel.example.test/feed.json")

    body = json.dumps({
        "entries": [
            {
                "id": f"AIKIDO-{input_eco}",
                "package_name": "testpkg",
                "package_version": "1.0",
                "ecosystem": input_eco,
            },
        ],
    }).encode("utf-8")
    with patch.object(enrichment, "_http_get", return_value=body):
        enrichment.fetch_aikido_iocs()

    ioc = SupplyChainIoc.objects.filter(advisory_id=f"AIKIDO-{input_eco}").first()
    assert ioc is not None
    assert ioc.purl.startswith(expected_purl_prefix)


@pytest.mark.django_db
def test_aikido_severity_unknown_defaults_to_critical(monkeypatch):
    _seed_deployed("pkg:npm/x@1.0", ecosystem="npm")
    monkeypatch.setenv("AIKIDO_INTEL_URL", "https://intel.example.test/feed.json")

    body = json.dumps({
        "entries": [
            {"id": "AIKIDO-1", "purl": "pkg:npm/x@1.0", "severity": "completely-bogus"},
            {"id": "AIKIDO-2", "purl": "pkg:npm/x@1.0"},  # missing severity
            {"id": "AIKIDO-3", "purl": "pkg:npm/x@1.0", "severity": "HIGH"},
        ],
    }).encode("utf-8")
    with patch.object(enrichment, "_http_get", return_value=body):
        enrichment.fetch_aikido_iocs()

    sevs = dict(SupplyChainIoc.objects.values_list("advisory_id", "severity"))
    assert sevs["AIKIDO-1"] == Severity.CRITICAL.value   # bogus → critical
    assert sevs["AIKIDO-2"] == Severity.CRITICAL.value   # missing → critical
    assert sevs["AIKIDO-3"] == Severity.HIGH.value       # known → preserved


@pytest.mark.django_db
def test_aikido_published_at_parsing(monkeypatch):
    _seed_deployed("pkg:npm/x@1.0", ecosystem="npm")
    monkeypatch.setenv("AIKIDO_INTEL_URL", "https://intel.example.test/feed.json")

    body = json.dumps({
        "entries": [
            {"id": "AIKIDO-iso-z", "purl": "pkg:npm/x@1.0",
             "published_at": "2026-04-25T08:00:00Z"},
            {"id": "AIKIDO-iso-tz", "purl": "pkg:npm/x@1.0",
             "published_at": "2026-04-25T08:00:00+02:00"},
            {"id": "AIKIDO-no-date", "purl": "pkg:npm/x@1.0"},
            {"id": "AIKIDO-garbage", "purl": "pkg:npm/x@1.0",
             "published_at": "not a date"},
        ],
    }).encode("utf-8")
    with patch.object(enrichment, "_http_get", return_value=body):
        enrichment.fetch_aikido_iocs()

    iocs = {i.advisory_id: i for i in SupplyChainIoc.objects.all()}
    assert iocs["AIKIDO-iso-z"].published_at is not None
    assert iocs["AIKIDO-iso-tz"].published_at is not None
    assert iocs["AIKIDO-no-date"].published_at is None
    assert iocs["AIKIDO-garbage"].published_at is None   # malformed → None, no crash


@pytest.mark.django_db
def test_aikido_normalises_purl_percent_40(monkeypatch):
    _seed_deployed("pkg:npm/lodash@4.17.21", ecosystem="npm")
    monkeypatch.setenv("AIKIDO_INTEL_URL", "https://intel.example.test/feed.json")

    body = json.dumps({
        "entries": [
            {"id": "AIKIDO-encoded", "purl": "pkg:npm/lodash%404.17.21"},
        ],
    }).encode("utf-8")
    with patch.object(enrichment, "_http_get", return_value=body):
        enrichment.fetch_aikido_iocs()

    stored_purl = SupplyChainIoc.objects.get(advisory_id="AIKIDO-encoded").purl
    assert stored_purl == "pkg:npm/lodash@4.17.21"


@pytest.mark.django_db
def test_aikido_handles_malformed_json_response(monkeypatch):
    _seed_deployed("pkg:npm/x@1.0", ecosystem="npm")
    monkeypatch.setenv("AIKIDO_INTEL_URL", "https://intel.example.test/feed.json")

    with patch.object(enrichment, "_http_get", return_value=b"{not json"):
        n = enrichment.fetch_aikido_iocs()
    assert n == 0
    assert SupplyChainIoc.objects.count() == 0
