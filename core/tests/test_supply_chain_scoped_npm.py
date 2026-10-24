"""Malicious-package matching on scoped npm packages — real data.

Regression for "Malicious package: router-devtools-core@1.168.1
(osv:MAL-2026-3475)" on an image that does not carry a compromised version.

OSV publishes the package of a scoped npm advisory as
`pkg:npm/%40tanstack/router-devtools-core`. The loader asked "does this
purl carry a version?" by looking for an `@` in the decoded purl — the
scope's own `@` answered yes, so the name-only purl was stored for an
advisory that lists exactly two compromised versions, and the matcher read
it as "every version is malicious".

`fixtures/supply_chain/` holds the advisories as OSV serves them and the
component entries of the SBOM of the affected image (frontend:pr-2951,
Trivy 0.76.1, CycloneDX) — trimmed to the packages that were wrongly flagged
plus a few unscoped ones for the targeted tests, and whole for the
"nothing on this image is flagged" tests at the end. They go through the real
path: CycloneDX → `parse_sbom_report` → `fetch_osv` (loader + matcher) →
Finding.
"""
from __future__ import annotations

import io
import json
import os
import tempfile
import zipfile
from datetime import timedelta
from pathlib import Path
from unittest.mock import patch

import pytest
from django.contrib.auth.models import User
from django.urls import reverse
from django.utils import timezone

from core.constants import Environment, Source
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
from core.parsers.trivy import parse_sbom_report
from core.services import enrichment
from core.services.supply_chain_matcher import match_iocs_to_components

FIXTURES = Path(__file__).resolve().parents[2] / "fixtures" / "supply_chain"

TRIMMED_SBOM = "frontend.sbom.cdx.json"
FULL_SBOM = "frontend-full.sbom.cdx.json"

TANSTACK = "pkg:npm/@tanstack/router-devtools-core"
SOLANA = "pkg:npm/@solana/web3.js"
GHSA_URL = "https://github.com/advisories/GHSA-8jwm-h66c-fj6r"


# ── helpers ──────────────────────────────────────────────────────


def _npm_zip() -> str:
    """A temp `all.zip` of the fixture advisories — what
    `_http_download_conditional` hands the fetcher (which unlinks it)."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for p in sorted((FIXTURES / "advisories" / "npm").glob("*.json")):
            zf.writestr(p.name, p.read_bytes())
    fd, path = tempfile.mkstemp(suffix=".zip")
    with os.fdopen(fd, "wb") as f:
        f.write(buf.getvalue())
    return path


def _fetch_advisories():
    with patch.object(enrichment, "_http_download_conditional",
                      side_effect=lambda url, *, state_key, suffix=".bin": _npm_zip()):
        return enrichment.fetch_osv()


def _trivy_component(scope: str | None, name: str, version: str) -> dict:
    """A CycloneDX component the way Trivy writes an npm package: for a
    scoped one the scope's `@` is percent-encoded in the purl and the scope
    sits in `group`."""
    if scope is None:
        purl = f"pkg:npm/{name}@{version}"
        return {"bom-ref": purl, "type": "library", "name": name, "version": version,
                "purl": purl}
    purl = f"pkg:npm/%40{scope}/{name}@{version}"
    return {"bom-ref": purl, "type": "library", "group": f"@{scope}", "name": name,
            "version": version, "purl": purl}


def _store_sbom(image: Image, extra_components: list[dict] | None = None, *,
                sbom: str = TRIMMED_SBOM) -> None:
    """An SBOM fixture (+ `extra_components`) through the real parser into
    SbomComponent rows, one per purl the way ingest stores them."""
    bom = json.loads((FIXTURES / sbom).read_text())
    bom["components"] = [*bom["components"], *(extra_components or [])]
    report = {
        "metadata": {"namespace": "payments", "labels": {
            "trivy-operator.resource.namespace": "payments",
            "trivy-operator.resource.kind": "Deployment",
            "trivy-operator.resource.name": "frontend",
            "trivy-operator.container.name": "app",
        }},
        "report": {"artifact": {"repository": "superapp/frontend", "tag": "pr-2951",
                                "digest": image.digest},
                   "components": bom},
    }
    by_purl = {c["purl"]: c for c in parse_sbom_report(report)["components"]}
    SbomComponent.objects.bulk_create([SbomComponent(image=image, **c) for c in by_purl.values()])


@pytest.fixture
def image(db):
    c = Cluster.objects.create(name="c1", environment=Environment.PROD.value)
    c.last_complete_inventory_at = timezone.now() - timedelta(hours=1)
    c.save()
    ns = Namespace.objects.create(cluster=c, name="payments")
    w = Workload.objects.create(cluster=c, namespace=ns, kind="Deployment", name="frontend",
                                deployed=True)
    img = Image.objects.create(digest="sha256:" + "b" * 64, ref="reg/superapp/frontend:pr-2951")
    WorkloadImageObservation.objects.create(workload=w, image=img, container_name="app",
                                            currently_deployed=True)
    return img


def _flagged() -> dict[str, Finding]:
    """installed purl → finding, for the supply-chain lane."""
    return {
        f.details["purl"]: f
        for f in Finding.objects.filter(source=Source.SUPPLY_CHAIN_IOC.value)
    }


# ── the reported false positives ─────────────────────────────────


def test_versions_that_are_not_on_the_advisory_are_not_flagged(image):
    """The image carries router-devtools-core@1.168.1 (and five more scoped
    packages that were flagged the same way); the advisories name other
    versions. Nothing may be flagged."""
    _store_sbom(image)

    _fetch_advisories()
    assert _flagged() == {}

    match_iocs_to_components()  # the full re-scan (`match_supply_chain`) agrees
    assert _flagged() == {}


def test_scoped_advisory_is_stored_per_compromised_version(image):
    _store_sbom(image)

    _fetch_advisories()

    purls = set(SupplyChainIoc.objects.filter(advisory_id="MAL-2026-3475")
                .values_list("purl", flat=True))
    assert purls == {f"{TANSTACK}@1.167.6", f"{TANSTACK}@1.167.9"}
    # No name-only row, which the matcher would read as "every version".
    assert not SupplyChainIoc.objects.filter(purl=TANSTACK).exists()


def test_compromised_versions_are_flagged_with_the_advisory_details(image):
    _store_sbom(image, [
        _trivy_component("tanstack", "router-devtools-core", "1.167.6"),
        _trivy_component("tanstack", "router-devtools-core", "1.167.9"),
    ])

    _fetch_advisories()
    flagged = _flagged()

    assert set(flagged) == {f"{TANSTACK}@1.167.6", f"{TANSTACK}@1.167.9"}
    f = flagged[f"{TANSTACK}@1.167.6"]
    assert (f.vuln_id, f.installed_version) == ("MAL-2026-3475", "1.167.6")
    d = f.details
    assert d["purl"] == f"{TANSTACK}@1.167.6"
    assert d["affected_versions"] == ["1.167.6", "1.167.9"]
    assert d["affected_ranges"] == []
    assert d["advisory_url"] == GHSA_URL
    assert d["aliases"] == ["GHSA-8jwm-h66c-fj6r"]
    assert any("tanstack.com/blog" in link for link in d["links"])
    assert GHSA_URL not in d["links"]


def test_bounded_range_advisory_flags_only_versions_inside_the_range(image):
    """@solana/web3.js: `introduced 1.95.6, fixed 1.95.8` — both 1.95.6 and
    1.95.7 were published malicious. The image's own 1.98.4 is outside."""
    _store_sbom(image, [
        _trivy_component("solana", "web3.js", v) for v in ("1.95.5", "1.95.6", "1.95.7", "1.95.8")
    ])

    _fetch_advisories()
    flagged = _flagged()

    assert set(flagged) == {f"{SOLANA}@1.95.6", f"{SOLANA}@1.95.7"}
    assert flagged[f"{SOLANA}@1.95.7"].details["affected_ranges"] == [">= 1.95.6, < 1.95.8"]
    assert flagged[f"{SOLANA}@1.95.7"].details["affected_versions"] == []


def test_stale_name_only_row_from_the_old_loader_does_not_flag_other_versions(image):
    """Databases loaded before the fix hold `pkg:npm/@tanstack/...` as a
    name-only IoC for this advisory. The matcher judges it against the
    versions the advisory lists, so those rows are harmless until the
    cleanup migration replaces them."""
    advisory = json.loads((FIXTURES / "advisories" / "npm" / "MAL-2026-3475.json").read_text())
    SupplyChainIoc.objects.create(
        purl=TANSTACK, feed_source="osv", advisory_id="MAL-2026-3475",
        severity="CRITICAL", advisory_url=GHSA_URL, raw=advisory,
    )
    _store_sbom(image, [_trivy_component("tanstack", "router-devtools-core", "1.167.6")])

    match_iocs_to_components()

    assert set(_flagged()) == {f"{TANSTACK}@1.167.6"}


# ── the whole real image ─────────────────────────────────────────

# The ten advisories (fixtures/supply_chain/advisories/npm) that name a
# package this image carries — found by asking OSV about every package in
# its SBOM. Six scoped / ranged, four unscoped near-misses (`debug@4.4.3`
# next to the compromised 4.4.2, `supports-color@10.2.2` next to 10.2.1, …).
IMAGE_ADVISORIES = {
    "MAL-2024-11183", "MAL-2025-46974", "MAL-2025-46981", "MAL-2026-2307", "MAL-2026-2853",
    "MAL-2026-3463", "MAL-2026-3465", "MAL-2026-3466", "MAL-2026-3473", "MAL-2026-3475",
}


def test_whole_image_has_no_malicious_package(image):
    """Every one of the image's 700+ npm packages against every malicious
    advisory that names one of them: nothing is flagged — in particular not
    the reported `router-devtools-core@1.168.1`, by either the incremental
    match inside the feed fetch or a full re-scan."""
    _store_sbom(image, sbom=FULL_SBOM)
    # The fixture really is the whole image, and the reported package is on it.
    assert SbomComponent.objects.filter(image=image).count() > 700
    assert SbomComponent.objects.filter(
        image=image, purl="pkg:npm/@tanstack/router-devtools-core@1.168.1").exists()

    _fetch_advisories()

    # The loader did read all ten advisories, so "no findings" is a verdict
    # on the versions, not on a feed that never loaded.
    assert set(SupplyChainIoc.objects.values_list("advisory_id", flat=True)) == IMAGE_ADVISORIES
    assert _flagged() == {}
    assert not Finding.objects.filter(title__contains="router-devtools-core@1.168.1").exists()

    match_iocs_to_components()
    assert _flagged() == {}


def test_whole_image_flags_exactly_the_compromised_package_added_to_it(image):
    """The image plus one genuinely compromised version: that one purl is
    the only finding among 700+ packages — including the reported
    1.168.1 of the same package, which stays unflagged next to it."""
    _store_sbom(image, [_trivy_component("tanstack", "router-devtools-core", "1.167.6")],
                sbom=FULL_SBOM)

    _fetch_advisories()

    assert set(_flagged()) == {f"{TANSTACK}@1.167.6"}


@pytest.mark.parametrize("advisory_id,name", [
    ("MAL-2025-46974", "debug"),
    ("MAL-2025-46981", "supports-color"),
    ("MAL-2026-2307", "axios"),
    ("MAL-2026-2853", "react-hook-form"),
])
def test_whole_image_flags_every_version_an_unscoped_advisory_lists(image, advisory_id, name):
    """The four unscoped advisories on the image's packages: each listed
    version is flagged when present, and only those."""
    advisory = json.loads(
        (FIXTURES / "advisories" / "npm" / f"{advisory_id}.json").read_text())
    versions = advisory["affected"][0]["versions"]
    _store_sbom(image, [_trivy_component(None, name, v) for v in versions], sbom=FULL_SBOM)

    _fetch_advisories()

    assert set(_flagged()) == {f"pkg:npm/{name}@{v}" for v in versions}


# ── the finding panel ────────────────────────────────────────────


def _panel(client, finding: Finding) -> str:
    client.force_login(User.objects.create_user(username="panel-viewer", password="x"))
    resp = client.get(reverse("findings-detail-panel", args=[finding.pk]))
    assert resp.status_code == 200
    return resp.content.decode()


def _compromised_finding(image) -> Finding:
    _store_sbom(image, [_trivy_component("tanstack", "router-devtools-core", "1.167.6")])
    _fetch_advisories()
    return _flagged()[f"{TANSTACK}@1.167.6"]


def test_panel_shows_full_purl_compromised_versions_and_advisory_link(client, image):
    body = _panel(client, _compromised_finding(image))

    assert "Malicious package" in body
    assert f"{TANSTACK}@1.167.6" in body  # the installed package, with its version
    assert "Compromised versions" in body
    assert "<code class=\"me-1\">1.167.6</code>" in body
    assert "<code class=\"me-1\">1.167.9</code>" in body
    assert f'href="{GHSA_URL}"' in body
    assert "MAL-2026-3475" in body and "GHSA-8jwm-h66c-fj6r" in body
    # The advisory's other references are listed too.
    assert "tanstack.com/blog/npm-supply-chain-compromise-postmortem" in body


def test_panel_shows_the_range_for_a_range_only_advisory(client, image):
    _store_sbom(image, [_trivy_component("solana", "web3.js", "1.95.7")])
    _fetch_advisories()

    body = _panel(client, _flagged()[f"{SOLANA}@1.95.7"])

    assert "Compromised versions" in body
    assert "&gt;= 1.95.6, &lt; 1.95.8" in body


def test_panel_for_a_finding_raised_before_versions_were_stored(client, image):
    """Older findings carry no `affected_versions`: the row is left out,
    the purl and advisory link still render."""
    f = _compromised_finding(image)
    for key in ("affected_versions", "affected_ranges", "aliases", "links"):
        f.details.pop(key)
    f.save(update_fields=["details"])

    body = _panel(client, f)

    assert "Compromised versions" not in body
    assert f"{TANSTACK}@1.167.6" in body
    assert f'href="{GHSA_URL}"' in body


def test_panel_does_not_link_a_non_http_advisory_url(client, image):
    f = _compromised_finding(image)
    f.details["advisory_url"] = "javascript:alert(1)"
    f.save(update_fields=["details"])

    assert "javascript:" not in _panel(client, f).split("Raw details JSON")[0]


def test_panel_has_no_malicious_package_section_for_other_sources(client, image):
    f = _compromised_finding(image)
    Finding.objects.filter(pk=f.pk).update(source=Source.TRIVY.value)
    f.refresh_from_db()

    assert "Malicious package" not in _panel(client, f).replace(f.title, "")
