"""Tests for `core.purl.normalize_purl` and end-to-end normalisation
across parser → ingest → search → matcher.
"""
from __future__ import annotations

import pytest

from core.constants import Environment
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
from core.parsers import trivy
from core.purl import (
    normalize_purl,
    parse_purl_name_version,
    purl_ecosystem,
)
from core.services.components import component_detail, search_by_purls
from core.services.supply_chain_matcher import match_iocs_to_components


# ── Unit: normalize_purl ────────────────────────────────────────


def test_normalize_replaces_percent_40_with_at():
    assert (
        normalize_purl("pkg:npm/lodash%404.17.21")
        == "pkg:npm/lodash@4.17.21"
    )


def test_normalize_idempotent_on_clean_purl():
    p = "pkg:npm/lodash@4.17.21"
    assert normalize_purl(p) == p


def test_normalize_handles_empty():
    assert normalize_purl("") == ""


def test_normalize_doesnt_touch_other_percent_encoded_chars():
    """Qualifiers may carry intentional percent-encoded chars; only
    `%40` is the version-separator bug we fix here.
    """
    p = "pkg:deb/debian/libc6%404.0-1?arch=amd64&distro=debian%2012"
    out = normalize_purl(p)
    assert "@" in out
    assert "%2012" in out  # leave other %XX alone


def test_normalize_handles_multiple_at_separators():
    # Pathological but: if a producer encoded multiple `@`s, fix all.
    assert (
        normalize_purl("pkg:foo/a%40b%40c")
        == "pkg:foo/a@b@c"
    )


# ── Unit: parse_purl_name_version ───────────────────────────────


@pytest.mark.parametrize("purl,expected_name,expected_version", [
    # Simple cases
    ("pkg:npm/lodash@4.17.21", "lodash", "4.17.21"),
    ("pkg:pypi/requests@2.28.0", "requests", "2.28.0"),
    ("pkg:cargo/serde@1.0.0", "serde", "1.0.0"),
    # No version
    ("pkg:pypi/requests", "requests", ""),
    ("pkg:npm/lodash", "lodash", ""),
    # Scoped names (the bug we're fixing)
    ("pkg:npm/@types/node@20.0.0", "@types/node", "20.0.0"),
    ("pkg:pypi/@ctx@0.1.2", "@ctx", "0.1.2"),
    ("pkg:npm/@scope/pkg-with-dashes@1.2.3", "@scope/pkg-with-dashes", "1.2.3"),
    # Namespaced (deb/rpm style)
    ("pkg:deb/debian/libc6@2.36-9", "debian/libc6", "2.36-9"),
    ("pkg:rpm/rhel/glibc@2.34-100", "rhel/glibc", "2.34-100"),
    # Qualifiers stripped
    ("pkg:deb/debian/libc6@2.36-9?arch=amd64", "debian/libc6", "2.36-9"),
    ("pkg:gomod/github.com/foo/bar@v1.0.0#subdir", "github.com/foo/bar", "v1.0.0"),
    # Edge cases
    ("", "", ""),
    ("not-a-purl", "not-a-purl", ""),
    ("pkg:npm/@scope-only", "@scope-only", ""),
])
def test_parse_purl_name_version(purl, expected_name, expected_version):
    name, version = parse_purl_name_version(purl)
    assert name == expected_name, f"name for {purl!r}"
    assert version == expected_version, f"version for {purl!r}"


# ── Unit: purl_ecosystem ────────────────────────────────────────


@pytest.mark.parametrize("purl,expected", [
    ("pkg:npm/lodash@4.17.21", "npm"),
    ("pkg:pypi/requests@2.28.0", "pypi"),
    ("pkg:deb/debian/libc6@2.36-9", "deb"),
    ("pkg:npm/@types/node@20.0.0", "npm"),
    ("pkg:golang/github.com/foo/bar@v1.0.0", "golang"),
    ("", ""),
    ("not-a-purl", ""),
    ("pkg:onlytype", "onlytype"),
])
def test_purl_ecosystem(purl, expected):
    assert purl_ecosystem(purl) == expected


# ── Parser: SbomReport with encoded purls ────────────────────────


def _sbom_with_encoded_purl():
    return {
        "apiVersion": "aquasecurity.github.io/v1alpha1",
        "kind": "SbomReport",
        "metadata": {
            "labels": {
                "trivy-operator.resource.namespace": "payments",
                "trivy-operator.resource.kind": "ReplicaSet",
                "trivy-operator.resource.name": "api",
                "trivy-operator.container.name": "main",
            },
        },
        "report": {
            "artifact": {
                "repository": "payments/api",
                "tag": "v1.2.3",
                "digest": "sha256:" + "a" * 64,
            },
            "components": {
                "components": [
                    {
                        "type": "library",
                        "name": "lodash",
                        "version": "4.17.21",
                        "purl": "pkg:npm/lodash%404.17.21",
                    },
                ],
            },
        },
    }


def test_parser_normalises_encoded_purls():
    parsed = trivy.parse_sbom_report(_sbom_with_encoded_purl())
    assert len(parsed["components"]) == 1
    assert parsed["components"][0]["purl"] == "pkg:npm/lodash@4.17.21"


# ── Search: input normalisation ─────────────────────────────────


@pytest.fixture
def deployed_lodash(db):
    c = Cluster.objects.create(name="c-norm", environment=Environment.PROD.value)
    ns = Namespace.objects.create(cluster=c, name="payments")
    w = Workload.objects.create(
        cluster=c, namespace=ns, kind="Deployment", name="api", deployed=True,
    )
    img = Image.objects.create(digest="sha256:" + "a" * 64, ref="reg/api:v1")
    WorkloadImageObservation.objects.create(
        workload=w, image=img, container_name="main", currently_deployed=True,
    )
    SbomComponent.objects.create(
        image=img, purl="pkg:npm/lodash@4.17.21",
        name="lodash", version="4.17.21", ecosystem="npm",
    )
    return c, w, img


@pytest.mark.django_db
def test_search_normalises_input_purls(deployed_lodash):
    # Caller supplies the broken `%40` form; we should still find it.
    rows = search_by_purls(purls=["pkg:npm/lodash%404.17.21"])
    assert len(rows) == 1
    assert rows[0]["purl"] == "pkg:npm/lodash@4.17.21"


@pytest.mark.django_db
def test_component_detail_normalises_input_purl(deployed_lodash):
    d = component_detail("pkg:npm/lodash%404.17.21")
    assert d is not None
    assert d["purl"] == "pkg:npm/lodash@4.17.21"


# ── Matcher: touched_purls normalisation ─────────────────────────


@pytest.mark.django_db
def test_matcher_normalises_touched_purls(deployed_lodash):
    SupplyChainIoc.objects.create(
        purl="pkg:npm/lodash@4.17.21",
        feed_source="osv",
        advisory_id="MAL-norm",
        severity="critical",
        title="x",
    )
    # Caller hands in `%40` form; matcher should normalise and still hit.
    n = match_iocs_to_components(
        touched_purls=["pkg:npm/lodash%404.17.21"],
    )
    assert n == 1
    assert Finding.objects.filter(source="supply_chain_ioc").count() == 1
