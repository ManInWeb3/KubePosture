"""core.osv_ranges — OSV `affected[]` evaluation, no DB.

The cases are the traps found while measuring OSV against Trivy on the
real fixtures (see docs/osv.md): SEMVER ranges are a *set* of intervals,
Go pseudo-versions sort as prereleases, `versions[]` is empty for
npm / Go / crates.io but enumerated for PyPI / Maven, and Trivy encodes
`+` as `%2B` in Go purls.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from core.osv_ranges import (
    covers_version,
    describe_blocks,
    evaluate,
    ioc_purls,
    is_open_ended,
    is_pinned,
)

FIXTURES = Path(__file__).resolve().parents[2] / "fixtures" / "osv" / "advisories"


def _affected(eco: str, osv_id: str, name: str) -> list[dict]:
    adv = json.loads((FIXTURES / eco / f"{osv_id}.json").read_text())
    return [a for a in adv["affected"] if a["package"]["name"] == name]


def _eval(eco, osv_id, name, version):
    """Evaluate `version` against every affected block of that package in
    the advisory (the loader stores one row per block)."""
    hits = [
        evaluate(version, versions=a.get("versions") or [], ranges=a.get("ranges") or [])
        for a in _affected(eco, osv_id, name)
    ]
    return [h for h in hits if h.affected]


# ── SEMVER ranges: npm / Go / crates.io ───────────────────────────


@pytest.mark.parametrize("version,affected,fixed", [
    ("4.17.20", True, "4.17.21"),
    ("4.17.21-beta.1", True, "4.17.21"),   # prerelease of the fix is still vulnerable
    ("4.17.21", False, ""),
    ("0.0.1", True, "4.17.21"),            # introduced "0" = every version
])
def test_npm_introduced_zero_fixed(version, affected, fixed):
    hits = _eval("npm", "GHSA-35jh-r3h4-6jhm", "lodash", version)
    assert bool(hits) is affected
    if affected:
        assert hits[0].fixed_version == fixed


def test_last_affected_is_inclusive():
    assert _eval("npm", "GHSA-35jh-r3h4-6jhm", "lodash.template", "4.5.0")
    assert not _eval("npm", "GHSA-35jh-r3h4-6jhm", "lodash.template", "4.5.1")
    assert _eval("npm", "GHSA-35jh-r3h4-6jhm", "lodash.template", "4.5.0")[0].fixed_version == ""


@pytest.mark.parametrize("version,affected,fixed", [
    # stdlib: [0, 1.19.6) ∪ [1.20.0-0, 1.20.1) — a sequential walk of the
    # events would reset the first interval and miss 1.19.5.
    ("1.19.5", True, "1.19.6"),
    ("v1.19.5", True, "1.19.6"),           # Trivy keeps the leading v
    ("1.19.6", False, ""),
    ("1.20.0", True, "1.20.1"),
    ("1.20.0-rc1", True, "1.20.1"),        # 1.20.0-0 lower bound admits prereleases
    ("1.20.1", False, ""),
    ("1.21.0", False, ""),
])
def test_go_multi_interval(version, affected, fixed):
    hits = _eval("Go", "GO-2023-1571", "stdlib", version)
    assert bool(hits) is affected
    if affected:
        assert hits[0].fixed_version == fixed


@pytest.mark.parametrize("version,affected", [
    ("v0.6.0", True),
    ("v0.0.0-20220722155237-a158d28d115b", True),   # pseudo-version < 0.7.0
    ("v0.7.0", False),
    ("v0.55.0", False),
])
def test_go_pseudo_versions(version, affected):
    assert bool(_eval("Go", "GO-2023-1571", "golang.org/x/net", version)) is affected


def test_go_pseudo_version_as_upper_bound_does_not_swallow_releases():
    """`fixed: 0.0.0-2020…` is a prerelease of 0.0.0: only older pseudo-
    versions are below it. univers got this wrong (flagged v0.52.0)."""
    ranges = [{"type": "SEMVER", "events": [
        {"introduced": "0"}, {"fixed": "0.0.0-20201216223049-8b5274cf687f"},
    ]}]
    assert not evaluate("v0.52.0", versions=[], ranges=ranges).affected
    assert evaluate("v0.0.0-20200101000000-aaaaaaaaaaaa", versions=[], ranges=ranges).affected


@pytest.mark.parametrize("version,affected", [
    ("v1.56.2", True), ("v1.56.3", False),
    ("v1.57.0", True), ("v1.57.1", False),
    ("v1.58.2", True), ("v1.58.3", False), ("v1.59.0", False),
    ("v1.56.2+incompatible", True),         # build metadata ignored in ordering
])
def test_go_three_intervals(version, affected):
    assert bool(_eval("Go", "GHSA-m425-mq94-257g", "google.golang.org/grpc", version)) is affected


def test_go_open_ended_range():
    """`introduced: 0` with no fixed event: every version, no fix known."""
    hits = _eval("Go", "GO-2025-3521", "k8s.io/kubernetes", "v1.33.7")
    assert hits and hits[0].fixed_version == ""


@pytest.mark.parametrize("version,affected", [
    ("1.20.2", True), ("1.18.4", False), ("1.6.0", False), ("1.23.1", False), ("1.22.0", True),
])
def test_cargo_three_intervals(version, affected):
    assert bool(_eval("crates.io", "RUSTSEC-2023-0001", "tokio", version)) is affected


# ── ECOSYSTEM ranges: PyPI / Maven use the enumerated versions[] ──


@pytest.mark.parametrize("version,affected", [
    ("2.28.0", True), ("2.31.0", False), ("2.2.1", False), ("2.30.0", True),
])
def test_pypi_enumerated_versions(version, affected):
    hits = _eval("PyPI", "GHSA-j8r2-6x86-q33q", "requests", version)
    assert bool(hits) is affected
    if affected:
        assert hits[0].fixed_version == "2.31.0"   # from the ECOSYSTEM range's `fixed`


@pytest.mark.parametrize("version,affected", [
    ("2.14.1", True), ("2.15.0", False), ("2.0-beta9", True), ("2.12.2", False), ("2.3.1", False),
])
def test_maven_enumerated_versions(version, affected):
    hits = _eval("Maven", "GHSA-jfh8-c2jp-5v3q", "org.apache.logging.log4j:log4j-core", version)
    assert bool(hits) is affected


def test_ecosystem_range_without_versions_is_not_guessed():
    """OSV enumerates versions for ECOSYSTEM ranges; when it hasn't, we
    don't invent Maven/PyPI ordering rules — report `unsupported`."""
    ranges = [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}]}]
    res = evaluate("1.0", versions=[], ranges=ranges)
    assert not res.affected and res.unsupported


def test_git_ranges_are_ignored():
    git_range = {"type": "GIT", "events": [
        {"introduced": "0"}, {"fixed": "74ea7cf7a6a27a4eeb2ae24e162bcc942a6706d5"},
    ]}
    res = evaluate("2.28.0", versions=["2.28.0"], ranges=[git_range])
    assert res.affected and not res.unsupported


# ── version normalisation ─────────────────────────────────────────


@pytest.mark.parametrize("version", [
    "v1.2.3",
    "1.2.3",
    "1.9.2-0.20260728194948-08633f6a24d3+dirty",
    "3.21.4-0.20210419000835-c7a38de76ee5+incompatible",
    "68.0.0+incompatible",
])
def test_real_go_versions_parse(version):
    ranges = [{"type": "SEMVER", "events": [{"introduced": "0"}]}]
    assert evaluate(version, versions=[], ranges=ranges).affected


def test_unparsable_version_is_unsupported_not_affected():
    ranges = [{"type": "SEMVER", "events": [{"introduced": "0"}]}]
    res = evaluate("not-a-version", versions=[], ranges=ranges)
    assert not res.affected and res.unsupported


# ── malicious-package blocks (IoC lane) ─────────────────────────


def _mal_block(**kw) -> dict:
    return {"package": {"name": "@tanstack/x", "ecosystem": "npm", "purl": "pkg:npm/%40tanstack/x"},
            **kw}


def test_ioc_purls_scoped_package_with_versions_is_one_purl_per_version():
    """The scope's own `@` is not a version separator."""
    block = _mal_block(versions=["1.167.9", "1.167.6", "1.167.9"])
    assert ioc_purls(block, "npm") == ["pkg:npm/@tanstack/x@1.167.9", "pkg:npm/@tanstack/x@1.167.6"]


def test_ioc_purls_ranges_only_block_is_name_only_scoped_or_not():
    ranges = [{"type": "SEMVER", "events": [{"introduced": "0"}]}]
    assert ioc_purls(_mal_block(ranges=ranges), "npm") == ["pkg:npm/@tanstack/x"]
    plain = {"package": {"name": "evil-pkg"}, "ranges": ranges}
    assert ioc_purls(plain, "npm") == ["pkg:npm/evil-pkg"]


def test_ioc_purls_explicit_versioned_purl_wins_over_versions():
    block = {"package": {"name": "lodash", "purl": "pkg:npm/lodash@4.17.21"},
             "versions": ["4.17.20"]}
    assert ioc_purls(block, "npm") == ["pkg:npm/lodash@4.17.21"]
    scoped = {"package": {"name": "@s/p", "purl": "pkg:npm/%40s/p@1.0.0"}}
    assert ioc_purls(scoped, "npm") == ["pkg:npm/@s/p@1.0.0"]


def test_ioc_purls_block_without_a_package_name_yields_nothing():
    assert ioc_purls({"versions": ["1.0.0"]}, "npm") == []
    assert ioc_purls({"package": {"name": "x"}, "versions": ["1.0.0"]}, "") == []


@pytest.mark.parametrize("version,expected", [
    ("1.95.5", False), ("1.95.6", True), ("1.95.7", True), ("1.95.8", False), ("1.98.4", False),
])
def test_covers_version_bounded_semver_range(version, expected):
    events = [{"introduced": "1.95.6"}, {"fixed": "1.95.8"}]
    block = {"ranges": [{"type": "SEMVER", "events": events}]}
    assert covers_version(version, block) is expected


def test_covers_version_enumerated_versions():
    block = {"versions": ["1.167.6", "1.167.9"]}
    assert covers_version("1.167.9", block) and not covers_version("1.168.1", block)


@pytest.mark.parametrize("block", [
    {"ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}]}]},   # the whole package
    {"ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}]}]},  # not interpreted
    {"ranges": [{"type": "GIT", "events": [{"introduced": "deadbeef"}]}]},
    {},
])
def test_covers_version_fails_open_for_what_it_cannot_interpret(block):
    assert covers_version("3.1.4", block)


def test_covers_version_unparsable_version_counts_as_covered():
    events = [{"introduced": "1.0.0"}, {"fixed": "2.0.0"}]
    block = {"ranges": [{"type": "SEMVER", "events": events}]}
    assert covers_version("not-a-version", block)


def test_describe_blocks_orders_versions_and_words_the_ranges():
    versions, ranges = describe_blocks([
        {"versions": ["1.10.0", "1.2.0", "weird"]},
        {"versions": ["1.2.0"], "ranges": [
            {"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "0.5.0"},
                                          {"introduced": "1.95.6"}, {"fixed": "1.95.8"},
                                          {"introduced": "3.0.0"}, {"last_affected": "3.2.0"},
                                          {"introduced": "4.0.0"}]},
            {"type": "SEMVER", "events": [{"introduced": "0"}]},
            {"type": "GIT", "events": [{"introduced": "deadbeef"}]},
        ]},
    ])
    assert versions == ["1.2.0", "1.10.0", "weird"]
    assert ranges == ["< 0.5.0", ">= 1.95.6, < 1.95.8", ">= 3.0.0, <= 3.2.0", ">= 4.0.0",
                      "all versions"]


def _semver(*events):
    return [{"type": "SEMVER", "events": list(events)}]


@pytest.mark.parametrize("versions, ranges, pinned, open_ended", [
    # GHSA for a single compromised release: exact list, no range.
    (["0.69.4"], [], True, False),
    # Go vulndb for the same: one `introduced`, nothing closes it.
    ([], _semver({"introduced": "0.69.4"}), False, True),
    # Any interval that closes is not open-ended; a later one that doesn't is.
    ([], _semver({"introduced": "1.0.0"}, {"fixed": "1.5.0"}), False, False),
    ([], _semver({"introduced": "1.0.0"}, {"fixed": "1.5.0"}, {"introduced": "2.0.0"}),
     False, True),
    ([], _semver({"introduced": "0"}, {"last_affected": "1.5.0"}), False, False),
    # PyPI / Maven carry both: neither pinned nor open-ended (the list is
    # the OSV-enumerated expansion of the range, not a statement of its own).
    (["1.0", "1.1"], [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}]}], False, False),
    # ECOSYSTEM / GIT ranges are not interpreted.
    ([], [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}]}], False, False),
    ([], [], False, False),
])
def test_pinned_and_open_ended_blocks(versions, ranges, pinned, open_ended):
    assert is_pinned(versions, ranges) is pinned
    assert is_open_ended(versions, ranges) is open_ended
