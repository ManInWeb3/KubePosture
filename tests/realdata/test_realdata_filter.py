"""Relevance filter and coverage over the real capture must match the
golden numbers recorded when the fixture was anonymised."""
from __future__ import annotations

import json

import pytest
from kubeposture_importer.coverage import compute_coverage
from kubeposture_importer.kinds import IMAGE_KINDS, SCAN_KINDS
from kubeposture_importer.relevance import apply_relevance_filter
from kubeposture_importer.snapshot_index import build_index

pytestmark = pytest.mark.realdata


def _report(by_kind, *, relevance=True):
    idx = build_index(by_kind)
    scan_items = {env_kind: list(by_kind[crd]) for crd, env_kind in SCAN_KINDS if crd in by_kind}
    filtered, stats = apply_relevance_filter(scan_items, idx, enabled=relevance)
    report = {"deployed_digests": len(idx.deployed_digests), "controllers": len(idx.controllers), "kinds": {}}
    for kind in filtered:
        cov = compute_coverage(kind, stats[kind], idx, threshold=0.9)
        report["kinds"][kind] = {**stats[kind].as_dict(), "count": len(filtered[kind]),
                                 "expected": cov.expected, "matched": cov.matched}
    return report, idx, stats, filtered


def test_filter_stats_match_golden(by_kind, golden):
    expected = golden("filter_stats.json")
    actual, idx, stats, _ = _report(by_kind)
    if actual != expected:
        unmatched = {k: sorted(s.unmatched_digests)[:10] for k, s in stats.items() if s.unmatched_digests}
        sources = {d: idx.digest_sources.get(d, []) for ds in unmatched.values() for d in ds}
        pytest.fail(
            "filter statistics drifted from golden/filter_stats.json\n"
            f"expected: {json.dumps(expected, sort_keys=True)}\n"
            f"actual:   {json.dumps(actual, sort_keys=True)}\n"
            f"unmatched digests (first 10 per kind): {json.dumps(unmatched)}\n"
            f"digest sources: {json.dumps(sources)}"
        )


def test_unfiltered_counts_match_golden(by_kind, golden):
    expected = golden("unfiltered_counts.json")
    actual, *_ = _report(by_kind, relevance=False)
    assert actual == expected


def test_every_kept_image_report_is_for_a_deployed_digest_and_coverage_is_sane(by_kind):
    _, idx, stats, filtered = _report(by_kind)
    assert idx.deployed_digests, "no deployed digest at all — pods without imageIDs?"
    for kind in IMAGE_KINDS:
        for item in filtered.get(kind, []):
            digest = (item.get("report") or {}).get("artifact", {}).get("digest", "").lower()
            assert digest in idx.deployed_digests
    for kind, s in stats.items():
        assert s.total == s.kept + s.dropped_no_subject + s.dropped_image_not_deployed, kind
