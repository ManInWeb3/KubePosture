"""Bundles built from the real capture: deterministic hashes, useful
compression, and the repository size budget."""
from __future__ import annotations

import sys

import pytest
from kubeposture_importer.bundle import BundleWriter
from kubeposture_importer.kinds import INVENTORY_ITEM_KINDS, SCAN_KINDS
from kubeposture_importer.relevance import apply_relevance_filter
from kubeposture_importer.snapshot_index import build_index
from kubeposture_importer.trim import derive_cluster_meta, trim_manifest

pytestmark = pytest.mark.realdata

MAX_COMPRESSED_ON_DISK = 3 * 1024 * 1024
MAX_UNCOMPRESSED = 25 * 1024 * 1024
MIN_SBOM_RATIO = 5.0
MIN_OVERALL_RATIO = 4.0


def _build(by_kind, tmp_path):
    idx = build_index(by_kind)
    scan_items = {env_kind: list(by_kind[crd]) for crd, env_kind in SCAN_KINDS if crd in by_kind}
    filtered, _ = apply_relevance_filter(scan_items, idx, enabled=True)
    metas = {}
    with BundleWriter(cluster="fixture", import_id="GOLDEN", kind="inventory", tmp_dir=tmp_path) as w:
        w.write_inventory_envelope(
            derive_cluster_meta("fixture", by_kind),
            (trim_manifest(it) for k in sorted(INVENTORY_ITEM_KINDS) for it in by_kind.get(k) or []),
        )
        metas["inventory"] = w.finish()
    for kind, items in filtered.items():
        with BundleWriter(cluster="fixture", import_id="GOLDEN", kind=kind, tmp_dir=tmp_path) as w:
            for item in items:
                w.write_item(item)
            metas[kind] = w.finish()
    return metas


def test_bundle_hashes_and_counts_match_golden(by_kind, golden, tmp_path):
    expected = golden("bundles.json")
    metas = _build(by_kind, tmp_path)
    actual = {k: {"count": m.count, "sha256": m.sha256} for k, m in metas.items()}
    assert actual == {k: {"count": v["count"], "sha256": v["sha256"]} for k, v in expected.items()}


def test_compression_ratio(by_kind, tmp_path):
    metas = _build(by_kind, tmp_path)
    total_u = sum(m.uncompressed_bytes for m in metas.values())
    total_c = sum(m.compressed_bytes for m in metas.values())
    assert total_u / total_c >= MIN_OVERALL_RATIO, f"overall ratio {total_u / total_c:.1f}x"
    if "trivy.SbomReport" in metas and metas["trivy.SbomReport"].count:
        m = metas["trivy.SbomReport"]
        assert m.uncompressed_bytes / m.compressed_bytes >= MIN_SBOM_RATIO


def test_fixture_size_budget(fixture_dir):
    import gzip
    on_disk = sum(p.stat().st_size for p in fixture_dir.rglob("*.gz"))
    uncompressed = sum(len(gzip.open(p, "rb").read()) for p in fixture_dir.rglob("*.gz"))
    assert on_disk <= MAX_COMPRESSED_ON_DISK, f"{on_disk / 1024 / 1024:.2f} MB on disk"
    assert uncompressed <= MAX_UNCOMPRESSED, f"{uncompressed / 1024 / 1024:.2f} MB uncompressed"


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="ru_maxrss semantics differ off Linux")
def test_peak_rss_stays_flat(by_kind, tmp_path):
    import resource
    before = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    _build(by_kind, tmp_path)
    after = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    assert (after - before) < 400 * 1024, f"bundle build grew RSS by {(after - before) / 1024:.0f} MB"
