"""The importer's streaming BundleWriter and the server's build_ndjson
(used by the test harness and the e2e tests) must emit byte-identical
bundles — otherwise the e2e suite would be testing a format the real
importer never sends."""
from __future__ import annotations

import gzip

from kubeposture_importer.bundle import BundleWriter

from core.services.bundle_ingest import build_ndjson

ITEMS = [
    {"apiVersion": "aquasecurity.github.io/v1alpha1", "kind": "VulnerabilityReport",
     "metadata": {"name": "r1", "labels": {"a": "b"}}, "report": {"vulnerabilities": [{"id": "CVE-1", "n": 1.5}]}},
    {"kind": "VulnerabilityReport", "metadata": {"name": "r2"}, "text": "ünïcode \n newline"},
]
META = {"name": "c", "k8s_version": "v1.30", "provider": "eks", "region": "eu"}


def test_scan_bundle_bytes_match(tmp_path):
    with BundleWriter(cluster="c", import_id="imp-1", kind="trivy.VulnerabilityReport", tmp_dir=tmp_path) as w:
        for item in ITEMS:
            w.write_item(item)
        meta = w.finish(coverage={"expected": 2, "matched": 2},
                        extra={"importer_version": "2.0.0", "relevance_filter": True, "filter": {"total": 2}})
    expected = build_ndjson(
        ITEMS, cluster="c", import_id="imp-1", kind="trivy.VulnerabilityReport",
        coverage={"expected": 2, "matched": 2},
        extra={"importer_version": "2.0.0", "relevance_filter": True, "filter": {"total": 2}},
    )
    assert gzip.decompress(meta.path.read_bytes()) == expected


def test_inventory_envelope_bytes_match(tmp_path):
    with BundleWriter(cluster="c", import_id="imp-1", kind="inventory", tmp_dir=tmp_path, complete_snapshot=True) as w:
        w.write_inventory_envelope(META, iter(ITEMS))
        meta = w.finish(extra={"importer_version": "2.0.0", "relevance_filter": True})
    envelope = {"cluster_meta": META, "complete_snapshot": True, "items": ITEMS}
    expected = build_ndjson(
        [envelope], cluster="c", import_id="imp-1", kind="inventory", complete_snapshot=True,
        extra={"importer_version": "2.0.0", "relevance_filter": True},
    )
    assert gzip.decompress(meta.path.read_bytes()) == expected
