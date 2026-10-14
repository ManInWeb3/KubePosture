import gzip
import hashlib
import json

import pytest
from kubeposture_importer.bundle import BundleWriter

ITEMS = [{"kind": "VulnerabilityReport", "metadata": {"name": f"r{i}"}, "n": i} for i in range(5)]


def _read(meta):
    raw = gzip.decompress(meta.path.read_bytes())
    head, _, body = raw.partition(b"\n")
    return json.loads(head)["manifest"], body


def _write(tmp_path, items, **kw):
    with BundleWriter(cluster="c", import_id="imp-1", kind="trivy.VulnerabilityReport", tmp_dir=tmp_path, **kw) as w:
        for item in items:
            w.write_item(item)
        return w.finish()


def test_sha256_and_count_cover_the_item_lines_exactly(tmp_path):
    meta = _write(tmp_path, ITEMS)
    manifest, body = _read(meta)
    expected_body = b"".join(json.dumps(i, separators=(",", ":")).encode() + b"\n" for i in ITEMS)
    assert body == expected_body
    assert manifest["sha256"] == meta.sha256 == hashlib.sha256(expected_body).hexdigest()
    assert manifest["count"] == meta.count == 5
    assert manifest["cluster"] == "c" and manifest["import_id"] == "imp-1"
    assert manifest["complete_snapshot"] is False
    assert meta.item_bytes == len(expected_body)
    assert meta.uncompressed_bytes == len(expected_body) + len(json.dumps({"manifest": manifest}, separators=(",", ":")).encode()) + 1
    assert meta.compressed_bytes == meta.path.stat().st_size


def test_gzip_round_trip_preserves_order(tmp_path):
    meta = _write(tmp_path, ITEMS)
    _, body = _read(meta)
    assert [json.loads(ln) for ln in body.splitlines()] == ITEMS


def test_empty_bundle(tmp_path):
    meta = _write(tmp_path, [])
    manifest, body = _read(meta)
    assert body == b""
    assert manifest["count"] == 0
    assert manifest["sha256"] == hashlib.sha256(b"").hexdigest()


def test_large_single_line_and_embedded_newlines(tmp_path):
    big = {"blob": "x" * (5 * 1024 * 1024), "text": "line1\nline2\r\nline3"}
    meta = _write(tmp_path, [big, {"after": True}])
    _, body = _read(meta)
    lines = body.split(b"\n")
    assert lines[-1] == b"" and len(lines) == 3, "one physical line per object despite embedded newlines"
    assert json.loads(lines[0]) == big


def test_inventory_envelope_streams_as_single_line_identical_to_json_dumps(tmp_path):
    meta_dict = {"name": "c", "k8s_version": "v1.30", "provider": "eks", "region": "eu"}
    items = [{"kind": "Namespace", "metadata": {"name": "ns"}}, {"kind": "Pod", "metadata": {"name": "p"}}]
    with BundleWriter(cluster="c", import_id="imp-1", kind="inventory", tmp_dir=tmp_path, complete_snapshot=True) as w:
        w.write_inventory_envelope(meta_dict, iter(items))
        meta = w.finish()
    manifest, body = _read(meta)
    expected = json.dumps({"cluster_meta": meta_dict, "complete_snapshot": True, "items": items},
                          separators=(",", ":")).encode() + b"\n"
    assert body == expected
    assert manifest["count"] == 1 and manifest["complete_snapshot"] is True
    assert manifest["sha256"] == hashlib.sha256(expected).hexdigest()


def test_empty_inventory_envelope(tmp_path):
    with BundleWriter(cluster="c", import_id="imp-1", kind="inventory", tmp_dir=tmp_path, complete_snapshot=True) as w:
        w.write_inventory_envelope({"name": "c"}, [])
        meta = w.finish()
    _, body = _read(meta)
    assert json.loads(body) == {"cluster_meta": {"name": "c"}, "complete_snapshot": True, "items": []}


def test_manifest_coverage_and_extra_fields(tmp_path):
    with BundleWriter(cluster="c", import_id="imp-1", kind="trivy.SbomReport", tmp_dir=tmp_path) as w:
        w.write_item(ITEMS[0])
        meta = w.finish(coverage={"expected": 3, "matched": 2}, extra={"importer_version": "2.0.0", "filter": {"total": 1}})
    manifest, _ = _read(meta)
    assert manifest["coverage"] == {"expected": 3, "matched": 2}
    assert manifest["importer_version"] == "2.0.0" and manifest["filter"] == {"total": 1}
    assert meta.manifest == manifest


def test_deterministic_compressed_bytes(tmp_path):
    a = _write(tmp_path / "a", ITEMS)
    b = _write(tmp_path / "b", ITEMS)
    assert a.path.read_bytes() == b.path.read_bytes()


def test_scratch_file_removed_and_only_the_gz_remains(tmp_path):
    meta = _write(tmp_path, ITEMS)
    assert [p.name for p in tmp_path.iterdir()] == [meta.path.name]
    meta.unlink()
    assert list(tmp_path.iterdir()) == []
    meta.unlink()  # idempotent


def test_exception_inside_writer_cleans_up_scratch(tmp_path):
    with pytest.raises(RuntimeError):
        with BundleWriter(cluster="c", import_id="imp-1", kind="k", tmp_dir=tmp_path) as w:
            w.write_item(ITEMS[0])
            raise RuntimeError("boom")
    assert list(tmp_path.iterdir()) == []


def test_finish_twice_is_an_error(tmp_path):
    w = BundleWriter(cluster="c", import_id="imp-1", kind="k", tmp_dir=tmp_path)
    w.finish()
    with pytest.raises(RuntimeError):
        w.finish()
