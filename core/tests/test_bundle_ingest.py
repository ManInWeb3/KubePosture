"""Service-level tests for core.services.bundle_ingest — spool / verify /
store / commit / abort, driven with in-memory gzip bodies exactly as the
upload view feeds them."""
from __future__ import annotations

import gzip
import hashlib
import io
import json
from unittest.mock import patch

import pytest
from django.test import override_settings

from core.constants import ImportMarkState, IngestQueueStatus
from core.models import Cluster, ImportMark, IngestQueue
from core.services import bundle_ingest as bi
from core.services.bundle_ingest import BundleError, BundleLimits, build_ndjson

MiB = 1024 * 1024
LIMITS = BundleLimits(
    max_compressed=10 * MiB, max_uncompressed=50 * MiB, max_items=1000, max_line_bytes=5 * MiB,
)
VULN = "trivy.VulnerabilityReport"
SBOM = "trivy.SbomReport"
INV = "inventory"
ITEM = {
    "apiVersion": "aquasecurity.github.io/v1alpha1", "kind": "VulnerabilityReport",
    "metadata": {"name": "x"}, "report": {"vulnerabilities": []},
}
ENVELOPE = {"cluster_meta": {"name": "c-bundle"}, "complete_snapshot": True, "items": []}


@pytest.fixture
def cluster(db):
    return Cluster.objects.create(name="c-bundle")


def _raw(import_id: str, kind: str, items: list[dict], **kw) -> bytes:
    return build_ndjson(items, cluster="c-bundle", import_id=import_id, kind=kind, **kw)


def _spool(raw: bytes, *, gz: bool = True, limits: BundleLimits = LIMITS):
    body = gzip.compress(raw) if gz else raw
    return bi.spool_bundle(io.BytesIO(body), gzip_encoded=gz, limits=limits)


def _store(cluster, raw: bytes, *, import_id: str, kind: str, limits: BundleLimits = LIMITS):
    with _spool(raw, limits=limits) as sp:
        bi.check_manifest(sp.manifest, import_id=import_id, kind=kind)
        bi.verify_bundle(sp, limits=limits)
        return bi.store_bundle(cluster=cluster, spooled=sp)


def _tamper(raw: bytes, **overrides) -> bytes:
    """Rewrite manifest fields without touching the item lines."""
    head, _, body = raw.partition(b"\n")
    doc = json.loads(head)
    doc["manifest"].update(overrides)
    return json.dumps(doc).encode() + b"\n" + body


def _manual(import_id: str, kind: str, body: bytes, *, count: int) -> bytes:
    """Manifest computed over an arbitrary (possibly invalid) body."""
    manifest = {
        "cluster": "c-bundle", "import_id": import_id, "kind": kind,
        "count": count, "sha256": hashlib.sha256(body).hexdigest(),
    }
    return json.dumps({"manifest": manifest}).encode() + b"\n" + body


def _err(fn, *args, **kwargs) -> BundleError:
    with pytest.raises(BundleError) as excinfo:
        fn(*args, **kwargs)
    return excinfo.value


# ── store ──────────────────────────────────────────────────────────


@pytest.mark.django_db
def test_store_bundle_inserts_rows_and_open_mark(cluster):
    raw = _raw("imp-1", VULN, [ITEM, ITEM])
    result = _store(cluster, raw, import_id="imp-1", kind=VULN)

    assert result.created is True
    assert result.rows_inserted == 2
    rows = list(IngestQueue.objects.filter(cluster_name="c-bundle", import_id="imp-1"))
    assert len(rows) == 2
    assert all(r.status == IngestQueueStatus.PENDING.value and r.kind == VULN for r in rows)
    mark = result.mark
    assert mark.state == ImportMarkState.OPEN.value
    assert mark.bundle_sha256 == json.loads(raw.partition(b"\n")[0])["manifest"]["sha256"]
    assert mark.coverage_expected is None and mark.coverage_matched is None
    assert mark.bundle_manifest == {}
    assert mark.observed_count is None


@pytest.mark.django_db
def test_store_bundle_persists_coverage_and_extra_manifest_fields(cluster):
    raw = _raw(
        "imp-1", VULN, [ITEM],
        coverage={"expected": 12, "matched": 11},
        extra={"importer_version": "2.0.0", "relevance_filter": True,
               "filter": {"total": 5, "kept": 1}},
    )
    mark = _store(cluster, raw, import_id="imp-1", kind=VULN).mark
    assert (mark.coverage_expected, mark.coverage_matched) == (12, 11)
    assert mark.bundle_manifest == {
        "importer_version": "2.0.0", "relevance_filter": True, "filter": {"total": 5, "kept": 1},
    }


@pytest.mark.django_db
def test_inventory_complete_snapshot_from_manifest_or_payload(cluster):
    raw = _raw("imp-1", INV, [{**ENVELOPE, "complete_snapshot": False}], complete_snapshot=True)
    _store(cluster, raw, import_id="imp-1", kind=INV)
    assert IngestQueue.objects.get(import_id="imp-1").complete_snapshot is True

    raw = _raw("imp-2", INV, [{**ENVELOPE, "complete_snapshot": True}], complete_snapshot=False)
    _store(cluster, raw, import_id="imp-2", kind=INV)
    assert IngestQueue.objects.get(import_id="imp-2").complete_snapshot is True

    raw = _raw("imp-3", INV, [{**ENVELOPE, "complete_snapshot": False}], complete_snapshot=False)
    _store(cluster, raw, import_id="imp-3", kind=INV)
    assert IngestQueue.objects.get(import_id="imp-3").complete_snapshot is False


@pytest.mark.django_db
def test_complete_snapshot_only_applies_to_inventory_kind(cluster):
    raw = _raw("imp-1", VULN, [ITEM], complete_snapshot=True)
    _store(cluster, raw, import_id="imp-1", kind=VULN)
    assert IngestQueue.objects.get(import_id="imp-1").complete_snapshot is False


@pytest.mark.django_db
def test_empty_bundle_creates_mark_without_rows(cluster):
    raw = _raw("imp-1", VULN, [])
    result = _store(cluster, raw, import_id="imp-1", kind=VULN)
    assert result.rows_inserted == 0
    assert result.mark.bundle_sha256 == bi.EMPTY_SHA256
    assert IngestQueue.objects.count() == 0
    assert ImportMark.objects.get(import_id="imp-1").state == ImportMarkState.OPEN.value


@pytest.mark.django_db
def test_started_at_is_shared_across_kinds_and_precedes_every_row(cluster):
    """Scan bundles may be uploaded before inventory; every row's
    created_at must still be >= the inventory mark's started_at, which
    is what last_complete_inventory_at advances to."""
    vuln = _store(cluster, _raw("imp-1", VULN, [ITEM]), import_id="imp-1", kind=VULN).mark
    sbom = _store(cluster, _raw("imp-1", SBOM, [ITEM]), import_id="imp-1", kind=SBOM).mark
    inv = _store(cluster, _raw("imp-1", INV, [ENVELOPE]), import_id="imp-1", kind=INV).mark

    assert vuln.started_at == sbom.started_at == inv.started_at
    earliest_row = min(IngestQueue.objects.values_list("created_at", flat=True))
    assert inv.started_at <= earliest_row


# ── verify / spool rejections (nothing stored) ─────────────────────


@pytest.mark.django_db
def test_sha256_mismatch_rejected(cluster):
    raw = _tamper(_raw("imp-1", VULN, [ITEM]), sha256="0" * 64)
    err = _err(_store, cluster, raw, import_id="imp-1", kind=VULN)
    assert err.code == "sha256_mismatch"
    assert err.detail["expected"] == "0" * 64
    assert IngestQueue.objects.count() == 0 and ImportMark.objects.count() == 0


@pytest.mark.django_db
def test_count_mismatch_rejected(cluster):
    raw = _tamper(_raw("imp-1", VULN, [ITEM]), count=5)
    err = _err(_store, cluster, raw, import_id="imp-1", kind=VULN)
    assert err.code == "count_mismatch"
    assert (err.detail["expected"], err.detail["actual"]) == (5, 1)
    assert ImportMark.objects.count() == 0


@pytest.mark.django_db
def test_malformed_line_rolls_back_mark_and_rows(cluster):
    body = b'{"ok":1}\n' + b"not json\n" + b'{"ok":2}\n'
    raw = _manual("imp-1", VULN, body, count=3)
    err = _err(_store, cluster, raw, import_id="imp-1", kind=VULN)
    assert err.code == "malformed_line"
    assert err.detail["line"] == 2
    assert IngestQueue.objects.count() == 0, "partial insert must roll back"
    assert ImportMark.objects.count() == 0, "mark created in the same txn must roll back"


@pytest.mark.django_db
def test_non_object_line_rejected(cluster):
    raw = _manual("imp-1", VULN, b"[1,2]\n", count=1)
    err = _err(_store, cluster, raw, import_id="imp-1", kind=VULN)
    assert err.code == "line_not_object"
    assert ImportMark.objects.count() == 0


def test_compressed_cap_enforced_while_streaming():
    limits = BundleLimits(max_compressed=100, max_uncompressed=50 * MiB, max_items=10, max_line_bytes=MiB)
    raw = _raw("imp-1", VULN, [ITEM] * 50)
    err = _err(_spool, raw, limits=limits)
    assert (err.code, err.http_status, err.detail["limit"]) == ("bundle_too_large", 413, "compressed")


def test_zip_bomb_stopped_by_uncompressed_cap():
    limits = BundleLimits(max_compressed=10 * MiB, max_uncompressed=MiB, max_items=10, max_line_bytes=10 * MiB)
    raw = _manual("imp-1", VULN, b"0" * (8 * MiB) + b"\n", count=1)
    assert len(gzip.compress(raw)) < 20_000, "precondition: body compresses by >400x"
    err = _err(_spool, raw, limits=limits)
    assert (err.code, err.detail["limit"]) == ("bundle_too_large", "uncompressed")


def test_item_and_line_caps_enforced():
    few = BundleLimits(max_compressed=MiB, max_uncompressed=MiB, max_items=1, max_line_bytes=MiB)
    with _spool(_raw("imp-1", VULN, [ITEM, ITEM])) as sp:
        err = _err(bi.verify_bundle, sp, limits=few)
    assert (err.code, err.detail["limit"]) == ("bundle_too_large", "items")

    short = BundleLimits(max_compressed=MiB, max_uncompressed=MiB, max_items=10, max_line_bytes=10)
    with _spool(_raw("imp-1", VULN, [ITEM])) as sp:
        err = _err(bi.verify_bundle, sp, limits=short)
    assert (err.code, err.detail["limit"]) == ("bundle_too_large", "line")


def test_corrupt_and_truncated_gzip_rejected():
    err = _err(bi.spool_bundle, io.BytesIO(b"definitely not gzip"), gzip_encoded=True, limits=LIMITS)
    assert err.code == "bad_gzip"
    truncated = gzip.compress(_raw("imp-1", VULN, [ITEM] * 20))[:-12]
    err = _err(bi.spool_bundle, io.BytesIO(truncated), gzip_encoded=True, limits=LIMITS)
    assert err.code == "bad_gzip"
    err = _err(bi.spool_bundle, io.BytesIO(b""), gzip_encoded=True, limits=LIMITS)
    assert err.code == "bad_gzip"


def test_identity_encoding_and_manifest_parsing():
    raw = _raw("imp-1", VULN, [ITEM], with_item_hashes=True)
    with _spool(raw, gz=False) as sp:
        assert sp.manifest.count == 1
        assert sp.manifest.item_sha256 is not None
        assert sp.compressed_bytes == sp.uncompressed_bytes == len(raw)
        bi.verify_bundle(sp, limits=LIMITS)


def test_missing_or_bad_manifest_rejected():
    assert _err(_spool, b"").code == "missing_manifest"
    assert _err(_spool, b'{"nope": 1}\n').code == "missing_manifest"
    assert _err(_spool, b"{not json\n").code == "bad_manifest"
    base = _raw("imp-1", VULN, [ITEM])
    assert _err(_spool, _tamper(base, count=-1)).detail["field"] == "count"
    assert _err(_spool, _tamper(base, sha256="xyz")).detail["field"] == "sha256"
    assert _err(_spool, _tamper(base, cluster="")).detail["field"] == "cluster"
    assert _err(_spool, _tamper(base, coverage="no")).detail["field"] == "coverage"
    assert _err(_spool, _tamper(base, item_sha256=["a" * 64, "b" * 64])).detail["field"] == "item_sha256"


def test_item_sha256_verified_when_present():
    raw = _raw("imp-1", VULN, [ITEM, {**ITEM, "metadata": {"name": "y"}}], with_item_hashes=True)
    with _spool(raw) as sp:
        bi.verify_bundle(sp, limits=LIMITS)
    head = json.loads(raw.partition(b"\n")[0])["manifest"]
    bad = _tamper(raw, item_sha256=[head["item_sha256"][0], "f" * 64])
    with _spool(bad) as sp:
        err = _err(bi.verify_bundle, sp, limits=LIMITS)
    assert (err.code, err.detail["line"]) == ("item_sha256_mismatch", 2)


def test_check_manifest_path_mismatch_and_unknown_kind():
    with _spool(_raw("imp-1", VULN, [ITEM])) as sp:
        err = _err(bi.check_manifest, sp.manifest, import_id="imp-2", kind=VULN)
        assert err.code == "manifest_mismatch"
        err = _err(bi.check_manifest, sp.manifest, import_id="imp-1", kind=SBOM)
        assert err.code == "manifest_mismatch"
    with _spool(_raw("imp-1", "trivy.Nope", [ITEM])) as sp:
        err = _err(bi.check_manifest, sp.manifest, import_id="imp-1", kind="trivy.Nope")
        assert err.code == "unknown_kind"


# ── idempotency / conflicts ────────────────────────────────────────


@pytest.mark.django_db
def test_reupload_same_sha_is_noop(cluster):
    raw = _raw("imp-1", VULN, [ITEM, ITEM])
    first = _store(cluster, raw, import_id="imp-1", kind=VULN)
    second = _store(cluster, raw, import_id="imp-1", kind=VULN)
    assert first.created is True and second.created is False
    assert second.mark.pk == first.mark.pk
    assert IngestQueue.objects.count() == 2, "no duplicate rows"


@pytest.mark.django_db
def test_reupload_different_sha_conflicts(cluster):
    _store(cluster, _raw("imp-1", VULN, [ITEM]), import_id="imp-1", kind=VULN)
    err = _err(_store, cluster, _raw("imp-1", VULN, [ITEM, ITEM]), import_id="imp-1", kind=VULN)
    assert (err.code, err.http_status) == ("bundle_conflict", 409)
    assert IngestQueue.objects.count() == 1


@pytest.mark.django_db
def test_upload_rejected_once_import_committed(cluster):
    _store(cluster, _raw("imp-1", INV, [ENVELOPE]), import_id="imp-1", kind=INV)
    bi.commit_import(cluster=cluster, import_id="imp-1", kinds=[(INV, 1)])
    err = _err(_store, cluster, _raw("imp-1", VULN, [ITEM]), import_id="imp-1", kind=VULN)
    assert (err.code, err.http_status) == ("import_already_committed", 409)
    assert err.detail["states"] == {INV: ImportMarkState.DRAINING.value}


# ── commit ─────────────────────────────────────────────────────────


@pytest.mark.django_db
def test_commit_flips_all_marks(cluster):
    _store(cluster, _raw("imp-1", INV, [ENVELOPE]), import_id="imp-1", kind=INV)
    _store(cluster, _raw("imp-1", VULN, [ITEM, ITEM]), import_id="imp-1", kind=VULN)
    _store(cluster, _raw("imp-1", SBOM, []), import_id="imp-1", kind=SBOM)

    result = bi.commit_import(cluster=cluster, import_id="imp-1", kinds=[(INV, 1), (VULN, 2), (SBOM, 0)])

    assert result.idempotent is False
    marks = {m.kind: m for m in ImportMark.objects.filter(import_id="imp-1")}
    assert all(m.state == ImportMarkState.DRAINING.value for m in marks.values())
    assert all(m.completed_at is not None for m in marks.values())
    assert {k: m.observed_count for k, m in marks.items()} == {INV: 1, VULN: 2, SBOM: 0}


@pytest.mark.django_db
@pytest.mark.parametrize(
    ("kinds", "code", "detail"),
    [
        ([(INV, 1)], "unlisted_kinds", {"kinds": [VULN]}),
        ([(INV, 1), (VULN, 1), (SBOM, 0)], "kind_not_uploaded", {"kinds": [SBOM]}),
        ([(INV, 1), (VULN, 3)], "count_mismatch", {"kind": VULN, "expected": 3, "actual": 1}),
    ],
)
def test_commit_rejections_change_nothing(cluster, kinds, code, detail):
    _store(cluster, _raw("imp-1", INV, [ENVELOPE]), import_id="imp-1", kind=INV)
    _store(cluster, _raw("imp-1", VULN, [ITEM]), import_id="imp-1", kind=VULN)

    err = _err(bi.commit_import, cluster=cluster, import_id="imp-1", kinds=kinds)

    assert (err.code, err.http_status) == (code, 409)
    for key, value in detail.items():
        assert err.detail[key] == value
    assert set(ImportMark.objects.filter(import_id="imp-1").values_list("state", flat=True)) == {
        ImportMarkState.OPEN.value,
    }


@pytest.mark.django_db
def test_commit_duplicate_kind_is_bad_request(cluster):
    _store(cluster, _raw("imp-1", INV, [ENVELOPE]), import_id="imp-1", kind=INV)
    err = _err(bi.commit_import, cluster=cluster, import_id="imp-1", kinds=[(INV, 1), (INV, 1)])
    assert err.code == "bad_request"


@pytest.mark.django_db
def test_commit_twice_identical_is_idempotent_different_is_conflict(cluster):
    _store(cluster, _raw("imp-1", INV, [ENVELOPE]), import_id="imp-1", kind=INV)
    first = bi.commit_import(cluster=cluster, import_id="imp-1", kinds=[(INV, 1)])
    again = bi.commit_import(cluster=cluster, import_id="imp-1", kinds=[(INV, 1)])
    assert first.idempotent is False and again.idempotent is True

    err = _err(bi.commit_import, cluster=cluster, import_id="imp-1", kinds=[(INV, 0)])
    assert err.code == "state_conflict"


@pytest.mark.django_db
def test_commit_after_abort_is_not_found(cluster):
    _store(cluster, _raw("imp-1", INV, [ENVELOPE]), import_id="imp-1", kind=INV)
    bi.abort_import(cluster=cluster, import_id="imp-1")
    err = _err(bi.commit_import, cluster=cluster, import_id="imp-1", kinds=[(INV, 1)])
    assert (err.code, err.http_status) == ("import_not_found", 404)


@pytest.mark.django_db
@override_settings(IMPORT_COVERAGE_ALERT_RATIO=0.9)
def test_commit_logs_error_below_coverage_threshold_only(cluster):
    _store(cluster, _raw("imp-1", VULN, [ITEM], coverage={"expected": 10, "matched": 5}),
           import_id="imp-1", kind=VULN)
    _store(cluster, _raw("imp-1", SBOM, [ITEM], coverage={"expected": 10, "matched": 9}),
           import_id="imp-1", kind=SBOM)
    _store(cluster, _raw("imp-1", INV, [ENVELOPE]), import_id="imp-1", kind=INV)

    with patch.object(bi.log, "error") as log_error:
        result = bi.commit_import(
            cluster=cluster, import_id="imp-1", kinds=[(VULN, 1), (SBOM, 1), (INV, 1)],
        )

    ratios = {e.kind: e.ratio for e in result.coverage}
    assert ratios == {VULN: 0.5, SBOM: 0.9, INV: None}
    assert log_error.call_count == 1
    assert log_error.call_args.args[0] == "import.coverage_low"
    assert log_error.call_args.kwargs["extra"]["kind"] == VULN


@pytest.mark.django_db
def test_coverage_expected_zero_is_full_coverage(cluster):
    _store(cluster, _raw("imp-1", VULN, [], coverage={"expected": 0, "matched": 0}),
           import_id="imp-1", kind=VULN)
    with patch.object(bi.log, "error") as log_error:
        result = bi.commit_import(cluster=cluster, import_id="imp-1", kinds=[(VULN, 0)])
    assert result.coverage[0].ratio == 1.0
    log_error.assert_not_called()


# ── abort ──────────────────────────────────────────────────────────


@pytest.mark.django_db
def test_abort_deletes_rows_and_marks_while_open(cluster):
    _store(cluster, _raw("imp-1", INV, [ENVELOPE]), import_id="imp-1", kind=INV)
    _store(cluster, _raw("imp-1", VULN, [ITEM, ITEM]), import_id="imp-1", kind=VULN)
    _store(cluster, _raw("imp-2", VULN, [ITEM]), import_id="imp-2", kind=VULN)  # untouched

    result = bi.abort_import(cluster=cluster, import_id="imp-1")

    assert (result.deleted_rows, result.deleted_marks) == (3, 2)
    assert not ImportMark.objects.filter(import_id="imp-1").exists()
    assert not IngestQueue.objects.filter(import_id="imp-1").exists()
    assert IngestQueue.objects.filter(import_id="imp-2").count() == 1


@pytest.mark.django_db
def test_abort_rejected_once_committed_and_unknown_is_not_found(cluster):
    _store(cluster, _raw("imp-1", INV, [ENVELOPE]), import_id="imp-1", kind=INV)
    bi.commit_import(cluster=cluster, import_id="imp-1", kinds=[(INV, 1)])
    err = _err(bi.abort_import, cluster=cluster, import_id="imp-1")
    assert (err.code, err.http_status) == ("import_already_committed", 409)
    assert IngestQueue.objects.filter(import_id="imp-1").count() == 1

    err = _err(bi.abort_import, cluster=cluster, import_id="never")
    assert (err.code, err.http_status) == ("import_not_found", 404)


# ── store_items (harness helper) ───────────────────────────────────


@pytest.mark.django_db
def test_store_items_round_trips_through_the_same_path(cluster):
    result = bi.store_items(
        cluster=cluster, import_id="imp-1", kind=INV, items=[ENVELOPE], complete_snapshot=True,
    )
    assert result.created and result.rows_inserted == 1
    row = IngestQueue.objects.get(import_id="imp-1")
    assert row.raw_json == ENVELOPE and row.complete_snapshot is True
    with pytest.raises(BundleError) as excinfo:
        bi.store_items(cluster=cluster, import_id="imp-1", kind="nope", items=[])
    assert excinfo.value.code == "unknown_kind"


# ── transfers that stop part-way ───────────────────────────────────

BIG = [{"kind": "VulnerabilityReport", "metadata": {"name": f"r{i}"}, "pad": "x" * 150} for i in range(40)]


def _cut_offsets(n: int, *, points: int = 60) -> list[int]:
    step = max(1, n // points)
    return sorted({*range(1, n, step), n - 1, n - 2, 1, 2, 3})


def test_gzip_stream_truncated_at_every_offset_never_yields_a_bundle():
    """No prefix of a gzip bundle — wherever the connection died, down to
    the last byte of the CRC trailer — may be accepted."""
    body = gzip.compress(_raw("imp-1", VULN, BIG))
    for cut in _cut_offsets(len(body)):
        with pytest.raises(BundleError) as excinfo:
            bi.spool_bundle(io.BytesIO(body[:cut]), gzip_encoded=True, limits=LIMITS).close()
        assert excinfo.value.code in {"bad_gzip", "missing_manifest", "bad_manifest"}, (cut, excinfo.value.code)


def _store_uncompressed(cluster, raw: bytes):
    with bi.spool_bundle(io.BytesIO(raw), gzip_encoded=False, limits=LIMITS) as sp:
        bi.check_manifest(sp.manifest, import_id="imp-1", kind=VULN)
        bi.verify_bundle(sp, limits=LIMITS)
        return bi.store_bundle(cluster=cluster, spooled=sp)


@pytest.mark.django_db
def test_uncompressed_stream_truncated_at_every_offset_never_stores_anything(cluster):
    """Same sweep without compression: a cut in the manifest, mid-line or
    exactly on a line boundary must all be rejected before any row or
    mark is written."""
    raw = _raw("imp-1", VULN, BIG)
    for cut in _cut_offsets(len(raw)):
        with pytest.raises(BundleError) as excinfo:
            _store_uncompressed(cluster, raw[:cut])
        assert excinfo.value.code in {
            "missing_manifest", "bad_manifest", "count_mismatch", "sha256_mismatch",
        }, (cut, excinfo.value.code)
        assert IngestQueue.objects.count() == 0 and ImportMark.objects.count() == 0, cut


@pytest.mark.django_db
def test_failure_mid_insert_rolls_back_every_row_and_the_mark(cluster):
    """The server itself dies part-way through writing a bundle (DB
    error on the third batch): the earlier batches and the mark must not
    survive, so a retry starts from nothing."""
    items = [{"kind": "VulnerabilityReport", "metadata": {"name": f"r{i}"}} for i in range(250)]
    raw = _raw("imp-1", VULN, items)
    real = IngestQueue.objects.bulk_create
    calls = {"n": 0}

    def flaky(objs, *a, **kw):
        calls["n"] += 1
        if calls["n"] == 3:
            raise RuntimeError("connection to the database was lost")
        return real(objs, *a, **kw)

    with patch.object(IngestQueue.objects, "bulk_create", side_effect=flaky):
        with pytest.raises(RuntimeError, match="database was lost"):
            _store(cluster, raw, import_id="imp-1", kind=VULN)

    assert calls["n"] == 3, "two batches had been written before the failure"
    assert IngestQueue.objects.count() == 0
    assert ImportMark.objects.count() == 0

    result = _store(cluster, raw, import_id="imp-1", kind=VULN)
    assert result.created and result.rows_inserted == 250
