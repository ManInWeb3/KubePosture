"""HTTP contract of the bundle endpoints (core/api/views_bundles.py):
bearer auth, content negotiation, streaming caps, error codes,
idempotency, commit / abort, and that the old per-item endpoints are
gone."""
from __future__ import annotations

import gzip
import json

import pytest
from django.test import override_settings

from core.api.auth import generate_token
from core.constants import ImportMarkState, IngestQueueStatus
from core.models import Cluster, ImportMark, IngestQueue, IngestToken
from core.services.bundle_ingest import build_ndjson

NDJSON = "application/x-ndjson"
VULN = "trivy.VulnerabilityReport"
INV = "inventory"
ITEM = {"kind": "VulnerabilityReport", "metadata": {"name": "x"}, "report": {"vulnerabilities": []}}
ENVELOPE = {"cluster_meta": {"name": "c-http"}, "items": []}


@pytest.fixture
def token(db) -> str:
    plain, hashed = generate_token()
    IngestToken.objects.create(name="views-bundles", token_hash=hashed)
    return plain


def _auth(token: str) -> dict:
    return {"HTTP_AUTHORIZATION": f"Bearer {token}"}


def _raw(import_id: str, kind: str, items: list[dict], **kw) -> bytes:
    return build_ndjson(items, cluster="c-http", import_id=import_id, kind=kind, **kw)


def _upload(client, token, import_id, kind, raw, *, gz=True, content_type=NDJSON, encoding=None):
    body = gzip.compress(raw) if gz else raw
    headers = dict(_auth(token))
    enc = encoding if encoding is not None else ("gzip" if gz else None)
    if enc:
        headers["HTTP_CONTENT_ENCODING"] = enc
    return client.post(
        f"/api/v1/imports/{import_id}/bundles/{kind}/", data=body,
        content_type=content_type, **headers,
    )


def _commit(client, token, import_id, kinds: dict[str, int], cluster="c-http"):
    return client.post(
        f"/api/v1/imports/{import_id}/commit/",
        data=json.dumps({"cluster": cluster, "kinds": [{"kind": k, "count": n} for k, n in kinds.items()]}),
        content_type="application/json", **_auth(token),
    )


def _abort(client, token, import_id, cluster="c-http"):
    return client.post(
        f"/api/v1/imports/{import_id}/abort/", data=json.dumps({"cluster": cluster}),
        content_type="application/json", **_auth(token),
    )


# ── upload ─────────────────────────────────────────────────────────


@pytest.mark.django_db
def test_upload_requires_bearer_token(client):
    resp = client.post(f"/api/v1/imports/imp-1/bundles/{VULN}/", data=b"", content_type=NDJSON)
    assert resp.status_code == 401


@pytest.mark.django_db
def test_upload_gzip_ndjson_stores_rows_and_open_mark(client, token):
    resp = _upload(client, token, "imp-1", VULN, _raw("imp-1", VULN, [ITEM, ITEM]))
    assert resp.status_code == 201, resp.content
    body = resp.json()
    assert body["status"] == "stored"
    assert (body["cluster"], body["import_id"], body["kind"]) == ("c-http", "imp-1", VULN)
    assert body["count"] == body["rows_inserted"] == 2
    assert Cluster.objects.filter(name="c-http").exists(), "cluster auto-registered"
    assert IngestQueue.objects.filter(status=IngestQueueStatus.PENDING.value).count() == 2
    assert ImportMark.objects.get(import_id="imp-1").state == ImportMarkState.OPEN.value


@pytest.mark.django_db
def test_upload_identity_encoding_accepted(client, token):
    resp = _upload(client, token, "imp-1", VULN, _raw("imp-1", VULN, [ITEM]), gz=False)
    assert resp.status_code == 201, resp.content


@pytest.mark.django_db
def test_upload_wrong_content_type_or_encoding_is_415(client, token):
    raw = _raw("imp-1", VULN, [ITEM])
    assert _upload(client, token, "imp-1", VULN, raw, content_type="application/json").status_code == 415
    assert _upload(client, token, "imp-1", VULN, raw, encoding="br").status_code == 415
    assert ImportMark.objects.count() == 0


@pytest.mark.django_db
@override_settings(IMPORT_BUNDLE_MAX_COMPRESSED_BYTES=16)
def test_upload_content_length_over_cap_is_413_before_body_is_read(client, token):
    resp = _upload(client, token, "imp-1", VULN, _raw("imp-1", VULN, [ITEM]))
    assert resp.status_code == 413
    assert resp.json() == {"error": "bundle_too_large", "limit": "compressed", "max_bytes": 16}


@pytest.mark.django_db
def test_upload_bad_import_id_is_400(client, token):
    resp = _upload(client, token, "bad id!", VULN, _raw("bad id!", VULN, [ITEM]))
    assert resp.status_code == 400
    assert resp.json()["error"] == "bad_import_id"


def _tamper(raw: bytes, **overrides) -> bytes:
    head, _, body = raw.partition(b"\n")
    doc = json.loads(head)
    doc["manifest"].update(overrides)
    return json.dumps(doc).encode() + b"\n" + body


@pytest.mark.django_db
@pytest.mark.parametrize(
    ("make", "path_import_id", "path_kind", "status", "code"),
    [
        (lambda: _tamper(_raw("imp-1", VULN, [ITEM]), sha256="0" * 64), "imp-1", VULN, 400, "sha256_mismatch"),
        (lambda: _tamper(_raw("imp-1", VULN, [ITEM]), count=2), "imp-1", VULN, 400, "count_mismatch"),
        (lambda: _raw("imp-1", VULN, [ITEM]), "imp-2", VULN, 400, "manifest_mismatch"),
        (lambda: _raw("imp-1", "trivy.Nope", [ITEM]), "imp-1", "trivy.Nope", 400, "unknown_kind"),
        (lambda: b"{garbage\n", "imp-1", VULN, 400, "bad_manifest"),
    ],
)
def test_upload_error_codes(client, token, make, path_import_id, path_kind, status, code):
    resp = _upload(client, token, path_import_id, path_kind, make())
    assert resp.status_code == status, resp.content
    assert resp.json()["error"] == code
    assert ImportMark.objects.count() == 0 and IngestQueue.objects.count() == 0


@pytest.mark.django_db
def test_upload_corrupt_gzip_is_400(client, token):
    resp = client.post(
        f"/api/v1/imports/imp-1/bundles/{VULN}/", data=b"not gzip at all",
        content_type=NDJSON, HTTP_CONTENT_ENCODING="gzip", **_auth(token),
    )
    assert resp.status_code == 400
    assert resp.json()["error"] == "bad_gzip"


@pytest.mark.django_db
def test_upload_reupload_conflict_and_after_commit(client, token):
    raw = _raw("imp-1", VULN, [ITEM])
    assert _upload(client, token, "imp-1", VULN, raw).status_code == 201
    again = _upload(client, token, "imp-1", VULN, raw)
    assert again.status_code == 200 and again.json()["status"] == "already_uploaded"
    assert IngestQueue.objects.count() == 1

    conflict = _upload(client, token, "imp-1", VULN, _raw("imp-1", VULN, [ITEM, ITEM]))
    assert conflict.status_code == 409 and conflict.json()["error"] == "bundle_conflict"

    assert _commit(client, token, "imp-1", {VULN: 1}).status_code == 200
    late = _upload(client, token, "imp-1", INV, _raw("imp-1", INV, [ENVELOPE]))
    assert late.status_code == 409 and late.json()["error"] == "import_already_committed"


# ── commit ─────────────────────────────────────────────────────────


@pytest.mark.django_db
def test_commit_success_and_idempotent_retry(client, token):
    _upload(client, token, "imp-1", INV, _raw("imp-1", INV, [ENVELOPE]))
    _upload(client, token, "imp-1", VULN, _raw("imp-1", VULN, [ITEM], coverage={"expected": 4, "matched": 3}))

    resp = _commit(client, token, "imp-1", {INV: 1, VULN: 1})
    assert resp.status_code == 200, resp.content
    body = resp.json()
    assert body["status"] == "committed" and body["committed_at"]
    assert {k["kind"]: (k["observed_count"], k["coverage_ratio"]) for k in body["kinds"]} == {
        INV: (1, None), VULN: (1, 0.75),
    }
    assert set(ImportMark.objects.values_list("state", flat=True)) == {ImportMarkState.DRAINING.value}

    retry = _commit(client, token, "imp-1", {INV: 1, VULN: 1})
    assert retry.status_code == 200 and retry.json()["status"] == "already_committed"


@pytest.mark.django_db
def test_commit_error_codes(client, token):
    assert _commit(client, token, "never", {INV: 1}).status_code == 404
    _upload(client, token, "imp-1", INV, _raw("imp-1", INV, [ENVELOPE]))
    bad_count = _commit(client, token, "imp-1", {INV: 2})
    assert bad_count.status_code == 409 and bad_count.json()["error"] == "count_mismatch"
    missing = _commit(client, token, "imp-1", {INV: 1, VULN: 0})
    assert missing.status_code == 409 and missing.json()["error"] == "kind_not_uploaded"
    assert ImportMark.objects.get(import_id="imp-1").state == ImportMarkState.OPEN.value


@pytest.mark.django_db
@pytest.mark.parametrize(
    "body",
    [
        {"cluster": "c-http"},
        {"cluster": "c-http", "kinds": []},
        {"cluster": "c-http", "kinds": [{"kind": INV}]},
        {"cluster": "c-http", "kinds": [{"kind": INV, "count": -1}]},
        {"cluster": "c-http", "kinds": [{"kind": INV, "count": True}]},
        {"cluster": "c-http", "kinds": ["inventory"]},
    ],
)
def test_commit_malformed_body_is_400(client, token, body):
    resp = client.post(
        "/api/v1/imports/imp-1/commit/", data=json.dumps(body),
        content_type="application/json", **_auth(token),
    )
    assert resp.status_code == 400
    assert resp.json()["error"] == "bad_request"


# ── abort ──────────────────────────────────────────────────────────


@pytest.mark.django_db
def test_abort_then_not_found_then_conflict_after_commit(client, token):
    _upload(client, token, "imp-1", INV, _raw("imp-1", INV, [ENVELOPE]))
    resp = _abort(client, token, "imp-1")
    assert resp.status_code == 200
    assert resp.json()["deleted_rows"] == 1 and resp.json()["deleted_marks"] == 1
    assert ImportMark.objects.count() == 0 and IngestQueue.objects.count() == 0
    assert _abort(client, token, "imp-1").status_code == 404

    _upload(client, token, "imp-2", INV, _raw("imp-2", INV, [ENVELOPE]))
    _commit(client, token, "imp-2", {INV: 1})
    late = _abort(client, token, "imp-2")
    assert late.status_code == 409 and late.json()["error"] == "import_already_committed"


# ── old protocol is gone ───────────────────────────────────────────


@pytest.mark.django_db
@pytest.mark.parametrize("path", ["/api/v1/imports/start/", "/api/v1/imports/finish/", "/api/v1/ingest/"])
def test_removed_per_item_endpoints_are_404(client, token, path):
    resp = client.post(path, data=json.dumps({"cluster": "c-http"}), content_type="application/json", **_auth(token))
    assert resp.status_code == 404
