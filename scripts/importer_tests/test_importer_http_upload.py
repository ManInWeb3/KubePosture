"""HttpClient retry matrix and the upload → commit → abort sequencing,
driven by a fake urlopen that records every request."""
import gzip
import http.client
import io
import json
from urllib.error import HTTPError

import pytest
from kubeposture_importer.bundle import BundleWriter
from kubeposture_importer.http import HttpClient
from kubeposture_importer.upload import (
    ImportInterrupted,
    UploadError,
    abort,
    commit,
    run_upload_plan,
    upload_bundle,
)


class _Resp:
    def __init__(self, status=200, body=None):
        self.status = status
        self._body = json.dumps(body if body is not None else {"status": "ok"}).encode()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def read(self):
        return self._body


def _http_error(code, body=None):
    return HTTPError("https://x", code, "err", {}, io.BytesIO(json.dumps(body or {"error": "e"}).encode()))


class FakeNet:
    """Queue of responses / exceptions, keyed by URL path prefix or global."""

    def __init__(self, script=None):
        self.script = list(script or [])
        self.calls = []       # (method, path, headers, body bytes)
        self.sleeps = []

    def urlopen(self, req, timeout=None):
        data = req.data
        if hasattr(data, "read"):
            body = data.read()
        else:
            body = data or b""
        self.calls.append((req.get_method(), req.full_url.split("//", 1)[1].split("/", 1)[1], dict(req.header_items()), body))
        nxt = self.script.pop(0) if self.script else _Resp()
        if callable(nxt):
            nxt = nxt(req)
        if isinstance(nxt, BaseException):
            raise nxt
        return nxt

    def client(self, **kw):
        return HttpClient("https://central", "tok", sleep=self.sleeps.append, urlopen_fn=self.urlopen, **kw)

    def paths(self):
        return [c[1] for c in self.calls]


def _bundle(tmp_path, kind="trivy.VulnerabilityReport", n=2):
    with BundleWriter(cluster="c", import_id="imp-1", kind=kind, tmp_dir=tmp_path) as w:
        for i in range(n):
            w.write_item({"i": i})
        return w.finish()


# ── HttpClient ─────────────────────────────────────────────────────


def test_post_file_sends_gzip_body_with_explicit_content_length_and_headers(tmp_path):
    net = FakeNet([_Resp(201, {"status": "stored"})])
    meta = _bundle(tmp_path)
    resp = upload_bundle(net.client(), import_id="imp-1", meta=meta)
    assert resp == {"status": "stored"}
    method, path, headers, body = net.calls[0]
    assert (method, path) == ("POST", "api/v1/imports/imp-1/bundles/trivy.VulnerabilityReport/")
    assert headers["Content-type"] == "application/x-ndjson"
    assert headers["Content-encoding"] == "gzip"
    assert headers["Content-length"] == str(meta.compressed_bytes) == str(len(body))
    assert headers["Authorization"] == "Bearer tok"
    assert gzip.decompress(body).count(b"\n") == 3  # manifest + 2 items
    assert "Transfer-encoding" not in headers


def test_retry_5xx_then_ok_rewinds_file_each_attempt(tmp_path):
    net = FakeNet([_http_error(503), _http_error(502), _Resp(201, {"status": "stored"})])
    meta = _bundle(tmp_path)
    upload_bundle(net.client(), import_id="imp-1", meta=meta)
    bodies = [c[3] for c in net.calls]
    assert len(bodies) == 3 and all(b == bodies[0] and len(b) == meta.compressed_bytes for b in bodies)
    assert net.sleeps == [2.5, 5.0]


@pytest.mark.parametrize("exc", [
    ConnectionResetError(104, "reset"), http.client.RemoteDisconnected("gone"), TimeoutError("slow"),
    _http_error(408), _http_error(429),
])
def test_retries_transient_failures(exc):
    net = FakeNet([exc, _Resp(200, {"status": "committed"})])
    result = net.client().post_json("/x/", {})
    assert result.ok and len(net.calls) == 2


@pytest.mark.parametrize("code", [400, 401, 403, 404, 409, 413, 422])
def test_fails_fast_on_client_errors(code):
    net = FakeNet([_http_error(code, {"error": "nope"})])
    result = net.client().post_json("/x/", {})
    assert not result.ok and result.status == code and not result.retryable
    assert len(net.calls) == 1 and net.sleeps == []


def test_exhausted_attempts_report_last_error():
    net = FakeNet([_http_error(500)] * 3)
    result = net.client().post_json("/x/", {})
    assert (result.ok, result.status, result.retryable) == (False, 500, True)
    assert len(net.calls) == 3


def test_deadline_exceeded_fails_without_a_network_attempt():
    clock = {"t": 100.0}
    net = FakeNet()
    client = HttpClient("https://c", "t", deadline_at=50.0, clock=lambda: clock["t"],
                        sleep=net.sleeps.append, urlopen_fn=net.urlopen)
    result = client.post_json("/x/", {})
    assert not result.ok and result.body == "upload deadline exceeded" and not result.retryable
    assert net.calls == []


def test_deadline_checked_between_retries():
    clock = {"t": 0.0}
    net = FakeNet([_http_error(500), _http_error(500), _Resp()])

    def sleep(s):
        clock["t"] += 100

    client = HttpClient("https://c", "t", deadline_at=50.0, clock=lambda: clock["t"],
                        sleep=sleep, urlopen_fn=net.urlopen)
    result = client.post_json("/x/", {})
    assert result.body == "upload deadline exceeded" and len(net.calls) == 1


def test_get_uses_short_retry_budget():
    net = FakeNet([ConnectionResetError(), ConnectionResetError(), ConnectionResetError()])
    result = net.client().get("/api/v1/imports/pending/?cluster=c")
    assert not result.ok and len(net.calls) == 3 and net.sleeps == [0.5, 1.0]


# ── upload / commit / abort ────────────────────────────────────────


def test_commit_body_lists_delivered_counts_including_zero():
    net = FakeNet([_Resp(200, {"status": "committed"})])
    commit(net.client(), import_id="imp-1", cluster="c", kinds={"inventory": 1, "trivy.SbomReport": 0})
    _, path, headers, body = net.calls[0]
    assert path == "api/v1/imports/imp-1/commit/"
    assert json.loads(body) == {
        "cluster": "c",
        "kinds": [{"kind": "inventory", "count": 1}, {"kind": "trivy.SbomReport", "count": 0}],
    }


def test_commit_4xx_raises_upload_error():
    net = FakeNet([_http_error(409, {"error": "count_mismatch"})])
    with pytest.raises(UploadError) as excinfo:
        commit(net.client(), import_id="imp-1", cluster="c", kinds={"inventory": 1})
    assert excinfo.value.step == "commit" and excinfo.value.status == 409
    assert "count_mismatch" in excinfo.value.detail


def test_abort_is_best_effort():
    logs = []
    net = FakeNet([_http_error(404)])
    assert abort(net.client(), import_id="imp-1", cluster="c", reason="x", log=logs.append) is False
    net = FakeNet([_Resp(200, {"status": "aborted"})])
    assert abort(net.client(), import_id="imp-1", cluster="c", reason="x", log=logs.append) is True
    assert any("ABORTED import_id=imp-1" in ln for ln in logs)


def test_run_plan_success_uploads_in_order_then_commits_no_abort(tmp_path):
    inv = _bundle(tmp_path / "a", kind="inventory", n=1)
    vuln = _bundle(tmp_path / "b", kind="trivy.VulnerabilityReport", n=3)
    sbom = _bundle(tmp_path / "c", kind="trivy.SbomReport", n=0)
    net = FakeNet([_Resp(201, {"status": "stored"})] * 3 + [_Resp(200, {"status": "committed"})])
    out = []
    rc = run_upload_plan(net.client(), import_id="imp-1", cluster="c", bundles=[inv, vuln, sbom],
                         out=out.append, err=out.append)
    assert rc == 0
    assert net.paths() == [
        "api/v1/imports/imp-1/bundles/inventory/",
        "api/v1/imports/imp-1/bundles/trivy.VulnerabilityReport/",
        "api/v1/imports/imp-1/bundles/trivy.SbomReport/",
        "api/v1/imports/imp-1/commit/",
    ]
    assert json.loads(net.calls[-1][3])["kinds"] == [
        {"kind": "inventory", "count": 1}, {"kind": "trivy.VulnerabilityReport", "count": 3},
        {"kind": "trivy.SbomReport", "count": 0},
    ]
    assert any(ln.startswith("COMMITTED import_id=imp-1") for ln in out)


def test_run_plan_failure_mid_way_aborts_once_and_skips_the_rest(tmp_path):
    bundles = [_bundle(tmp_path / str(i), kind=k, n=1) for i, k in
               enumerate(["inventory", "trivy.VulnerabilityReport", "trivy.SbomReport"])]
    net = FakeNet([_Resp(201), _http_error(500), _http_error(500), _http_error(500), _Resp(200, {"status": "aborted"})])
    errs = []
    rc = run_upload_plan(net.client(), import_id="imp-1", cluster="c", bundles=bundles, out=lambda _: None, err=errs.append)
    assert rc == 1
    assert net.paths() == [
        "api/v1/imports/imp-1/bundles/inventory/",
        "api/v1/imports/imp-1/bundles/trivy.VulnerabilityReport/",
        "api/v1/imports/imp-1/bundles/trivy.VulnerabilityReport/",
        "api/v1/imports/imp-1/bundles/trivy.VulnerabilityReport/",
        "api/v1/imports/imp-1/abort/",
    ], "SbomReport never uploaded, commit never attempted, abort exactly once"
    assert any("ABORTED" in e for e in errs)


def test_run_plan_abort_failure_still_returns_1(tmp_path):
    bundles = [_bundle(tmp_path, kind="inventory", n=1)]
    net = FakeNet([_http_error(400, {"error": "sha256_mismatch"}), ConnectionResetError(), ConnectionResetError(), ConnectionResetError()])
    errs = []
    rc = run_upload_plan(net.client(), import_id="imp-1", cluster="c", bundles=bundles, out=lambda _: None, err=errs.append)
    assert rc == 1 and net.paths()[-1] == "api/v1/imports/imp-1/abort/"
    assert any("sha256_mismatch" in e for e in errs)


def test_run_plan_commit_4xx_aborts_and_5xx_is_retried(tmp_path):
    bundles = [_bundle(tmp_path, kind="inventory", n=1)]
    net = FakeNet([_Resp(201), _http_error(409, {"error": "count_mismatch"}), _Resp(200)])
    assert run_upload_plan(net.client(), import_id="imp-1", cluster="c", bundles=bundles,
                           out=lambda _: None, err=lambda _: None) == 1
    assert net.paths()[-2:] == ["api/v1/imports/imp-1/commit/", "api/v1/imports/imp-1/abort/"]

    net = FakeNet([_Resp(201), _http_error(503), _Resp(200, {"status": "committed"})])
    assert run_upload_plan(net.client(), import_id="imp-1", cluster="c", bundles=bundles,
                           out=lambda _: None, err=lambda _: None) == 0
    assert net.paths().count("api/v1/imports/imp-1/commit/") == 2


def test_sigterm_during_upload_aborts(tmp_path):
    bundles = [_bundle(tmp_path / "a", kind="inventory", n=1), _bundle(tmp_path / "b", kind="trivy.SbomReport", n=1)]
    net = FakeNet([_Resp(201), ImportInterrupted(), _Resp(200, {"status": "aborted"})])
    errs = []
    rc = run_upload_plan(net.client(), import_id="imp-1", cluster="c", bundles=bundles, out=lambda _: None, err=errs.append)
    assert rc == 1
    assert net.paths()[-1] == "api/v1/imports/imp-1/abort/"
    assert any("SIGTERM" in e for e in errs)
