"""Transfers that don't complete.

The importer sends a full snapshot every cycle, so an import that didn't
land whole must leave NOTHING behind (or something the safety net
discards), never a half-applied cycle. These tests break the real
transfer in every way a network or a pod can:

  at the HTTP layer      body cut short; manifest cut; cut at every offset
  between the processes  connection dropped mid-body; response lost after
                         the server stored the bundle; commit response lost
                         or never successful
  process death          SIGTERM and SIGKILL while a bundle is in flight

The real `scripts/import-cluster.py` runs against `live_server`, through
tests/integration/_chaos_proxy.py where the network needs to misbehave.
"""
from __future__ import annotations

import gzip
import json
import socket
import time
from datetime import timedelta

import pytest
from django.core.management import call_command
from django.utils import timezone

from core.api.auth import generate_token
from core.constants import ImportDiscardReason, ImportMarkState
from core.models import Cluster, Finding, ImportMark, IngestQueue, IngestToken, Workload
from core.services.bundle_ingest import build_ndjson
from core.services.reaper import STUCK_OPEN_TIMEOUT_SECONDS
from core.services.worker import drain_until_empty

from ._chaos_proxy import ChaosProxy
from ._script_runner import run_import, start_import, write_synthetic_capture

pytestmark = [pytest.mark.e2e, pytest.mark.django_db(transaction=True)]

SBOM = "/bundles/trivy.SbomReport/"
NDJSON = "application/x-ndjson"


@pytest.fixture
def token() -> str:
    plain, hashed = generate_token()
    IngestToken.objects.create(name="e2e-interrupt", token_hash=hashed)
    return plain


@pytest.fixture
def capture(tmp_path):
    return write_synthetic_capture(tmp_path / "capture", cluster="e2e-interrupt")


@pytest.fixture
def scratch(tmp_path):
    d = tmp_path / "scratch"
    d.mkdir()
    return d


def _expected_rows(summary: dict) -> int:
    return sum(k["count"] for k in summary["kinds"].values())


def _assert_clean_import_applied(cluster: str) -> None:
    c = Cluster.objects.get(name=cluster)
    marks = list(ImportMark.objects.filter(cluster=c))
    assert marks and all(m.state == ImportMarkState.REAPED.value and not m.discard_reason for m in marks)
    assert c.last_complete_inventory_at is not None
    assert Workload.objects.get(cluster=c, kind="Deployment", name="api").deployed is True
    assert Finding.objects.filter(vuln_id="CVE-2024-100").count() == 1
    assert IngestQueue.objects.count() == 0


# ── raw HTTP: the body never arrives whole ─────────────────────────


def _post_raw(live_server, path: str, token: str, body: bytes, *, declared_length: int,
              gzip_encoded: bool = True) -> tuple[int, dict]:
    """Send `body` but announce `declared_length`, then half-close the
    socket — exactly what a connection that dies mid-upload looks like to
    the server. Returns the server's answer."""
    host, port = live_server.url.split("//")[1].split(":")
    headers = [
        f"POST {path} HTTP/1.1", f"Host: {host}:{port}", f"Authorization: Bearer {token}",
        f"Content-Type: {NDJSON}", f"Content-Length: {declared_length}", "Connection: close",
    ]
    if gzip_encoded:
        headers.append("Content-Encoding: gzip")
    with socket.create_connection((host, int(port)), timeout=30) as sock:
        sock.sendall(("\r\n".join(headers) + "\r\n\r\n").encode() + body)
        sock.shutdown(socket.SHUT_WR)
        raw = b""
        while chunk := sock.recv(65536):
            raw += chunk
    head, _, payload = raw.partition(b"\r\n\r\n")
    status = int(head.split(b" ", 2)[1])
    try:
        return status, json.loads(payload)
    except ValueError:
        return status, {}


def _bundle(items: int = 30, *, import_id: str = "IMPTRUNC00000000000000001") -> bytes:
    docs = [{"kind": "VulnerabilityReport", "metadata": {"name": f"r{i}"}, "pad": "x" * 200} for i in range(items)]
    return build_ndjson(docs, cluster="e2e-trunc", import_id=import_id, kind="trivy.VulnerabilityReport")


def _nothing_stored(cluster: str = "e2e-trunc") -> bool:
    return not ImportMark.objects.filter(cluster__name=cluster).exists() and not IngestQueue.objects.exists()


@pytest.mark.parametrize("keep_fraction", [0.05, 0.25, 0.5, 0.75, 0.95])
def test_gzip_body_cut_short_is_rejected_and_nothing_is_stored(live_server, token, keep_fraction):
    body = gzip.compress(_bundle())
    cut = body[: int(len(body) * keep_fraction)]
    status, doc = _post_raw(
        live_server, "/api/v1/imports/IMPTRUNC00000000000000001/bundles/trivy.VulnerabilityReport/",
        token, cut, declared_length=len(body),
    )
    assert status == 400 and doc["error"] == "bad_gzip", doc
    assert _nothing_stored()


@pytest.mark.parametrize("keep_fraction", [0.1, 0.5, 0.9, 0.999])
def test_uncompressed_body_cut_short_is_rejected_and_nothing_is_stored(live_server, token, keep_fraction):
    body = _bundle()
    cut = body[: int(len(body) * keep_fraction)]
    status, doc = _post_raw(
        live_server, "/api/v1/imports/IMPTRUNC00000000000000001/bundles/trivy.VulnerabilityReport/",
        token, cut, declared_length=len(body), gzip_encoded=False,
    )
    assert status == 400, doc
    assert doc["error"] in {"count_mismatch", "sha256_mismatch", "bad_manifest", "missing_manifest"}, doc
    assert _nothing_stored()


def test_body_cut_inside_the_manifest_line_is_rejected(live_server, token):
    body = _bundle()
    status, doc = _post_raw(
        live_server, "/api/v1/imports/IMPTRUNC00000000000000001/bundles/trivy.VulnerabilityReport/",
        token, body[:40], declared_length=len(body), gzip_encoded=False,
    )
    assert status == 400 and doc["error"] in {"bad_manifest", "missing_manifest"}, doc
    assert _nothing_stored()


def test_a_cut_upload_does_not_poison_the_retry(live_server, token):
    path = "/api/v1/imports/IMPTRUNC00000000000000001/bundles/trivy.VulnerabilityReport/"
    full = gzip.compress(_bundle())
    status, _ = _post_raw(live_server, path, token, full[: len(full) // 2], declared_length=len(full))
    assert status == 400 and _nothing_stored()
    status, doc = _post_raw(live_server, path, token, full, declared_length=len(full))
    assert status == 201 and doc["rows_inserted"] == 30
    assert IngestQueue.objects.count() == 30


# ── real importer, misbehaving network ─────────────────────────────


def test_connection_cut_mid_body_is_retried_and_the_import_still_commits(live_server, token, capture, scratch):
    with ChaosProxy(live_server.url, cut_request={SBOM: 1}) as proxy:
        run = run_import(cluster="e2e-interrupt", folder=capture, url=proxy.url, token=token, tmp_dir=scratch)
    assert run.returncode == 0, run.stderr
    assert proxy.count(SBOM) == 2, "first attempt cut mid-body, the retry went through"
    assert IngestQueue.objects.count() == _expected_rows(run.summary), "no duplicates, nothing missing"

    drain_until_empty()
    _assert_clean_import_applied("e2e-interrupt")


def test_response_lost_after_the_server_stored_the_bundle_is_idempotent(live_server, token, capture, scratch):
    """The server processed the whole upload, the answer never arrived,
    the importer re-sends identical bytes: `already_uploaded`, no
    duplicate rows."""
    with ChaosProxy(live_server.url, drop_response={SBOM: 1}) as proxy:
        run = run_import(cluster="e2e-interrupt", folder=capture, url=proxy.url, token=token, tmp_dir=scratch)
    assert run.returncode == 0, run.stderr
    assert proxy.count(SBOM) == 2
    assert IngestQueue.objects.count() == _expected_rows(run.summary), "re-upload inserted nothing twice"
    assert ImportMark.objects.filter(cluster__name="e2e-interrupt", kind="trivy.SbomReport").count() == 1

    drain_until_empty()
    _assert_clean_import_applied("e2e-interrupt")


def test_commit_response_lost_the_retried_commit_is_accepted(live_server, token, capture, scratch):
    with ChaosProxy(live_server.url, drop_response={"/commit/": 1}) as proxy:
        run = run_import(cluster="e2e-interrupt", folder=capture, url=proxy.url, token=token, tmp_dir=scratch)
    assert run.returncode == 0, run.stderr
    assert proxy.count("/commit/") == 2
    assert not any(p.endswith("/abort/") for p in proxy.seen)

    drain_until_empty()
    _assert_clean_import_applied("e2e-interrupt")


def test_commit_that_never_succeeds_aborts_and_leaves_the_server_empty(live_server, token, capture, scratch):
    """Every bundle landed but the commit can't get through: nothing is
    claimable yet, so the importer aborts and the server holds nothing."""
    with ChaosProxy(live_server.url, fail_paths={"/commit/": 503}) as proxy:
        run = run_import(cluster="e2e-interrupt", folder=capture, url=proxy.url, token=token, tmp_dir=scratch)
    assert run.returncode == 1
    assert proxy.count("/commit/") == 3, "5xx retried, then given up"
    assert proxy.seen[-1].endswith("/abort/")
    assert "ABORTED import_id=" in run.stderr
    assert run.summary["aborted"] is True

    assert drain_until_empty()["claimed"] == 0
    assert not ImportMark.objects.filter(cluster__name="e2e-interrupt").exists()
    assert not IngestQueue.objects.exists()
    assert not Workload.objects.filter(cluster__name="e2e-interrupt").exists()

    again = run_import(cluster="e2e-interrupt", folder=capture, url=live_server.url, token=token, tmp_dir=scratch)
    assert again.returncode == 0, again.stderr


def test_every_bundle_failing_leaves_no_trace_whatever_the_failure(live_server, token, capture, scratch):
    """The first bundle can't be delivered at all (the very first
    request is cut every time): nothing was stored, so there is nothing
    to abort and nothing to clean."""
    with ChaosProxy(live_server.url, cut_request={"/bundles/inventory/": 99}) as proxy:
        run = run_import(cluster="e2e-interrupt", folder=capture, url=proxy.url, token=token, tmp_dir=scratch)
    assert run.returncode == 1 and run.summary["aborted"] is True
    assert proxy.count("/bundles/inventory/") == 3
    assert not ImportMark.objects.exists() and not IngestQueue.objects.exists()


# ── the importer process dies ──────────────────────────────────────


def test_sigterm_mid_upload_aborts_so_the_server_keeps_nothing(live_server, token, capture, scratch):
    import signal
    with ChaosProxy(live_server.url, hold_paths={SBOM}) as proxy:
        reached = proxy.watch(SBOM)
        proc = start_import(cluster="e2e-interrupt", folder=capture, url=proxy.url, token=token, tmp_dir=scratch)
        assert reached.wait(timeout=60), "importer never reached the SBOM upload"
        time.sleep(0.2)
        proc.send_signal(signal.SIGTERM)
        _, stderr = proc.communicate(timeout=60)
    assert proc.returncode == 1, stderr
    assert "SIGTERM" in stderr and "ABORTED import_id=" in stderr
    assert proxy.seen[-1].endswith("/abort/")
    assert not ImportMark.objects.exists() and not IngestQueue.objects.exists()


def test_sigkill_mid_upload_leaves_only_open_marks_the_safety_net_discards(live_server, token, capture, scratch):
    """A hard kill gives the importer no chance to abort. The bundles
    that already landed sit behind `open` marks: never claimable, never
    processed, discarded by the safety net after the TTL, and the next
    cycle starts clean."""
    with ChaosProxy(live_server.url, hold_paths={SBOM}) as proxy:
        reached = proxy.watch(SBOM)
        proc = start_import(cluster="e2e-interrupt", folder=capture, url=proxy.url, token=token, tmp_dir=scratch)
        assert reached.wait(timeout=60), "importer never reached the SBOM upload"
        time.sleep(0.2)
        proc.kill()
        proc.communicate(timeout=60)
    assert proc.returncode != 0

    marks = {m.kind: m for m in ImportMark.objects.filter(cluster__name="e2e-interrupt")}
    assert "trivy.SbomReport" not in marks, "the frozen upload never reached the server"
    assert "inventory" in marks and len(marks) >= 3
    assert all(m.state == ImportMarkState.OPEN.value for m in marks.values())
    assert IngestQueue.objects.exists(), "the delivered bundles are queued but gated"

    assert drain_until_empty()["claimed"] == 0, "nothing of a half-delivered import is processed"
    assert not Workload.objects.filter(cluster__name="e2e-interrupt").exists()
    assert Cluster.objects.get(name="e2e-interrupt").last_complete_inventory_at is None

    ImportMark.objects.filter(cluster__name="e2e-interrupt").update(
        started_at=timezone.now() - timedelta(seconds=STUCK_OPEN_TIMEOUT_SECONDS + 60),
    )
    call_command("reap_safety_net")
    discarded = list(ImportMark.objects.filter(cluster__name="e2e-interrupt"))
    assert all(m.state == ImportMarkState.REAPED.value for m in discarded)
    assert all(m.discard_reason == ImportDiscardReason.STUCK_OPEN.value for m in discarded)
    assert not IngestQueue.objects.exists()

    again = run_import(cluster="e2e-interrupt", folder=capture, url=live_server.url, token=token, tmp_dir=scratch)
    assert again.returncode == 0, again.stderr
    drain_until_empty()
    assert Workload.objects.get(cluster__name="e2e-interrupt", kind="Deployment", name="api").deployed is True
    assert Finding.objects.filter(vuln_id="CVE-2024-100").count() == 1
