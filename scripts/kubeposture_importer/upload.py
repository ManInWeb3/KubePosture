"""Upload plan: every bundle, then commit — or abort and report.

Nothing the server stores becomes claimable until `commit` succeeds, so
a failure anywhere (a bundle that won't upload, a commit the server
rejects, a SIGTERM) ends with `abort` and a non-zero exit, and the next
cycle starts fresh with a new import_id.
"""
from __future__ import annotations

import sys
from collections.abc import Callable

from .bundle import BundleMeta
from .http import HttpClient, HttpResult

NDJSON = "application/x-ndjson"


class UploadError(RuntimeError):
    def __init__(self, step: str, result: HttpResult, *, kind: str = ""):
        self.step = step
        self.kind = kind
        self.status = result.status
        self.detail = result.body[:300]
        where = f"{step} {kind}".strip()
        super().__init__(f"{where} failed ({result.status}): {self.detail}")


class ImportInterrupted(BaseException):
    """Raised from the SIGTERM handler so the in-flight import is aborted
    server-side before Kubernetes SIGKILLs the pod."""


BUNDLE_HEADERS = {"Content-Type": NDJSON, "Content-Encoding": "gzip"}


def upload_bundle(client: HttpClient, *, import_id: str, meta: BundleMeta) -> dict:
    with open(meta.path, "rb") as fh:
        result = client.post_file(
            f"/api/v1/imports/{import_id}/bundles/{meta.kind}/",
            fh, content_length=meta.compressed_bytes, headers=BUNDLE_HEADERS,
        )
    if not result.ok or result.status not in (200, 201):
        raise UploadError("upload", result, kind=meta.kind)
    return result.json() or {}


def commit(client: HttpClient, *, import_id: str, cluster: str, kinds: dict[str, int]) -> dict:
    body = {
        "cluster": cluster,
        "kinds": [{"kind": k, "count": n} for k, n in kinds.items()],
    }
    result = client.post_json(f"/api/v1/imports/{import_id}/commit/", body)
    if not result.ok:
        raise UploadError("commit", result)
    return result.json() or {}


def abort(client: HttpClient, *, import_id: str, cluster: str, reason: str,
          log: Callable[[str], None] | None = None) -> bool:
    """Best effort — never raises. A failed abort is harmless: the
    server's stuck-open sweep discards the import after its TTL — but
    that TTL is 30 minutes during which the cluster reads as in-flight,
    so the abort ignores the upload deadline: a tripped deadline is the
    main reason we are aborting in the first place."""
    log = log or (lambda msg: print(msg, file=sys.stderr))
    try:
        result = client.post_json(
            f"/api/v1/imports/{import_id}/abort/", {"cluster": cluster}, ignore_deadline=True,
        )
    except Exception as exc:  # pragma: no cover - defensive
        log(f"  abort {import_id}: {exc}")
        return False
    if result.ok:
        log(f"ABORTED import_id={import_id} reason={reason}")
        return True
    log(f"  abort {import_id} returned {result.status}: {result.body[:200]} (reason={reason})")
    return False


def run_upload_plan(
    client: HttpClient,
    *,
    import_id: str,
    cluster: str,
    bundles: list[BundleMeta],
    out: Callable[[str], None] = print,
    err: Callable[[str], None] | None = None,
) -> int:
    """Upload every bundle in order, then commit. Returns the exit code:
    0 committed, 1 aborted (after an upload / commit failure or SIGTERM)."""
    err = err or (lambda msg: print(msg, file=sys.stderr))
    uploaded: dict[str, int] = {}
    try:
        for meta in bundles:
            resp = upload_bundle(client, import_id=import_id, meta=meta)
            uploaded[meta.kind] = meta.count
            out(
                f"  upload {meta.kind}: {resp.get('status', 'ok')} count={meta.count} "
                f"bytes={meta.compressed_bytes} (uncompressed {meta.uncompressed_bytes})"
            )
        resp = commit(client, import_id=import_id, cluster=cluster, kinds=uploaded)
        out(f"COMMITTED import_id={import_id} status={resp.get('status', 'committed')} kinds={len(uploaded)}")
        return 0
    except UploadError as exc:
        err(f"  {exc}")
        abort(client, import_id=import_id, cluster=cluster, reason=f"{exc.step} {exc.kind}".strip(), log=err)
        return 1
    except ImportInterrupted:
        err("  SIGTERM received mid-import")
        abort(client, import_id=import_id, cluster=cluster, reason="sigterm", log=err)
        return 1
