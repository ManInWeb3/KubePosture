"""Bundle writer — one gzip NDJSON file per kind, built in a single pass.

Byte format (identical to the server's `build_ndjson`, which the test
suite checks):

    {"manifest": {...}}\n          ← line 1, needs count + sha256 of what follows
    <item JSON>\n                   ← compact `json.dumps(separators=(",", ":"))`
    ...

The manifest must come first but depends on the items, so items are
streamed to an uncompressed scratch file (hashing and counting as they
go), then the final `.ndjson.gz` is written as manifest line + a chunked
copy of the scratch file through one gzip member. Memory stays flat; the
scratch file costs one extra sequential read of ~20 MB on /tmp.

`gzip` is written with `mtime=0` so identical input yields identical
compressed bytes (golden files, idempotent re-uploads).
"""
from __future__ import annotations

import gzip
import hashlib
import json
import os
import shutil
import tempfile
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path

_COPY_CHUNK = 1024 * 1024


def _dumps(obj) -> bytes:
    return json.dumps(obj, separators=(",", ":")).encode("utf-8")


@dataclass(frozen=True)
class BundleMeta:
    kind: str
    path: Path
    count: int
    sha256: str
    item_bytes: int          # uncompressed bytes of the item lines
    uncompressed_bytes: int  # manifest line + item lines
    compressed_bytes: int
    manifest: dict

    def unlink(self) -> None:
        try:
            os.unlink(self.path)
        except FileNotFoundError:
            pass


class BundleWriter:
    def __init__(self, *, cluster: str, import_id: str, kind: str, tmp_dir: Path,
                 complete_snapshot: bool = False, compresslevel: int = 6):
        self.cluster = cluster
        self.import_id = import_id
        self.kind = kind
        self.tmp_dir = Path(tmp_dir)
        self.complete_snapshot = complete_snapshot
        self.compresslevel = compresslevel
        self.count = 0
        self.item_bytes = 0
        self._sha = hashlib.sha256()
        self.tmp_dir.mkdir(parents=True, exist_ok=True)
        self._scratch = tempfile.NamedTemporaryFile(
            prefix=f"kp-{kind}-", suffix=".ndjson", dir=self.tmp_dir, delete=False,
        )
        self._closed = False

    # ── writing ────────────────────────────────────────────────────

    def _raw(self, data: bytes) -> None:
        self._scratch.write(data)
        self._sha.update(data)
        self.item_bytes += len(data)

    def write_item(self, obj: dict) -> None:
        self._raw(_dumps(obj) + b"\n")
        self.count += 1

    def write_inventory_envelope(self, cluster_meta: dict, items: Iterable[dict]) -> None:
        """Stream `{"cluster_meta":…,"complete_snapshot":…,"items":[…]}` as
        ONE line without materialising the envelope — byte-identical to
        `json.dumps` of the same dict with that key order."""
        self._raw(b'{"cluster_meta":' + _dumps(cluster_meta)
                  + b',"complete_snapshot":' + (b"true" if self.complete_snapshot else b"false")
                  + b',"items":[')
        first = True
        for item in items:
            if not first:
                self._raw(b",")
            first = False
            self._raw(_dumps(item))
        self._raw(b"]}\n")
        self.count += 1

    # ── finishing ──────────────────────────────────────────────────

    def manifest(self, *, coverage: dict | None = None, extra: dict | None = None) -> dict:
        manifest: dict = {
            "cluster": self.cluster,
            "import_id": self.import_id,
            "kind": self.kind,
            "count": self.count,
            "sha256": self._sha.hexdigest(),
            "complete_snapshot": self.complete_snapshot,
        }
        if coverage is not None:
            manifest["coverage"] = coverage
        if extra:
            manifest.update(extra)
        return manifest

    def finish(self, *, coverage: dict | None = None, extra: dict | None = None) -> BundleMeta:
        if self._closed:
            raise RuntimeError("BundleWriter already finished")
        self._closed = True
        self._scratch.flush()
        self._scratch.close()
        manifest = self.manifest(coverage=coverage, extra=extra)
        manifest_line = _dumps({"manifest": manifest}) + b"\n"

        final = tempfile.NamedTemporaryFile(
            prefix=f"kp-{self.kind}-", suffix=".ndjson.gz", dir=self.tmp_dir, delete=False,
        )
        try:
            with final, gzip.GzipFile(
                filename="", fileobj=final, mode="wb", mtime=0, compresslevel=self.compresslevel,
            ) as gz:
                gz.write(manifest_line)
                with open(self._scratch.name, "rb") as src:
                    shutil.copyfileobj(src, gz, _COPY_CHUNK)
        finally:
            os.unlink(self._scratch.name)
        path = Path(final.name)
        return BundleMeta(
            kind=self.kind,
            path=path,
            count=self.count,
            sha256=manifest["sha256"],
            item_bytes=self.item_bytes,
            uncompressed_bytes=self.item_bytes + len(manifest_line),
            compressed_bytes=path.stat().st_size,
            manifest=manifest,
        )

    def abort(self) -> None:
        """Discard scratch state after an error."""
        if not self._closed:
            self._closed = True
            self._scratch.close()
            try:
                os.unlink(self._scratch.name)
            except FileNotFoundError:
                pass

    def __enter__(self) -> "BundleWriter":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        if exc_type is not None:
            self.abort()
