"""Bundle ingest — the server half of the import protocol.

The importer uploads ONE gzip NDJSON bundle per `(import_id, kind)`:

    line 1      {"manifest": {cluster, import_id, kind, count, sha256, ...}}
    line 2..N+1 one CRD JSON object per line
                (kind `inventory`: exactly one line — the envelope
                 {cluster_meta, items[]})

then commits the whole import in one call. Three guarantees this module
provides:

- **Atomic per bundle.** The body is streamed to a spool file with hard
  caps on compressed / decompressed size (zip-bomb safe), the item
  lines are hashed and counted in a byte-only pass and compared to the
  manifest, and only then are the IngestQueue rows and the ImportMark
  (state `open`) written — in one transaction. Any failure stores
  nothing. Re-uploading the same `(cluster, import_id, kind)` with the
  same sha256 is a no-op; a different sha256 is a conflict.
- **Atomic per import.** `commit_import` verifies every listed kind has
  a mark whose live row count equals the importer's delivered count,
  that no uploaded kind was left unlisted, and flips all marks to
  `draining` together. Nothing is claimable until then.
- **Import-wide `started_at`.** `_reap_inventory` advances
  `cluster.last_complete_inventory_at` to the inventory mark's
  `started_at`, and `Finding.last_seen` is each row's `created_at`
  (core.services.ingest). Default views hide findings with
  `last_seen < last_complete_inventory_at`, so every row of the import
  — whichever kind was uploaded first — must have `created_at >=
  started_at`. The first bundle for an import fixes `started_at`; every
  later bundle copies it. A per-import advisory lock serialises that
  step so parallel uploads of different kinds can't each think they
  are first.
"""
from __future__ import annotations

import hashlib
import io
import json
import logging
import re
import tempfile
import zlib
from dataclasses import dataclass, field

from django.conf import settings
from django.db import connection, transaction
from django.db.models import Min
from django.utils import timezone

from core.constants import ImportMarkState
from core.models import Cluster, ImportMark, IngestQueue
from core.parsers import kyverno as kyverno_parser
from core.parsers import trivy as trivy_parser
from core.services.queue import count_rows

log = logging.getLogger("core.bundle_ingest")

INVENTORY_KIND = "inventory"
KNOWN_KINDS: frozenset[str] = (
    frozenset({INVENTORY_KIND})
    | frozenset(trivy_parser.PARSERS_BY_KIND)
    | frozenset(kyverno_parser.PARSERS_BY_KIND)
)

EMPTY_SHA256 = hashlib.sha256(b"").hexdigest()

_CHUNK = 64 * 1024
# Upper bound on bytes one decompress() step may emit — keeps a highly
# compressible body from expanding a 64 KiB chunk into memory all at once.
_DECOMPRESS_STEP = 1024 * 1024
_SPOOL_MAX_MEMORY = 8 * 1024 * 1024
_BULK_BATCH = 100
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
# Manifest keys with their own columns / handling; everything else is
# persisted verbatim in ImportMark.bundle_manifest. `complete_snapshot`
# and `item_sha256` are legacy keys an older importer may still send —
# accepted and ignored, never stored.
_CORE_MANIFEST_KEYS = frozenset({
    "cluster", "import_id", "kind", "count", "sha256",
    "complete_snapshot", "coverage", "item_sha256",
})


class BundleError(Exception):
    """A protocol violation the caller turns into an HTTP response.
    `code` is the machine-readable error, `detail` the extra fields."""

    def __init__(self, code: str, *, http_status: int = 400, **detail):
        super().__init__(code)
        self.code = code
        self.http_status = http_status
        self.detail = detail

    def as_body(self) -> dict:
        return {"error": self.code, **self.detail}


@dataclass(frozen=True)
class BundleLimits:
    max_compressed: int
    max_uncompressed: int
    max_items: int
    max_line_bytes: int
    tmp_dir: str | None = None

    @classmethod
    def from_settings(cls) -> "BundleLimits":
        return cls(
            max_compressed=settings.IMPORT_BUNDLE_MAX_COMPRESSED_BYTES,
            max_uncompressed=settings.IMPORT_BUNDLE_MAX_UNCOMPRESSED_BYTES,
            max_items=settings.IMPORT_BUNDLE_MAX_ITEMS,
            max_line_bytes=settings.IMPORT_BUNDLE_MAX_LINE_BYTES,
            tmp_dir=settings.IMPORT_BUNDLE_TMP_DIR,
        )


@dataclass
class Manifest:
    cluster: str
    import_id: str
    kind: str
    count: int
    sha256: str
    coverage_expected: int | None = None
    coverage_matched: int | None = None
    extra: dict = field(default_factory=dict)


class SpooledBundle:
    """Decompressed bundle on disk (or in memory when small), positioned
    after the manifest line. Context manager; closing deletes the file."""

    def __init__(self, file, manifest: Manifest, *, compressed_bytes: int,
                 uncompressed_bytes: int, item_offset: int):
        self.file = file
        self.manifest = manifest
        self.compressed_bytes = compressed_bytes
        self.uncompressed_bytes = uncompressed_bytes
        self.item_offset = item_offset

    def iter_item_lines(self):
        self.file.seek(self.item_offset)
        yield from iter(self.file.readline, b"")

    def close(self) -> None:
        self.file.close()

    def __enter__(self) -> "SpooledBundle":
        return self

    def __exit__(self, *exc) -> None:
        self.close()


@dataclass(frozen=True)
class StoreResult:
    mark: ImportMark
    created: bool          # False → identical bundle already stored (no-op)
    rows_inserted: int


@dataclass(frozen=True)
class CoverageEntry:
    kind: str
    expected: int | None
    matched: int | None
    ratio: float | None


@dataclass(frozen=True)
class CommitResult:
    marks: list[ImportMark]
    idempotent: bool       # True → was already committed with identical counts
    coverage: list[CoverageEntry]


@dataclass(frozen=True)
class AbortResult:
    deleted_rows: int
    deleted_marks: int


# ── Manifest ───────────────────────────────────────────────────────


def _opt_int(value, *, field_name: str) -> int | None:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise BundleError("bad_manifest", field=field_name, detail="must be a non-negative integer")
    return value


def parse_manifest(line: bytes) -> Manifest:
    try:
        doc = json.loads(line)
    except ValueError as exc:
        raise BundleError("bad_manifest", detail=f"line 1 is not JSON: {exc}") from None
    if not isinstance(doc, dict) or not isinstance(doc.get("manifest"), dict):
        raise BundleError("missing_manifest", detail='line 1 must be {"manifest": {...}}')
    m = doc["manifest"]

    def _required_str(key: str) -> str:
        value = m.get(key)
        if not isinstance(value, str) or not value.strip():
            raise BundleError("bad_manifest", field=key, detail="required non-empty string")
        return value.strip()

    cluster = _required_str("cluster")
    import_id = _required_str("import_id")
    kind = _required_str("kind")
    count = _opt_int(m.get("count"), field_name="count")
    if count is None:
        raise BundleError("bad_manifest", field="count", detail="required")
    sha = m.get("sha256")
    if not isinstance(sha, str) or not _HEX64.match(sha.lower()):
        raise BundleError("bad_manifest", field="sha256", detail="required 64-hex string")
    sha = sha.lower()

    expected = matched = None
    coverage = m.get("coverage")
    if coverage is not None:
        if not isinstance(coverage, dict):
            raise BundleError("bad_manifest", field="coverage", detail="must be an object")
        expected = _opt_int(coverage.get("expected"), field_name="coverage.expected")
        matched = _opt_int(coverage.get("matched"), field_name="coverage.matched")

    extra = {k: v for k, v in m.items() if k not in _CORE_MANIFEST_KEYS}
    return Manifest(
        cluster=cluster, import_id=import_id, kind=kind, count=count, sha256=sha,
        coverage_expected=expected, coverage_matched=matched, extra=extra,
    )


def check_manifest(manifest: Manifest, *, import_id: str, kind: str) -> None:
    """The manifest must agree with the URL it was posted to, and name a
    kind the worker can dispatch — a typo'd kind used to produce rows
    that processed as `skipped: unknown_kind`."""
    if manifest.import_id != import_id or manifest.kind != kind:
        raise BundleError(
            "manifest_mismatch",
            path_import_id=import_id, path_kind=kind,
            manifest_import_id=manifest.import_id, manifest_kind=manifest.kind,
        )
    if kind not in KNOWN_KINDS:
        raise BundleError("unknown_kind", kind=kind)


# ── Spool + verify ─────────────────────────────────────────────────


class _Inflater:
    """Streaming single-member gzip decoder with bounded output per step."""

    def __init__(self) -> None:
        self._d = zlib.decompressobj(16 + zlib.MAX_WBITS)

    def feed(self, data: bytes):
        try:
            out = self._d.decompress(data, _DECOMPRESS_STEP)
            if out:
                yield out
            while self._d.unconsumed_tail:
                out = self._d.decompress(self._d.unconsumed_tail, _DECOMPRESS_STEP)
                if out:
                    yield out
        except zlib.error as exc:
            raise BundleError("bad_gzip", detail=str(exc)) from None

    def finish(self):
        if not self._d.eof:
            raise BundleError("bad_gzip", detail="truncated gzip stream")
        if self._d.unused_data.strip():
            raise BundleError("bad_gzip", detail="trailing data after gzip member")
        out = self._d.flush()
        if out:
            yield out


def spool_bundle(stream, *, gzip_encoded: bool, limits: BundleLimits) -> SpooledBundle:
    """Read the request body to a spool file, decompressing on the fly,
    enforcing the compressed and decompressed caps, and parse line 1 as
    the manifest. Returns the bundle positioned at the first item line.
    """
    spool = tempfile.SpooledTemporaryFile(max_size=_SPOOL_MAX_MEMORY, dir=limits.tmp_dir)
    compressed = 0
    uncompressed = 0

    def _write(out: bytes) -> None:
        nonlocal uncompressed
        uncompressed += len(out)
        if uncompressed > limits.max_uncompressed:
            raise BundleError("bundle_too_large", http_status=413, limit="uncompressed",
                              max_bytes=limits.max_uncompressed)
        spool.write(out)

    try:
        inflater = _Inflater() if gzip_encoded else None
        while True:
            chunk = stream.read(_CHUNK) if stream is not None else b""
            if not chunk:
                break
            compressed += len(chunk)
            if compressed > limits.max_compressed:
                raise BundleError("bundle_too_large", http_status=413, limit="compressed",
                                  max_bytes=limits.max_compressed)
            if inflater is not None:
                for out in inflater.feed(chunk):
                    _write(out)
            else:
                _write(chunk)
        if inflater is not None:
            if compressed == 0:
                raise BundleError("bad_gzip", detail="empty body")
            for out in inflater.finish():
                _write(out)

        spool.seek(0)
        first = spool.readline()
        if not first.strip():
            raise BundleError("missing_manifest", detail="empty body")
        manifest = parse_manifest(first)
        return SpooledBundle(
            spool, manifest,
            compressed_bytes=compressed, uncompressed_bytes=uncompressed,
            item_offset=spool.tell(),
        )
    except BaseException:
        spool.close()
        raise


def verify_bundle(spooled: SpooledBundle, *, limits: BundleLimits) -> None:
    """Byte-only pass over the item lines: caps, count, sha256. No JSON
    parsing, no DB — the common mismatch failures never get near a
    transaction.

    `sha256` covers the item lines exactly as sent, each including its
    trailing newline.
    """
    m = spooled.manifest
    if m.count > limits.max_items:
        raise BundleError("bundle_too_large", http_status=413, limit="items", max_items=limits.max_items)
    digest = hashlib.sha256()
    count = 0
    for raw in spooled.iter_item_lines():
        count += 1
        if count > limits.max_items:
            raise BundleError("bundle_too_large", http_status=413, limit="items", max_items=limits.max_items)
        if len(raw) > limits.max_line_bytes:
            raise BundleError("bundle_too_large", http_status=413, limit="line", line=count,
                              max_bytes=limits.max_line_bytes)
        digest.update(raw)
    if count != m.count:
        raise BundleError("count_mismatch", expected=m.count, actual=count)
    actual = digest.hexdigest()
    if actual != m.sha256:
        raise BundleError("sha256_mismatch", expected=m.sha256, actual=actual)


# ── Store / commit / abort ─────────────────────────────────────────


def _lock_import(cluster_name: str, import_id: str) -> None:
    """Transaction-scoped advisory lock on one import. Must run inside
    an atomic block."""
    with connection.cursor() as cur:
        cur.execute("SELECT pg_advisory_xact_lock(hashtext(%s))", [f"{cluster_name}/{import_id}"])


@transaction.atomic
def store_bundle(*, cluster: Cluster, spooled: SpooledBundle) -> StoreResult:
    """Insert the bundle's rows and its `open` mark in one transaction.
    Caller has already run `check_manifest` and `verify_bundle`."""
    m = spooled.manifest
    _lock_import(cluster.name, m.import_id)

    siblings = ImportMark.objects.filter(cluster=cluster, import_id=m.import_id)
    committed = siblings.exclude(state=ImportMarkState.OPEN.value).values_list("kind", "state")
    if committed.exists():
        raise BundleError(
            "import_already_committed", http_status=409,
            states={k: s for k, s in committed},
        )
    existing = siblings.filter(kind=m.kind).first()
    if existing is not None:
        if existing.bundle_sha256 == m.sha256:
            return StoreResult(existing, created=False, rows_inserted=0)
        raise BundleError("bundle_conflict", http_status=409, existing_sha256=existing.bundle_sha256)

    # Import-wide started_at — see module docstring.
    started_at = siblings.aggregate(first=Min("started_at"))["first"] or timezone.now()
    mark = ImportMark.objects.create(
        cluster=cluster,
        kind=m.kind,
        import_id=m.import_id,
        state=ImportMarkState.OPEN.value,
        started_at=started_at,
        bundle_sha256=m.sha256,
        coverage_expected=m.coverage_expected,
        coverage_matched=m.coverage_matched,
        bundle_manifest=m.extra,
    )

    inserted = 0
    batch: list[IngestQueue] = []
    for line_no, raw in enumerate(spooled.iter_item_lines(), start=1):
        try:
            payload = json.loads(raw)
        except ValueError as exc:
            raise BundleError("malformed_line", line=line_no, detail=str(exc)[:200]) from None
        if not isinstance(payload, dict):
            raise BundleError("line_not_object", line=line_no)
        batch.append(IngestQueue(
            cluster_name=cluster.name,
            kind=m.kind,
            import_id=m.import_id,
            raw_json=payload,
        ))
        if len(batch) >= _BULK_BATCH:
            IngestQueue.objects.bulk_create(batch)
            inserted += len(batch)
            batch = []
    if batch:
        IngestQueue.objects.bulk_create(batch)
        inserted += len(batch)

    log.info(
        "bundle.stored",
        extra={
            "cluster": cluster.name, "import_id": m.import_id, "kind": m.kind,
            "rows": inserted, "compressed_bytes": spooled.compressed_bytes,
            "uncompressed_bytes": spooled.uncompressed_bytes,
        },
    )
    return StoreResult(mark, created=True, rows_inserted=inserted)


def build_ndjson(
    items: list[dict],
    *,
    cluster: str,
    import_id: str,
    kind: str,
    coverage: dict | None = None,
    extra: dict | None = None,
) -> bytes:
    """Serialise items + a matching manifest line. Shared by
    `store_items` (test harness) and the test-suite; the importer has
    its own streaming writer that produces the identical byte format."""
    lines = [json.dumps(item, separators=(",", ":")).encode("utf-8") + b"\n" for item in items]
    body = b"".join(lines)
    manifest: dict = {
        "cluster": cluster,
        "import_id": import_id,
        "kind": kind,
        "count": len(lines),
        "sha256": hashlib.sha256(body).hexdigest(),
    }
    if coverage is not None:
        manifest["coverage"] = coverage
    if extra:
        manifest.update(extra)
    return json.dumps({"manifest": manifest}, separators=(",", ":")).encode("utf-8") + b"\n" + body


def store_items(
    *,
    cluster: Cluster,
    import_id: str,
    kind: str,
    items: list[dict],
    coverage: dict | None = None,
    extra: dict | None = None,
) -> StoreResult:
    """In-process equivalent of a bundle upload — the testing harness
    and tests use it so they exercise the exact store path."""
    raw = build_ndjson(
        items, cluster=cluster.name, import_id=import_id, kind=kind,
        coverage=coverage, extra=extra,
    )
    limits = BundleLimits.from_settings()
    with spool_bundle(io.BytesIO(raw), gzip_encoded=False, limits=limits) as spooled:
        check_manifest(spooled.manifest, import_id=import_id, kind=kind)
        verify_bundle(spooled, limits=limits)
        return store_bundle(cluster=cluster, spooled=spooled)


def _coverage_entries(marks: list[ImportMark]) -> list[CoverageEntry]:
    out = []
    for m in marks:
        ratio = None
        if m.coverage_expected is not None:
            ratio = 1.0 if m.coverage_expected == 0 else (m.coverage_matched or 0) / m.coverage_expected
        out.append(CoverageEntry(m.kind, m.coverage_expected, m.coverage_matched, ratio))
    return out


@transaction.atomic
def commit_import(*, cluster: Cluster, import_id: str, kinds: list[tuple[str, int]]) -> CommitResult:
    """Flip every mark of the import to `draining` in one transaction,
    after checking the importer's view of the import against what was
    stored. Idempotent for an identical retry."""
    listed: dict[str, int] = {}
    for kind, count in kinds:
        if kind in listed:
            raise BundleError("bad_request", detail=f"kind listed twice: {kind}")
        listed[kind] = count

    _lock_import(cluster.name, import_id)
    marks = list(
        ImportMark.objects.select_for_update()
        .filter(cluster=cluster, import_id=import_id)
        .order_by("kind")
    )
    if not marks:
        raise BundleError("import_not_found", http_status=404)

    have = {m.kind: m for m in marks}
    missing = sorted(set(listed) - set(have))
    if missing:
        raise BundleError("kind_not_uploaded", http_status=409, kinds=missing)
    unlisted = sorted(set(have) - set(listed))
    if unlisted:
        raise BundleError("unlisted_kinds", http_status=409, kinds=unlisted)

    states = {m.kind: m.state for m in marks}
    if all(m.state != ImportMarkState.OPEN.value for m in marks):
        if all(m.observed_count == listed[m.kind] for m in marks):
            return CommitResult(marks, idempotent=True, coverage=_coverage_entries(marks))
        raise BundleError("state_conflict", http_status=409, states=states)
    if any(m.state != ImportMarkState.OPEN.value for m in marks):
        raise BundleError("state_conflict", http_status=409, states=states)

    for m in marks:
        actual = count_rows(cluster_name=cluster.name, kind=m.kind, import_id=import_id)
        if actual != listed[m.kind]:
            raise BundleError(
                "count_mismatch", http_status=409,
                kind=m.kind, expected=listed[m.kind], actual=actual,
            )

    now = timezone.now()
    for m in marks:
        m.state = ImportMarkState.DRAINING.value
        m.observed_count = listed[m.kind]
        m.completed_at = now
    ImportMark.objects.bulk_update(marks, ["state", "observed_count", "completed_at"])

    coverage = _coverage_entries(marks)
    threshold = settings.IMPORT_COVERAGE_ALERT_RATIO
    for entry in coverage:
        if entry.ratio is not None and entry.ratio < threshold:
            log.error(
                "import.coverage_low",
                extra={
                    "cluster": cluster.name, "import_id": import_id, "kind": entry.kind,
                    "expected": entry.expected, "matched": entry.matched,
                    "ratio": round(entry.ratio, 3), "threshold": threshold,
                },
            )
    log.info(
        "import.committed",
        extra={"cluster": cluster.name, "import_id": import_id, "kinds": listed},
    )
    return CommitResult(marks, idempotent=False, coverage=coverage)


@transaction.atomic
def abort_import(*, cluster: Cluster, import_id: str) -> AbortResult:
    """Drop everything for an import the importer gave up on. Only while
    nothing has been committed — afterwards the worker may already be
    applying it."""
    _lock_import(cluster.name, import_id)
    marks = ImportMark.objects.select_for_update().filter(cluster=cluster, import_id=import_id)
    if not marks.exists():
        raise BundleError("import_not_found", http_status=404)
    committed = marks.exclude(state=ImportMarkState.OPEN.value).values_list("kind", "state")
    if committed.exists():
        raise BundleError(
            "import_already_committed", http_status=409,
            states={k: s for k, s in committed},
        )
    rows = IngestQueue.objects.filter(cluster_name=cluster.name, import_id=import_id).delete()[0]
    n = marks.delete()[0]
    log.warning(
        "import.aborted",
        extra={"cluster": cluster.name, "import_id": import_id, "rows": rows, "marks": n},
    )
    return AbortResult(deleted_rows=rows, deleted_marks=n)
