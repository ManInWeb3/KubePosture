"""Bundle import endpoints — see core.services.bundle_ingest for the
protocol. All three require IngestBearerAuthentication; the cluster
comes from the manifest / body and is auto-registered.

  POST /api/v1/imports/<import_id>/bundles/<kind>/
        Content-Type: application/x-ndjson
        Content-Encoding: gzip (or identity)
        body: manifest line + one CRD JSON object per line
        → 201 stored | 200 already_uploaded | 4xx (see BundleError codes)

  POST /api/v1/imports/<import_id>/commit/
        body: {cluster, kinds: [{kind, count}, ...]}
        → 200 committed | 200 already_committed | 404 | 409

  POST /api/v1/imports/<import_id>/abort/
        body: {cluster}
        → 200 aborted | 404 | 409
"""
from __future__ import annotations

import re

from rest_framework import status
from rest_framework.decorators import (
    api_view,
    authentication_classes,
    parser_classes,
    permission_classes,
)
from rest_framework.response import Response

from core.api.auth import (
    IngestBearerAuthentication,
    IsIngestAuthenticated,
    require_cluster,
)
from core.services import bundle_ingest
from core.services.bundle_ingest import BundleError

_IMPORT_ID_RE = re.compile(r"^[A-Za-z0-9_-]{1,32}$")
_NDJSON = "application/x-ndjson"


def _error(exc: BundleError) -> Response:
    return Response(exc.as_body(), status=exc.http_status)


def _bad_request(detail: str) -> Response:
    return Response({"error": "bad_request", "detail": detail}, status=status.HTTP_400_BAD_REQUEST)


@api_view(["POST"])
@authentication_classes([IngestBearerAuthentication])
@permission_classes([IsIngestAuthenticated])
@parser_classes([])
def bundle_upload(request, import_id: str, kind: str):
    """Streams the body — never touches `request.data`, so DRF's JSON
    parser (and Django's DATA_UPLOAD_MAX_MEMORY_SIZE) are out of the
    picture; the caps in BundleLimits are the guard."""
    if not _IMPORT_ID_RE.match(import_id):
        return Response({"error": "bad_import_id"}, status=status.HTTP_400_BAD_REQUEST)

    content_type = (request.content_type or "").split(";")[0].strip().lower()
    if content_type != _NDJSON:
        return Response(
            {"error": "unsupported_media_type", "expected": _NDJSON},
            status=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
        )
    encoding = (request.META.get("HTTP_CONTENT_ENCODING") or "identity").strip().lower()
    if encoding not in ("gzip", "identity"):
        return Response(
            {"error": "unsupported_content_encoding", "encoding": encoding},
            status=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
        )

    limits = bundle_ingest.BundleLimits.from_settings()
    declared = request.META.get("CONTENT_LENGTH")
    if declared:
        try:
            if int(declared) > limits.max_compressed:
                return Response(
                    {"error": "bundle_too_large", "limit": "compressed", "max_bytes": limits.max_compressed},
                    status=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                )
        except ValueError:
            pass

    try:
        with bundle_ingest.spool_bundle(
            request.stream, gzip_encoded=(encoding == "gzip"), limits=limits,
        ) as spooled:
            bundle_ingest.check_manifest(spooled.manifest, import_id=import_id, kind=kind)
            cluster = require_cluster(request, spooled.manifest.cluster)
            bundle_ingest.verify_bundle(spooled, limits=limits)
            result = bundle_ingest.store_bundle(cluster=cluster, spooled=spooled)
    except BundleError as exc:
        return _error(exc)

    mark = result.mark
    return Response(
        {
            "status": "stored" if result.created else "already_uploaded",
            "cluster": cluster.name,
            "import_id": import_id,
            "kind": kind,
            "count": spooled.manifest.count,
            "sha256": mark.bundle_sha256,
            "started_at": mark.started_at.isoformat(),
            "rows_inserted": result.rows_inserted,
        },
        status=status.HTTP_201_CREATED if result.created else status.HTTP_200_OK,
    )


@api_view(["POST"])
@authentication_classes([IngestBearerAuthentication])
@permission_classes([IsIngestAuthenticated])
def import_commit(request, import_id: str):
    if not _IMPORT_ID_RE.match(import_id):
        return Response({"error": "bad_import_id"}, status=status.HTTP_400_BAD_REQUEST)
    body = request.data
    if not isinstance(body, dict):
        return _bad_request("body must be a JSON object")
    raw_kinds = body.get("kinds")
    if not isinstance(raw_kinds, list) or not raw_kinds:
        return _bad_request("kinds must be a non-empty list of {kind, count}")
    kinds: list[tuple[str, int]] = []
    for entry in raw_kinds:
        if not isinstance(entry, dict):
            return _bad_request("each kinds entry must be an object")
        kind = entry.get("kind")
        count = entry.get("count")
        if not isinstance(kind, str) or not kind.strip():
            return _bad_request("kinds[].kind must be a non-empty string")
        if isinstance(count, bool) or not isinstance(count, int) or count < 0:
            return _bad_request("kinds[].count must be a non-negative integer")
        kinds.append((kind.strip(), count))
    cluster = require_cluster(request, body.get("cluster") or "")

    try:
        result = bundle_ingest.commit_import(cluster=cluster, import_id=import_id, kinds=kinds)
    except BundleError as exc:
        return _error(exc)

    completed_at = max((m.completed_at for m in result.marks if m.completed_at), default=None)
    return Response({
        "status": "already_committed" if result.idempotent else "committed",
        "cluster": cluster.name,
        "import_id": import_id,
        "committed_at": completed_at.isoformat() if completed_at else None,
        "kinds": [
            {
                "kind": entry.kind,
                "observed_count": next(m.observed_count for m in result.marks if m.kind == entry.kind),
                "coverage_ratio": None if entry.ratio is None else round(entry.ratio, 4),
            }
            for entry in result.coverage
        ],
    })


@api_view(["POST"])
@authentication_classes([IngestBearerAuthentication])
@permission_classes([IsIngestAuthenticated])
def import_abort(request, import_id: str):
    if not _IMPORT_ID_RE.match(import_id):
        return Response({"error": "bad_import_id"}, status=status.HTTP_400_BAD_REQUEST)
    body = request.data if isinstance(request.data, dict) else {}
    cluster = require_cluster(request, body.get("cluster") or "")
    try:
        result = bundle_ingest.abort_import(cluster=cluster, import_id=import_id)
    except BundleError as exc:
        return _error(exc)
    return Response({
        "status": "aborted",
        "cluster": cluster.name,
        "import_id": import_id,
        "deleted_rows": result.deleted_rows,
        "deleted_marks": result.deleted_marks,
    })
