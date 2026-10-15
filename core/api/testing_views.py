"""/api/v1/testing/* harness endpoints — gated by TESTING_HARNESS_ENABLED.

Lets a test drive the pipeline synchronously against a throwable DB
without going through HTTP bundle uploads.

Endpoints:

  POST /api/v1/testing/reset/
        TRUNCATE every app table (preserves auth_user / Django internals).
  POST /api/v1/testing/load_scenario/
        body: {cluster, import_id, payloads: [...], finishes: [...]}
        Synchronous: stores one bundle per (import_id, kind) through the
        same service the upload endpoint uses, commits each import,
        drains the queue inline, fires reaps.

The former run_snapshot / run_enrichment / advance_clock / assert_batch
endpoints and the assertion DSL had no callers and were removed; the
realdata e2e tests assert through the ORM instead.
"""
from __future__ import annotations

from django.conf import settings
from django.db import connection
from django.utils import timezone
from rest_framework import status
from rest_framework.decorators import (
    api_view,
    authentication_classes,
    permission_classes,
)
from rest_framework.permissions import AllowAny
from rest_framework.response import Response

from core.models import (
    Cluster,
    EpssScore,
    Finding,
    FindingAction,
    Image,
    ImportMark,
    IngestQueue,
    IngestToken,
    KevEntry,
    Namespace,
    ScanInconsistency,
    Snapshot,
    Workload,
    WorkloadAlias,
    WorkloadImageObservation,
    WorkloadSignal,
)
from core.services import worker as worker_service
from core.services.bundle_ingest import BundleError, commit_import, store_items


def _gated() -> Response | None:
    if not getattr(settings, "TESTING_HARNESS_ENABLED", False):
        return Response(
            {"error": "testing harness disabled"},
            status=status.HTTP_403_FORBIDDEN,
        )
    return None


_RESET_TABLES = [
    Finding,
    FindingAction,
    Snapshot,
    ScanInconsistency,
    WorkloadSignal,
    WorkloadAlias,
    WorkloadImageObservation,
    IngestQueue,
    ImportMark,
    Workload,
    Image,
    Namespace,
    IngestToken,
    Cluster,
    EpssScore,
    KevEntry,
]


@api_view(["POST"])
@authentication_classes([])
@permission_classes([AllowAny])
def reset(request):
    if (gate := _gated()):
        return gate
    table_names = [m._meta.db_table for m in _RESET_TABLES]
    quoted = ", ".join(f'"{t}"' for t in table_names)
    with connection.cursor() as cur:
        cur.execute(f"TRUNCATE {quoted} RESTART IDENTITY CASCADE")
    return Response({
        "reset_at": timezone.now().isoformat(),
        "truncated_tables": table_names,
    })


def _ensure_cluster(name: str) -> Cluster:
    cluster, _ = Cluster.objects.get_or_create(name=name)
    return cluster


@api_view(["POST"])
@authentication_classes([])
@permission_classes([AllowAny])
def load_scenario(request):
    """Replay one scenario synchronously.

    Body:
       {
         "cluster": "...",
         "import_id": "...",
         "payloads": [
            {"kind": "...", "payload": {...}, "import_id": "..."?},
            ...
         ],
         "finishes": [{"kind": "...", "observed_count": N, "import_id": "..."?}, ...]
       }

    Payloads are grouped into one bundle per (import_id, kind) and
    stored via `bundle_ingest.store_items`; each import_id named in
    `finishes` is then committed with those counts (a finish for a kind
    with no payloads stores an empty bundle first — count 0 is a valid
    outage signal). `observed_count` must equal the number of payloads
    posted for that kind, exactly as a real commit requires. A legacy
    `starts` list is accepted and ignored.
    """
    if (gate := _gated()):
        return gate

    body = request.data
    cluster_name = body["cluster"]
    import_id = body.get("import_id") or ""
    cluster = _ensure_cluster(cluster_name)

    payloads = body.get("payloads") or []
    finishes = body.get("finishes") or []

    grouped: dict[tuple[str, str], list[dict]] = {}
    for env in payloads:
        key = (env.get("import_id") or import_id, env["kind"])
        grouped.setdefault(key, []).append(env.get("payload") or {})

    finishes_by_import: dict[str, list[tuple[str, int]]] = {}
    for f in finishes:
        iid = f.get("import_id") or import_id
        finishes_by_import.setdefault(iid, []).append((f["kind"], int(f["observed_count"])))
        grouped.setdefault((iid, f["kind"]), [])

    try:
        for (iid, kind), items in grouped.items():
            store_items(cluster=cluster, import_id=iid, kind=kind, items=items)
        for iid, kinds in finishes_by_import.items():
            commit_import(cluster=cluster, import_id=iid, kinds=kinds)
    except BundleError as exc:
        return Response(exc.as_body(), status=exc.http_status)

    # Drain queue + fire reaps.
    totals = worker_service.drain_until_empty()
    return Response({
        "cluster": cluster_name,
        "import_id": import_id,
        "bundles": len(grouped),
        "payloads": len(payloads),
        "finishes": len(finishes),
        **totals,
    })
