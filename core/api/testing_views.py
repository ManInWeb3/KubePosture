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
  POST /api/v1/testing/run_snapshot/
        Fires the daily snapshot-capture inline.
  POST /api/v1/testing/run_enrichment/
        body: {source: "epss"|"kev", path: "..."}
        Loads a fixture file off disk and applies it.
  POST /api/v1/testing/advance_clock/
        body: {seconds: N}
        Shifts every stored timestamp in app tables backwards by
        N seconds. Real timezone.now() is unchanged, so any
        time-based gate (safety-net 1h, expires_at, last_seen
        staleness) sees pre-existing rows as "older" — exactly
        what tests need to assert TTL/aging behaviour without
        sleeping.
  POST /api/v1/testing/assert_batch/
        body: {assertions: [...]}  →  {results: [...]}
"""
from __future__ import annotations

from datetime import timedelta

from django.conf import settings
from django.db import connection, transaction
from django.db.models import F
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
from core.services.test_assertions import evaluate_assertions


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
            {"kind": "...", "payload": {...}, "complete_snapshot": true,
             "import_id": "..."?},
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
    complete: dict[tuple[str, str], bool] = {}
    for env in payloads:
        key = (env.get("import_id") or import_id, env["kind"])
        payload = env.get("payload") or {}
        grouped.setdefault(key, []).append(payload)
        flag = env.get("complete_snapshot")
        if flag is None and isinstance(payload, dict):
            flag = payload.get("complete_snapshot")
        if flag:
            complete[key] = True

    finishes_by_import: dict[str, list[tuple[str, int]]] = {}
    for f in finishes:
        iid = f.get("import_id") or import_id
        finishes_by_import.setdefault(iid, []).append((f["kind"], int(f["observed_count"])))
        grouped.setdefault((iid, f["kind"]), [])

    try:
        for (iid, kind), items in grouped.items():
            store_items(
                cluster=cluster, import_id=iid, kind=kind, items=items,
                complete_snapshot=complete.get((iid, kind), False),
            )
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


@api_view(["POST"])
@authentication_classes([])
@permission_classes([AllowAny])
def run_snapshot(request):
    if (gate := _gated()):
        return gate
    from core.services.snapshot import capture_daily_heartbeat
    n = capture_daily_heartbeat()
    return Response({"snapshot_rows_written": n})


@api_view(["POST"])
@authentication_classes([])
@permission_classes([AllowAny])
def run_enrichment(request):
    if (gate := _gated()):
        return gate
    body = request.data
    source = body.get("source")
    path = body.get("path")
    if not source or not path:
        return Response(
            {"error": "source and path are required"},
            status=status.HTTP_400_BAD_REQUEST,
        )
    from core.services.enrichment import (
        load_epss_from_file,
        load_kev_from_file,
    )
    if source == "epss":
        n = load_epss_from_file(path)
    elif source == "kev":
        n = load_kev_from_file(path)
    else:
        return Response(
            {"error": f"unknown source: {source}"},
            status=status.HTTP_400_BAD_REQUEST,
        )
    return Response({"source": source, "rows": n})


# ── advance_clock (Option B: shift stored timestamps backwards) ──
#
# Each entry: (Model, [field_name, ...]). Listed fields are shifted
# backwards by `seconds` in one transaction. Nullable columns are
# safe — F("col") - delta on NULL stays NULL.
_CLOCK_SHIFTABLE: list[tuple[type, list[str]]] = [
    (ImportMark, ["started_at", "completed_at"]),
    (IngestQueue, ["created_at", "claimed_at", "processed_at"]),
    (Workload, ["last_inventory_at", "first_seen_at", "last_seen_at"]),
    (WorkloadImageObservation, ["first_seen_at", "last_seen_at"]),
    (WorkloadAlias, ["last_seen_at"]),
    (WorkloadSignal, ["first_seen_at", "last_seen_at"]),
    (Finding, ["first_seen", "last_seen"]),
    (FindingAction, ["created_at", "expires_at", "sla_due_at", "revoked_at"]),
    (Image, ["first_seen_at", "last_seen_at"]),
    (Namespace, ["first_seen_at", "last_seen_at", "deactivated_at"]),
    (Cluster, ["created_at", "last_seen_at", "last_complete_inventory_at"]),
    (IngestToken, ["created_at", "last_used_at", "revoked_at"]),
    (ScanInconsistency, ["first_observed_at", "last_observed_at"]),
    (Snapshot, ["captured_at"]),
    (EpssScore, ["fetched_at"]),
    (KevEntry, ["fetched_at"]),
]


@api_view(["POST"])
@authentication_classes([])
@permission_classes([AllowAny])
def advance_clock(request):
    """Shift every stored timestamp backwards by `seconds` so real
    `timezone.now()` looks `seconds` further in the future. Forward-
    only; no clock mocking — only column rewrites. See module
    docstring for the rationale.
    """
    if (gate := _gated()):
        return gate
    try:
        seconds = int(request.data.get("seconds", 0))
    except (TypeError, ValueError):
        return Response(
            {"error": "seconds must be an integer"},
            status=status.HTTP_400_BAD_REQUEST,
        )
    if seconds < 0:
        return Response(
            {"error": "negative seconds not supported"},
            status=status.HTTP_400_BAD_REQUEST,
        )
    delta = timedelta(seconds=seconds)
    shifted: dict[str, int] = {}
    with transaction.atomic():
        for model, fields in _CLOCK_SHIFTABLE:
            updates = {f: F(f) - delta for f in fields}
            n = model.objects.update(**updates)
            shifted[model._meta.db_table] = n
    return Response({
        "advanced_seconds": seconds,
        "now": timezone.now().isoformat(),
        "shifted": shifted,
    })


@api_view(["POST"])
@authentication_classes([])
@permission_classes([AllowAny])
def assert_batch(request):
    if (gate := _gated()):
        return gate
    body = request.data
    assertions = body.get("assertions") or []
    results = evaluate_assertions(assertions)
    summary = {
        "total": len(results),
        "passed": sum(1 for r in results if r["pass"]),
        "failed": sum(1 for r in results if not r["pass"]),
    }
    return Response({"summary": summary, "results": results})
