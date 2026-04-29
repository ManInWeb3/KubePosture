"""/api/v1/testing/* harness endpoints — gated by TESTING_HARNESS_ENABLED.

Per dev_docs/12-testing.md *Test-harness HTTP API*. The mock_tests
pytest plugin uses these to drive scenarios end-to-end against a
throwable DB.

Endpoints:

  POST /api/v1/testing/reset/
        TRUNCATE every app table (preserves auth_user / Django internals).
  POST /api/v1/testing/load_scenario/
        body: {cluster, scenario_dir} OR {cluster, payloads: [...], finishes: [...]}
        Synchronous: registers the cluster + token, posts each
        ingest payload to /ingest/ effectively, drains the queue
        inline, fires reaps.
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

import json
import os
from datetime import timedelta
from pathlib import Path

from django.conf import settings
from django.db import connection, transaction
from django.db.models import F
from rest_framework import status
from rest_framework.decorators import (
    api_view,
    authentication_classes,
    permission_classes,
)
from rest_framework.permissions import AllowAny
from rest_framework.response import Response

from core.constants import ImportMarkState
from core.models import (
    Cluster,
    IngestToken,
    Finding,
    FindingAction,
    Image,
    ImportMark,
    IngestQueue,
    Namespace,
    ScanInconsistency,
    Snapshot,
    Workload,
    WorkloadAlias,
    WorkloadImageObservation,
    WorkloadSignal,
    EpssScore,
    KevEntry,
)
from core.services.test_assertions import evaluate_assertions
from core.services.queue import enqueue
from core.services import worker as worker_service
from django.utils import timezone


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


def _post_envelope_directly(envelope: dict) -> int:
    """Bypass HTTP — enqueue an ingest payload as if the API were called."""
    payload = envelope.get("payload") or {}
    complete_snapshot = envelope.get("complete_snapshot")
    if complete_snapshot is None and isinstance(payload, dict):
        complete_snapshot = bool(payload.get("complete_snapshot"))
    item = enqueue(
        cluster_name=envelope["cluster"],
        kind=envelope["kind"],
        import_id=envelope["import_id"],
        raw_json=payload,
        complete_snapshot=bool(complete_snapshot),
    )
    return item.id


def _ensure_cluster(name: str) -> Cluster:
    cluster, _ = Cluster.objects.get_or_create(name=name)
    return cluster


@api_view(["POST"])
@authentication_classes([])
@permission_classes([AllowAny])
def load_scenario(request):
    """Replay one scenario synchronously.

    Two body shapes:

    1. Inline payloads (preferred for the runner):
       {
         "cluster": "...",
         "import_id": "...",
         "starts": [{"kind": "..."}, ...],          # /imports/start/ calls
         "payloads": [
            {"kind": "...", "payload": {...}, "complete_snapshot": true},
            ...
         ],
         "finishes": [{"kind": "...", "observed_count": N}, ...]
       }

    2. Disk-rooted: {"scenario_dir": "/abs/path/to/01-happy-path"}
       — reads imports/*.json + 007_finish.yaml etc.
    """
    if (gate := _gated()):
        return gate

    body = request.data
    if scenario_dir := body.get("scenario_dir"):
        return _load_from_disk(scenario_dir, body)
    return _load_inline(body)


def _load_inline(body: dict) -> Response:
    cluster_name = body["cluster"]
    import_id = body.get("import_id") or ""
    cluster = _ensure_cluster(cluster_name)

    starts = body.get("starts") or []
    payloads = body.get("payloads") or []
    finishes = body.get("finishes") or []

    # /imports/start/
    for s in starts:
        ImportMark.open(
            cluster=cluster,
            kind=s["kind"],
            import_id=s.get("import_id", import_id),
        )

    # /ingest/
    for env in payloads:
        env.setdefault("cluster", cluster_name)
        env.setdefault("import_id", import_id)
        _post_envelope_directly(env)

    # /imports/finish/
    for f in finishes:
        ImportMark.objects.filter(
            cluster=cluster,
            kind=f["kind"],
            import_id=f.get("import_id", import_id),
        ).update(
            state=ImportMarkState.DRAINING.value,
            completed_at=timezone.now(),
            observed_count=f["observed_count"],
        )

    # Drain queue + fire reaps.
    totals = worker_service.drain_until_empty()
    return Response({
        "cluster": cluster_name,
        "import_id": import_id,
        "starts": len(starts),
        "payloads": len(payloads),
        "finishes": len(finishes),
        **totals,
    })


def _load_from_disk(scenario_dir: str, body: dict) -> Response:
    base = Path(scenario_dir).resolve()
    imports_dir = base / "imports"
    if not imports_dir.is_dir():
        return Response(
            {"error": f"no imports/ directory at {base}"},
            status=status.HTTP_400_BAD_REQUEST,
        )

    cluster_name = body.get("cluster") or ""
    import_id_default = body.get("import_id") or ""

    files = sorted(p for p in imports_dir.iterdir() if p.is_file())

    # Pass 1 — discover all (import_id, kind) tuples we'll touch and
    # build the post-plan. We split *List wrappers up-front because
    # each item posts as its own /ingest/ payload with its own kind.
    finishes_collected: list[dict] = []
    post_plan: list[dict] = []  # list of envelopes to post, in order
    for p in files:
        name_lower = p.name.lower()
        if "finish" in name_lower:
            finishes_collected.extend(_parse_finishes(p, import_id_default))
            continue
        if p.suffix.lower() != ".json":
            continue
        doc = json.loads(p.read_text())

        if _looks_like_inventory_envelope(doc):
            post_plan.append({
                "cluster": cluster_name,
                "kind": "inventory",
                "import_id": import_id_default,
                "payload": doc,
                "complete_snapshot": bool(doc.get("complete_snapshot")),
            })
            continue

        if _looks_like_list_wrapper(doc):
            for item in doc.get("items") or []:
                ikind = _envelope_kind_for_item_kind(item.get("kind"))
                if not ikind:
                    continue
                post_plan.append({
                    "cluster": cluster_name,
                    "kind": ikind,
                    "import_id": import_id_default,
                    "payload": item,
                    "complete_snapshot": False,
                })
            continue

        # Single-item file — try to derive its kind directly.
        ikind = _envelope_kind_for_item_kind(doc.get("kind")) if isinstance(doc, dict) else None
        if ikind:
            post_plan.append({
                "cluster": cluster_name,
                "kind": ikind,
                "import_id": import_id_default,
                "payload": doc,
                "complete_snapshot": False,
            })

    # Pass 2 — /imports/start/ for every (import_id, kind) we'll post
    # AND every kind referenced in finishes (a finish file may declare
    # a kind we didn't post — observed_count=0 is valid).
    cluster = _ensure_cluster(cluster_name)
    kinds_to_open: dict[str, set[str]] = {}
    for env in post_plan:
        kinds_to_open.setdefault(env["import_id"], set()).add(env["kind"])
    for f in finishes_collected:
        kinds_to_open.setdefault(f.get("import_id", import_id_default), set()).add(f["kind"])
    for iid, kinds in kinds_to_open.items():
        for k in kinds:
            ImportMark.open(cluster=cluster, kind=k, import_id=iid)

    posted: list[str] = []
    for env in post_plan:
        _post_envelope_directly(env)
        posted.append(env["kind"])

    # Apply collected finishes.
    for f in finishes_collected:
        ImportMark.objects.filter(
            cluster=cluster,
            kind=f["kind"],
            import_id=f.get("import_id", import_id_default),
        ).update(
            state=ImportMarkState.DRAINING.value,
            completed_at=timezone.now(),
            observed_count=f["observed_count"],
        )

    totals = worker_service.drain_until_empty()
    return Response({
        "cluster": cluster_name,
        "scenario_dir": str(base),
        "posted": posted,
        "finishes": len(finishes_collected),
        **totals,
    })


def _looks_like_inventory_envelope(doc: dict) -> bool:
    if not isinstance(doc, dict):
        return False
    if "cluster_meta" in doc and "items" in doc:
        return True
    return False


def _looks_like_list_wrapper(doc: dict) -> bool:
    if not isinstance(doc, dict):
        return False
    if "kind" not in doc:
        return False
    if not str(doc.get("kind", "")).endswith("List"):
        return False
    return isinstance(doc.get("items"), list)


_ITEM_KIND_TO_ENVELOPE = {
    "VulnerabilityReport": "trivy.VulnerabilityReport",
    "ConfigAuditReport": "trivy.ConfigAuditReport",
    "ExposedSecretReport": "trivy.ExposedSecretReport",
    "RbacAssessmentReport": "trivy.RbacAssessmentReport",
    "ClusterRbacAssessmentReport": "trivy.ClusterRbacAssessmentReport",
    "InfraAssessmentReport": "trivy.InfraAssessmentReport",
    "ClusterInfraAssessmentReport": "trivy.InfraAssessmentReport",
    "ClusterComplianceReport": "trivy.ClusterComplianceReport",
    "PolicyReport": "kyverno.PolicyReport",
    "ClusterPolicyReport": "kyverno.ClusterPolicyReport",
}


def _envelope_kind_for_item_kind(item_kind: str | None) -> str | None:
    if not item_kind:
        return None
    return _ITEM_KIND_TO_ENVELOPE.get(item_kind)


_FILENAME_TO_KIND = [
    ("inventory", "inventory"),
    ("trivy_vuln", "trivy.VulnerabilityReport"),
    ("trivy_configaudit", "trivy.ConfigAuditReport"),
    ("trivy_exposedsecret", "trivy.ExposedSecretReport"),
    ("trivy_rbac", "trivy.RbacAssessmentReport"),
    ("trivy_clusterrbac", "trivy.ClusterRbacAssessmentReport"),
    ("trivy_infra", "trivy.InfraAssessmentReport"),
    ("trivy_compliance", "trivy.ClusterComplianceReport"),
    ("kyverno_clusterpolicy", "kyverno.ClusterPolicyReport"),
    ("kyverno_policy", "kyverno.PolicyReport"),
]


def _kind_for_filename(name: str) -> str | None:
    lower = name.lower()
    for token, kind in _FILENAME_TO_KIND:
        if token in lower:
            return kind
    return None


def _parse_finishes(path: Path, default_import_id: str = "") -> list[dict]:
    text = path.read_text()
    # Try JSON first, fall back to a tiny YAML reader for the simple shape:
    #   cluster: name
    #   import_id: id
    #   finishes:
    #     - kind: ...
    #       observed_count: N
    try:
        doc = json.loads(text)
    except json.JSONDecodeError:
        doc = _parse_simple_yaml(text)
    finishes = doc.get("finishes") or []
    iid = doc.get("import_id") or default_import_id
    out = []
    for f in finishes:
        out.append({
            "kind": f["kind"],
            "observed_count": int(f.get("observed_count") or 0),
            "import_id": iid,
        })
    return out


def _parse_simple_yaml(text: str) -> dict:
    """Minimal YAML reader for the shape used by `*_finish.yaml`. NOT a
    general parser — just enough for the harness fixtures.
    """
    out: dict = {}
    current_list_key: str | None = None
    current_list: list[dict] | None = None
    current_dict: dict | None = None
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].rstrip()
        if not line.strip():
            continue
        stripped = line.lstrip(" ")
        indent = len(line) - len(stripped)

        if indent == 0 and stripped.endswith(":"):
            current_list_key = stripped[:-1].strip()
            current_list = []
            out[current_list_key] = current_list
            current_dict = None
            continue
        if indent == 0 and ":" in stripped:
            k, _, v = stripped.partition(":")
            out[k.strip()] = v.strip()
            current_list_key = None
            current_list = None
            current_dict = None
            continue
        if indent >= 2 and stripped.startswith("- "):
            current_dict = {}
            assert current_list is not None
            current_list.append(current_dict)
            tail = stripped[2:]
            if ":" in tail:
                k, _, v = tail.partition(":")
                current_dict[k.strip()] = v.strip()
            continue
        if current_dict is not None and ":" in stripped:
            k, _, v = stripped.partition(":")
            current_dict[k.strip()] = v.strip()
    return out


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
    (IngestQueue, ["created_at", "processed_at"]),
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
