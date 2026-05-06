"""KubePostureNG ingest endpoints.

  POST /api/v1/imports/start/
        body: {cluster, kind, import_id}
        action: upsert ImportMark (state=open, started_at=now())

  POST /api/v1/imports/finish/
        body: {cluster, kind, import_id, observed_count}
        action: ImportMark.state=draining, completed_at=now(),
                observed_count=N. Worker may now claim items.

  POST /api/v1/ingest/
        body: {cluster, kind, import_id, payload, complete_snapshot?}
        action: enqueue raw payload in IngestQueue.

  POST /api/v1/cluster-metadata/sync/
        body: {cluster, k8s_version?, provider?, region?}
        action: thin cluster-row metadata upsert. Most live data flows
                via the inventory-kind ingest path now.

  GET  /api/v1/imports/pending/?cluster=<name>
        action: return {pending, requested_at, in_flight} so a workload-
                cluster trigger CronJob can poll cheaply and only run a
                full import when an admin has clicked "Re-import".

  POST /api/v1/imports/pending/clear/
        body: {cluster, satisfied_at}
        action: clear `reimport_requested_at` IFF stored value is older
                than (or equal to) satisfied_at. Mid-import re-clicks
                survive — a newer request stays pending.

All endpoints require IngestBearerAuthentication. Tokens are not
cluster-bound — the cluster comes from the payload's `cluster`
field and is auto-registered on first observation.
"""
from __future__ import annotations

import os
from datetime import timedelta

from django.utils import timezone
from django.utils.dateparse import parse_datetime
from rest_framework import status
from rest_framework.decorators import (
    api_view,
    authentication_classes,
    permission_classes,
)
from rest_framework.response import Response

from core.api.auth import (
    IngestBearerAuthentication,
    IsIngestAuthenticated,
    require_cluster,
)
from core.constants import ImportMarkState
from core.models import Cluster, ImportMark
from core.services.queue import enqueue

# TTL for the in-flight-import "lock". An open/draining ImportMark older
# than this is treated as abandoned (crashed importer), not actively
# running, so the next on-demand trigger tick can start a fresh import.
# Configurable via the IMPORT_LOCK_TIMEOUT_SECONDS env var (chart value
# app.env). Default 1800s = 30min, matching the workload-cluster job's
# activeDeadlineSeconds (900s) with 2x headroom for slow networks.
IMPORT_LOCK_TIMEOUT = timedelta(
    seconds=int(os.environ.get("IMPORT_LOCK_TIMEOUT_SECONDS", "1800"))
)


@api_view(["POST"])
@authentication_classes([IngestBearerAuthentication])
@permission_classes([IsIngestAuthenticated])
def imports_start(request):
    body = request.data
    cluster = require_cluster(request, body.get("cluster") or "")
    kind = (body.get("kind") or "").strip()
    import_id = (body.get("import_id") or "").strip()
    if not kind or not import_id:
        return Response(
            {"error": "kind and import_id are required"},
            status=status.HTTP_400_BAD_REQUEST,
        )
    mark, created = ImportMark.open(cluster=cluster, kind=kind, import_id=import_id)
    return Response(
        {
            "cluster": cluster.name,
            "kind": kind,
            "import_id": import_id,
            "started_at": mark.started_at.isoformat(),
            "state": mark.state,
            "created": created,
        },
        status=status.HTTP_201_CREATED if created else status.HTTP_200_OK,
    )


@api_view(["POST"])
@authentication_classes([IngestBearerAuthentication])
@permission_classes([IsIngestAuthenticated])
def imports_finish(request):
    body = request.data
    cluster = require_cluster(request, body.get("cluster") or "")
    kind = (body.get("kind") or "").strip()
    import_id = (body.get("import_id") or "").strip()
    observed_count = body.get("observed_count")
    if not kind or not import_id or observed_count is None:
        return Response(
            {"error": "kind, import_id, observed_count are required"},
            status=status.HTTP_400_BAD_REQUEST,
        )
    mark = ImportMark.objects.filter(
        cluster=cluster, kind=kind, import_id=import_id
    ).first()
    if mark is None:
        return Response(
            {"error": "no matching ImportMark — call /imports/start/ first"},
            status=status.HTTP_404_NOT_FOUND,
        )
    mark.state = ImportMarkState.DRAINING.value
    mark.completed_at = timezone.now()
    mark.observed_count = int(observed_count)
    mark.save(update_fields=["state", "completed_at", "observed_count"])
    return Response(
        {
            "cluster": cluster.name,
            "kind": kind,
            "import_id": import_id,
            "observed_count": mark.observed_count,
            "state": mark.state,
        }
    )


@api_view(["POST"])
@authentication_classes([IngestBearerAuthentication])
@permission_classes([IsIngestAuthenticated])
def ingest(request):
    body = request.data
    cluster = require_cluster(request, body.get("cluster") or "")
    kind = (body.get("kind") or "").strip()
    import_id = (body.get("import_id") or "").strip()
    if not kind or not import_id:
        return Response(
            {"error": "kind and import_id are required"},
            status=status.HTTP_400_BAD_REQUEST,
        )
    payload = body.get("payload")
    if payload is None:
        return Response(
            {"error": "payload is required"},
            status=status.HTTP_400_BAD_REQUEST,
        )
    complete_snapshot = bool(body.get("complete_snapshot") or payload.get("complete_snapshot") if isinstance(payload, dict) else False)
    item = enqueue(
        cluster_name=cluster.name,
        kind=kind,
        import_id=import_id,
        raw_json=payload,
        complete_snapshot=complete_snapshot,
    )
    return Response(
        {
            "queue_id": item.id,
            "cluster": cluster.name,
            "kind": kind,
            "import_id": import_id,
            "complete_snapshot": complete_snapshot,
        },
        status=status.HTTP_202_ACCEPTED,
    )


def _is_in_flight(cluster: Cluster) -> bool:
    """True if any open/draining ImportMark for the cluster started within
    IMPORT_LOCK_TIMEOUT. Marks past the timeout don't gate a fresh
    import — they're treated as abandoned (crashed importer).
    """
    cutoff = timezone.now() - IMPORT_LOCK_TIMEOUT
    return ImportMark.objects.filter(
        cluster=cluster,
        state__in=[ImportMarkState.OPEN.value, ImportMarkState.DRAINING.value],
        started_at__gt=cutoff,
    ).exists()


@api_view(["GET"])
@authentication_classes([IngestBearerAuthentication])
@permission_classes([IsIngestAuthenticated])
def imports_pending(request):
    """Cheap poll endpoint for the trigger CronJob.

    Returns whether a reimport has been requested and whether one is
    already running, so the trigger can decide whether to spawn the
    heavy import inline.
    """
    name = (request.query_params.get("cluster") or "").strip()
    if not name:
        return Response(
            {"error": "query param 'cluster' is required"},
            status=status.HTTP_400_BAD_REQUEST,
        )
    cluster = Cluster.objects.filter(name=name).first()
    if cluster is None:
        # Idempotent: unknown cluster has no pending request.
        return Response({
            "cluster": name,
            "pending": False,
            "requested_at": None,
            "in_flight": False,
        })
    return Response({
        "cluster": cluster.name,
        "pending": cluster.reimport_requested_at is not None,
        "requested_at": (
            cluster.reimport_requested_at.isoformat()
            if cluster.reimport_requested_at else None
        ),
        "in_flight": _is_in_flight(cluster),
    })


@api_view(["POST"])
@authentication_classes([IngestBearerAuthentication])
@permission_classes([IsIngestAuthenticated])
def imports_pending_clear(request):
    """Conditional clear of `reimport_requested_at`.

    Clears IFF the stored timestamp is <= satisfied_at. A newer request
    that arrived during the import survives so the next trigger picks
    it up.
    """
    body = request.data
    cluster = require_cluster(request, body.get("cluster") or "")
    raw = body.get("satisfied_at")
    if not raw:
        return Response(
            {"error": "satisfied_at is required (ISO-8601)"},
            status=status.HTTP_400_BAD_REQUEST,
        )
    satisfied_at = parse_datetime(raw) if isinstance(raw, str) else None
    if satisfied_at is None:
        return Response(
            {"error": "satisfied_at must be an ISO-8601 datetime string"},
            status=status.HTTP_400_BAD_REQUEST,
        )
    cleared = False
    current = cluster.reimport_requested_at
    if current is not None and current <= satisfied_at:
        Cluster.objects.filter(pk=cluster.pk).update(
            reimport_requested_at=None,
            reimport_requested_by=None,
        )
        cleared = True
    return Response({
        "cluster": cluster.name,
        "cleared": cleared,
        "still_pending_at": (
            current.isoformat()
            if current is not None and not cleared else None
        ),
    })


@api_view(["POST"])
@authentication_classes([IngestBearerAuthentication])
@permission_classes([IsIngestAuthenticated])
def cluster_metadata_sync(request):
    """Thin upsert: fields not auto-replaced by the inventory parser."""
    body = request.data
    cluster = require_cluster(request, body.get("cluster") or body.get("cluster_name") or "")
    changed: list[str] = []
    if (v := body.get("k8s_version")) and cluster.k8s_version != v:
        cluster.k8s_version = v
        changed.append("k8s_version")
    if (p := body.get("provider")) and not cluster.provider_is_manual:
        if cluster.provider != p:
            cluster.provider = p
            changed.append("provider")
    if (r := body.get("region")) is not None and not cluster.region_is_manual:
        if cluster.region != r:
            cluster.region = r
            changed.append("region")
    cluster.last_seen_at = timezone.now()
    changed.append("last_seen_at")
    cluster.save(update_fields=changed)
    return Response({
        "cluster": cluster.name,
        "k8s_version": cluster.k8s_version,
        "provider": cluster.provider,
        "region": cluster.region,
        "changed": changed,
    })
