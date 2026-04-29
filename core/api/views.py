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

All endpoints require IngestBearerAuthentication. Tokens are not
cluster-bound — the cluster comes from the payload's `cluster`
field and is auto-registered on first observation.
"""
from __future__ import annotations

from django.utils import timezone
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
