import logging

from rest_framework import generics, status
from rest_framework.authentication import TokenAuthentication
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from core.api.filters import FindingFilter
from core.api.permissions import IsAdmin, IsOperator, IsServiceAccount
from core.api.serializers import FindingSerializer
from core.models import Finding
from core.services.queue import enqueue

logger = logging.getLogger(__name__)


class IngestView(APIView):
    """
    POST /api/v1/ingest/

    Accepts raw CRD JSON (Trivy or Kyverno). Routes by `kind` field to parser.
    Cluster identified via X-Cluster-Name header or CRD metadata.
    Restricted to service accounts (username prefix svc-*).

    Always queues: INSERT into IngestQueue → return 202 Accepted (~2ms).
    Queue processor (manage.py process_ingest_queue) handles parsing/dedup.

    Convention A1: This is the only write path for security data.
    Convention A3: Payload is raw CRD JSON — scanners don't transform.
    """

    authentication_classes = [TokenAuthentication]
    permission_classes = [IsServiceAccount]

    def post(self, request):
        cluster_name = request.headers.get("X-Cluster-Name")
        # Deprecated header (kept for one release while old import scripts roll out)
        k8s_version = request.headers.get("X-Cluster-K8s-Version", "").strip()
        payload = request.data

        if not isinstance(payload, dict):
            return Response(
                {"error": "Request body must be a JSON object"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        # Extract cluster_name from CRD labels if not in header
        if not cluster_name:
            cluster_name = self._extract_cluster_name(payload)

        if not cluster_name:
            return Response(
                {"error": "X-Cluster-Name header required or cluster name must be in CRD metadata"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        # Legacy: keep cluster.k8s_version in sync via this header for old import
        # scripts. New scripts use /cluster-metadata/sync/ instead.
        if k8s_version:
            from core.models import Cluster
            Cluster.objects.filter(name=cluster_name).exclude(
                k8s_version=k8s_version
            ).update(k8s_version=k8s_version)

        item = enqueue(cluster_name=cluster_name, raw_json=payload)

        kind = payload.get("kind", "")
        if not kind and "operatorObject" in payload:
            kind = payload["operatorObject"].get("kind", "")

        return Response(
            {
                "status": "queued",
                "queue_id": item.pk,
                "cluster": cluster_name,
                "kind": kind,
            },
            status=status.HTTP_202_ACCEPTED,
        )

    @staticmethod
    def _extract_cluster_name(payload: dict) -> str | None:
        """Try to extract cluster name from CRD metadata labels."""
        labels = payload.get("metadata", {}).get("labels", {})
        for key in ("trivy-operator.cluster.name", "cluster"):
            if key in labels:
                return labels[key]
        # Envelope format
        if "operatorObject" in payload:
            inner_labels = payload.get("operatorObject", {}).get("metadata", {}).get("labels", {})
            for key in ("trivy-operator.cluster.name", "cluster"):
                if key in inner_labels:
                    return inner_labels[key]
        return None


class ClusterMetadataSyncView(APIView):
    """
    POST /api/v1/cluster-metadata/sync/

    Called by the import script once per run, before findings ingest.
    Seeds cluster-level metadata (k8s_version, provider, region) and
    per-namespace exposure flags from auto-detect.

    Admin manual overrides are respected: fields where *_is_manual=True
    are left alone.

    Convention A1: This is an ingest endpoint — only service accounts.
    """

    authentication_classes = [TokenAuthentication]
    permission_classes = [IsServiceAccount]

    def post(self, request):
        from django.db import transaction
        from django.utils import timezone

        from core.constants import Status
        from core.models import Finding, Namespace
        from core.services.ingest import get_or_create_cluster
        from core.services.priority import recalculate_cluster_priorities

        payload = request.data
        if not isinstance(payload, dict):
            return Response(
                {"error": "Request body must be a JSON object"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        cluster_name = (payload.get("cluster_name") or "").strip()
        if not cluster_name:
            return Response(
                {"error": "cluster_name is required"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        cluster = get_or_create_cluster(cluster_name)

        # --- Cluster-level metadata (respect manual overrides) ----------
        cluster_updated_fields = []
        k8s_version = (payload.get("k8s_version") or "").strip()
        if k8s_version and cluster.k8s_version != k8s_version:
            cluster.k8s_version = k8s_version
            cluster_updated_fields.append("k8s_version")

        provider = (payload.get("provider") or "").strip()
        if provider and not cluster.provider_is_manual and cluster.provider != provider:
            cluster.provider = provider
            cluster_updated_fields.append("provider")

        region = (payload.get("region") or "").strip()
        if region and not cluster.region_is_manual and cluster.region != region:
            cluster.region = region
            cluster_updated_fields.append("region")

        if cluster_updated_fields:
            cluster.save(update_fields=cluster_updated_fields)

        # --- Namespaces --------------------------------------------------
        ns_payload = payload.get("namespaces") or []
        if not isinstance(ns_payload, list):
            return Response(
                {"error": "namespaces must be a list"},
                status=status.HTTP_400_BAD_REQUEST,
            )
        # complete_snapshot=True is the authoritative signal from the import
        # script that this payload lists every namespace observed in the
        # cluster. Only then can we deactivate namespaces missing from it.
        # Partial syncs (e.g. interrupted discovery) must leave active=False
        # behavior alone to avoid ghost-deleting surviving namespaces.
        complete_snapshot = bool(payload.get("complete_snapshot", False))

        created_count = 0
        updated_count = 0
        skipped_manual = 0
        reactivated_count = 0
        exposure_changed = False
        seen_names: set[str] = set()

        for entry in ns_payload:
            if not isinstance(entry, dict):
                continue
            name = (entry.get("name") or "").strip()
            if not name:
                continue
            seen_names.add(name)
            exposed = bool(entry.get("internet_exposed", False))
            labels = entry.get("labels") or {}
            annotations = entry.get("annotations") or {}

            ns, created = Namespace.objects.get_or_create(
                cluster=cluster, name=name,
            )
            fields_to_update = ["last_seen"]

            if created:
                created_count += 1
                ns.internet_exposed = exposed
                fields_to_update.append("internet_exposed")
                exposure_changed = exposure_changed or exposed
            else:
                if not ns.active:
                    ns.active = True
                    ns.deactivated_at = None
                    fields_to_update.extend(["active", "deactivated_at"])
                    reactivated_count += 1
                    exposure_changed = exposure_changed or ns.internet_exposed

                if not ns.exposure_is_manual:
                    if ns.internet_exposed != exposed:
                        ns.internet_exposed = exposed
                        fields_to_update.append("internet_exposed")
                        exposure_changed = True
                    updated_count += 1
                else:
                    skipped_manual += 1

            if labels != ns.labels:
                ns.labels = labels
                fields_to_update.append("labels")
            if annotations != ns.annotations:
                ns.annotations = annotations
                fields_to_update.append("annotations")

            ns.save(update_fields=fields_to_update)

        # --- Deactivation sweep (only on a complete snapshot) ------------
        # Wrapped in a single transaction so that a crash between the two
        # UPDATEs can't leave namespaces inactive with their active findings
        # still flagged active — which would be invisible to the next sync
        # (the sweep only re-selects namespaces currently active=True).
        deactivated_count = 0
        cascaded_findings = 0
        if complete_snapshot:
            missing_ids = list(
                Namespace.objects.filter(cluster=cluster, active=True)
                .exclude(name__in=seen_names)
                .values_list("id", flat=True)
            )
            if missing_ids:
                now = timezone.now()
                with transaction.atomic():
                    deactivated_count = Namespace.objects.filter(
                        id__in=missing_ids
                    ).update(active=False, deactivated_at=now)
                    cascaded_findings = Finding.objects.filter(
                        cluster=cluster,
                        namespace_id__in=missing_ids,
                        status__in=[Status.ACTIVE, Status.ACKNOWLEDGED],
                    ).update(status=Status.RESOLVED, resolved_at=now)
                exposure_changed = True
                logger.info(
                    "Deactivated %d namespaces (cascaded %d findings to resolved) for cluster %s",
                    deactivated_count,
                    cascaded_findings,
                    cluster.name,
                )

        if exposure_changed or "provider" in cluster_updated_fields:
            recalculate_cluster_priorities(cluster)

        return Response(
            {
                "cluster": {
                    "name": cluster.name,
                    "updated_fields": cluster_updated_fields,
                },
                "namespaces": {
                    "created": created_count,
                    "updated": updated_count,
                    "reactivated": reactivated_count,
                    "skipped_manual": skipped_manual,
                    "deactivated": deactivated_count,
                    "cascaded_findings_resolved": cascaded_findings,
                    "complete_snapshot": complete_snapshot,
                    "total": len(ns_payload),
                },
            },
            status=status.HTTP_200_OK,
        )


class FindingListView(generics.ListAPIView):
    """GET /api/v1/findings/ — filtered, paginated finding list."""

    permission_classes = [IsAuthenticated]
    serializer_class = FindingSerializer
    filterset_class = FindingFilter
    queryset = Finding.objects.select_related("cluster").all()


class FindingDetailView(generics.RetrieveAPIView):
    """GET /api/v1/findings/{id}/ — single finding detail."""

    permission_classes = [IsAuthenticated]
    serializer_class = FindingSerializer
    queryset = Finding.objects.select_related("cluster").all()


# ── Lifecycle action endpoints (Convention A2) ─────────────────


class _FindingActionView(APIView):
    """Base for explicit finding action endpoints."""

    def get_finding_or_404(self, pk):
        from django.shortcuts import get_object_or_404

        return get_object_or_404(Finding, pk=pk)


class AcknowledgeView(_FindingActionView):
    """POST /api/v1/findings/{id}/acknowledge/ — operator+"""

    permission_classes = [IsAuthenticated, IsOperator]

    def post(self, request, pk):
        from core.services.lifecycle import LifecycleError, acknowledge

        try:
            finding = acknowledge(pk, request.user)
        except Finding.DoesNotExist:
            return Response({"error": "Finding not found"}, status=status.HTTP_404_NOT_FOUND)
        except LifecycleError as e:
            return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)

        return Response({"status": finding.status, "id": finding.pk})


class AcceptRiskView(_FindingActionView):
    """POST /api/v1/findings/{id}/accept-risk/ — admin-only, requires reason + until"""

    permission_classes = [IsAuthenticated, IsAdmin]

    def post(self, request, pk):
        import datetime

        from core.services.lifecycle import LifecycleError, accept_risk

        reason = request.data.get("reason", "")
        until = request.data.get("until")
        if not reason:
            return Response(
                {"error": "reason is required"}, status=status.HTTP_400_BAD_REQUEST
            )
        if not until:
            return Response(
                {"error": "until (expiry date) is required"}, status=status.HTTP_400_BAD_REQUEST
            )
        try:
            until_date = datetime.date.fromisoformat(str(until))
        except ValueError:
            return Response(
                {"error": "until must be a valid date (YYYY-MM-DD)"},
                status=status.HTTP_400_BAD_REQUEST,
            )
        if until_date <= datetime.date.today():
            return Response(
                {"error": "until must be in the future"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        try:
            finding = accept_risk(pk, request.user, reason, until_date)
        except Finding.DoesNotExist:
            return Response({"error": "Finding not found"}, status=status.HTTP_404_NOT_FOUND)
        except LifecycleError as e:
            return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)

        return Response({
            "status": finding.status,
            "id": finding.pk,
            "accepted_until": str(finding.accepted_until),
        })


class FalsePositiveView(_FindingActionView):
    """POST /api/v1/findings/{id}/false-positive/ — admin-only, requires reason"""

    permission_classes = [IsAuthenticated, IsAdmin]

    def post(self, request, pk):
        from core.services.lifecycle import LifecycleError, false_positive

        reason = request.data.get("reason", "")
        if not reason:
            return Response(
                {"error": "reason is required"}, status=status.HTTP_400_BAD_REQUEST
            )

        try:
            finding = false_positive(pk, request.user, reason, )
        except Finding.DoesNotExist:
            return Response({"error": "Finding not found"}, status=status.HTTP_404_NOT_FOUND)
        except LifecycleError as e:
            return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)

        return Response({"status": finding.status, "id": finding.pk})


class ReactivateView(_FindingActionView):
    """POST /api/v1/findings/{id}/reactivate/ — admin-only"""

    permission_classes = [IsAuthenticated, IsAdmin]

    def post(self, request, pk):
        from core.services.lifecycle import LifecycleError, reactivate

        try:
            finding = reactivate(pk, request.user)
        except Finding.DoesNotExist:
            return Response({"error": "Finding not found"}, status=status.HTTP_404_NOT_FOUND)
        except LifecycleError as e:
            return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)

        return Response({"status": finding.status, "id": finding.pk})
