"""Import-pipeline gauges: queue oldest-age and scan-coverage ratio."""
from __future__ import annotations

from datetime import timedelta

import pytest
from django.utils import timezone

from core.constants import ImportDiscardReason, ImportMarkState, IngestQueueStatus
from core.metrics import registry as metrics_registry
from core.models import Cluster, ImportMark, IngestQueue


@pytest.fixture(autouse=True)
def _reset_metrics_cache():
    metrics_registry.reset()
    yield
    metrics_registry.reset()


def _mark(cluster, kind, import_id, *, started_at, state=ImportMarkState.REAPED.value,
          expected=None, matched=None, discard_reason=""):
    return ImportMark.objects.create(
        cluster=cluster, kind=kind, import_id=import_id, state=state, started_at=started_at,
        coverage_expected=expected, coverage_matched=matched, discard_reason=discard_reason,
    )


@pytest.mark.django_db
def test_ingest_queue_oldest_age_gauge_per_status(client):
    old = IngestQueue.objects.create(cluster_name="c", kind="k", import_id="i", raw_json={},
                                     status=IngestQueueStatus.PENDING.value)
    IngestQueue.objects.create(cluster_name="c", kind="k", import_id="i", raw_json={},
                               status=IngestQueueStatus.PENDING.value)
    IngestQueue.objects.filter(pk=old.pk).update(created_at=timezone.now() - timedelta(seconds=600))

    body = client.get("/metrics").content.decode()
    line = next(ln for ln in body.splitlines()
                if ln.startswith('kubeposture_ingest_queue_oldest_age_seconds{status="pending"}'))
    assert float(line.split()[-1]) >= 600


@pytest.mark.django_db
def test_import_scan_coverage_ratio_uses_latest_committed_mark_per_cluster_kind(client):
    c = Cluster.objects.create(name="prod-east")
    now = timezone.now()
    kind = "trivy.VulnerabilityReport"
    _mark(c, kind, "imp-old", started_at=now - timedelta(hours=2), expected=10, matched=2)
    _mark(c, kind, "imp-new", started_at=now - timedelta(hours=1), expected=10, matched=9)
    # Newer but discarded → ignored.
    _mark(c, kind, "imp-disc", started_at=now, expected=10, matched=0,
          discard_reason=ImportDiscardReason.STUCK_OPEN.value)
    # Still open → not committed → ignored.
    _mark(c, kind, "imp-open", started_at=now, state=ImportMarkState.OPEN.value, expected=10, matched=0)
    # Zero denominator → no gauge.
    _mark(c, "trivy.SbomReport", "imp-new", started_at=now, expected=0, matched=0)
    _mark(c, "inventory", "imp-new", started_at=now)

    body = client.get("/metrics").content.decode()
    lines = [ln for ln in body.splitlines() if ln.startswith("kubeposture_import_scan_coverage_ratio{")]
    assert len(lines) == 1
    assert 'cluster="prod-east"' in lines[0] and f'kind="{kind}"' in lines[0]
    assert float(lines[0].split()[-1]) == pytest.approx(0.9)


def _gauge(body, name, status):
    line = next(ln for ln in body.splitlines() if ln.startswith(f'{name}{{status="{status}"}}'))
    return float(line.split()[-1])


@pytest.mark.django_db
def test_ingest_queue_gauges_report_every_status_as_zero_when_empty(client):
    """An empty status must be 0, not an absent series (gaps in Grafana)."""
    IngestQueue.objects.create(cluster_name="c", kind="k", import_id="i", raw_json={},
                               status=IngestQueueStatus.PROCESSING.value)

    body = client.get("/metrics").content.decode()

    for status in IngestQueueStatus.values:
        expected_depth = 1 if status == IngestQueueStatus.PROCESSING.value else 0
        assert _gauge(body, "kubeposture_ingest_queue_depth", status) == expected_depth
    assert _gauge(body, "kubeposture_ingest_queue_oldest_age_seconds", "pending") == 0


@pytest.mark.django_db
def test_ingest_queue_depth_uses_short_ttl_not_business_ttl(client, monkeypatch):
    """Queue gauges refresh on the queue TTL even while business gauges stay cached."""
    monkeypatch.setenv("METRICS_QUEUE_TTL_SECONDS", "0")
    client.get("/metrics")
    IngestQueue.objects.create(cluster_name="c", kind="k", import_id="i", raw_json={},
                               status=IngestQueueStatus.PENDING.value)

    body = client.get("/metrics").content.decode()

    assert _gauge(body, "kubeposture_ingest_queue_depth", "pending") == 1
