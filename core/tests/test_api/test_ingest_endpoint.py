import json
from pathlib import Path

import pytest

from core.models import Finding, IngestQueue
from core.models.queue import QueueStatus
from core.services.queue import process_batch

FIXTURES = Path(__file__).parent.parent / "fixtures"


def _load_fixture(name: str) -> dict:
    return json.loads((FIXTURES / name).read_text())


def _ingest_and_process(auth_client, payload, cluster="test-cluster"):
    """POST to ingest (queues), then process the queue item."""
    resp = auth_client.post(
        "/api/v1/ingest/",
        data=payload,
        format="json",
        HTTP_X_CLUSTER_NAME=cluster,
    )
    assert resp.status_code == 202
    process_batch(batch_size=10)
    return resp


@pytest.mark.django_db
class TestIngestEndpoint:
    def test_unauthenticated_returns_401(self, api_client):
        resp = api_client.post(
            "/api/v1/ingest/",
            data={"kind": "VulnerabilityReport"},
            format="json",
        )
        assert resp.status_code == 401

    def test_returns_202_queued(self, auth_client):
        payload = _load_fixture("vulnerability_report.json")
        resp = auth_client.post(
            "/api/v1/ingest/",
            data=payload,
            format="json",
            HTTP_X_CLUSTER_NAME="test-cluster",
        )
        assert resp.status_code == 202
        data = resp.json()
        assert data["status"] == "queued"
        assert data["queue_id"] is not None
        assert data["cluster"] == "test-cluster"
        assert data["kind"] == "VulnerabilityReport"

    def test_queued_item_processed(self, auth_client):
        payload = _load_fixture("vulnerability_report.json")
        _ingest_and_process(auth_client, payload)

        assert Finding.objects.count() == 2
        assert IngestQueue.objects.filter(status=QueueStatus.DONE).count() == 1

    def test_missing_cluster_returns_400(self, auth_client):
        payload = {"kind": "VulnerabilityReport", "metadata": {"labels": {}}}
        resp = auth_client.post(
            "/api/v1/ingest/",
            data=payload,
            format="json",
        )
        assert resp.status_code == 400

    def test_invalid_body_returns_400(self, auth_client):
        resp = auth_client.post(
            "/api/v1/ingest/",
            data="not json",
            content_type="text/plain",
            HTTP_X_CLUSTER_NAME="test-cluster",
        )
        assert resp.status_code in (400, 415)

    def test_bad_kind_fails_in_queue(self, auth_client):
        """Bad kind is accepted into queue but fails during processing."""
        payload = {"kind": "UnknownReport"}
        resp = auth_client.post(
            "/api/v1/ingest/",
            data=payload,
            format="json",
            HTTP_X_CLUSTER_NAME="test-cluster",
        )
        assert resp.status_code == 202  # queued OK

        process_batch(batch_size=1)
        item = IngestQueue.objects.first()
        assert item.status == QueueStatus.PENDING  # back to pending for retry
        assert item.attempts == 1

    def test_extracts_cluster_from_labels(self, auth_client):
        payload = _load_fixture("vulnerability_report.json")
        payload["metadata"]["labels"]["cluster"] = "from-labels"
        resp = auth_client.post(
            "/api/v1/ingest/",
            data=payload,
            format="json",
        )
        assert resp.status_code == 202
        assert resp.json()["cluster"] == "from-labels"


@pytest.mark.django_db
class TestFindingEndpoints:
    def test_list_findings(self, auth_client):
        _ingest_and_process(auth_client, _load_fixture("vulnerability_report.json"))

        resp = auth_client.get("/api/v1/findings/")
        assert resp.status_code == 200
        assert resp.json()["count"] == 2

    def test_filter_by_severity(self, auth_client):
        _ingest_and_process(auth_client, _load_fixture("vulnerability_report.json"))

        resp = auth_client.get("/api/v1/findings/?severity=Critical")
        assert resp.json()["count"] == 1

    def test_detail_view(self, auth_client):
        _ingest_and_process(auth_client, _load_fixture("vulnerability_report.json"))

        finding = Finding.objects.first()
        resp = auth_client.get(f"/api/v1/findings/{finding.pk}/")
        assert resp.status_code == 200
        assert resp.json()["vuln_id"] == finding.vuln_id
        assert "details" in resp.json()
