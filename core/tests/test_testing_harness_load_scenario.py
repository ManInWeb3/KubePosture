"""The /api/v1/testing/load_scenario/ harness must go through the same
bundle store + commit path as a real upload."""
from __future__ import annotations

import json

import pytest
from django.test import override_settings

from core.constants import ImportMarkState
from core.models import Cluster, ImportMark, IngestQueue, Workload

pytestmark = pytest.mark.usefixtures("_harness_routes")


@pytest.fixture
def _harness_routes():
    with override_settings(TESTING_HARNESS_ENABLED=True, ROOT_URLCONF="core.tests.harness_urls"):
        yield

INV_ENVELOPE = {
    "cluster_meta": {"name": "c-harness"},
    "items": [
        {"apiVersion": "v1", "kind": "Namespace", "metadata": {"name": "ns"}},
        {
            "apiVersion": "apps/v1", "kind": "Deployment",
            "metadata": {"name": "api", "namespace": "ns"},
            "spec": {
                "replicas": 1, "selector": {"matchLabels": {"app": "api"}},
                "template": {"metadata": {"labels": {"app": "api"}},
                             "spec": {"containers": [{"name": "app", "image": "r/app:1"}]}},
            },
        },
    ],
}


def _load(client, body: dict):
    return client.post(
        "/api/v1/testing/load_scenario/", data=json.dumps(body), content_type="application/json",
    )


@pytest.mark.django_db(transaction=True)
def test_inline_scenario_stores_bundles_commits_and_drains(client):
    resp = _load(client, {
        "cluster": "c-harness", "import_id": "imp-1",
        "starts": [{"kind": "inventory"}],  # legacy, ignored
        "payloads": [{"kind": "inventory", "payload": INV_ENVELOPE}],
        "finishes": [{"kind": "inventory", "observed_count": 1}],
    })
    assert resp.status_code == 200, resp.content
    body = resp.json()
    assert body["bundles"] == 1 and body["ok"] == 1 and body["reaps_fired"] == 1

    mark = ImportMark.objects.get(import_id="imp-1", kind="inventory")
    assert mark.state == ImportMarkState.REAPED.value
    assert mark.observed_count == 1
    assert Cluster.objects.get(name="c-harness").last_complete_inventory_at == mark.started_at
    assert Workload.objects.get(name="api").deployed is True
    assert IngestQueue.objects.count() == 0, "reap deletes the rows"


@pytest.mark.django_db(transaction=True)
def test_finish_with_zero_count_and_no_payloads_creates_empty_mark(client):
    resp = _load(client, {
        "cluster": "c-harness", "import_id": "imp-1",
        "payloads": [{"kind": "inventory", "payload": INV_ENVELOPE}],
        "finishes": [
            {"kind": "inventory", "observed_count": 1},
            {"kind": "trivy.VulnerabilityReport", "observed_count": 0},
        ],
    })
    assert resp.status_code == 200, resp.content
    vuln = ImportMark.objects.get(import_id="imp-1", kind="trivy.VulnerabilityReport")
    assert vuln.state == ImportMarkState.REAPED.value
    assert vuln.observed_count == 0


@pytest.mark.django_db(transaction=True)
def test_count_mismatch_in_finish_is_rejected(client):
    resp = _load(client, {
        "cluster": "c-harness", "import_id": "imp-1",
        "payloads": [{"kind": "inventory", "payload": INV_ENVELOPE}],
        "finishes": [{"kind": "inventory", "observed_count": 3}],
    })
    assert resp.status_code == 409
    assert resp.json()["error"] == "count_mismatch"
    assert ImportMark.objects.get(import_id="imp-1").state == ImportMarkState.OPEN.value
