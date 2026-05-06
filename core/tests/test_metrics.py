"""Tests for /metrics endpoint, business collector, and TTL cache."""
from __future__ import annotations

import pytest

from core.metrics import registry as metrics_registry
from core.models import Cluster, Finding, Namespace, Workload


@pytest.fixture(autouse=True)
def _reset_metrics_cache():
    """Drop any TTL-cached values between tests so DB state is reflected."""
    metrics_registry.reset()
    yield
    metrics_registry.reset()


@pytest.fixture
def cluster_prod(db):
    return Cluster.objects.create(name="prod-east", environment="prod")


@pytest.fixture
def cluster_dev(db):
    return Cluster.objects.create(name="dev-eu", environment="dev")


@pytest.fixture
def ns_payments(db, cluster_prod):
    return Namespace.objects.create(
        cluster=cluster_prod, name="payments", internet_exposed=True, active=True,
    )


@pytest.fixture
def workload_api(db, cluster_prod, ns_payments):
    return Workload.objects.create(
        cluster=cluster_prod, namespace=ns_payments, kind="Deployment",
        name="api", deployed=True, publicly_exposed=True,
    )


@pytest.fixture
def finding_immediate(db, cluster_prod, workload_api):
    return Finding.objects.create(
        cluster=cluster_prod, workload=workload_api,
        source="trivy", category="vulnerability", vuln_id="CVE-2024-1",
        title="t1", severity="critical", effective_priority="immediate",
        hash_code="hash-imm",
    )


@pytest.fixture
def finding_scheduled(db, cluster_prod, workload_api):
    return Finding.objects.create(
        cluster=cluster_prod, workload=workload_api,
        source="trivy", category="vulnerability", vuln_id="CVE-2024-2",
        title="t2", severity="medium", effective_priority="scheduled",
        hash_code="hash-sched",
    )


# ── Endpoint contract ──────────────────────────────────────────────


def test_metrics_endpoint_returns_200(client, db):
    response = client.get("/metrics")
    assert response.status_code == 200
    assert response["Content-Type"].startswith("text/plain")


def test_metrics_endpoint_unauthenticated(client, db):
    """Match /healthz pattern — no login required."""
    response = client.get("/metrics")
    assert response.status_code == 200


def test_metrics_emits_python_runtime(client, db):
    body = client.get("/metrics").content.decode()
    assert "python_info" in body
    assert "process_resident_memory_bytes" in body or "process_virtual_memory_bytes" in body


def test_metrics_emits_clusters_gauge(client, cluster_prod, cluster_dev):
    body = client.get("/metrics").content.decode()
    assert "kubeposture_clusters_total" in body
    assert 'environment="prod"' in body
    assert 'environment="dev"' in body


# ── Business collector ────────────────────────────────────────────


def test_findings_open_grouped_by_priority(
    client, cluster_prod, finding_immediate, finding_scheduled,
):
    body = client.get("/metrics").content.decode()
    assert "kubeposture_findings_open" in body
    assert 'effective_priority="immediate"' in body
    assert 'effective_priority="scheduled"' in body
    assert 'cluster="prod-east"' in body
    assert 'namespace="payments"' in body


def test_workloads_total_filters_to_deployed(
    client, cluster_prod, ns_payments, workload_api,
):
    """Undeployed workloads must not appear in kubeposture_workloads_total."""
    Workload.objects.create(
        cluster=cluster_prod, namespace=ns_payments, kind="Deployment",
        name="api-old", deployed=False, publicly_exposed=False,
    )
    body = client.get("/metrics").content.decode()
    # Find the workloads_total lines specifically.
    lines = [
        line for line in body.splitlines()
        if line.startswith("kubeposture_workloads_total{")
    ]
    # The deployed workload contributes one series with value 1.0.
    deployed_lines = [l for l in lines if 'cluster="prod-east"' in l]
    assert deployed_lines, f"expected deployed workload in metric, got {lines}"
    # Sum of values should be 1 (only the deployed one).
    total = sum(float(l.rsplit(" ", 1)[1]) for l in deployed_lines)
    assert total == 1.0


def test_workloads_publicly_exposed(
    client, cluster_prod, ns_payments, workload_api,
):
    body = client.get("/metrics").content.decode()
    assert "kubeposture_workloads_publicly_exposed" in body
    exposed_lines = [
        l for l in body.splitlines()
        if l.startswith("kubeposture_workloads_publicly_exposed{")
        and 'cluster="prod-east"' in l
    ]
    assert exposed_lines
    total = sum(float(l.rsplit(" ", 1)[1]) for l in exposed_lines)
    assert total == 1.0


def test_namespaces_total_only_active(
    client, cluster_prod, ns_payments,
):
    Namespace.objects.create(
        cluster=cluster_prod, name="kube-system", internet_exposed=False, active=False,
    )
    body = client.get("/metrics").content.decode()
    lines = [
        l for l in body.splitlines()
        if l.startswith("kubeposture_namespaces_total{")
    ]
    total = sum(float(l.rsplit(" ", 1)[1]) for l in lines)
    assert total == 1.0


# ── Request middleware ───────────────────────────────────────────


def test_request_middleware_increments_counter(client, db):
    # Hit a non-skipped endpoint.
    client.get("/api/v1/clusters/")
    body = client.get("/metrics").content.decode()
    assert "django_http_requests_total" in body
    assert "django_http_request_duration_seconds" in body


def test_metrics_endpoint_excluded_from_request_counter(client, db):
    """Self-instrumentation would create a feedback loop — make sure /metrics is skipped."""
    client.get("/metrics")
    client.get("/metrics")
    body = client.get("/metrics").content.decode()
    # No counter entry should mention the metrics view.
    metric_lines = [
        l for l in body.splitlines()
        if l.startswith("django_http_requests_total{")
    ]
    assert not any("metrics" in l.lower() for l in metric_lines)


# ── TTL cache ────────────────────────────────────────────────────


def test_collector_cache_serves_stale_within_ttl(
    client, cluster_prod, finding_immediate, monkeypatch,
):
    """Within TTL, mutations to the DB are NOT visible — proving the cache is in play."""
    monkeypatch.setenv("METRICS_BUSINESS_TTL_SECONDS", "3600")
    metrics_registry.reset()

    body1 = client.get("/metrics").content.decode()
    assert 'effective_priority="immediate"' in body1

    # Add a second finding — but the cached collect() result still serves the
    # snapshot from the first request.
    Finding.objects.create(
        cluster=cluster_prod, workload=finding_immediate.workload,
        source="trivy", category="vulnerability", vuln_id="CVE-2024-3",
        title="t3", severity="critical", effective_priority="immediate",
        hash_code="hash-imm-2",
    )
    body2 = client.get("/metrics").content.decode()

    # Pull all immediate-priority lines and sum values.
    def _sum_immediate(body: str) -> float:
        return sum(
            float(l.rsplit(" ", 1)[1])
            for l in body.splitlines()
            if l.startswith("kubeposture_findings_open{")
            and 'effective_priority="immediate"' in l
        )

    assert _sum_immediate(body1) == _sum_immediate(body2), (
        "cache should suppress the new finding within TTL"
    )

    # After reset, the new finding is visible.
    metrics_registry.reset()
    body3 = client.get("/metrics").content.decode()
    assert _sum_immediate(body3) == _sum_immediate(body1) + 1
