"""Read API tests.

Each resource: list 200 + filter + detail 200 + anonymous denied.
Plus a few tricky cases that exercise computed fields / joins
(image `currently_deployed` per cluster scope, finding by severity
+ priority compose, etc.).

Data setup is hand-built (not the scenario harness) so we control
exactly what each test sees and don't pull in scan-related noise.
"""
from __future__ import annotations

from datetime import timedelta

import pytest
from django.contrib.auth.models import User
from django.utils import timezone

from core.models import (
    Cluster,
    Finding,
    Image,
    Namespace,
    Workload,
    WorkloadImageObservation,
)


# ── Fixtures ──────────────────────────────────────────────────────


@pytest.fixture
def authed_user(db):
    user = User.objects.create_user(username="reader", password="x")
    return user


@pytest.fixture
def authed_client(client, authed_user):
    client.force_login(authed_user)
    return client


@pytest.fixture
def cluster_a(db):
    c = Cluster.objects.create(
        name="cluster-a", environment="prod", provider="aws", region="eu-west-1",
    )
    c.last_complete_inventory_at = timezone.now()
    c.save()
    return c


@pytest.fixture
def cluster_b(db):
    c = Cluster.objects.create(
        name="cluster-b", environment="staging", provider="aws", region="eu-west-1",
    )
    c.last_complete_inventory_at = timezone.now()
    c.save()
    return c


@pytest.fixture
def ns_payments(db, cluster_a):
    return Namespace.objects.create(
        cluster=cluster_a, name="payments", internet_exposed=False,
        contains_sensitive_data=True,
    )


@pytest.fixture
def ns_public(db, cluster_a):
    return Namespace.objects.create(
        cluster=cluster_a, name="public-web", internet_exposed=True,
    )


@pytest.fixture
def workload_api(db, cluster_a, ns_payments):
    return Workload.objects.create(
        cluster=cluster_a, namespace=ns_payments, kind="Deployment",
        name="api-server", deployed=True, last_inventory_at=cluster_a.last_complete_inventory_at,
    )


@pytest.fixture
def workload_frontend(db, cluster_a, ns_public):
    return Workload.objects.create(
        cluster=cluster_a, namespace=ns_public, kind="Deployment",
        name="frontend", deployed=True, publicly_exposed=True,
        last_inventory_at=cluster_a.last_complete_inventory_at,
    )


@pytest.fixture
def image_api(db, cluster_a, workload_api):
    img = Image.objects.create(digest="sha256:" + "a" * 64, ref="x:api-v1")
    obs = WorkloadImageObservation.objects.create(
        workload=workload_api, image=img, container_name="app",
    )
    WorkloadImageObservation.objects.filter(pk=obs.pk).update(
        last_seen_at=cluster_a.last_complete_inventory_at + timedelta(seconds=1),
    )
    return img


@pytest.fixture
def image_frontend(db, cluster_a, workload_frontend):
    img = Image.objects.create(digest="sha256:" + "c" * 64, ref="x:frontend-v3")
    obs = WorkloadImageObservation.objects.create(
        workload=workload_frontend, image=img, container_name="app",
    )
    WorkloadImageObservation.objects.filter(pk=obs.pk).update(
        last_seen_at=cluster_a.last_complete_inventory_at + timedelta(seconds=1),
    )
    return img


@pytest.fixture
def image_orphan(db):
    """An Image with no observation — shouldn't be currently_deployed anywhere."""
    return Image.objects.create(digest="sha256:" + "0" * 64, ref="x:orphan")


@pytest.fixture
def finding_critical(db, cluster_a, workload_api, image_api):
    return Finding.objects.create(
        cluster=cluster_a, workload=workload_api, image=image_api,
        source="trivy", category="vulnerability", vuln_id="CVE-2024-1234",
        pkg_name="libc6", title="critical thing",
        severity="critical", effective_priority="immediate",
        kev_listed=True, hash_code="h1",
    )


@pytest.fixture
def finding_high(db, cluster_a, workload_api, image_api):
    return Finding.objects.create(
        cluster=cluster_a, workload=workload_api, image=image_api,
        source="trivy", category="vulnerability", vuln_id="CVE-2024-5678",
        pkg_name="openssl", title="high thing",
        severity="high", effective_priority="out_of_cycle",
        kev_listed=False, hash_code="h2",
    )


# ── Anonymous denial ──────────────────────────────────────────────


@pytest.mark.parametrize("path", [
    "/api/v1/clusters/",
    "/api/v1/namespaces/",
    "/api/v1/workloads/",
    "/api/v1/findings/",
    "/api/v1/images/",
])
def test_anonymous_denied(client, db, path):
    response = client.get(path)
    assert response.status_code in (401, 403)


# ── Cluster ───────────────────────────────────────────────────────


def test_cluster_list_returns_paginated(authed_client, cluster_a, cluster_b):
    response = authed_client.get("/api/v1/clusters/")
    assert response.status_code == 200
    data = response.json()
    assert "count" in data and "results" in data
    assert data["count"] == 2
    names = {row["name"] for row in data["results"]}
    assert names == {"cluster-a", "cluster-b"}


def test_cluster_filter_by_environment(authed_client, cluster_a, cluster_b):
    response = authed_client.get("/api/v1/clusters/?environment=prod")
    data = response.json()
    assert data["count"] == 1
    assert data["results"][0]["name"] == "cluster-a"


def test_cluster_detail(authed_client, cluster_a):
    response = authed_client.get(f"/api/v1/clusters/{cluster_a.id}/")
    assert response.status_code == 200
    body = response.json()
    assert body["name"] == "cluster-a"
    assert body["environment"] == "prod"
    assert "last_complete_inventory_at" in body


# ── Namespace ─────────────────────────────────────────────────────


def test_namespace_list_includes_cluster_name(authed_client, ns_payments, ns_public):
    response = authed_client.get("/api/v1/namespaces/")
    data = response.json()
    assert data["count"] == 2
    for row in data["results"]:
        assert row["cluster_name"] == "cluster-a"


def test_namespace_filter_by_internet_exposed(authed_client, ns_payments, ns_public):
    response = authed_client.get("/api/v1/namespaces/?internet_exposed=true")
    data = response.json()
    assert data["count"] == 1
    assert data["results"][0]["name"] == "public-web"


# ── Workload ──────────────────────────────────────────────────────


def test_workload_list_returns_two(authed_client, workload_api, workload_frontend):
    response = authed_client.get("/api/v1/workloads/")
    data = response.json()
    assert data["count"] == 2


def test_workload_filter_by_cluster_and_kind(
    authed_client, workload_api, workload_frontend
):
    response = authed_client.get("/api/v1/workloads/?cluster=cluster-a&kind=Deployment")
    data = response.json()
    assert data["count"] == 2


def test_workload_search_by_name_substring(
    authed_client, workload_api, workload_frontend
):
    response = authed_client.get("/api/v1/workloads/?name=api")
    data = response.json()
    assert data["count"] == 1
    assert data["results"][0]["name"] == "api-server"


def test_workload_filter_by_publicly_exposed(
    authed_client, workload_api, workload_frontend
):
    response = authed_client.get("/api/v1/workloads/?publicly_exposed=true")
    data = response.json()
    assert data["count"] == 1
    assert data["results"][0]["name"] == "frontend"


def test_workload_detail_carries_namespace_name(authed_client, workload_api):
    response = authed_client.get(f"/api/v1/workloads/{workload_api.id}/")
    body = response.json()
    assert body["namespace_name"] == "payments"
    assert body["cluster_name"] == "cluster-a"


# ── Finding ───────────────────────────────────────────────────────


def test_finding_list_returns_all(authed_client, finding_critical, finding_high):
    response = authed_client.get("/api/v1/findings/")
    assert response.status_code == 200
    data = response.json()
    assert data["count"] == 2


def test_finding_filter_by_severity(
    authed_client, finding_critical, finding_high
):
    response = authed_client.get("/api/v1/findings/?severity=critical")
    data = response.json()
    assert data["count"] == 1
    assert data["results"][0]["vuln_id"] == "CVE-2024-1234"


def test_finding_filter_by_priority(
    authed_client, finding_critical, finding_high
):
    response = authed_client.get("/api/v1/findings/?effective_priority=immediate")
    data = response.json()
    assert data["count"] == 1
    assert data["results"][0]["severity"] == "critical"


def test_finding_filter_by_severity_and_priority_compose(
    authed_client, finding_critical, finding_high
):
    response = authed_client.get(
        "/api/v1/findings/?severity=high&effective_priority=out_of_cycle"
    )
    data = response.json()
    assert data["count"] == 1
    assert data["results"][0]["vuln_id"] == "CVE-2024-5678"


def test_finding_filter_by_kev(authed_client, finding_critical, finding_high):
    response = authed_client.get("/api/v1/findings/?kev_listed=true")
    data = response.json()
    assert data["count"] == 1
    assert data["results"][0]["vuln_id"] == "CVE-2024-1234"


def test_finding_search_by_vuln_id_substring(
    authed_client, finding_critical, finding_high
):
    response = authed_client.get("/api/v1/findings/?vuln_id=CVE-2024-1234")
    data = response.json()
    assert data["count"] == 1


def test_finding_filter_by_workload_name(
    authed_client, finding_critical, finding_high
):
    response = authed_client.get("/api/v1/findings/?workload=api-server")
    data = response.json()
    assert data["count"] == 2


def test_finding_detail_carries_joined_strings(authed_client, finding_critical):
    response = authed_client.get(f"/api/v1/findings/{finding_critical.id}/")
    body = response.json()
    assert body["cluster_name"] == "cluster-a"
    assert body["workload_name"] == "api-server"
    assert body["workload_namespace"] == "payments"


# ── Image ─────────────────────────────────────────────────────────


def test_image_list_includes_currently_deployed(
    authed_client, image_api, image_frontend, image_orphan
):
    response = authed_client.get("/api/v1/images/")
    data = response.json()
    assert data["count"] == 3
    by_digest = {row["digest"]: row for row in data["results"]}
    # Without a cluster scope, currently_deployed is true if ANY workload
    # uses the image and the time-anchor lines up. image_api + image_frontend
    # have observations bumped after their workload's cluster's last_complete_*
    assert by_digest["sha256:" + "a" * 64]["currently_deployed"] is True
    assert by_digest["sha256:" + "c" * 64]["currently_deployed"] is True
    # The orphan has no observation at all.
    assert by_digest["sha256:" + "0" * 64]["currently_deployed"] is False


def test_image_filter_currently_deployed_true(
    authed_client, image_api, image_frontend, image_orphan
):
    response = authed_client.get("/api/v1/images/?currently_deployed=true")
    data = response.json()
    assert data["count"] == 2


def test_image_filter_currently_deployed_false(
    authed_client, image_api, image_frontend, image_orphan
):
    response = authed_client.get("/api/v1/images/?currently_deployed=false")
    data = response.json()
    assert data["count"] == 1
    assert data["results"][0]["digest"] == "sha256:" + "0" * 64


def test_image_currently_deployed_scoped_per_cluster(
    authed_client, cluster_a, cluster_b, image_api
):
    """An image deployed in cluster-a is NOT currently_running when
    we scope the query to cluster-b."""
    response_a = authed_client.get(
        "/api/v1/images/?cluster=cluster-a&currently_deployed=true"
    )
    response_b = authed_client.get(
        "/api/v1/images/?cluster=cluster-b&currently_deployed=true"
    )
    assert response_a.json()["count"] == 1
    assert response_b.json()["count"] == 0


def test_image_detail_by_digest(authed_client, image_api):
    response = authed_client.get(f"/api/v1/images/{image_api.digest}/")
    assert response.status_code == 200
    body = response.json()
    assert body["ref"] == "x:api-v1"
    assert body["currently_deployed"] is True


def test_image_filter_by_repository_substring(
    authed_client, image_api, image_frontend, image_orphan
):
    # ref="x:api-v1" — repository is empty; we instead search by ref
    response = authed_client.get("/api/v1/images/?ref=api")
    data = response.json()
    assert data["count"] == 1
    assert data["results"][0]["ref"] == "x:api-v1"
