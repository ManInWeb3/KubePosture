"""Tests for the `/findings/` triage list view."""
from __future__ import annotations

from datetime import timedelta

import pytest
from django.contrib.auth.models import User
from django.urls import reverse
from django.utils import timezone

from core.constants import (
    Category,
    Environment,
    PriorityBand,
    Severity,
    Source,
)
from core.models import Cluster, Finding, Namespace, Workload


@pytest.fixture
def viewer(db):
    user = User.objects.create_user(username="viewer1", password="x")
    return user


@pytest.fixture
def cluster(db):
    return Cluster.objects.create(name="c-list", environment=Environment.PROD.value)


@pytest.fixture
def namespace(cluster):
    return Namespace.objects.create(
        cluster=cluster, name="default", internet_exposed=True,
    )


@pytest.fixture
def workload(cluster, namespace):
    return Workload.objects.create(
        cluster=cluster, namespace=namespace,
        kind="Deployment", name="api", deployed=True,
    )


def _make_finding(workload, *, hash_code, **overrides) -> Finding:
    defaults = dict(
        cluster=workload.cluster,
        workload=workload,
        source=Source.TRIVY.value,
        category=Category.VULNERABILITY.value,
        vuln_id="CVE-2024-0001",
        title="test finding",
        severity=Severity.HIGH.value,
        effective_priority=PriorityBand.SCHEDULED.value,
        kev_listed=False,
        first_seen=timezone.now(),
        last_seen=timezone.now(),
    )
    defaults.update(overrides)
    return Finding.objects.create(hash_code=hash_code, **defaults)


def test_anonymous_redirects_to_login(client):
    resp = client.get(reverse("findings-list"))
    assert resp.status_code == 302


def test_logged_in_get_renders_full_page(client, viewer, workload):
    _make_finding(workload, hash_code="h1")
    client.force_login(viewer)
    resp = client.get(reverse("findings-list"))
    assert resp.status_code == 200
    body = resp.content.decode()
    # Page chrome
    assert "Findings" in body
    # Filter form
    assert 'id="findings-filters"' in body
    # Offcanvas container is present
    assert 'id="finding-detail-offcanvas"' in body
    # Preset chips render
    assert "Today's triage" in body
    assert "KEV exploited" in body
    # Tile labels
    assert "Immediate active" in body
    assert "On exposed namespaces" in body


def test_htmx_partial_response(client, viewer, workload):
    _make_finding(workload, hash_code="h1")
    client.force_login(viewer)
    resp = client.get(
        reverse("findings-list"),
        HTTP_HX_REQUEST="true",
        HTTP_HX_TARGET="finding-rows",
    )
    assert resp.status_code == 200
    body = resp.content.decode()
    # Partial: no <html> wrapper, but has the row's offcanvas hooks
    assert "<html" not in body
    assert "finding-detail-offcanvas" in body


def test_priority_filter_narrows(client, viewer, workload):
    _make_finding(workload, hash_code="h1",
                  effective_priority=PriorityBand.IMMEDIATE.value, vuln_id="CVE-A")
    _make_finding(workload, hash_code="h2",
                  effective_priority=PriorityBand.DEFER.value, vuln_id="CVE-B")
    client.force_login(viewer)
    resp = client.get(reverse("findings-list"), {"priority": "immediate"})
    body = resp.content.decode()
    assert "CVE-A" in body
    assert "CVE-B" not in body


def test_kev_filter_narrows(client, viewer, workload):
    _make_finding(workload, hash_code="h1", kev_listed=True,  vuln_id="CVE-K")
    _make_finding(workload, hash_code="h2", kev_listed=False, vuln_id="CVE-N")
    client.force_login(viewer)
    resp = client.get(reverse("findings-list"), {"kev": "1"})
    body = resp.content.decode()
    assert "CVE-K" in body
    assert "CVE-N" not in body


def test_invalid_filter_values_are_dropped(client, viewer, workload):
    """Garbage `epss` / `age` values are coerced to empty so the
    queryset isn't filtered by gibberish."""
    _make_finding(workload, hash_code="h1", vuln_id="CVE-Z")
    client.force_login(viewer)
    resp = client.get(reverse("findings-list"), {
        "epss": "lolnope", "age": "garbage",
    })
    assert resp.status_code == 200
    assert "CVE-Z" in resp.content.decode()


def test_internet_checkbox_filters_to_exposed_namespace(client, viewer, cluster):
    exposed_ns = Namespace.objects.create(
        cluster=cluster, name="edge", internet_exposed=True,
    )
    internal_ns = Namespace.objects.create(
        cluster=cluster, name="internal", internet_exposed=False,
    )
    w_exp = Workload.objects.create(
        cluster=cluster, namespace=exposed_ns,
        kind="Deployment", name="frontend", deployed=True,
    )
    w_int = Workload.objects.create(
        cluster=cluster, namespace=internal_ns,
        kind="Deployment", name="backend", deployed=True,
    )
    _make_finding(w_exp, hash_code="he", vuln_id="CVE-EDGE")
    _make_finding(w_int, hash_code="hi", vuln_id="CVE-INTERNAL")

    client.force_login(viewer)
    resp = client.get(reverse("findings-list"), {"internet": "1"})
    body = resp.content.decode()

    assert "CVE-EDGE" in body
    assert "CVE-INTERNAL" not in body


def test_tile_counts_ignore_their_own_dimension(client, viewer, workload):
    """Filtering by ?priority=defer should still show non-zero
    `# Immediate active` (the tile's count drops the priority dim)."""
    _make_finding(workload, hash_code="h_imm",
                  effective_priority=PriorityBand.IMMEDIATE.value)
    _make_finding(workload, hash_code="h_defer",
                  effective_priority=PriorityBand.DEFER.value)
    client.force_login(viewer)
    resp = client.get(reverse("findings-list"), {"priority": "defer"})
    body = resp.content.decode()
    # Find the Immediate-active tile and confirm its number is "1", not "0".
    # Tile markup: <div class="subheader">Immediate active</div>
    #              <div class="h1 m-0 text-red">N</div>
    idx = body.find("Immediate active")
    assert idx != -1
    snippet = body[idx:idx + 400]
    assert ">1<" in snippet, snippet


def test_active_preset_highlights_today(client, viewer, workload):
    _make_finding(workload, hash_code="h1")
    client.force_login(viewer)
    resp = client.get(
        reverse("findings-list"),
        {"priority": "immediate", "internet": "1"},
    )
    body = resp.content.decode()
    # The "Today's triage" anchor should carry .active when the URL
    # exactly matches its preset.
    idx = body.find("Today's triage")
    assert idx != -1
    snippet = body[max(0, idx - 250):idx]
    assert "active" in snippet


def test_pagination_advances_with_page_param(client, viewer, workload):
    # Need >50 to get a second page.
    for i in range(55):
        _make_finding(
            workload,
            hash_code=f"h_{i}",
            vuln_id=f"CVE-2024-{i:04d}",
            title=f"finding {i}",
        )
    client.force_login(viewer)
    resp1 = client.get(reverse("findings-list"))
    assert resp1.status_code == 200
    body1 = resp1.content.decode()
    assert "Page 1 of 2" in body1

    resp2 = client.get(reverse("findings-list"), {"page": 2})
    assert resp2.status_code == 200
    body2 = resp2.content.decode()
    assert "Page 2 of 2" in body2
