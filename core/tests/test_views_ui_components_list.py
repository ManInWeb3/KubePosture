"""Tests for the `/components/` SBOM browser list view."""
from __future__ import annotations

import urllib.parse

import pytest
from django.contrib.auth.models import User
from django.urls import reverse

from core.constants import Environment
from core.models import (
    Cluster,
    Image,
    Namespace,
    SbomComponent,
    Workload,
    WorkloadImageObservation,
)


@pytest.fixture
def viewer(db):
    return User.objects.create_user(username="viewer1", password="x")


@pytest.fixture
def cluster(db):
    return Cluster.objects.create(name="c-cmp", environment=Environment.PROD.value)


@pytest.fixture
def namespace(cluster):
    return Namespace.objects.create(cluster=cluster, name="default")


@pytest.fixture
def workload(cluster, namespace):
    return Workload.objects.create(
        cluster=cluster, namespace=namespace,
        kind="Deployment", name="api", deployed=True,
    )


@pytest.fixture
def image(db):
    return Image.objects.create(digest="sha256:" + "a" * 64, ref="registry/api:v1")


@pytest.fixture
def deployed_obs(workload, image):
    return WorkloadImageObservation.objects.create(
        workload=workload, image=image, container_name="app",
        currently_deployed=True,
    )


@pytest.fixture
def component(image):
    return SbomComponent.objects.create(
        image=image, purl="pkg:npm/lodash@4.17.21",
        name="lodash", version="4.17.21", ecosystem="npm",
    )


def test_anonymous_redirects_to_login(client):
    resp = client.get(reverse("components-list"))
    assert resp.status_code == 302


def test_logged_in_renders_full_page(client, viewer, deployed_obs, component):
    client.force_login(viewer)
    resp = client.get(reverse("components-list"))
    assert resp.status_code == 200
    body = resp.content.decode()
    assert "Components" in body
    assert "lodash" in body
    assert "pkg:npm/lodash@4.17.21" in body
    assert 'id="components-filters"' in body
    assert 'id="component-detail-offcanvas"' in body


def test_name_filter_narrows(client, viewer, deployed_obs, component, image):
    SbomComponent.objects.create(
        image=image, purl="pkg:npm/express@4.18.0",
        name="express", version="4.18.0", ecosystem="npm",
    )
    client.force_login(viewer)
    resp = client.get(reverse("components-list") + "?name=lod")
    body = resp.content.decode()
    assert "lodash" in body
    assert "express" not in body


def test_image_filter_scopes_to_image_and_shows_chip(client, viewer, deployed_obs, component, image):
    # A component on a different image must not appear when scoped.
    other = Image.objects.create(digest="sha256:" + "b" * 64, ref="registry/other:v1")
    SbomComponent.objects.create(
        image=other, purl="pkg:npm/express@4.18.0",
        name="express", version="4.18.0", ecosystem="npm",
    )
    client.force_login(viewer)
    resp = client.get(reverse("components-list") + "?image=" + urllib.parse.quote(image.digest))
    body = resp.content.decode()
    assert "lodash" in body
    assert "express" not in body
    # Scope chip surfaces the image ref.
    assert "registry/api:v1" in body


def test_image_filter_unknown_digest_falls_back_to_all(client, viewer, deployed_obs, component):
    client.force_login(viewer)
    resp = client.get(reverse("components-list") + "?image=sha256:" + "f" * 64)
    assert resp.status_code == 200
    # Unknown digest is dropped; the list is not scoped to nothing.
    assert "lodash" in resp.content.decode()


def test_htmx_partial_returns_rows_only(client, viewer, deployed_obs, component):
    client.force_login(viewer)
    resp = client.get(
        reverse("components-list"),
        HTTP_HX_REQUEST="true",
        HTTP_HX_TARGET="component-rows",
    )
    assert resp.status_code == 200
    body = resp.content.decode()
    assert "lodash" in body
    # Partial should NOT contain page chrome.
    assert "Components" not in body or "<h2" not in body


def test_detail_panel_returns_component_info(client, viewer, deployed_obs, component):
    client.force_login(viewer)
    url = (
        reverse("components-detail-panel")
        + "?purl=" + urllib.parse.quote("pkg:npm/lodash@4.17.21")
    )
    resp = client.get(url)
    assert resp.status_code == 200
    body = resp.content.decode()
    assert "lodash" in body
    assert "4.17.21" in body
    assert "registry/api:v1" in body
    assert "Deployment/api" in body


def test_detail_panel_404_for_unknown_purl(client, viewer):
    client.force_login(viewer)
    url = (
        reverse("components-detail-panel")
        + "?purl=" + urllib.parse.quote("pkg:npm/does-not-exist@0.0.0")
    )
    resp = client.get(url)
    assert resp.status_code == 404


def test_undeployed_excluded_by_default(client, viewer, workload, image):
    # Image observed but not currently deployed.
    WorkloadImageObservation.objects.create(
        workload=workload, image=image, container_name="app",
        currently_deployed=False,
    )
    SbomComponent.objects.create(
        image=image, purl="pkg:npm/orphan-only@1.0",
        name="orphan-only", version="1.0", ecosystem="npm",
    )
    client.force_login(viewer)
    resp = client.get(reverse("components-list"))
    assert "orphan-only" not in resp.content.decode()
    assert "pkg:npm/orphan-only@1.0" not in resp.content.decode()

    resp2 = client.get(reverse("components-list") + "?include_inactive=1")
    assert "pkg:npm/orphan-only@1.0" in resp2.content.decode()
