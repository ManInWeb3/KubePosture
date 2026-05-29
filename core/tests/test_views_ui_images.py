"""Quick integration test for the /images/ view rendering."""
import pytest
from datetime import timedelta
from django.contrib.auth.models import User
from django.urls import reverse
from django.utils import timezone

from core.constants import Environment, PriorityBand
from core.models import Cluster, Finding, Image, Namespace, Workload, WorkloadImageObservation


@pytest.fixture
def viewer(db):
    return User.objects.create_user(username="iv", password="x")


@pytest.fixture
def authed(client, viewer):
    client.force_login(viewer)
    return client


@pytest.fixture
def scene(db):
    c = Cluster.objects.create(name="cv", environment=Environment.PROD.value)
    c.last_complete_inventory_at = timezone.now()
    c.save()
    ns = Namespace.objects.create(cluster=c, name="n")
    w = Workload.objects.create(cluster=c, namespace=ns, kind="Deployment", name="api",
                                deployed=True, last_inventory_at=c.last_complete_inventory_at)
    img = Image.objects.create(digest="sha256:" + "a" * 64, ref="reg/api:v1",
                                registry="reg", repository="api")
    obs = WorkloadImageObservation.objects.create(workload=w, image=img,
                                                   container_name="app", currently_deployed=True)
    WorkloadImageObservation.objects.filter(pk=obs.pk).update(
        last_seen_at=c.last_complete_inventory_at + timedelta(seconds=1))
    Finding.objects.create(cluster=c, workload=w, image=img,
                          source="trivy", category="vulnerability", vuln_id="CVE-1",
                          title="bug", severity="critical",
                          effective_priority=PriorityBand.IMMEDIATE.value, hash_code="h1")
    return {"image": img, "workload": w}


def test_list_view_renders(authed, scene):
    resp = authed.get(reverse("images-list"))
    assert resp.status_code == 200
    body = resp.content.decode()
    assert "Images" in body
    assert "reg/api:v1" in body
    assert "image-rows" in body


def test_list_view_htmx_partial(authed, scene):
    resp = authed.get(reverse("images-list"), HTTP_HX_REQUEST="true", HTTP_HX_TARGET="image-rows")
    assert resp.status_code == 200
    body = resp.content.decode()
    assert "<html" not in body.lower()
    assert "reg/api:v1" in body


def test_detail_view_renders(authed, scene):
    digest = scene["image"].digest
    resp = authed.get(reverse("images-detail", kwargs={"digest": digest}))
    assert resp.status_code == 200
    body = resp.content.decode()
    assert digest in body
    assert "CVE-1" in body
    assert "Deployment" in body
    assert scene["workload"].name in body


def test_detail_view_invalid_digest_404(authed, scene):
    resp = authed.get("/images/not-a-digest/")
    assert resp.status_code == 404


def test_detail_view_unknown_digest_404(authed, scene):
    resp = authed.get(reverse("images-detail", kwargs={"digest": "sha256:" + "0" * 64}))
    assert resp.status_code == 404
