"""Hardening-preview upload (`POST /workloads/<kind>/<name>/`): every
rejection must be visible to the user on the page they land on, a good
scan lands in the session and renders as a PREVIEW, and the pk in the form
can't be pointed at another workload."""
from __future__ import annotations

import json

import pytest
from django.contrib.auth.models import User
from django.core.files.uploadedfile import SimpleUploadedFile
from django.urls import reverse

from core.constants import Environment
from core.models import Cluster, Namespace, Workload
from core.services import hardening_preview
from core.views_ui import _HARDENING_PREVIEW_MAX_BYTES


@pytest.fixture
def authed(client, db):
    client.force_login(User.objects.create_user(username="hu", password="x"))
    return client


@pytest.fixture
def workload(db):
    c = Cluster.objects.create(name="cp", environment=Environment.PROD.value)
    ns = Namespace.objects.create(cluster=c, name="n")
    return Workload.objects.create(cluster=c, namespace=ns, kind="Deployment", name="api", deployed=True)


def _cli():
    return {"ArtifactName": "reg/api:hardened", "Results": [{
        "Target": "reg/api:hardened (debian 12)",
        "Vulnerabilities": [{"VulnerabilityID": "CVE-2024-1", "PkgName": "libc6", "InstalledVersion": "1.0",
                             "FixedVersion": "1.1", "Severity": "HIGH", "Title": "t",
                             "CVSS": {"nvd": {"V3Score": 7.5, "V3Vector": "x"}}}],
    }]}


def _url(w):
    return reverse("workloads-detail", kwargs={"kind": w.kind, "name": w.name})


def _post(client, w, **data):
    return client.post(_url(w), {"workload_id": w.pk, **data}, follow=True)


@pytest.mark.parametrize(("data", "message"), [
    ({}, "Attach a Trivy JSON file"),
    ({"scan_text": "{nope"}, "Could not parse JSON"),
    ({"scan_text": json.dumps({"not": "trivy"})}, "Not a Trivy CLI scan"),
], ids=["empty", "bad-json", "not-trivy"])
def test_rejections_are_shown_on_the_page_the_user_lands_on(authed, workload, data, message):
    resp = _post(authed, workload, **data)
    assert resp.status_code == 200
    assert message in resp.content.decode(), "base.html must render flash messages"
    assert not any(k.startswith(hardening_preview.SESSION_PREFIX) for k in authed.session.keys())


def test_oversized_upload_is_rejected_before_parsing(authed, workload):
    big = SimpleUploadedFile("scan.json", b"{" + b" " * _HARDENING_PREVIEW_MAX_BYTES + b"}")
    resp = _post(authed, workload, scan=big)
    assert "too large" in resp.content.decode()


def test_pasted_scan_lands_in_the_session_and_renders_as_preview(authed, workload):
    resp = authed.post(_url(workload), {"workload_id": workload.pk, "scan_text": json.dumps(_cli())})
    assert resp.status_code == 302 and "&image=candidate:" in resp["Location"]
    assert any(k.startswith(f"{hardening_preview.SESSION_PREFIX}:{workload.pk}:") for k in authed.session.keys())

    page = authed.get(resp["Location"])
    assert page.context["is_preview"] is True
    assert "PREVIEW" in page.content.decode()
    assert [f["vuln_id"] for f in page.context["findings"]] == ["CVE-2024-1"]

    cid = resp["Location"].rsplit("candidate:", 1)[1]
    authed.post(_url(workload), {"workload_id": workload.pk, "action": "clear", "candidate_id": cid})
    assert not any(k.startswith(hardening_preview.SESSION_PREFIX) for k in authed.session.keys())


def test_forged_workload_id_cannot_target_another_workload(authed, workload):
    other = Workload.objects.create(cluster=workload.cluster, namespace=workload.namespace,
                                    kind="Deployment", name="victim", deployed=True)
    resp = authed.post(_url(workload), {"workload_id": other.pk, "scan_text": json.dumps(_cli())})
    assert resp.status_code == 404
    assert authed.post(_url(workload), {"workload_id": "abc"}).status_code == 404


def test_anonymous_post_is_redirected(client, workload):
    resp = client.post(_url(workload), {"workload_id": workload.pk})
    assert resp.status_code == 302 and resp["Location"].startswith("/accounts/login/")
