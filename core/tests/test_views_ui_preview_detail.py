"""View test for the hardening-preview finding detail offcanvas.

Preview findings are never persisted, so the row click hits a session-backed
endpoint (`preview-finding-detail-panel`) rather than the DB-backed
`findings-detail-panel`. Locks the contract that a stashed preview finding
renders its full CVE detail.
"""
import pytest
from django.contrib.auth.models import User
from django.urls import reverse

from core.constants import Environment, PriorityBand
from core.models import Cluster, Namespace, Workload
from core.services import hardening_preview


@pytest.fixture
def authed(client, db):
    user = User.objects.create_user(username="pv", password="x")
    client.force_login(user)
    return client


@pytest.fixture
def scene(db):
    c = Cluster.objects.create(name="cp", environment=Environment.PROD.value)
    ns = Namespace.objects.create(cluster=c, name="n")
    w = (
        Workload.objects
        .select_related("cluster", "namespace")
        .prefetch_related("signals")
        .get(pk=Workload.objects.create(
            cluster=c, namespace=ns, kind="Deployment", name="api", deployed=True,
        ).pk)
    )
    return {"workload": w}


def _cli_json():
    return {
        "ArtifactName": "reg/api:hardened",
        "Results": [{
            "Target": "reg/api:hardened (debian 12)",
            "Vulnerabilities": [{
                "VulnerabilityID": "CVE-2024-0001",
                "PkgName": "libc6",
                "InstalledVersion": "1.0",
                "FixedVersion": "1.1",
                "Severity": "HIGH",
                "Title": "Heap overflow in libc6",
                "Description": "A nasty heap overflow.",
                "PrimaryURL": "https://example.com/cve",
                "CVSS": {"nvd": {"V3Score": 7.5, "V3Vector": "AV:N"}},
            }],
        }],
    }


def _stash(client, workload):
    result = hardening_preview.preview_trivy_cli_scan(workload, _cli_json())
    session = client.session
    session[hardening_preview._session_key(workload.pk, result.candidate_id)] = {
        "candidate_id": result.candidate_id,
        "digest": result.digest,
        "image_ref": result.image_ref,
        "findings": result.findings,
        "counts": result.counts,
        "total": result.total,
        "ts": 9_999_999_999.0,  # far future so the TTL check never expires it
    }
    session.save()
    return result


def test_preview_detail_panel_renders_cve_details(authed, scene):
    w = scene["workload"]
    result = _stash(authed, w)
    idx = result.findings[0]["idx"]

    resp = authed.get(reverse(
        "preview-finding-detail-panel",
        args=[w.pk, result.candidate_id, idx],
    ))

    assert resp.status_code == 200
    body = resp.content.decode()
    assert "CVE-2024-0001" in body
    assert "A nasty heap overflow." in body
    assert "https://example.com/cve" in body
    assert "reg/api:hardened" in body
    assert "PREVIEW" in body


def test_preview_detail_panel_404_for_expired_preview(authed, scene):
    w = scene["workload"]
    resp = authed.get(reverse(
        "preview-finding-detail-panel",
        args=[w.pk, "missing", 0],
    ))
    assert resp.status_code == 404


def test_preview_detail_panel_404_for_unknown_idx(authed, scene):
    w = scene["workload"]
    result = _stash(authed, w)
    resp = authed.get(reverse(
        "preview-finding-detail-panel",
        args=[w.pk, result.candidate_id, 999],
    ))
    assert resp.status_code == 404
