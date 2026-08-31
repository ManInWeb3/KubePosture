"""End-to-end import lifecycle tests — real HTTP views, real queue drain.

Unlike every other "integration" test in this repo, these drive the
actual production entry points: `POST /api/v1/imports/start/` ->
`POST /api/v1/ingest/` -> `POST /api/v1/imports/finish/` (bearer-token
auth included), then `core.services.worker.drain_until_empty()` (the
same call `manage.py process_ingest_queue` makes) — not direct ORM
seeding, and not the `core/api/testing_views.py` harness (which bypasses
the views entirely via `ImportMark.open()` / `queue.enqueue()` calls).
`tests/scenario_runner/test_scenarios.py` was meant to cover this via
mocked import fixtures, but its `Architecture/mock_tests/` fixture tree
is gitignored and absent from this checkout — it can't even be
collected here. This module exists to give the import pipeline *some*
real, HTTP-driven, DB-asserting coverage in a checkout without that
fixture data.

Each test asserts on the actual downstream state the pipeline exists to
maintain: `Workload.deployed`, `WorkloadImageObservation.currently_deployed`
/ `Image.objects.currently_running()`, `Finding` visibility, `WorkloadSignal`,
and `SbomComponent` — not just "the queue drained without error".
"""
from __future__ import annotations

import json
from datetime import timedelta

import pytest
from django.utils import timezone

from core.api.auth import generate_token
from core.constants import IngestQueueStatus
from core.models import (
    Cluster,
    Finding,
    Image,
    IngestToken,
    SbomComponent,
    ScanInconsistency,
    Workload,
    WorkloadImageObservation,
    WorkloadSignal,
)
from core.services.inventory import default_finding_qs, restrict_to_currently_deployed_images
from core.services.worker import drain_until_empty


# ── HTTP + drain helpers ─────────────────────────────────────────


@pytest.fixture
def token(db) -> str:
    plain, hashed = generate_token()
    IngestToken.objects.create(name="e2e-test", token_hash=hashed)
    return plain


def _auth(token: str) -> dict:
    return {"HTTP_AUTHORIZATION": f"Bearer {token}"}


def _start(client, token, *, cluster: str, kind: str, import_id: str):
    resp = client.post(
        "/api/v1/imports/start/",
        data=json.dumps({"cluster": cluster, "kind": kind, "import_id": import_id}),
        content_type="application/json",
        **_auth(token),
    )
    assert resp.status_code in (200, 201), resp.content
    return resp


def _ingest(client, token, *, cluster: str, kind: str, import_id: str, payload: dict,
            complete_snapshot: bool = False):
    resp = client.post(
        "/api/v1/ingest/",
        data=json.dumps({
            "cluster": cluster, "kind": kind, "import_id": import_id,
            "payload": payload, "complete_snapshot": complete_snapshot,
        }),
        content_type="application/json",
        **_auth(token),
    )
    assert resp.status_code == 202, resp.content
    return resp


def _finish(client, token, *, cluster: str, kind: str, import_id: str, observed_count: int):
    resp = client.post(
        "/api/v1/imports/finish/",
        data=json.dumps({
            "cluster": cluster, "kind": kind, "import_id": import_id,
            "observed_count": observed_count,
        }),
        content_type="application/json",
        **_auth(token),
    )
    assert resp.status_code == 200, resp.content
    return resp


def _drain():
    return drain_until_empty(limit=100)


def _run_inventory_cycle(client, token, *, cluster: str, import_id: str, items: list[dict],
                          complete: bool = True):
    """One full inventory cycle through the real views, then drain."""
    _start(client, token, cluster=cluster, kind="inventory", import_id=import_id)
    envelope = {
        "cluster_meta": {"name": cluster},
        "complete_snapshot": complete,
        "items": items,
    }
    _ingest(
        client, token, cluster=cluster, kind="inventory", import_id=import_id,
        payload=envelope, complete_snapshot=complete,
    )
    _finish(
        client, token, cluster=cluster, kind="inventory", import_id=import_id,
        observed_count=len(items),
    )
    return _drain()


# ── K8s manifest builders (mirrors core/tests/parsers/test_inventory_parser.py) ──


def _ns_manifest(name: str) -> dict:
    return {
        "apiVersion": "v1", "kind": "Namespace",
        "metadata": {"name": name, "labels": {}, "annotations": {}},
    }


def _deployment_manifest(name: str, namespace: str, *, replicas: int = 1,
                          image: str = "registry.x/app:1") -> dict:
    return {
        "apiVersion": "apps/v1", "kind": "Deployment",
        "metadata": {"name": name, "namespace": namespace, "labels": {"app": name}},
        "spec": {
            "replicas": replicas,
            "selector": {"matchLabels": {"app": name}},
            "template": {
                "metadata": {"labels": {"app": name}},
                "spec": {"containers": [{"name": "app", "image": image}]},
            },
        },
    }


def _replicaset_manifest(name: str, namespace: str, owner_deployment: str, *,
                          image: str = "registry.x/app:1") -> dict:
    return {
        "apiVersion": "apps/v1", "kind": "ReplicaSet",
        "metadata": {
            "name": name, "namespace": namespace,
            "labels": {"app": owner_deployment, "pod-template-hash": "abc"},
            "ownerReferences": [
                {"apiVersion": "apps/v1", "kind": "Deployment",
                 "name": owner_deployment, "controller": True},
            ],
        },
        "spec": {
            "replicas": 1,
            "selector": {"matchLabels": {"app": owner_deployment}},
            "template": {
                "metadata": {"labels": {"app": owner_deployment}},
                "spec": {"containers": [{"name": "app", "image": image}]},
            },
        },
    }


def _pod_manifest(name: str, namespace: str, *, owner: dict | None = None,
                   image: str = "registry.x/app:1", digest: str | None = None) -> dict:
    digest = digest or ("sha256:" + "a" * 64)
    meta: dict = {"name": name, "namespace": namespace, "labels": {"app": name}}
    if owner is not None:
        meta["ownerReferences"] = [owner]
    return {
        "apiVersion": "v1", "kind": "Pod",
        "metadata": meta,
        "spec": {"containers": [{"name": "app", "image": image}]},
        "status": {
            "phase": "Running",
            "containerStatuses": [{
                "name": "app", "image": image,
                "imageID": f"{image.split(':')[0]}@{digest}",
                "ready": True, "started": True,
            }],
        },
    }


def _deployment_replicaset_pod(name: str, namespace: str, *, image: str = "registry.x/app:1",
                                digest: str | None = None, replicas: int = 1) -> list[dict]:
    """A full Deployment -> ReplicaSet -> Pod chain, as a real cluster reports it."""
    rs_name = f"{name}-7d9f5b6c8d"
    pod_name = f"{rs_name}-x1"
    rs_owner = {"apiVersion": "apps/v1", "kind": "ReplicaSet", "name": rs_name, "controller": True}
    return [
        _deployment_manifest(name, namespace, image=image, replicas=replicas),
        _replicaset_manifest(rs_name, namespace, name, image=image),
        _pod_manifest(pod_name, namespace, owner=rs_owner, image=image, digest=digest),
    ]


def _vuln_report(*, namespace: str, workload_kind: str, workload_name: str,
                  container: str = "app", image_digest: str, image_repo: str = "registry.x/app",
                  image_tag: str = "1", vulns: list[dict] | None = None) -> dict:
    """Trivy labels the report with the SCANNED controller (typically the
    ReplicaSet, not the Deployment) — matching real Trivy Operator output.
    """
    return {
        "apiVersion": "aquasecurity.github.io/v1alpha1", "kind": "VulnerabilityReport",
        "metadata": {
            "name": f"{workload_kind.lower()}-{workload_name}-{container}",
            "namespace": namespace,
            "labels": {
                "trivy-operator.resource.namespace": namespace,
                "trivy-operator.resource.kind": workload_kind,
                "trivy-operator.resource.name": workload_name,
                "trivy-operator.container.name": container,
            },
        },
        "report": {
            "scanner": {"name": "Trivy", "vendor": "Aqua Security", "version": "0.52.0"},
            "artifact": {"repository": image_repo, "tag": image_tag, "digest": image_digest},
            "os": {"family": "debian", "name": "12"},
            "vulnerabilities": vulns or [],
        },
    }


def _vuln(vid: str, *, pkg: str = "libc6", severity: str = "CRITICAL", score: float = 9.8) -> dict:
    return {
        "vulnerabilityID": vid, "resource": pkg, "installedVersion": "1.0",
        "fixedVersion": "1.1", "severity": severity, "score": score,
        "title": f"Test issue {vid}", "primaryLink": f"https://avd.aquasec.com/nvd/{vid.lower()}",
        "links": [],
    }


def _sbom_report(*, namespace: str, workload_kind: str, workload_name: str,
                  container: str = "app", image_digest: str, image_repo: str = "registry.x/app",
                  image_tag: str = "1", components: list[dict] | None = None) -> dict:
    return {
        "apiVersion": "aquasecurity.github.io/v1alpha1", "kind": "SbomReport",
        "metadata": {
            "name": f"{workload_kind.lower()}-{workload_name}-{container}",
            "namespace": namespace,
            "labels": {
                "trivy-operator.resource.namespace": namespace,
                "trivy-operator.resource.kind": workload_kind,
                "trivy-operator.resource.name": workload_name,
                "trivy-operator.container.name": container,
            },
        },
        "report": {
            "artifact": {"repository": image_repo, "tag": image_tag, "digest": image_digest},
            "components": {
                "bomFormat": "CycloneDX", "specVersion": "1.4",
                "metadata": {"component": {"type": "container", "name": f"{image_repo}:{image_tag}"}},
                "components": components or [],
            },
        },
    }


def _policy_report(*, namespace: str, results: list[dict]) -> dict:
    return {
        "apiVersion": "wgpolicyk8s.io/v1alpha2", "kind": "PolicyReport",
        "metadata": {"namespace": namespace, "name": "polr-x"},
        "scope": {},
        "results": results,
    }


def _kyverno_result(*, policy: str = "disallow-host-namespaces", subject_kind: str,
                     subject_name: str, subject_namespace: str) -> dict:
    return {
        "policy": policy, "rule": "host-namespaces", "result": "fail", "severity": "high",
        "message": f"Workload {subject_name} violates host-namespaces",
        "subjects": [{"kind": subject_kind, "name": subject_name, "namespace": subject_namespace}],
    }


# ── A. Basic deployed tracking ────────────────────────────────────


@pytest.mark.django_db(transaction=True)
def test_full_inventory_cycle_marks_workload_and_image_deployed(client, token):
    items = [_ns_manifest("ns"), *_deployment_replicaset_pod("api", "ns")]
    totals = _run_inventory_cycle(client, token, cluster="e2e-c1", import_id="imp-1", items=items)

    assert totals["reaps_fired"] >= 1

    wl = Workload.objects.get(cluster__name="e2e-c1", namespace__name="ns",
                               kind="Deployment", name="api")
    assert wl.deployed is True

    image = Image.objects.get(digest="sha256:" + "a" * 64)
    assert Image.objects.currently_running(cluster=wl.cluster).filter(pk=image.pk).exists()
    obs = WorkloadImageObservation.objects.get(workload=wl, image=image)
    assert obs.currently_deployed is True


# ── B. Removed vs. scaled-to-zero ─────────────────────────────────


@pytest.mark.django_db(transaction=True)
def test_workload_absent_from_next_complete_cycle_becomes_undeployed(client, token):
    items = [_ns_manifest("ns"), *_deployment_replicaset_pod("api", "ns")]
    _run_inventory_cycle(client, token, cluster="e2e-c2", import_id="imp-1", items=items)

    # Cycle 2: the Deployment is gone entirely (deleted from the cluster).
    _run_inventory_cycle(
        client, token, cluster="e2e-c2", import_id="imp-2",
        items=[_ns_manifest("ns")], complete=True,
    )

    wl = Workload.objects.get(cluster__name="e2e-c2", name="api")
    assert wl.deployed is False
    obs = WorkloadImageObservation.objects.get(workload=wl)
    assert obs.currently_deployed is False
    assert not Image.objects.currently_running(cluster=wl.cluster).filter(
        digest="sha256:" + "a" * 64,
    ).exists()


@pytest.mark.django_db(transaction=True)
def test_scaled_to_zero_is_undeployed_but_row_persists_unlike_removal(client, token):
    """replicas=0 lands the same `deployed=False` as full removal, but —
    unlike removal — the Workload row's `last_inventory_at` keeps
    advancing every cycle, since it's still IN inventory, just at 0 pods."""
    items = [_ns_manifest("ns"), *_deployment_replicaset_pod("api", "ns", replicas=1)]
    _run_inventory_cycle(client, token, cluster="e2e-c3", import_id="imp-1", items=items)
    wl = Workload.objects.get(cluster__name="e2e-c3", name="api")
    assert wl.deployed is True
    first_cycle_seen_at = wl.last_inventory_at

    scaled = [_ns_manifest("ns"), _deployment_manifest("api", "ns", replicas=0)]
    _run_inventory_cycle(client, token, cluster="e2e-c3", import_id="imp-2", items=scaled)

    wl.refresh_from_db()
    assert wl.deployed is False
    assert wl.last_inventory_at > first_cycle_seen_at, (
        "a scaled-to-zero workload is still observed every cycle, unlike a removed one"
    )


# ── C. Image upgrade ───────────────────────────────────────────────


@pytest.mark.django_db(transaction=True)
def test_image_upgrade_flips_currently_deployed_from_old_to_new(client, token):
    old_digest = "sha256:" + "b" * 64
    new_digest = "sha256:" + "c" * 64

    items_v1 = [_ns_manifest("ns"), *_deployment_replicaset_pod(
        "api", "ns", image="registry.x/app:1", digest=old_digest,
    )]
    _run_inventory_cycle(client, token, cluster="e2e-c4", import_id="imp-1", items=items_v1)

    items_v2 = [_ns_manifest("ns"), *_deployment_replicaset_pod(
        "api", "ns", image="registry.x/app:2", digest=new_digest,
    )]
    _run_inventory_cycle(client, token, cluster="e2e-c4", import_id="imp-2", items=items_v2)

    wl = Workload.objects.get(cluster__name="e2e-c4", name="api")
    assert wl.deployed is True

    old_image = Image.objects.get(digest=old_digest)
    new_image = Image.objects.get(digest=new_digest)
    assert WorkloadImageObservation.objects.get(workload=wl, image=old_image).currently_deployed is False
    assert WorkloadImageObservation.objects.get(workload=wl, image=new_image).currently_deployed is True

    running_digests = set(
        Image.objects.currently_running(cluster=wl.cluster).values_list("digest", flat=True)
    )
    assert new_digest in running_digests
    assert old_digest not in running_digests


# ── D. Vulnerability findings, resolved via the ReplicaSet alias ──


@pytest.mark.django_db(transaction=True)
def test_vulnerability_report_resolves_to_deployment_via_replicaset_alias(client, token):
    """Trivy labels the report with the ReplicaSet it actually scanned —
    the finding must still land on the Deployment, not the ReplicaSet."""
    digest = "sha256:" + "d" * 64
    inv_items = [_ns_manifest("ns"), *_deployment_replicaset_pod(
        "api", "ns", image="registry.x/app:1", digest=digest,
    )]
    _start(client, token, cluster="e2e-c5", kind="inventory", import_id="imp-1")
    _start(client, token, cluster="e2e-c5", kind="trivy.VulnerabilityReport", import_id="imp-1")

    envelope = {"cluster_meta": {"name": "e2e-c5"}, "complete_snapshot": True, "items": inv_items}
    _ingest(client, token, cluster="e2e-c5", kind="inventory", import_id="imp-1",
            payload=envelope, complete_snapshot=True)

    vuln_payload = _vuln_report(
        namespace="ns", workload_kind="ReplicaSet", workload_name="api-7d9f5b6c8d",
        image_digest=digest, vulns=[_vuln("CVE-2024-1")],
    )
    _ingest(client, token, cluster="e2e-c5", kind="trivy.VulnerabilityReport", import_id="imp-1",
            payload=vuln_payload)

    _finish(client, token, cluster="e2e-c5", kind="inventory", import_id="imp-1",
            observed_count=len(inv_items))
    _finish(client, token, cluster="e2e-c5", kind="trivy.VulnerabilityReport", import_id="imp-1",
            observed_count=1)
    _drain()

    wl = Workload.objects.get(cluster__name="e2e-c5", kind="Deployment", name="api")
    finding = Finding.objects.get(vuln_id="CVE-2024-1")
    assert finding.workload_id == wl.id, "must resolve to the Deployment, not the ReplicaSet"

    visible = restrict_to_currently_deployed_images(default_finding_qs()).filter(pk=finding.pk)
    assert visible.exists()


@pytest.mark.django_db(transaction=True)
def test_finding_no_longer_visible_once_its_image_is_replaced(client, token):
    """CVE found on image A; workload redeploys to fixed image B. The old
    Finding (bound to image A) must drop out of default visibility even
    though the workload itself stays deployed and healthy."""
    digest_a = "sha256:" + "1" * 64
    digest_b = "sha256:" + "2" * 64

    def _cycle(import_id, image_tag, digest, vulns):
        inv_items = [_ns_manifest("ns"), *_deployment_replicaset_pod(
            "api", "ns", image=f"registry.x/app:{image_tag}", digest=digest,
        )]
        _start(client, token, cluster="e2e-c6", kind="inventory", import_id=import_id)
        _start(client, token, cluster="e2e-c6", kind="trivy.VulnerabilityReport", import_id=import_id)
        envelope = {"cluster_meta": {"name": "e2e-c6"}, "complete_snapshot": True, "items": inv_items}
        _ingest(client, token, cluster="e2e-c6", kind="inventory", import_id=import_id,
                payload=envelope, complete_snapshot=True)
        vuln_payload = _vuln_report(
            namespace="ns", workload_kind="ReplicaSet", workload_name="api-7d9f5b6c8d",
            image_digest=digest, image_tag=image_tag, vulns=vulns,
        )
        _ingest(client, token, cluster="e2e-c6", kind="trivy.VulnerabilityReport", import_id=import_id,
                payload=vuln_payload)
        _finish(client, token, cluster="e2e-c6", kind="inventory", import_id=import_id,
                observed_count=len(inv_items))
        _finish(client, token, cluster="e2e-c6", kind="trivy.VulnerabilityReport", import_id=import_id,
                observed_count=1)
        _drain()

    _cycle("imp-1", "1", digest_a, [_vuln("CVE-2024-2")])
    old_finding = Finding.objects.get(vuln_id="CVE-2024-2")
    assert restrict_to_currently_deployed_images(default_finding_qs()).filter(
        pk=old_finding.pk,
    ).exists()

    # Redeploy onto a fixed image — CVE-2024-2 no longer reported at all.
    _cycle("imp-2", "2", digest_b, [])

    assert not restrict_to_currently_deployed_images(default_finding_qs()).filter(
        pk=old_finding.pk,
    ).exists(), "finding bound to the old, no-longer-deployed image must drop out of view"


# ── E. Scanner-outage protection ──────────────────────────────────


@pytest.mark.django_db(transaction=True)
def test_scanner_outage_does_not_hide_existing_finding(client, token):
    """A VulnerabilityReport outage (observed_count=0 for a still-deployed
    image) must not make the existing finding disappear — even after a
    LATER complete inventory cycle advances the cluster's watermark past
    the finding's frozen last_seen."""
    digest = "sha256:" + "3" * 64
    inv_items = [_ns_manifest("ns"), *_deployment_replicaset_pod(
        "api", "ns", image="registry.x/app:1", digest=digest,
    )]
    _start(client, token, cluster="e2e-c7", kind="inventory", import_id="imp-1")
    _start(client, token, cluster="e2e-c7", kind="trivy.VulnerabilityReport", import_id="imp-1")
    envelope = {"cluster_meta": {"name": "e2e-c7"}, "complete_snapshot": True, "items": inv_items}
    _ingest(client, token, cluster="e2e-c7", kind="inventory", import_id="imp-1",
            payload=envelope, complete_snapshot=True)
    vuln_payload = _vuln_report(
        namespace="ns", workload_kind="ReplicaSet", workload_name="api-7d9f5b6c8d",
        image_digest=digest, vulns=[_vuln("CVE-2024-3")],
    )
    _ingest(client, token, cluster="e2e-c7", kind="trivy.VulnerabilityReport", import_id="imp-1",
            payload=vuln_payload)
    _finish(client, token, cluster="e2e-c7", kind="inventory", import_id="imp-1",
            observed_count=len(inv_items))
    _finish(client, token, cluster="e2e-c7", kind="trivy.VulnerabilityReport", import_id="imp-1",
            observed_count=1)
    _drain()

    finding = Finding.objects.get(vuln_id="CVE-2024-3")

    # Cycle 2: same inventory (workload still deployed on the same image),
    # but Trivy itself goes down — zero VulnerabilityReport items posted.
    _start(client, token, cluster="e2e-c7", kind="inventory", import_id="imp-2")
    _start(client, token, cluster="e2e-c7", kind="trivy.VulnerabilityReport", import_id="imp-2")
    envelope2 = {"cluster_meta": {"name": "e2e-c7"}, "complete_snapshot": True, "items": inv_items}
    _ingest(client, token, cluster="e2e-c7", kind="inventory", import_id="imp-2",
            payload=envelope2, complete_snapshot=True)
    _finish(client, token, cluster="e2e-c7", kind="inventory", import_id="imp-2",
            observed_count=len(inv_items))
    _finish(client, token, cluster="e2e-c7", kind="trivy.VulnerabilityReport", import_id="imp-2",
            observed_count=0)  # outage: nothing reported
    _drain()

    assert ScanInconsistency.objects.filter(
        cluster__name="e2e-c7", image_digest=digest, seen_in_scans=False,
    ).exists()

    visible = restrict_to_currently_deployed_images(default_finding_qs()).filter(pk=finding.pk)
    assert visible.exists(), (
        "an unresolved scan outage must keep the finding visible even after "
        "a later complete inventory cycle advances the watermark"
    )


# ── F. SBOM ingestion + field-truncation fix ──────────────────────


@pytest.mark.django_db(transaction=True)
def test_sbom_report_persists_components_and_truncates_oversized_fields(client, token):
    digest = "sha256:" + "4" * 64
    inv_items = [_ns_manifest("ns"), *_deployment_replicaset_pod(
        "api", "ns", image="registry.x/app:1", digest=digest,
    )]
    _start(client, token, cluster="e2e-c8", kind="inventory", import_id="imp-1")
    _start(client, token, cluster="e2e-c8", kind="trivy.SbomReport", import_id="imp-1")
    envelope = {"cluster_meta": {"name": "e2e-c8"}, "complete_snapshot": True, "items": inv_items}
    _ingest(client, token, cluster="e2e-c8", kind="inventory", import_id="imp-1",
            payload=envelope, complete_snapshot=True)

    oversized_name = "x" * 400  # SbomComponent.name is max_length=255
    sbom_payload = _sbom_report(
        namespace="ns", workload_kind="ReplicaSet", workload_name="api-7d9f5b6c8d",
        image_digest=digest,
        components=[{
            "type": "library",
            "name": oversized_name,
            "version": "1.0",
            "purl": "pkg:generic/oversized@1.0",
            "properties": [],
        }],
    )
    _ingest(client, token, cluster="e2e-c8", kind="trivy.SbomReport", import_id="imp-1",
            payload=sbom_payload)

    _finish(client, token, cluster="e2e-c8", kind="inventory", import_id="imp-1",
            observed_count=len(inv_items))
    _finish(client, token, cluster="e2e-c8", kind="trivy.SbomReport", import_id="imp-1",
            observed_count=1)
    totals = _drain()

    assert totals["failed"] == 0, "oversized SBOM field must be truncated, not crash the item"
    component = SbomComponent.objects.get(purl="pkg:generic/oversized@1.0")
    assert len(component.name) == 255
    assert component.name == oversized_name[:255]


# ── G. Kyverno: Pod-scoped resolution + no Finding rows (v1 scope) ──


@pytest.mark.django_db(transaction=True)
def test_kyverno_pod_scoped_result_resolves_to_deployment_via_alias(client, token):
    """Kyverno's subject is the literal Pod — must resolve through
    Pod -> ReplicaSet -> Deployment (the persisted-alias fix) to land the
    WorkloadSignal on the Deployment. Also confirms the documented v1
    behavior: no Finding row is created from a Kyverno result."""
    rs_name = "api-7d9f5b6c8d"
    pod_name = f"{rs_name}-x1"
    inv_items = [
        _ns_manifest("ns"),
        _deployment_manifest("api", "ns"),
        _replicaset_manifest(rs_name, "ns", "api"),
        _pod_manifest(pod_name, "ns", owner={
            "apiVersion": "apps/v1", "kind": "ReplicaSet", "name": rs_name, "controller": True,
        }),
    ]
    _start(client, token, cluster="e2e-c9", kind="inventory", import_id="imp-1")
    _start(client, token, cluster="e2e-c9", kind="kyverno.PolicyReport", import_id="imp-1")
    envelope = {"cluster_meta": {"name": "e2e-c9"}, "complete_snapshot": True, "items": inv_items}
    _ingest(client, token, cluster="e2e-c9", kind="inventory", import_id="imp-1",
            payload=envelope, complete_snapshot=True)

    policy_payload = _policy_report(namespace="ns", results=[
        _kyverno_result(subject_kind="Pod", subject_name=pod_name, subject_namespace="ns"),
    ])
    _ingest(client, token, cluster="e2e-c9", kind="kyverno.PolicyReport", import_id="imp-1",
            payload=policy_payload)

    _finish(client, token, cluster="e2e-c9", kind="inventory", import_id="imp-1",
            observed_count=len(inv_items))
    _finish(client, token, cluster="e2e-c9", kind="kyverno.PolicyReport", import_id="imp-1",
            observed_count=1)
    totals = _drain()

    assert totals["failed"] == 0

    wl = Workload.objects.get(cluster__name="e2e-c9", kind="Deployment", name="api")
    signal = WorkloadSignal.objects.get(
        workload=wl, signal_id="kyverno:disallow-host-namespaces",
    )
    assert signal.currently_active is True

    assert not Finding.objects.filter(source="kyverno").exists(), (
        "Kyverno fail-results are WorkloadSignal-only in v1 — no Finding rows"
    )


# ── H. Two clusters ingesting independently ───────────────────────


@pytest.mark.django_db(transaction=True)
def test_two_clusters_do_not_cross_contaminate(client, token):
    items_a = [_ns_manifest("ns"), *_deployment_replicaset_pod(
        "api", "ns", image="registry.x/app:1", digest="sha256:" + "5" * 64,
    )]
    items_b = [_ns_manifest("ns"), *_deployment_replicaset_pod(
        "api", "ns", image="registry.x/app:1", digest="sha256:" + "6" * 64,
    )]

    _run_inventory_cycle(client, token, cluster="e2e-ca", import_id="imp-1", items=items_a)
    _run_inventory_cycle(client, token, cluster="e2e-cb", import_id="imp-1", items=items_b)

    wl_a = Workload.objects.get(cluster__name="e2e-ca", name="api")
    wl_b = Workload.objects.get(cluster__name="e2e-cb", name="api")
    assert wl_a.id != wl_b.id
    assert wl_a.deployed is True and wl_b.deployed is True

    image_a = Image.objects.get(digest="sha256:" + "5" * 64)
    image_b = Image.objects.get(digest="sha256:" + "6" * 64)
    assert Image.objects.currently_running(cluster=wl_a.cluster).filter(pk=image_a.pk).exists()
    assert not Image.objects.currently_running(cluster=wl_a.cluster).filter(pk=image_b.pk).exists()
    assert Image.objects.currently_running(cluster=wl_b.cluster).filter(pk=image_b.pk).exists()
    assert not Image.objects.currently_running(cluster=wl_b.cluster).filter(pk=image_a.pk).exists()
