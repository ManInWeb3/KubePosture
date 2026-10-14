"""End-to-end import lifecycle tests — real HTTP views, real queue drain.

Unlike every other "integration" test in this repo, these drive the
actual production entry points: `POST /api/v1/imports/<id>/bundles/<kind>/`
(gzip NDJSON, bearer-token auth) -> `POST /api/v1/imports/<id>/commit/`,
then `core.services.worker.drain_until_empty()` (the same call
`manage.py process_ingest_queue` makes) — not direct ORM seeding, and
not the `core/api/testing_views.py` harness. The bundle bytes are built
with `core.services.bundle_ingest.build_ndjson`, which produces the same
format the importer's streaming writer emits.

Each test asserts on the actual downstream state the pipeline exists to
maintain: `Workload.deployed`, `WorkloadImageObservation.currently_deployed`
/ `Image.objects.currently_running()`, `Finding` visibility, `WorkloadSignal`,
and `SbomComponent` — not just "the queue drained without error".
"""
from __future__ import annotations

import gzip
import json
from datetime import timedelta
from unittest.mock import patch

import pytest
from django.core.management import call_command
from django.utils import timezone

from core.api.auth import generate_token
from core.constants import ImportDiscardReason, ImportMarkState
from core.models import (
    Finding,
    Image,
    ImportMark,
    IngestQueue,
    IngestToken,
    SbomComponent,
    ScanInconsistency,
    Workload,
    WorkloadImageObservation,
    WorkloadSignal,
)
from core.services import ingest as ingest_service
from core.services.bundle_ingest import build_ndjson
from core.services.inventory import default_finding_qs, restrict_to_currently_deployed_images
from core.services.reaper import STUCK_OPEN_TIMEOUT_SECONDS
from core.services.worker import drain_until_empty

VULN = "trivy.VulnerabilityReport"
SBOM = "trivy.SbomReport"
KYVERNO = "kyverno.PolicyReport"

pytestmark = pytest.mark.e2e


# ── HTTP + drain helpers ─────────────────────────────────────────


@pytest.fixture
def token(db) -> str:
    plain, hashed = generate_token()
    IngestToken.objects.create(name="e2e-test", token_hash=hashed)
    return plain


def _auth(token: str) -> dict:
    return {"HTTP_AUTHORIZATION": f"Bearer {token}"}


def _bundle_bytes(*, cluster: str, import_id: str, kind: str, items: list[dict],
                  complete_snapshot: bool = False, coverage: dict | None = None) -> bytes:
    return build_ndjson(
        items, cluster=cluster, import_id=import_id, kind=kind,
        complete_snapshot=complete_snapshot, coverage=coverage,
    )


def _upload_bundle(client, token, *, cluster: str, import_id: str, kind: str, items: list[dict],
                   complete_snapshot: bool = False, coverage: dict | None = None, expect: int = 201):
    raw = _bundle_bytes(
        cluster=cluster, import_id=import_id, kind=kind, items=items,
        complete_snapshot=complete_snapshot, coverage=coverage,
    )
    resp = client.post(
        f"/api/v1/imports/{import_id}/bundles/{kind}/",
        data=gzip.compress(raw),
        content_type="application/x-ndjson",
        HTTP_CONTENT_ENCODING="gzip",
        **_auth(token),
    )
    assert resp.status_code == expect, resp.content
    return resp


def _commit(client, token, *, cluster: str, import_id: str, kinds: dict[str, int], expect: int = 200):
    resp = client.post(
        f"/api/v1/imports/{import_id}/commit/",
        data=json.dumps({
            "cluster": cluster,
            "kinds": [{"kind": k, "count": n} for k, n in kinds.items()],
        }),
        content_type="application/json",
        **_auth(token),
    )
    assert resp.status_code == expect, resp.content
    return resp


def _abort(client, token, *, cluster: str, import_id: str, expect: int = 200):
    resp = client.post(
        f"/api/v1/imports/{import_id}/abort/",
        data=json.dumps({"cluster": cluster}),
        content_type="application/json",
        **_auth(token),
    )
    assert resp.status_code == expect, resp.content
    return resp


def _drain():
    return drain_until_empty(limit=100)


def _envelope(cluster: str, items: list[dict], *, complete: bool = True) -> dict:
    return {"cluster_meta": {"name": cluster}, "complete_snapshot": complete, "items": items}


def _run_inventory_cycle(client, token, *, cluster: str, import_id: str, items: list[dict],
                          complete: bool = True):
    """One full inventory cycle through the real views, then drain."""
    _upload_bundle(
        client, token, cluster=cluster, import_id=import_id, kind="inventory",
        items=[_envelope(cluster, items, complete=complete)], complete_snapshot=complete,
    )
    _commit(client, token, cluster=cluster, import_id=import_id, kinds={"inventory": 1})
    return _drain()


def _run_cycle(client, token, *, cluster: str, import_id: str, inv_items: list[dict],
               scans: dict[str, list[dict]]):
    """Inventory + any number of scan kinds, one commit, then drain."""
    _upload_bundle(
        client, token, cluster=cluster, import_id=import_id, kind="inventory",
        items=[_envelope(cluster, inv_items)], complete_snapshot=True,
    )
    kinds = {"inventory": 1}
    for kind, items in scans.items():
        _upload_bundle(client, token, cluster=cluster, import_id=import_id, kind=kind, items=items)
        kinds[kind] = len(items)
    _commit(client, token, cluster=cluster, import_id=import_id, kinds=kinds)
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

    mark = ImportMark.objects.get(cluster__name="e2e-c1", kind="inventory", import_id="imp-1")
    assert mark.state == ImportMarkState.REAPED.value
    assert wl.cluster.last_complete_inventory_at == mark.started_at


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
    the finding must still land on the Deployment, not the ReplicaSet.
    The scan bundle is uploaded BEFORE inventory, as the importer does."""
    digest = "sha256:" + "d" * 64
    inv_items = [_ns_manifest("ns"), *_deployment_replicaset_pod(
        "api", "ns", image="registry.x/app:1", digest=digest,
    )]
    vuln_payload = _vuln_report(
        namespace="ns", workload_kind="ReplicaSet", workload_name="api-7d9f5b6c8d",
        image_digest=digest, vulns=[_vuln("CVE-2024-1")],
    )
    _upload_bundle(client, token, cluster="e2e-c5", import_id="imp-1", kind=VULN, items=[vuln_payload])
    _upload_bundle(client, token, cluster="e2e-c5", import_id="imp-1", kind="inventory",
                   items=[_envelope("e2e-c5", inv_items)], complete_snapshot=True)
    _commit(client, token, cluster="e2e-c5", import_id="imp-1", kinds={"inventory": 1, VULN: 1})
    _drain()

    wl = Workload.objects.get(cluster__name="e2e-c5", kind="Deployment", name="api")
    finding = Finding.objects.get(vuln_id="CVE-2024-1")
    assert finding.workload_id == wl.id, "must resolve to the Deployment, not the ReplicaSet"

    visible = restrict_to_currently_deployed_images(default_finding_qs()).filter(pk=finding.pk)
    assert visible.exists()
    # Import-wide started_at: the scan rows were created before the
    # inventory bundle existed, yet the finding is not hidden behind the
    # anchor the inventory reap advanced to.
    assert finding.last_seen >= wl.cluster.last_complete_inventory_at


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
        vuln_payload = _vuln_report(
            namespace="ns", workload_kind="ReplicaSet", workload_name="api-7d9f5b6c8d",
            image_digest=digest, image_tag=image_tag, vulns=vulns,
        )
        _run_cycle(client, token, cluster="e2e-c6", import_id=import_id,
                   inv_items=inv_items, scans={VULN: [vuln_payload]})

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
    """A VulnerabilityReport outage — the importer uploads an EMPTY
    bundle (count 0) for a still-deployed image — must not make the
    existing finding disappear, even after a LATER complete inventory
    cycle advances the cluster's watermark past the finding's frozen
    last_seen."""
    digest = "sha256:" + "3" * 64
    inv_items = [_ns_manifest("ns"), *_deployment_replicaset_pod(
        "api", "ns", image="registry.x/app:1", digest=digest,
    )]
    vuln_payload = _vuln_report(
        namespace="ns", workload_kind="ReplicaSet", workload_name="api-7d9f5b6c8d",
        image_digest=digest, vulns=[_vuln("CVE-2024-3")],
    )
    _run_cycle(client, token, cluster="e2e-c7", import_id="imp-1",
               inv_items=inv_items, scans={VULN: [vuln_payload]})
    finding = Finding.objects.get(vuln_id="CVE-2024-3")

    # Cycle 2: same inventory (workload still deployed on the same image),
    # but Trivy itself goes down — zero VulnerabilityReport items.
    _run_cycle(client, token, cluster="e2e-c7", import_id="imp-2",
               inv_items=inv_items, scans={VULN: []})

    assert ImportMark.objects.get(cluster__name="e2e-c7", kind=VULN, import_id="imp-2").observed_count == 0
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
    totals = _run_cycle(client, token, cluster="e2e-c8", import_id="imp-1",
                        inv_items=inv_items, scans={SBOM: [sbom_payload]})

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
    policy_payload = _policy_report(namespace="ns", results=[
        _kyverno_result(subject_kind="Pod", subject_name=pod_name, subject_namespace="ns"),
    ])
    totals = _run_cycle(client, token, cluster="e2e-c9", import_id="imp-1",
                        inv_items=inv_items, scans={KYVERNO: [policy_payload]})

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


# ── I. Abort leaves nothing behind ────────────────────────────────


@pytest.mark.django_db(transaction=True)
def test_abort_leaves_no_rows_or_marks_and_next_import_works(client, token):
    digest = "sha256:" + "7" * 64
    inv_items = [_ns_manifest("ns"), *_deployment_replicaset_pod("api", "ns", digest=digest)]
    _upload_bundle(client, token, cluster="e2e-ci", import_id="imp-1", kind="inventory",
                   items=[_envelope("e2e-ci", inv_items)], complete_snapshot=True)
    _upload_bundle(client, token, cluster="e2e-ci", import_id="imp-1", kind=VULN, items=[
        _vuln_report(namespace="ns", workload_kind="ReplicaSet", workload_name="api-7d9f5b6c8d",
                     image_digest=digest, vulns=[_vuln("CVE-2024-9")]),
    ])

    _abort(client, token, cluster="e2e-ci", import_id="imp-1")
    totals = _drain()

    assert totals["claimed"] == 0
    assert not ImportMark.objects.filter(cluster__name="e2e-ci").exists()
    assert not IngestQueue.objects.filter(cluster_name="e2e-ci").exists()
    assert not Workload.objects.filter(cluster__name="e2e-ci").exists()
    assert not Finding.objects.filter(vuln_id="CVE-2024-9").exists()

    _run_inventory_cycle(client, token, cluster="e2e-ci", import_id="imp-2", items=inv_items)
    assert Workload.objects.get(cluster__name="e2e-ci", name="api").deployed is True


# ── J. Lost response → re-upload is idempotent ────────────────────


@pytest.mark.django_db(transaction=True)
def test_reupload_after_lost_response_is_idempotent_end_to_end(client, token):
    inv_items = [_ns_manifest("ns"), *_deployment_replicaset_pod("api", "ns")]
    envelope = [_envelope("e2e-cj", inv_items)]
    _upload_bundle(client, token, cluster="e2e-cj", import_id="imp-1", kind="inventory",
                   items=envelope, complete_snapshot=True, expect=201)
    # The importer never saw the 201 and retries the identical bytes.
    resp = _upload_bundle(client, token, cluster="e2e-cj", import_id="imp-1", kind="inventory",
                          items=envelope, complete_snapshot=True, expect=200)
    assert resp.json()["status"] == "already_uploaded"

    _commit(client, token, cluster="e2e-cj", import_id="imp-1", kinds={"inventory": 1})
    # And a retried commit is accepted too.
    resp = _commit(client, token, cluster="e2e-cj", import_id="imp-1", kinds={"inventory": 1})
    assert resp.json()["status"] == "already_committed"

    totals = _drain()
    assert totals["ok"] == 1
    assert Workload.objects.get(cluster__name="e2e-cj", name="api").deployed is True


# ── K. Queue holds in-flight work only ────────────────────────────


@pytest.mark.django_db(transaction=True)
def test_queue_empty_after_reap_with_failures_recorded_on_the_mark(client, token):
    digest = "sha256:" + "8" * 64
    inv_items = [_ns_manifest("ns"), *_deployment_replicaset_pod("api", "ns", digest=digest)]
    vuln_payload = _vuln_report(
        namespace="ns", workload_kind="ReplicaSet", workload_name="api-7d9f5b6c8d",
        image_digest=digest, vulns=[_vuln("CVE-2024-10")],
    )
    real_process_item = ingest_service.process_item

    def _flaky(item):
        if item.kind == VULN:
            raise RuntimeError("vuln parser exploded")
        return real_process_item(item)

    with patch("core.services.ingest.process_item", side_effect=_flaky):
        totals = _run_cycle(client, token, cluster="e2e-ck", import_id="imp-1",
                            inv_items=inv_items, scans={VULN: [vuln_payload, vuln_payload]})

    assert (totals["ok"], totals["failed"]) == (1, 2)
    assert IngestQueue.objects.filter(cluster_name="e2e-ck").count() == 0, (
        "done AND failed rows are deleted at reap"
    )
    marks = {m.kind: m for m in ImportMark.objects.filter(cluster__name="e2e-ck", import_id="imp-1")}
    assert all(m.state == ImportMarkState.REAPED.value for m in marks.values())
    assert marks["inventory"].failed_count == 0
    assert marks[VULN].failed_count == 2
    assert "vuln parser exploded" in marks[VULN].last_error
    assert Workload.objects.get(cluster__name="e2e-ck", name="api").deployed is True


# ── L. Uncommitted import is never processed, then discarded ──────


@pytest.mark.django_db(transaction=True)
def test_uncommitted_import_is_never_processed_and_is_discarded_by_safety_net(client, token):
    inv_items = [_ns_manifest("ns"), *_deployment_replicaset_pod("api", "ns")]
    _upload_bundle(client, token, cluster="e2e-cl", import_id="imp-1", kind="inventory",
                   items=[_envelope("e2e-cl", inv_items)], complete_snapshot=True)
    _upload_bundle(client, token, cluster="e2e-cl", import_id="imp-1", kind=VULN, items=[])

    assert _drain()["claimed"] == 0, "open marks are not claimable"
    assert not Workload.objects.filter(cluster__name="e2e-cl").exists()

    # The importer died before commit; the lock window and then the
    # stuck-open TTL pass.
    ImportMark.objects.filter(cluster__name="e2e-cl").update(
        started_at=timezone.now() - timedelta(seconds=STUCK_OPEN_TIMEOUT_SECONDS + 60),
    )
    with patch("core.services.reaper._maybe_capture_heartbeat"):
        call_command("reap_safety_net")

    marks = list(ImportMark.objects.filter(cluster__name="e2e-cl"))
    assert len(marks) == 2
    assert all(m.state == ImportMarkState.REAPED.value for m in marks)
    assert all(m.discard_reason == ImportDiscardReason.STUCK_OPEN.value for m in marks)
    assert not IngestQueue.objects.filter(cluster_name="e2e-cl").exists()
    assert not Workload.objects.filter(cluster__name="e2e-cl").exists()

    pending = client.get("/api/v1/imports/pending/?cluster=e2e-cl", **_auth(token))
    assert pending.status_code == 200 and pending.json()["in_flight"] is False

    _run_inventory_cycle(client, token, cluster="e2e-cl", import_id="imp-2", items=inv_items)
    assert Workload.objects.get(cluster__name="e2e-cl", name="api").deployed is True
