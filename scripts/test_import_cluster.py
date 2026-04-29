"""Regression tests for scripts/import-cluster.py.

These reproduce the silent-data-loss bug observed against a real
cluster: the kubernetes Python client's `sanitize_for_serialization`
strips `kind` / `apiVersion` from individual items in typed list
responses, so the importer was posting inventory items with
`kind: None` and central's parser silently dropped all 267 of them.

The CRD-listing path was unaffected (it calls `setdefault("kind", ...)`
explicitly), so Trivy/Kyverno findings still landed — that's why
the live-cluster import showed 0 workloads but 11 cluster-scoped
RBAC findings.

These tests:
  - Mock the kubernetes Python client to return real typed objects
    (V1Namespace, V1Deployment, V1Pod, V1ReplicaSet) — same shapes
    the live SDK produces.
  - Call `collect_from_kube_api` and assert each emitted dict carries
    the right `kind` and `apiVersion`.

Before the fix to the `_list` helper they FAIL. After the fix they
pass.
"""
from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from unittest.mock import MagicMock

import pytest


# ── Loader: import-cluster.py uses a hyphen, so plain `import` fails.

_REPO_ROOT = Path(__file__).resolve().parents[1]
_SCRIPT_PATH = _REPO_ROOT / "scripts" / "import-cluster.py"


def _load_importer_module():
    """Load scripts/import-cluster.py as a module (handles hyphenated name)."""
    spec = importlib.util.spec_from_file_location("import_cluster", _SCRIPT_PATH)
    assert spec and spec.loader, f"failed to load spec for {_SCRIPT_PATH}"
    mod = importlib.util.module_from_spec(spec)
    sys.modules["import_cluster"] = mod
    spec.loader.exec_module(mod)
    return mod


# ── Fixtures: real typed kubernetes objects (no mock for items themselves).

def _v1_namespace(name: str):
    from kubernetes.client import V1Namespace, V1ObjectMeta
    return V1Namespace(metadata=V1ObjectMeta(name=name, labels={"team": "x"}))


def _v1_deployment(name: str, namespace: str):
    from kubernetes.client import (
        V1Container, V1Deployment, V1DeploymentSpec, V1LabelSelector,
        V1ObjectMeta, V1PodSpec, V1PodTemplateSpec,
    )
    return V1Deployment(
        metadata=V1ObjectMeta(name=name, namespace=namespace, labels={"app": name}),
        spec=V1DeploymentSpec(
            replicas=1,
            selector=V1LabelSelector(match_labels={"app": name}),
            template=V1PodTemplateSpec(
                metadata=V1ObjectMeta(labels={"app": name}),
                spec=V1PodSpec(containers=[V1Container(name="app", image="x:1")]),
            ),
        ),
    )


def _v1_replicaset(name: str, namespace: str, owner_deployment: str):
    from kubernetes.client import (
        V1Container, V1LabelSelector, V1ObjectMeta, V1OwnerReference,
        V1PodSpec, V1PodTemplateSpec, V1ReplicaSet, V1ReplicaSetSpec,
    )
    return V1ReplicaSet(
        metadata=V1ObjectMeta(
            name=name,
            namespace=namespace,
            owner_references=[
                V1OwnerReference(
                    api_version="apps/v1",
                    kind="Deployment",
                    name=owner_deployment,
                    uid="00000000-0000-0000-0000-000000000000",
                    controller=True,
                )
            ],
        ),
        spec=V1ReplicaSetSpec(
            replicas=1,
            selector=V1LabelSelector(match_labels={"app": owner_deployment}),
            template=V1PodTemplateSpec(
                metadata=V1ObjectMeta(labels={"app": owner_deployment}),
                spec=V1PodSpec(containers=[V1Container(name="app", image="x:1")]),
            ),
        ),
    )


def _v1_pod(name: str, namespace: str):
    from kubernetes.client import (
        V1Container, V1ObjectMeta, V1Pod, V1PodSpec,
    )
    return V1Pod(
        metadata=V1ObjectMeta(name=name, namespace=namespace, labels={"app": name}),
        spec=V1PodSpec(containers=[V1Container(name="app", image="x:1")]),
    )


def _list_response(items):
    """Wrap items in a MagicMock that mimics the *List response shape."""
    resp = MagicMock()
    resp.items = items
    return resp


def _build_mock_module(*, namespaces=(), deployments=(), pods=(), replicasets=(), crd_items=None):
    """Build a fake `kubernetes.client` module suitable for collect_from_kube_api.

    Returns a MagicMock that behaves like the `client` module passed
    to `collect_from_kube_api`. Each `*Api()` factory returns a
    sub-mock whose list_* methods yield the supplied typed objects.
    """
    mod = MagicMock()
    # Real ApiException class so the importer's `except client_module.ApiException`
    # works correctly — the importer uses isinstance checking via except.
    from kubernetes.client.exceptions import ApiException
    mod.ApiException = ApiException

    core = MagicMock()
    core.list_namespace.return_value = _list_response(list(namespaces))
    core.list_pod_for_all_namespaces.return_value = _list_response(list(pods))
    core.list_service_for_all_namespaces.return_value = _list_response([])
    core.list_node.return_value = _list_response([])
    mod.CoreV1Api.return_value = core

    apps = MagicMock()
    apps.list_deployment_for_all_namespaces.return_value = _list_response(list(deployments))
    apps.list_stateful_set_for_all_namespaces.return_value = _list_response([])
    apps.list_daemon_set_for_all_namespaces.return_value = _list_response([])
    apps.list_replica_set_for_all_namespaces.return_value = _list_response(list(replicasets))
    mod.AppsV1Api.return_value = apps

    batch = MagicMock()
    batch.list_cron_job_for_all_namespaces.return_value = _list_response([])
    batch.list_job_for_all_namespaces.return_value = _list_response([])
    mod.BatchV1Api.return_value = batch

    net = MagicMock()
    net.list_ingress_for_all_namespaces.return_value = _list_response([])
    net.list_network_policy_for_all_namespaces.return_value = _list_response([])
    mod.NetworkingV1Api.return_value = net

    # CRD path: returns a plain dict (already with apiVersion/kind from upstream).
    custom = MagicMock()
    custom.list_cluster_custom_object.return_value = {"items": list(crd_items or [])}
    mod.CustomObjectsApi.return_value = custom

    # VersionApi for cluster_meta — return something benign.
    ver = MagicMock()
    ver.git_version = "v1.30.2"
    mod.VersionApi.return_value.get_code.return_value = ver

    return mod


# ── Tests ─────────────────────────────────────────────────────────


def test_list_namespace_items_carry_kind_and_apiversion():
    """Regression: typed-list serialization strips kind on items."""
    mod = _load_importer_module()
    fake_module = _build_mock_module(namespaces=[_v1_namespace("test-ns")])

    out = mod.collect_from_kube_api(fake_module)

    assert "Namespace" in out
    assert len(out["Namespace"]) == 1
    item = out["Namespace"][0]
    assert item.get("kind") == "Namespace", (
        f"item missing kind=Namespace; got: {item.get('kind')!r}. "
        "This is the production bug — kubernetes Python client's "
        "sanitize_for_serialization doesn't populate kind on typed items."
    )
    assert item.get("apiVersion") == "v1"


def test_list_deployment_items_carry_kind_and_apiversion():
    mod = _load_importer_module()
    fake_module = _build_mock_module(
        deployments=[_v1_deployment("api-server", "payments")]
    )

    out = mod.collect_from_kube_api(fake_module)

    assert len(out["Deployment"]) == 1
    item = out["Deployment"][0]
    assert item.get("kind") == "Deployment"
    assert item.get("apiVersion") == "apps/v1"


def test_list_pod_items_carry_kind_and_apiversion():
    mod = _load_importer_module()
    fake_module = _build_mock_module(pods=[_v1_pod("api-server-x1", "payments")])

    out = mod.collect_from_kube_api(fake_module)

    assert len(out["Pod"]) == 1
    item = out["Pod"][0]
    assert item.get("kind") == "Pod"
    assert item.get("apiVersion") == "v1"


def test_list_replicaset_items_carry_kind_and_apiversion():
    """ReplicaSet matters because alias resolution depends on kind."""
    mod = _load_importer_module()
    fake_module = _build_mock_module(
        replicasets=[_v1_replicaset("api-aaa11", "payments", "api-server")]
    )

    out = mod.collect_from_kube_api(fake_module)

    assert len(out["ReplicaSet"]) == 1
    item = out["ReplicaSet"][0]
    assert item.get("kind") == "ReplicaSet"
    assert item.get("apiVersion") == "apps/v1"


def test_crd_listing_path_unaffected_by_typed_list_bug():
    """Sanity check: CRD path already stamps kind/apiVersion via setdefault.
    This test passes BOTH before and after the fix — proves the fix
    doesn't regress the working path."""
    mod = _load_importer_module()
    fake_crd_item = {
        "metadata": {"name": "report-1", "namespace": "payments"},
        "report": {"vulnerabilities": []},
    }
    fake_module = _build_mock_module(crd_items=[fake_crd_item])

    out = mod.collect_from_kube_api(fake_module)

    # CRD path stamps kind via _kind_for_plural → 'VulnerabilityReport'
    assert len(out["VulnerabilityReport"]) >= 1
    assert out["VulnerabilityReport"][0]["kind"] == "VulnerabilityReport"
    assert out["VulnerabilityReport"][0]["apiVersion"] == "aquasecurity.github.io/v1alpha1"
