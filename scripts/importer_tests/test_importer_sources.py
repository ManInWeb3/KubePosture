"""Sources: the live kube-api collector (mocked `kubernetes.client`) and
the captured-folder reader.

The kind-stamping tests reproduce a real silent-data-loss bug: the
kubernetes Python client's `sanitize_for_serialization` strips `kind` /
`apiVersion` from items in typed list responses, so the importer posted
inventory items with `kind: None` and central dropped all of them.
"""
from __future__ import annotations

import gzip
import json
from unittest.mock import MagicMock

import pytest
from kubeposture_importer.sources.folder import collect_from_folder
from kubeposture_importer.sources.kube import collect_from_kube_api

# ── kube-api: real typed kubernetes objects, mocked API classes ───────

kubernetes = pytest.importorskip("kubernetes")


def _v1_namespace(name: str):
    from kubernetes.client import V1Namespace, V1ObjectMeta
    return V1Namespace(metadata=V1ObjectMeta(name=name, labels={"team": "x"}))


def _v1_deployment(name: str, namespace: str):
    from kubernetes.client import (
        V1Container,
        V1Deployment,
        V1DeploymentSpec,
        V1LabelSelector,
        V1ObjectMeta,
        V1PodSpec,
        V1PodTemplateSpec,
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
        V1Container,
        V1LabelSelector,
        V1ObjectMeta,
        V1OwnerReference,
        V1PodSpec,
        V1PodTemplateSpec,
        V1ReplicaSet,
        V1ReplicaSetSpec,
    )
    return V1ReplicaSet(
        metadata=V1ObjectMeta(
            name=name, namespace=namespace,
            owner_references=[V1OwnerReference(
                api_version="apps/v1", kind="Deployment", name=owner_deployment,
                uid="00000000-0000-0000-0000-000000000000", controller=True,
            )],
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
    from kubernetes.client import V1Container, V1ObjectMeta, V1Pod, V1PodSpec
    return V1Pod(
        metadata=V1ObjectMeta(name=name, namespace=namespace, labels={"app": name}),
        spec=V1PodSpec(containers=[V1Container(name="app", image="x:1")]),
    )


def _list_response(items):
    resp = MagicMock()
    resp.items = items
    return resp


def _build_mock_module(*, namespaces=(), deployments=(), pods=(), replicasets=(), crd=None):
    """Fake `kubernetes.client` module. `crd` maps plural → list | ApiException | Exception;
    unlisted plurals get an empty list."""
    from kubernetes.client.exceptions import ApiException
    mod = MagicMock()
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

    crd = crd or {}

    def _list_custom(*, group, version, plural, _request_timeout=None):
        value = crd.get(plural, [])
        if isinstance(value, BaseException):
            raise value
        return {"items": list(value)}

    custom = MagicMock()
    custom.list_cluster_custom_object.side_effect = _list_custom
    mod.CustomObjectsApi.return_value = custom

    ver = MagicMock()
    ver.git_version = "v1.30.2"
    mod.VersionApi.return_value.get_code.return_value = ver
    return mod


@pytest.mark.parametrize(
    ("kwargs", "kind", "api_version"),
    [
        ({"namespaces": [_v1_namespace("test-ns")]}, "Namespace", "v1"),
        ({"deployments": [_v1_deployment("api", "payments")]}, "Deployment", "apps/v1"),
        ({"pods": [_v1_pod("api-x1", "payments")]}, "Pod", "v1"),
        ({"replicasets": [_v1_replicaset("api-aaa11", "payments", "api")]}, "ReplicaSet", "apps/v1"),
    ],
)
def test_typed_list_items_carry_kind_and_apiversion(kwargs, kind, api_version):
    out = collect_from_kube_api(_build_mock_module(**kwargs))
    assert len(out[kind]) == 1
    assert out[kind][0].get("kind") == kind, "kubernetes client strips kind from typed list items"
    assert out[kind][0].get("apiVersion") == api_version


def test_crd_items_are_stamped_and_404_means_absent():
    from kubernetes.client.exceptions import ApiException
    mod = _build_mock_module(crd={
        "vulnerabilityreports": [{"metadata": {"name": "r1"}, "report": {}}],
        "sbomreports": ApiException(status=404, reason="Not Found"),
        "policyreports": [],
    })
    out = collect_from_kube_api(mod)
    assert out["VulnerabilityReport"][0]["kind"] == "VulnerabilityReport"
    assert out["VulnerabilityReport"][0]["apiVersion"] == "aquasecurity.github.io/v1alpha1"
    assert "SbomReport" not in out, "CRD not installed → kind omitted from the import"
    assert out["PolicyReport"] == [], "CRD installed, no objects → empty list (count-0 bundle)"
    assert out["__version__"] == {"git_version": "v1.30.2"}


def test_crd_other_errors_yield_empty_list_and_warn(capsys):
    from kubernetes.client.exceptions import ApiException
    mod = _build_mock_module(crd={"configauditreports": ApiException(status=500, reason="Boom")})
    out = collect_from_kube_api(mod)
    assert out["ConfigAuditReport"] == []
    assert "WARN: list configauditreports" in capsys.readouterr().err


# ── folder ────────────────────────────────────────────────────────────


def _write(path, doc, *, gz=False):
    path.parent.mkdir(parents=True, exist_ok=True)
    data = json.dumps(doc).encode()
    if gz:
        path.write_bytes(gzip.compress(data))
    else:
        path.write_bytes(data)


def test_collect_from_folder_handles_wrappers_lists_single_objects_and_gz(tmp_path):
    _write(tmp_path / "kubeapi/pods.json", {"kind": "PodList", "items": [{"metadata": {"name": "p"}}]})
    _write(tmp_path / "kubeapi/deployments.json", [{"metadata": {"name": "d"}}])
    _write(tmp_path / "kubeapi/namespaces.json.gz", {"kind": "NamespaceList", "items": [{"metadata": {"name": "ns"}}]}, gz=True)
    _write(tmp_path / "trivy/sbomreports.json", {"kind": "SbomReportList", "items": []})
    _write(tmp_path / "kyverno/policyreports.json", {"metadata": {"name": "single"}})
    _write(tmp_path / "kubeapi/version.json", {"gitVersion": "v1.29.0"})

    out = collect_from_folder(tmp_path)

    assert out["Pod"] == [{"metadata": {"name": "p"}, "kind": "Pod"}]
    assert out["Deployment"][0]["kind"] == "Deployment"
    assert out["Namespace"][0]["metadata"]["name"] == "ns"
    assert out["SbomReport"] == [], "present but empty → []"
    assert "VulnerabilityReport" not in out, "missing file → absent"
    assert out["PolicyReport"][0]["kind"] == "PolicyReport"
    assert out["__version__"] == {"git_version": "v1.29.0"}


def test_collect_from_folder_reads_kubectl_version_shape(tmp_path):
    _write(tmp_path / "kubeapi/version.json", {"clientVersion": {}, "serverVersion": {"gitVersion": "v1.31.1"}})
    assert collect_from_folder(tmp_path)["__version__"] == {"git_version": "v1.31.1"}


def test_typed_list_error_fails_the_cycle_instead_of_shipping_a_partial_inventory():
    """A transient kube-api error on an inventory list used to yield `[]`;
    the server treats a committed inventory as complete, so one timeout
    on `list_namespace` would deactivate every namespace of the cluster.
    Now it raises before any byte is sent."""
    from kubeposture_importer.sources.kube import InventoryListError
    from kubernetes.client.exceptions import ApiException
    mod = _build_mock_module(namespaces=[_v1_namespace("test-ns")])
    mod.CoreV1Api.return_value.list_namespace.side_effect = ApiException(status=500, reason="Boom")
    with pytest.raises(InventoryListError, match="namespaces: 500 Boom"):
        collect_from_kube_api(mod)


def test_typed_list_404_is_still_an_empty_kind(capsys):
    from kubernetes.client.exceptions import ApiException
    mod = _build_mock_module()
    mod.NetworkingV1Api.return_value.list_network_policy_for_all_namespaces.side_effect = \
        ApiException(status=404, reason="Not Found")
    out = collect_from_kube_api(mod)
    assert out["NetworkPolicy"] == []
    assert "WARN: networkpolicies" in capsys.readouterr().err
