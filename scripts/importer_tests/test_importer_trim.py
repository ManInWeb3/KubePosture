import pytest
from kubeposture_importer.trim import derive_cluster_meta, trim_manifest


def test_trim_pod_keeps_container_statuses_only():
    pod = {
        "kind": "Pod",
        "metadata": {"name": "p", "uid": "u", "resourceVersion": "1", "managedFields": [{}],
                     "creationTimestamp": "t", "annotations": {
                         "kubectl.kubernetes.io/last-applied-configuration": "{}", "keep": "me"},
                     "ownerReferences": [{"kind": "ReplicaSet", "name": "rs", "controller": True}],
                     "deletionTimestamp": "t2"},
        "spec": {"containers": []},
        "status": {"phase": "Running", "containerStatuses": [{"imageID": "x@sha256:a"}],
                   "initContainerStatuses": [{"imageID": "y@sha256:b"}], "conditions": []},
    }
    out = trim_manifest(pod)
    assert out["metadata"] == {"name": "p", "annotations": {"keep": "me"},
                               "ownerReferences": [{"kind": "ReplicaSet", "name": "rs", "controller": True}],
                               "deletionTimestamp": "t2"}
    assert out["status"] == {"containerStatuses": [{"imageID": "x@sha256:a"}],
                             "initContainerStatuses": [{"imageID": "y@sha256:b"}]}
    assert "conditions" not in out["status"]
    assert pod["metadata"]["uid"] == "u", "input not mutated"


def test_trim_non_pod_drops_status_entirely():
    out = trim_manifest({"kind": "Deployment", "metadata": {"name": "d"}, "spec": {}, "status": {"replicas": 1}})
    assert "status" not in out


@pytest.mark.parametrize(
    ("provider_id", "labels", "expected"),
    [
        ("aws:///eu-west-1a/i-123", {"eks.amazonaws.com/nodegroup": "x", "topology.kubernetes.io/region": "eu-west-1"}, ("eks", "eu-west-1")),
        ("aws:///eu-west-1a/i-123", {}, ("aws", "")),
        ("gce://proj/zone/node", {"cloud.google.com/gke-nodepool": "p", "failure-domain.beta.kubernetes.io/region": "us-c1"}, ("gke", "us-c1")),
        ("azure:///subscriptions/x", {"kubernetes.azure.com/agentpool": "a"}, ("aks", "")),
        ("", {}, ("onprem", "")),
    ],
)
def test_derive_cluster_meta(provider_id, labels, expected):
    by_kind = {"__version__": {"git_version": "v1.30.0"},
               "Node": [{"metadata": {"labels": labels}, "spec": {"providerID": provider_id}}]}
    meta = derive_cluster_meta("c", by_kind)
    assert (meta["provider"], meta["region"]) == expected
    assert meta == {"name": "c", "k8s_version": "v1.30.0", "provider": expected[0], "region": expected[1]}


def test_derive_cluster_meta_without_nodes():
    assert derive_cluster_meta("c", {}) == {"name": "c", "k8s_version": "", "provider": "onprem", "region": ""}
