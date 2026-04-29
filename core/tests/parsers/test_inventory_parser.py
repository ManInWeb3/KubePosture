"""Unit tests for core.parsers.inventory.

Focus: alias resolution and standalone-Pod detection — the densest
logic in the parser. These run on `parse_envelope` only (no DB
writes) so they're fast.
"""
from __future__ import annotations

import pytest

from core.models import Cluster
from core.parsers import inventory as inv
from core.constants import WorkloadKind


def _envelope(*items: dict, complete: bool = True) -> dict:
    return {
        "cluster_meta": {"name": "test-cluster"},
        "complete_snapshot": complete,
        "items": list(items),
    }


def _ns(name: str) -> dict:
    return {
        "apiVersion": "v1",
        "kind": "Namespace",
        "metadata": {"name": name, "labels": {}, "annotations": {}},
    }


def _deployment(name: str, namespace: str, image: str = "registry.x/app:1") -> dict:
    return {
        "apiVersion": "apps/v1",
        "kind": "Deployment",
        "metadata": {"name": name, "namespace": namespace, "labels": {"app": name}},
        "spec": {
            "replicas": 1,
            "selector": {"matchLabels": {"app": name}},
            "template": {
                "metadata": {"labels": {"app": name}},
                "spec": {"containers": [{"name": "app", "image": image}]},
            },
        },
    }


def _replicaset(name: str, namespace: str, owner_deployment: str, image: str = "registry.x/app:1") -> dict:
    return {
        "apiVersion": "apps/v1",
        "kind": "ReplicaSet",
        "metadata": {
            "name": name,
            "namespace": namespace,
            "labels": {"app": owner_deployment, "pod-template-hash": "abc"},
            "ownerReferences": [
                {"apiVersion": "apps/v1", "kind": "Deployment", "name": owner_deployment, "controller": True}
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


def _pod(
    name: str,
    namespace: str,
    *,
    image: str = "registry.x/app:1",
    owner: dict | None = None,
) -> dict:
    meta: dict = {"name": name, "namespace": namespace, "labels": {"app": name}}
    if owner is not None:
        meta["ownerReferences"] = [owner]
    return {
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": meta,
        "spec": {"containers": [{"name": "app", "image": image}]},
        "status": {
            "phase": "Running",
            "containerStatuses": [
                {
                    "name": "app",
                    "image": image,
                    "imageID": f"{image}@sha256:" + "a" * 64,
                    "ready": True,
                    "started": True,
                }
            ],
        },
    }


def _cronjob(name: str, namespace: str, image: str = "registry.x/app:1") -> dict:
    return {
        "apiVersion": "batch/v1",
        "kind": "CronJob",
        "metadata": {"name": name, "namespace": namespace, "labels": {"app": name}},
        "spec": {
            "schedule": "0 0 * * *",
            "jobTemplate": {
                "spec": {
                    "template": {
                        "metadata": {"labels": {"app": name}},
                        "spec": {"containers": [{"name": "app", "image": image}]},
                    }
                }
            },
        },
    }


def _job(name: str, namespace: str, *, owner_cronjob: str | None = None, image: str = "registry.x/app:1") -> dict:
    meta: dict = {"name": name, "namespace": namespace, "labels": {"app": name}}
    if owner_cronjob:
        meta["ownerReferences"] = [
            {"apiVersion": "batch/v1", "kind": "CronJob", "name": owner_cronjob, "controller": True}
        ]
    return {
        "apiVersion": "batch/v1",
        "kind": "Job",
        "metadata": meta,
        "spec": {
            "template": {
                "metadata": {"labels": {"app": name}},
                "spec": {
                    "restartPolicy": "OnFailure",
                    "containers": [{"name": "app", "image": image}],
                },
            }
        },
    }


# ── Tests ─────────────────────────────────────────────────────────


def _cluster() -> Cluster:
    return Cluster(name="test-cluster", id=1)


def test_naked_pod_becomes_standalone_workload_kind_pod():
    """A Pod with no ownerReferences becomes a Workload kind=Pod."""
    payload = _envelope(_ns("ns"), _pod("naked-runner", "ns"))
    st = inv.parse_envelope(payload, _cluster())

    key = ("ns", WorkloadKind.POD.value, "naked-runner")
    assert key in st.workloads, "naked Pod should become a standalone Workload"
    assert st.workloads[key].kind == WorkloadKind.POD.value


def test_pod_with_live_controller_owner_is_not_a_workload():
    """A Pod owned by a present ReplicaSet does NOT become a Workload."""
    rs_owner = {
        "apiVersion": "apps/v1",
        "kind": "ReplicaSet",
        "name": "api-server-7d9f5b6c8d",
        "controller": True,
    }
    payload = _envelope(
        _ns("ns"),
        _deployment("api-server", "ns"),
        _replicaset("api-server-7d9f5b6c8d", "ns", "api-server"),
        _pod("api-server-7d9f5b6c8d-x1", "ns", owner=rs_owner),
    )
    st = inv.parse_envelope(payload, _cluster())

    pod_key = ("ns", WorkloadKind.POD.value, "api-server-7d9f5b6c8d-x1")
    assert pod_key not in st.workloads, "owned Pod must not become a Workload"

    # Deployment IS a workload
    dep_key = ("ns", WorkloadKind.DEPLOYMENT.value, "api-server")
    assert dep_key in st.workloads


def test_replicaset_with_owner_does_not_become_workload():
    """ReplicaSets are alias objects, not workloads."""
    payload = _envelope(
        _ns("ns"),
        _deployment("api", "ns"),
        _replicaset("api-aaa11", "ns", "api"),
    )
    st = inv.parse_envelope(payload, _cluster())

    rs_key = ("ns", "ReplicaSet", "api-aaa11")
    assert rs_key not in st.workloads
    # But it's tracked in aliases
    assert ("ns", "ReplicaSet", "api-aaa11") in st.aliases


def test_job_owned_by_cronjob_is_alias_not_workload():
    """Job with CronJob owner → alias to CronJob, not its own workload."""
    payload = _envelope(
        _ns("ns"),
        _cronjob("nightly-backup", "ns"),
        _job("nightly-backup-1234", "ns", owner_cronjob="nightly-backup"),
    )
    st = inv.parse_envelope(payload, _cluster())

    cj_key = ("ns", WorkloadKind.CRONJOB.value, "nightly-backup")
    job_key = ("ns", WorkloadKind.JOB.value, "nightly-backup-1234")
    assert cj_key in st.workloads
    assert job_key not in st.workloads
    # Job is tracked as alias to CronJob
    assert ("ns", "Job", "nightly-backup-1234") in st.aliases


def test_standalone_job_no_cronjob_owner_is_a_workload():
    """A Job without a CronJob owner is itself a workload."""
    payload = _envelope(_ns("ns"), _job("backup-once", "ns"))
    st = inv.parse_envelope(payload, _cluster())

    job_key = ("ns", WorkloadKind.JOB.value, "backup-once")
    assert job_key in st.workloads


def test_complete_snapshot_flag_propagates_to_staging():
    """complete_snapshot from envelope is reflected on staging."""
    st_complete = inv.parse_envelope(
        _envelope(_ns("ns"), _deployment("a", "ns"), complete=True), _cluster()
    )
    assert st_complete.complete_snapshot is True

    st_partial = inv.parse_envelope(
        _envelope(_ns("ns"), _deployment("a", "ns"), complete=False), _cluster()
    )
    assert st_partial.complete_snapshot is False


def test_cluster_meta_extracted_from_envelope():
    payload = {
        "cluster_meta": {"name": "test", "k8s_version": "v1.30.2", "provider": "aws"},
        "items": [],
    }
    st = inv.parse_envelope(payload, _cluster())
    assert st.cluster_meta["k8s_version"] == "v1.30.2"
    assert st.cluster_meta["provider"] == "aws"


def test_empty_envelope_does_not_crash():
    """An empty inventory payload parses to empty staging without raising."""
    st = inv.parse_envelope({}, _cluster())
    assert st.workloads == {}
    assert st.complete_snapshot is False


def test_unknown_kind_silently_skipped():
    """A kind not in the dispatch table doesn't crash the parser."""
    payload = _envelope(
        _ns("ns"),
        {"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": "x", "namespace": "ns"}},
        _deployment("api", "ns"),
    )
    st = inv.parse_envelope(payload, _cluster())
    # ConfigMap silently skipped; Deployment still parsed
    assert ("ns", WorkloadKind.DEPLOYMENT.value, "api") in st.workloads


def test_pod_security_signals_detected_from_pod_spec():
    """Pod with hostNetwork=true emits a kp:has-host-network signal."""
    pod = _pod("naked", "ns")
    pod["spec"]["hostNetwork"] = True
    pod["spec"]["hostPID"] = True
    payload = _envelope(_ns("ns"), pod)
    st = inv.parse_envelope(payload, _cluster())

    key = ("ns", WorkloadKind.POD.value, "naked")
    sigs = st.derived_signals.get(key, set())
    # Signal IDs are namespaced kp:* — exact ID pattern verified by signals tests;
    # for parser test we just confirm signals are present
    assert sigs, "hostNetwork/hostPID should produce derived signals"


@pytest.mark.django_db
def test_image_currently_running_anchored_on_cluster_last_complete_inventory():
    """Regression test for the Image.deployed → derived refactor.

    An image is `currently_running` iff some observation's
    `last_seen_at >= cluster.last_complete_inventory_at`. Verifies
    the safety belt: an observation older than the cluster's last
    complete cycle is excluded (the sidecar-removed semantic from
    scenario 13), but a partial cycle does NOT advance the anchor
    (the scenario 5 / 6 semantic) so prior observations stay valid.
    """
    from datetime import timedelta
    from django.utils import timezone
    from core.models import (
        Cluster as ClusterM, Image, Namespace, Workload,
        WorkloadImageObservation,
    )

    cluster = ClusterM.objects.create(name="anchor-test-cluster")
    ns = Namespace.objects.create(cluster=cluster, name="ns")

    t0 = timezone.now() - timedelta(hours=1)
    t_complete = timezone.now() - timedelta(minutes=30)
    cluster.last_complete_inventory_at = t_complete
    cluster.save()

    wl = Workload.objects.create(
        cluster=cluster, namespace=ns, kind="Deployment", name="api",
        deployed=True, last_inventory_at=t_complete,
    )

    img_current = Image.objects.create(digest="sha256:" + "a" * 64, ref="x:current")
    img_stale = Image.objects.create(digest="sha256:" + "b" * 64, ref="x:stale")

    obs_current = WorkloadImageObservation.objects.create(
        workload=wl, image=img_current, container_name="app",
    )
    WorkloadImageObservation.objects.filter(pk=obs_current.pk).update(
        last_seen_at=t_complete + timedelta(seconds=1),
    )
    obs_stale = WorkloadImageObservation.objects.create(
        workload=wl, image=img_stale, container_name="sidecar",
    )
    WorkloadImageObservation.objects.filter(pk=obs_stale.pk).update(
        last_seen_at=t0,
    )

    running = set(
        Image.objects.currently_running(cluster=cluster).values_list("digest", flat=True)
    )
    assert img_current.digest in running
    assert img_stale.digest not in running

    # No complete cycle ever ran → cluster.last_complete_inventory_at is NULL
    # → nothing can be claimed deployed (correct: we have no proof).
    cluster.last_complete_inventory_at = None
    cluster.save()
    assert Image.objects.currently_running(cluster=cluster).count() == 0


def test_items_without_kind_are_counted_not_silently_dropped():
    """Regression for the production bug where the kubernetes Python
    client's typed-list serialization stripped `kind` from each item,
    causing 267 inventory items to be silently dropped at parse time.

    The parser must surface this as `unknown_kind_skipped > 0` so the
    worker logs a WARNING — silent no-op = silent data loss.
    """
    payload = {
        "cluster_meta": {"name": "test"},
        "complete_snapshot": True,
        "items": [
            # No `kind` — the exact shape produced by the buggy importer
            {"apiVersion": "v1", "metadata": {"name": "ns1"}},
            {"apiVersion": "apps/v1", "metadata": {"name": "d1", "namespace": "ns1"}},
            {"apiVersion": "v1", "metadata": {"name": "p1", "namespace": "ns1"},
             "spec": {"containers": [{"name": "c", "image": "x:1"}]}},
        ],
    }
    st = inv.parse_envelope(payload, _cluster())
    assert st.unknown_kind_skipped == 3
    assert st.workloads == {}
    # Items lacking even apiVersion/metadata don't count (skip the noise)
    payload_noise = {
        "cluster_meta": {"name": "test"},
        "items": [{}, {"x": "y"}],  # nothing recognisable
    }
    st_noise = inv.parse_envelope(payload_noise, _cluster())
    assert st_noise.unknown_kind_skipped == 0


def test_two_workloads_same_name_different_namespace_kept_separate():
    """Different namespaces → different staging keys."""
    payload = _envelope(
        _ns("a"),
        _ns("b"),
        _deployment("worker", "a"),
        _deployment("worker", "b"),
    )
    st = inv.parse_envelope(payload, _cluster())

    assert ("a", WorkloadKind.DEPLOYMENT.value, "worker") in st.workloads
    assert ("b", WorkloadKind.DEPLOYMENT.value, "worker") in st.workloads
    assert len(st.workloads) == 2
