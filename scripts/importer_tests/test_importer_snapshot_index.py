from kubeposture_importer.snapshot_index import build_index, resolve_subject

from .fixtures_builders import (
    SHA_A,
    SHA_B,
    SHA_C,
    SHA_OLD,
    by_kind,
    cronjob,
    daemonset,
    deployment,
    deployment_chain,
    job,
    owner,
    pod,
    replicaset,
    statefulset,
)


def test_deployed_digests_union_of_pod_status_and_pinned_specs():
    items = by_kind(
        *deployment_chain("api", digest=SHA_A),
        statefulset("db", image=f"r/db:1@{SHA_B}"),           # pinned spec, no pod yet
        deployment("web", image="r/web:1"),                   # unpinned, no pod → nothing
    )
    idx = build_index(items)
    assert idx.deployed_digests == {SHA_A, SHA_B}
    assert any(s.startswith("Pod ns/api-abc-x1") for s in idx.digest_sources[SHA_A])
    assert idx.digest_sources[SHA_B] == ["StatefulSet ns/db:app"]


def test_init_container_statuses_and_pinned_init_images_included():
    items = by_kind(
        deployment("api", init_image=f"r/init:1@{SHA_C}"),
        pod("api-abc-x1", owner_ref=owner("ReplicaSet", "api-abc"), digest=SHA_A, init_digest=SHA_B),
    )
    assert build_index(items).deployed_digests == {SHA_A, SHA_B, SHA_C}


def test_replicaset_template_digest_is_not_included():
    """Trivy keeps reports for historical ReplicaSets; their images are not
    running and the server never reads RS templates either."""
    items = by_kind(
        deployment("api"),
        replicaset("api-old", owner_name="api", image=f"r/app:0@{SHA_OLD}", replicas=0),
    )
    assert build_index(items).deployed_digests == set()


def test_terminating_crashloop_and_pending_pods():
    items = by_kind(
        pod("terminating", digest=SHA_A, terminating=True),
        pod("crashloop", digest=SHA_B, phase="Running"),          # has imageID → included
        pod("pullbackoff", digest=None, phase="Pending"),         # no imageID → nothing
    )
    assert build_index(items).deployed_digests == {SHA_A, SHA_B}


def test_scaled_to_zero_deployment_pinned_digest_still_included():
    """Superset on purpose: no replicas check on the importer side."""
    items = by_kind(deployment("api", image=f"r/app:1@{SHA_A}", replicas=0))
    assert build_index(items).deployed_digests == {SHA_A}


def test_ephemeral_container_statuses_ignored():
    items = by_kind(pod("p", digest=SHA_A, ephemeral_digest=SHA_B))
    assert build_index(items).deployed_digests == {SHA_A}


def test_cronjob_template_digest_nested_path():
    items = by_kind(cronjob("nightly", image=f"r/cron:1@{SHA_C}"))
    idx = build_index(items)
    assert idx.deployed_digests == {SHA_C}
    assert ("ns", "CronJob", "nightly") in idx.controllers


def test_image_id_forms_all_normalise():
    items = by_kind(
        pod("a", digest=SHA_A, image_id_style="repo"),
        pod("b", digest=SHA_B, image_id_style="docker-pullable"),
        pod("c", digest=SHA_C, image_id_style="bare"),
    )
    assert build_index(items).deployed_digests == {SHA_A, SHA_B, SHA_C}


def test_controllers_exclude_owned_jobs_pods_and_replicasets():
    items = by_kind(
        *deployment_chain("api"),
        daemonset("agent"),
        cronjob("nightly"),
        job("nightly-123", owner_ref={"apiVersion": "batch/v1", "kind": "CronJob", "name": "nightly", "controller": True}),
        pod("nightly-123-p", owner_ref={"apiVersion": "batch/v1", "kind": "Job", "name": "nightly-123", "controller": True}),
        job("oneoff"),
        pod("standalone", owner_ref=None),
    )
    idx = build_index(items)
    assert idx.controllers == {
        ("ns", "Deployment", "api"), ("kube-system", "DaemonSet", "agent"), ("ns", "CronJob", "nightly"),
        ("ns", "Job", "oneoff"), ("ns", "Pod", "standalone"),
    }
    assert ("ns", "ReplicaSet", "api-abc") in idx.present


def test_resolve_pod_via_replicaset_to_deployment_and_via_job_to_cronjob():
    items = by_kind(
        *deployment_chain("api"),
        cronjob("nightly"),
        job("nightly-123", owner_ref={"apiVersion": "batch/v1", "kind": "CronJob", "name": "nightly", "controller": True}),
        pod("nightly-123-p", owner_ref={"apiVersion": "batch/v1", "kind": "Job", "name": "nightly-123", "controller": True}),
    )
    idx = build_index(items)
    assert resolve_subject(idx, "ns", "Pod", "api-abc-x1") == ("ns", "Deployment", "api")
    assert resolve_subject(idx, "ns", "ReplicaSet", "api-abc") == ("ns", "Deployment", "api")
    assert resolve_subject(idx, "ns", "Pod", "nightly-123-p") == ("ns", "CronJob", "nightly")
    assert resolve_subject(idx, "ns", "Job", "nightly-123") == ("ns", "CronJob", "nightly")
    assert resolve_subject(idx, "ns", "Deployment", "api") == ("ns", "Deployment", "api")


def test_resolve_standalone_pod_and_job_to_themselves():
    idx = build_index(by_kind(job("oneoff"), pod("standalone")))
    assert resolve_subject(idx, "ns", "Job", "oneoff") == ("ns", "Job", "oneoff")
    assert resolve_subject(idx, "ns", "Pod", "standalone") == ("ns", "Pod", "standalone")


def test_resolve_returns_none_when_chain_leaves_snapshot():
    # RS present but its Deployment is gone; a Service is never a workload.
    idx = build_index(by_kind(replicaset("api-old", owner_name="api")))
    assert resolve_subject(idx, "ns", "ReplicaSet", "api-old") is None
    assert resolve_subject(idx, "ns", "Service", "api") is None
    assert resolve_subject(idx, "ns", "Deployment", "missing") is None
    assert resolve_subject(idx, "ns", "", "x") is None


def test_resolve_terminates_on_owner_cycle():
    a = {"apiVersion": "v1", "kind": "Pod", "metadata": {"name": "a", "namespace": "ns",
         "ownerReferences": [owner("Pod", "b")]}, "spec": {}, "status": {}}
    b = {"apiVersion": "v1", "kind": "Pod", "metadata": {"name": "b", "namespace": "ns",
         "ownerReferences": [owner("Pod", "a")]}, "spec": {}, "status": {}}
    idx = build_index(by_kind(a, b))
    assert resolve_subject(idx, "ns", "Pod", "a") is None


def test_owner_without_controller_flag_is_ignored():
    """Mirrors the server: only `controller: true` references count, so
    such a Pod is a top-level workload of its own."""
    items = by_kind(
        deployment("api"),
        pod("api-abc-x1", owner_ref=owner("ReplicaSet", "api-abc", controller=False)),
    )
    idx = build_index(items)
    assert ("ns", "Pod", "api-abc-x1") in idx.controllers
    assert ("ns", "Pod", "api-abc-x1") not in idx.owners
