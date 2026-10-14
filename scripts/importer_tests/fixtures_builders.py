"""Small K8s / Trivy / Kyverno object builders shared by the importer
tests (stdlib only — no Django)."""
from __future__ import annotations

SHA_A = "sha256:" + "a" * 64
SHA_B = "sha256:" + "b" * 64
SHA_C = "sha256:" + "c" * 64
SHA_OLD = "sha256:" + "0" * 64


def owner(kind: str, name: str, *, controller: bool = True) -> dict:
    return {"apiVersion": "apps/v1", "kind": kind, "name": name, "controller": controller}


def namespace(name: str) -> dict:
    return {"apiVersion": "v1", "kind": "Namespace", "metadata": {"name": name}}


def _template(image: str, *, init_image: str | None = None, name: str = "app") -> dict:
    spec: dict = {"containers": [{"name": name, "image": image}]}
    if init_image:
        spec["initContainers"] = [{"name": "init", "image": init_image}]
    return {"metadata": {"labels": {"app": name}}, "spec": spec}


def deployment(name: str, ns: str = "ns", *, image: str = "r/app:1", replicas: int = 1,
               init_image: str | None = None) -> dict:
    return {
        "apiVersion": "apps/v1", "kind": "Deployment",
        "metadata": {"name": name, "namespace": ns},
        "spec": {"replicas": replicas, "template": _template(image, init_image=init_image)},
    }


def statefulset(name: str, ns: str = "ns", *, image: str = "r/db:1") -> dict:
    return {"apiVersion": "apps/v1", "kind": "StatefulSet", "metadata": {"name": name, "namespace": ns},
            "spec": {"replicas": 1, "template": _template(image)}}


def daemonset(name: str, ns: str = "kube-system", *, image: str = "r/agent:1") -> dict:
    return {"apiVersion": "apps/v1", "kind": "DaemonSet", "metadata": {"name": name, "namespace": ns},
            "spec": {"template": _template(image)}}


def cronjob(name: str, ns: str = "ns", *, image: str = "r/cron:1") -> dict:
    return {
        "apiVersion": "batch/v1", "kind": "CronJob",
        "metadata": {"name": name, "namespace": ns},
        "spec": {"schedule": "* * * * *", "jobTemplate": {"spec": {"template": _template(image)}}},
    }


def job(name: str, ns: str = "ns", *, image: str = "r/job:1", owner_ref: dict | None = None) -> dict:
    md: dict = {"name": name, "namespace": ns}
    if owner_ref:
        md["ownerReferences"] = [owner_ref]
    return {"apiVersion": "batch/v1", "kind": "Job", "metadata": md,
            "spec": {"template": _template(image)}}


def replicaset(name: str, ns: str = "ns", *, owner_name: str, image: str = "r/app:1", replicas: int = 1) -> dict:
    return {
        "apiVersion": "apps/v1", "kind": "ReplicaSet",
        "metadata": {"name": name, "namespace": ns, "ownerReferences": [owner("Deployment", owner_name)]},
        "spec": {"replicas": replicas, "template": _template(image)},
    }


def pod(name: str, ns: str = "ns", *, owner_ref: dict | None = None, image: str = "r/app:1",
        digest: str | None = SHA_A, image_id_style: str = "repo", phase: str = "Running",
        init_digest: str | None = None, terminating: bool = False, ephemeral_digest: str | None = None) -> dict:
    md: dict = {"name": name, "namespace": ns, "labels": {"app": name}}
    if owner_ref:
        md["ownerReferences"] = [owner_ref]
    if terminating:
        md["deletionTimestamp"] = "2026-01-01T00:00:00Z"
    status: dict = {"phase": phase}
    if digest:
        repo = image.split(":")[0]
        image_id = {
            "repo": f"{repo}@{digest}",
            "docker-pullable": f"docker-pullable://{repo}@{digest}",
            "bare": digest,
        }[image_id_style]
        status["containerStatuses"] = [{"name": "app", "image": image, "imageID": image_id}]
    else:
        status["containerStatuses"] = [{"name": "app", "image": image, "imageID": ""}]
    if init_digest:
        status["initContainerStatuses"] = [{"name": "init", "image": "r/init:1", "imageID": f"r/init@{init_digest}"}]
    if ephemeral_digest:
        status["ephemeralContainerStatuses"] = [{"name": "dbg", "image": "r/dbg:1", "imageID": f"r/dbg@{ephemeral_digest}"}]
    return {"apiVersion": "v1", "kind": "Pod", "metadata": md,
            "spec": {"containers": [{"name": "app", "image": image}]}, "status": status}


def trivy_report(kind: str, *, ns: str = "ns", subject_kind: str = "ReplicaSet", subject_name: str = "api-abc",
                 digest: str | None = SHA_A, container: str = "app") -> dict:
    labels = {
        "trivy-operator.resource.kind": subject_kind,
        "trivy-operator.resource.name": subject_name,
        "trivy-operator.container.name": container,
    }
    if ns:
        labels["trivy-operator.resource.namespace"] = ns
    report: dict = {"artifact": {"repository": "r/app", "tag": "1"}}
    if digest is not None:
        report["artifact"]["digest"] = digest
    return {"apiVersion": "aquasecurity.github.io/v1alpha1", "kind": kind,
            "metadata": {"name": f"{subject_kind.lower()}-{subject_name}-{container}", "namespace": ns, "labels": labels},
            "report": report}


def policy_report(*, ns: str = "ns", results: list[dict] | None = None, scope: dict | None = None,
                  name: str = "polr-x") -> dict:
    doc: dict = {"apiVersion": "wgpolicyk8s.io/v1alpha2", "kind": "PolicyReport",
                 "metadata": {"name": name, "namespace": ns}, "results": results or []}
    if scope is not None:
        doc["scope"] = scope
    return doc


def kyverno_result(*, result: str = "fail", subjects: list[dict] | None = None, resources: list[dict] | None = None,
                   policy: str = "disallow-host-namespaces") -> dict:
    doc: dict = {"policy": policy, "rule": "r", "result": result, "severity": "high", "message": "m"}
    if subjects is not None:
        doc["subjects"] = subjects
    if resources is not None:
        doc["resources"] = resources
    return doc


def subject(kind: str, name: str, ns: str | None = "ns") -> dict:
    doc = {"kind": kind, "name": name}
    if ns is not None:
        doc["namespace"] = ns
    return doc


def deployment_chain(name: str, ns: str = "ns", *, digest: str = SHA_A, image: str = "r/app:1",
                     rs_suffix: str = "abc", replicas: int = 1) -> list[dict]:
    rs_name = f"{name}-{rs_suffix}"
    return [
        deployment(name, ns, image=image, replicas=replicas),
        replicaset(rs_name, ns, owner_name=name, image=image, replicas=replicas),
        pod(f"{rs_name}-x1", ns, owner_ref=owner("ReplicaSet", rs_name), image=image, digest=digest),
    ]


def by_kind(*items: dict) -> dict[str, list[dict]]:
    out: dict[str, list[dict]] = {}
    for item in items:
        out.setdefault(item["kind"], []).append(item)
    return out
