"""Live kube-api source. `kubernetes` is imported lazily so the rest of
the importer (and its tests) stay stdlib-only."""
from __future__ import annotations

import sys

from ..kinds import CRD_SOURCES

K8S_TIMEOUT: tuple[int, int] = (10, 60)


class InventoryListError(RuntimeError):
    """A typed (inventory) list call failed. Every committed inventory is
    treated server-side as a complete snapshot, so a transient kube-api
    error must fail the cycle before any byte is sent — shipping `[]` for
    Namespaces or Deployments would deactivate every namespace / retire
    every workload of the cluster at reap."""


def load_kube_config(kubeconfig: str | None, in_cluster: bool):
    from kubernetes import client, config  # type: ignore
    if in_cluster:
        config.load_incluster_config()
    elif kubeconfig:
        config.load_kube_config(config_file=kubeconfig)
    else:
        config.load_kube_config()
    return client


def _to_dict(obj) -> dict:
    """Convert a kubernetes-client object back to a dict."""
    from kubernetes.client import ApiClient  # type: ignore
    return ApiClient().sanitize_for_serialization(obj)


def collect_from_kube_api(client_module) -> dict:
    """Return `{kind: [items]}` from a live cluster.

    Typed (inventory) lists use `_request_timeout=K8S_TIMEOUT`; any
    error other than a 404 raises `InventoryListError` (see its
    docstring). CRD lists that 404 (operator not installed) are OMITTED
    from the result and other CRD errors yield `[]` — see
    sources/__init__.py for why an empty scan list is the right signal
    for a scanner outage.
    """
    out: dict[str, list[dict]] = {}
    core = client_module.CoreV1Api()
    apps = client_module.AppsV1Api()
    batch = client_module.BatchV1Api()
    net = client_module.NetworkingV1Api()
    custom = client_module.CustomObjectsApi()

    def _list(label, fn, *, kind: str, api_version: str, **kwargs):
        # The kubernetes Python client's `sanitize_for_serialization`
        # does NOT populate `kind` / `apiVersion` on items returned
        # from typed list endpoints — those fields live on the *List
        # wrapper, not on each item. Central's parser dispatches by
        # `item["kind"]`, so stamp them here.
        try:
            res = fn(_request_timeout=K8S_TIMEOUT, **kwargs)
            items = getattr(res, "items", None) or []
            out_items = []
            for it in items:
                d = _to_dict(it)
                if isinstance(d, dict):
                    d.setdefault("kind", kind)
                    d.setdefault("apiVersion", api_version)
                out_items.append(d)
            return out_items
        except client_module.ApiException as e:
            if e.status == 404:
                # Resource type not served by this API server — the kind
                # is legitimately empty here.
                print(f"  WARN: {label}: not found, treating as empty", file=sys.stderr)
                return []
            raise InventoryListError(f"{label}: {e.status} {e.reason}") from e
        except Exception as e:  # pragma: no cover
            raise InventoryListError(f"{label}: {e}") from e

    out["Namespace"] = _list("namespaces", core.list_namespace, kind="Namespace", api_version="v1")
    out["Deployment"] = _list("deployments", apps.list_deployment_for_all_namespaces, kind="Deployment", api_version="apps/v1")
    out["StatefulSet"] = _list("statefulsets", apps.list_stateful_set_for_all_namespaces, kind="StatefulSet", api_version="apps/v1")
    out["DaemonSet"] = _list("daemonsets", apps.list_daemon_set_for_all_namespaces, kind="DaemonSet", api_version="apps/v1")
    out["CronJob"] = _list("cronjobs", batch.list_cron_job_for_all_namespaces, kind="CronJob", api_version="batch/v1")
    out["Job"] = _list("jobs", batch.list_job_for_all_namespaces, kind="Job", api_version="batch/v1")
    out["ReplicaSet"] = _list("replicasets", apps.list_replica_set_for_all_namespaces, kind="ReplicaSet", api_version="apps/v1")
    out["Pod"] = _list("pods", core.list_pod_for_all_namespaces, kind="Pod", api_version="v1")
    out["Service"] = _list("services", core.list_service_for_all_namespaces, kind="Service", api_version="v1")
    out["Ingress"] = _list("ingresses", net.list_ingress_for_all_namespaces, kind="Ingress", api_version="networking.k8s.io/v1")
    out["NetworkPolicy"] = _list("networkpolicies", net.list_network_policy_for_all_namespaces, kind="NetworkPolicy", api_version="networking.k8s.io/v1")
    out["Node"] = _list("nodes", core.list_node, kind="Node", api_version="v1")

    for group, version, plural, kind, _cluster_scoped in CRD_SOURCES:
        items = _list_crd(client_module, custom, group, version, plural, kind)
        if items is not None:
            out[kind] = items

    try:
        ver = client_module.VersionApi().get_code(_request_timeout=K8S_TIMEOUT)
        out["__version__"] = {"git_version": ver.git_version}
    except Exception:
        out["__version__"] = {}

    return out


def _list_crd(client_module, custom, group: str, version: str, plural: str, kind: str) -> list[dict] | None:
    """`None` when the CRD isn't installed (404); `[]` on other errors
    (logged) so the kind is still reported, just empty."""
    try:
        resp = custom.list_cluster_custom_object(
            group=group, version=version, plural=plural,
            _request_timeout=K8S_TIMEOUT,
        )
    except client_module.ApiException as e:
        if e.status == 404:
            return None
        print(f"  WARN: list {plural}: {e.reason}", file=sys.stderr)
        return []
    except Exception as e:  # pragma: no cover
        print(f"  WARN: list {plural}: {e}", file=sys.stderr)
        return []
    items = resp.get("items") or []
    for it in items:
        if isinstance(it, dict):
            it.setdefault("apiVersion", f"{group}/{version}")
            it.setdefault("kind", kind)
    return items


def cleanup_failed_sibling_jobs(client_module, *, namespace: str, cronjob_name: str) -> None:
    """Delete failed Jobs owned by `cronjob_name` after a successful run.

    Transient failures (connection resets, etc.) that later resolve on
    their own otherwise sit in the CronJob's Job history and keep
    tripping failed-job alerts even though the underlying issue is gone.
    Only Jobs still carrying a Failed status are removed — the Job
    currently executing this script isn't Failed yet, so it's untouched.
    """
    batch = client_module.BatchV1Api()
    try:
        cronjob = batch.read_namespaced_cron_job(
            cronjob_name, namespace, _request_timeout=K8S_TIMEOUT,
        )
    except Exception as e:
        print(f"  cleanup: could not read CronJob {cronjob_name}: {e}", file=sys.stderr)
        return
    cronjob_uid = cronjob.metadata.uid

    try:
        jobs = batch.list_namespaced_job(namespace, _request_timeout=K8S_TIMEOUT).items
    except Exception as e:
        print(f"  cleanup: could not list Jobs in {namespace}: {e}", file=sys.stderr)
        return

    deleted = 0
    for job in jobs:
        owned_by_cronjob = any(
            ref.kind == "CronJob" and ref.uid == cronjob_uid
            for ref in (job.metadata.owner_references or [])
        )
        if not owned_by_cronjob:
            continue
        status = job.status
        if not (status.failed or 0) or (status.succeeded or 0):
            continue
        try:
            batch.delete_namespaced_job(
                job.metadata.name, namespace,
                propagation_policy="Background",
                _request_timeout=K8S_TIMEOUT,
            )
            deleted += 1
            print(f"  cleanup: deleted failed Job {job.metadata.name}")
        except Exception as e:
            print(f"  cleanup: failed to delete Job {job.metadata.name}: {e}", file=sys.stderr)
