#!/usr/bin/env python3
"""KubePostureNG importer.

Per dev_docs/04-ingestion.md:
  1. Generate ULID `import_id` for the cycle.
  2. For each kind (inventory + each Trivy CRD + each Kyverno CRD):
       POST /api/v1/imports/start/  → opens an ImportMark (state=open).
       POST /api/v1/ingest/         → enqueues the raw payload.
       POST /api/v1/imports/finish/ → flips mark to draining,
                                      observed_count set.
  3. Inventory payload is an envelope `{cluster_meta, complete_snapshot,
     items: [...raw K8s manifests, trimmed...]}`. Other CRD kinds are
     posted one-item-per-call.

Two modes:

  Live (default): list directly from kube-api.
      python scripts/import-cluster.py <cluster> --in-cluster
      python scripts/import-cluster.py <cluster> --kubeconfig ~/.kube/config

  From-folder: replay a captured kubectl-dump tree.
      python scripts/import-cluster.py <cluster> --from-folder <path>
      where <path> contains:
        kubeapi/{deployments.json, statefulsets.json, daemonsets.json,
                 cronjobs.json, jobs.json, replicasets.json, pods.json,
                 services.json, ingresses.json, namespaces.json,
                 networkpolicies.json, nodes.json, version.json}
        trivy/{vulnerabilityreports.json, configauditreports.json,
               exposedsecretreports.json, rbacassessmentreports.json,
               clusterrbacassessmentreports.json,
               infraassessmentreports.json, clustercompliancereports.json}
        kyverno/{policyreports.json, clusterpolicyreports.json}

Auth:
  Authorization: Bearer <token> on every POST.
  Token from $KUBEPOSTURE_TOKEN or positional CLI arg.
"""
from __future__ import annotations

import argparse
import json
import os
import secrets
import socket
import sys
import time
from pathlib import Path
from typing import Iterable
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


# ── ULID-ish generator (no external dep) ─────────────────────────

_ULID_ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"


def _ulid() -> str:
    """26-char Crockford-base32 ULID. Time prefix + random."""
    ts = int(time.time() * 1000)
    head_chars = []
    for _ in range(10):
        head_chars.append(_ULID_ALPHABET[ts & 0x1F])
        ts >>= 5
    head = "".join(reversed(head_chars))
    rand = "".join(_ULID_ALPHABET[secrets.randbits(5)] for _ in range(16))
    return head + rand


# ── HTTP helpers ──────────────────────────────────────────────────

K8S_TIMEOUT: tuple[int, int] = (10, 60)
HTTP_TIMEOUT: int = 30
HTTP_MAX_ATTEMPTS: int = 3
HTTP_RETRY_BASE_DELAY: float = 1.5


def _post(base_url: str, token: str, path: str, body: dict) -> tuple[bool, int, str]:
    url = f"{base_url.rstrip('/')}{path}"
    data = json.dumps(body).encode()
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }
    req = Request(url, data=data, headers=headers, method="POST")
    last_status = 0
    last_detail = ""
    for attempt in range(1, HTTP_MAX_ATTEMPTS + 1):
        try:
            with urlopen(req, timeout=HTTP_TIMEOUT) as resp:
                return True, resp.status, resp.read().decode(errors="replace")[:500]
        except HTTPError as e:
            last_status = e.code
            try:
                last_detail = e.read().decode(errors="replace")[:300]
            except Exception:
                last_detail = ""
            if 400 <= e.code < 500:
                return False, e.code, last_detail
        except URLError as e:
            last_detail = f"connection error: {e.reason}"
        except socket.timeout:
            last_detail = f"timeout after {HTTP_TIMEOUT}s"

        if attempt < HTTP_MAX_ATTEMPTS:
            time.sleep(HTTP_RETRY_BASE_DELAY * (2 ** (attempt - 1)))
    return False, last_status, last_detail


# ── Trim helpers ──────────────────────────────────────────────────

_TRIM_METADATA_KEYS = {
    "managedFields",
    "creationTimestamp",
    "resourceVersion",
    "generation",
    "uid",
    "selfLink",
}

_TRIM_ANNOTATIONS = {
    "kubectl.kubernetes.io/last-applied-configuration",
    "deployment.kubernetes.io/revision",
}


def trim_manifest(item: dict) -> dict:
    """Drop noise the central parser never reads.

    Preserves `.status.containerStatuses[*].imageID` on Pods because
    it carries the digest of the actually-running image — the one
    field central reads from `.status`.
    """
    out = json.loads(json.dumps(item))  # deep copy
    md = out.get("metadata") or {}
    for k in list(md.keys()):
        if k in _TRIM_METADATA_KEYS:
            md.pop(k, None)
    annotations = md.get("annotations") or {}
    for k in list(annotations.keys()):
        if k in _TRIM_ANNOTATIONS:
            annotations.pop(k, None)

    if out.get("kind") == "Pod":
        # Keep status.containerStatuses; drop everything else in status.
        status = out.get("status") or {}
        keep = {}
        for key in ("containerStatuses", "initContainerStatuses"):
            if key in status:
                keep[key] = status[key]
        if keep:
            out["status"] = keep
        elif "status" in out:
            del out["status"]
    elif "status" in out:
        del out["status"]

    return out


# ── Kube-api source ───────────────────────────────────────────────

def _load_kube_config(kubeconfig: str | None, in_cluster: bool):
    from kubernetes import client, config  # type: ignore
    if in_cluster:
        config.load_incluster_config()
    elif kubeconfig:
        config.load_kube_config(config_file=kubeconfig)
    else:
        config.load_kube_config()
    return client


def collect_from_kube_api(client_module) -> dict:
    """Return a dict of `{kind: [items]}` from a live cluster.

    Uses `_request_timeout=K8S_TIMEOUT` on every list call; swallows
    404 (CRDs not installed); logs other errors but continues.
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
        # `item["kind"]`, so stamp them here. Mirrors the explicit
        # setdefault on the CRD path below (line ~243).
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
            if e.status != 404:
                print(f"  WARN: {label}: {e.reason}", file=sys.stderr)
            return []
        except Exception as e:  # pragma: no cover
            print(f"  WARN: {label}: {e}", file=sys.stderr)
            return []

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

    # Trivy + Kyverno CRDs.
    out["VulnerabilityReport"] = _list_crds(custom, "aquasecurity.github.io", "v1alpha1", "vulnerabilityreports")
    out["ConfigAuditReport"] = _list_crds(custom, "aquasecurity.github.io", "v1alpha1", "configauditreports")
    out["ExposedSecretReport"] = _list_crds(custom, "aquasecurity.github.io", "v1alpha1", "exposedsecretreports")
    out["RbacAssessmentReport"] = _list_crds(custom, "aquasecurity.github.io", "v1alpha1", "rbacassessmentreports")
    out["ClusterRbacAssessmentReport"] = _list_crds(custom, "aquasecurity.github.io", "v1alpha1", "clusterrbacassessmentreports", cluster_scoped=True)
    out["InfraAssessmentReport"] = _list_crds(custom, "aquasecurity.github.io", "v1alpha1", "infraassessmentreports")
    out["ClusterComplianceReport"] = _list_crds(custom, "aquasecurity.github.io", "v1alpha1", "clustercompliancereports", cluster_scoped=True)
    out["PolicyReport"] = _list_crds(custom, "wgpolicyk8s.io", "v1alpha2", "policyreports")
    out["ClusterPolicyReport"] = _list_crds(custom, "wgpolicyk8s.io", "v1alpha2", "clusterpolicyreports", cluster_scoped=True)

    # Cluster meta from VersionApi.
    try:
        ver = client_module.VersionApi().get_code(_request_timeout=K8S_TIMEOUT)
        out["__version__"] = {"git_version": ver.git_version}
    except Exception:
        out["__version__"] = {}

    return out


def _list_crds(custom, group: str, version: str, plural: str, cluster_scoped: bool = False) -> list[dict]:
    try:
        resp = custom.list_cluster_custom_object(
            group=group, version=version, plural=plural,
            _request_timeout=K8S_TIMEOUT,
        )
        items = resp.get("items") or []
        for it in items:
            it.setdefault("apiVersion", f"{group}/{version}")
            it.setdefault("kind", _kind_for_plural(plural))
        return items
    except Exception as e:  # pragma: no cover
        print(f"  WARN: list {plural}: {e}", file=sys.stderr)
        return []


def _kind_for_plural(plural: str) -> str:
    table = {
        "vulnerabilityreports": "VulnerabilityReport",
        "configauditreports": "ConfigAuditReport",
        "exposedsecretreports": "ExposedSecretReport",
        "rbacassessmentreports": "RbacAssessmentReport",
        "clusterrbacassessmentreports": "ClusterRbacAssessmentReport",
        "infraassessmentreports": "InfraAssessmentReport",
        "clustercompliancereports": "ClusterComplianceReport",
        "policyreports": "PolicyReport",
        "clusterpolicyreports": "ClusterPolicyReport",
    }
    return table.get(plural, plural)


def _to_dict(obj) -> dict:
    """Convert a kubernetes-client object back to a dict."""
    from kubernetes.client import ApiClient  # type: ignore
    return ApiClient().sanitize_for_serialization(obj)


# ── From-folder source ───────────────────────────────────────────

# Map filename → (kind, group, version)
_FROM_FOLDER_KUBEAPI = {
    "namespaces.json": "Namespace",
    "deployments.json": "Deployment",
    "statefulsets.json": "StatefulSet",
    "daemonsets.json": "DaemonSet",
    "cronjobs.json": "CronJob",
    "jobs.json": "Job",
    "replicasets.json": "ReplicaSet",
    "pods.json": "Pod",
    "services.json": "Service",
    "ingresses.json": "Ingress",
    "networkpolicies.json": "NetworkPolicy",
    "nodes.json": "Node",
}

_FROM_FOLDER_TRIVY = {
    "vulnerabilityreports.json": "VulnerabilityReport",
    "configauditreports.json": "ConfigAuditReport",
    "exposedsecretreports.json": "ExposedSecretReport",
    "rbacassessmentreports.json": "RbacAssessmentReport",
    "clusterrbacassessmentreports.json": "ClusterRbacAssessmentReport",
    "infraassessmentreports.json": "InfraAssessmentReport",
    "clustercompliancereports.json": "ClusterComplianceReport",
}

_FROM_FOLDER_KYVERNO = {
    "policyreports.json": "PolicyReport",
    "clusterpolicyreports.json": "ClusterPolicyReport",
}


def collect_from_folder(root: Path) -> dict:
    """Read a captured kubectl-dump tree. Each `*.json` is the output
    of `kubectl get <kind> -A -o json` (a `*List` wrapper with
    `items: [...]`).
    """
    out: dict[str, list[dict]] = {}

    def _read(rel_dir: str, mapping: dict[str, str]):
        d = root / rel_dir
        if not d.is_dir():
            return
        for fname, kind in mapping.items():
            p = d / fname
            if not p.is_file():
                continue
            doc = json.loads(p.read_text())
            items = doc.get("items") if isinstance(doc, dict) else None
            if items is None and isinstance(doc, list):
                items = doc
            elif items is None:
                items = [doc]
            for it in items:
                if isinstance(it, dict):
                    it.setdefault("kind", kind)
            out.setdefault(kind, []).extend(items or [])

    _read("kubeapi", _FROM_FOLDER_KUBEAPI)
    _read("trivy", _FROM_FOLDER_TRIVY)
    _read("kyverno", _FROM_FOLDER_KYVERNO)

    # Cluster version, if captured.
    ver_path = root / "kubeapi" / "version.json"
    if ver_path.is_file():
        ver_doc = json.loads(ver_path.read_text())
        out["__version__"] = {"git_version": ver_doc.get("gitVersion", "")}
    return out


# ── Cluster-meta extraction ──────────────────────────────────────

def derive_cluster_meta(cluster_name: str, by_kind: dict) -> dict:
    """Pull k8s_version, provider, region from the captured items."""
    ver = (by_kind.get("__version__") or {}).get("git_version") or ""
    provider, region = "onprem", ""
    nodes = by_kind.get("Node") or []
    if nodes:
        first = nodes[0]
        labels = (first.get("metadata") or {}).get("labels") or {}
        spec = first.get("spec") or {}
        pid = (spec.get("providerID") or "").lower()
        if pid.startswith("aws://"):
            provider = "eks" if any(k.startswith("eks.amazonaws.com/") for k in labels) else "aws"
        elif pid.startswith("gce://"):
            provider = "gke" if any(k.startswith("cloud.google.com/gke-") for k in labels) else "gcp"
        elif pid.startswith("azure://"):
            provider = "aks" if any(k.startswith("kubernetes.azure.com/") for k in labels) else "azure"
        for key in ("topology.kubernetes.io/region", "failure-domain.beta.kubernetes.io/region"):
            if labels.get(key):
                region = labels[key]
                break
    return {
        "name": cluster_name,
        "k8s_version": ver,
        "provider": provider,
        "region": region,
    }


# ── Posting plan ─────────────────────────────────────────────────

# Maps the Item kind → (envelope_kind_string).
_INVENTORY_ITEM_KINDS = {
    "Namespace", "Deployment", "StatefulSet", "DaemonSet", "CronJob",
    "Job", "ReplicaSet", "Pod", "Service", "Ingress", "NetworkPolicy",
}

_SCAN_KINDS = [
    ("VulnerabilityReport", "trivy.VulnerabilityReport"),
    ("ConfigAuditReport", "trivy.ConfigAuditReport"),
    ("ExposedSecretReport", "trivy.ExposedSecretReport"),
    ("RbacAssessmentReport", "trivy.RbacAssessmentReport"),
    ("ClusterRbacAssessmentReport", "trivy.ClusterRbacAssessmentReport"),
    ("InfraAssessmentReport", "trivy.InfraAssessmentReport"),
    ("ClusterComplianceReport", "trivy.ClusterComplianceReport"),
    ("PolicyReport", "kyverno.PolicyReport"),
    ("ClusterPolicyReport", "kyverno.ClusterPolicyReport"),
]


def post_cycle(*, base_url: str, token: str, cluster: str, by_kind: dict) -> int:
    import_id = _ulid()
    cluster_meta = derive_cluster_meta(cluster, by_kind)

    # Build inventory items list.
    inventory_items: list[dict] = []
    for k in _INVENTORY_ITEM_KINDS:
        for it in by_kind.get(k) or []:
            inventory_items.append(trim_manifest(it))

    print(f"\n== import_id={import_id} ==")

    # 1) /imports/start/ for inventory + each scan kind that has items.
    kinds_to_open = ["inventory"]
    for crd_kind, env_kind in _SCAN_KINDS:
        if by_kind.get(crd_kind):
            kinds_to_open.append(env_kind)

    for k in kinds_to_open:
        ok, status, detail = _post(base_url, token, "/api/v1/imports/start/", {
            "cluster": cluster, "kind": k, "import_id": import_id,
        })
        if not ok:
            print(f"  imports/start {k}: FAILED ({status}): {detail}", file=sys.stderr)
            return 1

    # 2) /ingest/ — scan CRDs first (Trivy, Kyverno). Posting these
    # before inventory ensures Image rows already carry their findings
    # by the time the inventory parser links a workload to the image.
    scan_counts: dict[str, int] = {}
    for crd_kind, env_kind in _SCAN_KINDS:
        items = by_kind.get(crd_kind) or []
        for it in items:
            ok, status, detail = _post(base_url, token, "/api/v1/ingest/", {
                "cluster": cluster,
                "kind": env_kind,
                "import_id": import_id,
                "payload": it,
                "complete_snapshot": False,
            })
            if not ok:
                print(f"  ingest {env_kind}: FAILED ({status}): {detail}", file=sys.stderr)
        scan_counts[env_kind] = len(items)
        if items:
            print(f"  ingest {env_kind}: {len(items)} items")

    # 3) /ingest/ — inventory envelope (after scans so finding-image
    # links are already in place).
    inv_payload = {
        "cluster_meta": cluster_meta,
        "complete_snapshot": True,
        "items": inventory_items,
    }
    ok, status, detail = _post(base_url, token, "/api/v1/ingest/", {
        "cluster": cluster,
        "kind": "inventory",
        "import_id": import_id,
        "payload": inv_payload,
        "complete_snapshot": True,
    })
    if not ok:
        print(f"  ingest inventory: FAILED ({status}): {detail}", file=sys.stderr)
        return 1
    print(f"  ingest inventory: {len(inventory_items)} items")

    # 4) /imports/finish/ — inventory + each scan kind we opened.
    finish_pairs: list[tuple[str, int]] = [("inventory", 1)]
    for crd_kind, env_kind in _SCAN_KINDS:
        if env_kind in kinds_to_open:
            finish_pairs.append((env_kind, scan_counts.get(env_kind, 0)))

    for kind, count in finish_pairs:
        ok, status, detail = _post(base_url, token, "/api/v1/imports/finish/", {
            "cluster": cluster, "kind": kind, "import_id": import_id,
            "observed_count": count,
        })
        if not ok:
            print(f"  imports/finish {kind}: FAILED ({status}): {detail}", file=sys.stderr)
            return 1
    print(f"  finish: {len(finish_pairs)} kinds")
    return 0


# ── CLI ───────────────────────────────────────────────────────────

def main() -> int:
    parser = argparse.ArgumentParser(description="KubePostureNG importer")
    parser.add_argument("cluster_name")
    parser.add_argument("token", nargs="?", default=None,
                        help="Bearer token. Falls back to $KUBEPOSTURE_TOKEN.")
    parser.add_argument("--kubeconfig", default=None)
    parser.add_argument("--in-cluster", action="store_true",
                        help="Use in-cluster ServiceAccount config.")
    parser.add_argument("--from-folder", default=None,
                        help="Replay a captured `kubectl get -o json` dump tree.")
    args = parser.parse_args()

    base_url = os.environ.get("KUBEPOSTURE_URL", "http://localhost:8000")
    token = args.token or os.environ.get("KUBEPOSTURE_TOKEN", "")
    if not token:
        print("error: token required (positional arg or $KUBEPOSTURE_TOKEN)", file=sys.stderr)
        return 2

    if args.from_folder:
        root = Path(args.from_folder).resolve()
        if not root.is_dir():
            print(f"error: --from-folder path is not a directory: {root}", file=sys.stderr)
            return 2
        print(f"Reading captured cluster from {root}")
        by_kind = collect_from_folder(root)
    else:
        print("Loading kube-api config...")
        try:
            client_module = _load_kube_config(args.kubeconfig, args.in_cluster)
        except Exception as e:
            print(f"error: failed to load kube config: {e}", file=sys.stderr)
            return 2
        print("Listing from kube-api...")
        by_kind = collect_from_kube_api(client_module)

    return post_cycle(
        base_url=base_url,
        token=token,
        cluster=args.cluster_name,
        by_kind=by_kind,
    )


if __name__ == "__main__":
    sys.exit(main())
