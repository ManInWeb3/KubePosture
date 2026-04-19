#!/usr/bin/env python3
"""
Import security data from a K8s cluster into KubePosture.

Fetches Trivy CRDs (7 types) and Kyverno PolicyReports from a cluster
using the kubernetes Python client, then POSTs each to the KubePosture
ingest API.

Usage:
  # Import everything (Trivy + Kyverno):
  python scripts/import-cluster.py cluster-name-1 <token>

  # Trivy only:
  python scripts/import-cluster.py cluster-name-1 <token> --trivy

  # Kyverno only:
  python scripts/import-cluster.py cluster-name-1 <token> --kyverno

  # Custom kubeconfig:
  python scripts/import-cluster.py cluster-name-1 <token> --kubeconfig /path/to/kubeconfig

  # In-cluster (ServiceAccount, for CronJob pods):
  python scripts/import-cluster.py cluster-name-1 <token> --in-cluster

  # Custom KubePosture URL:
  KUBEPOSTURE_URL=https://kubeposture.central.someorg.xyz \\
    python scripts/import-cluster.py cluster-name-1 <token>

Environment variables:
  KUBEPOSTURE_URL  — API base URL (default: http://localhost:8000)

Requirements:
  pip install kubernetes
"""
import argparse
import json
import os
import sys
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

try:
    from kubernetes import client, config
except ImportError:
    print(
        "Error: 'kubernetes' package required. Install: pip install kubernetes",
        file=sys.stderr,
    )
    sys.exit(1)


# ── Trivy CRD types ──────────────────────────────────────────

TRIVY_GROUP = "aquasecurity.github.io"
TRIVY_VERSION = "v1alpha1"
TRIVY_CRDS = [
    ("vulnerabilityreports", True, "VulnerabilityReport"),
    ("configauditreports", True, "ConfigAuditReport"),
    ("exposedsecretreports", True, "ExposedSecretReport"),
    ("rbacassessmentreports", True, "RbacAssessmentReport"),
    ("infraassessmentreports", True, "InfraAssessmentReport"),
    ("clustercompliancereports", False, "ClusterComplianceReport"),
    ("sbomreports", True, "SbomReport"),
]

# ── Kyverno CRD types ────────────────────────────────────────

KYVERNO_GROUP = "wgpolicyk8s.io"
KYVERNO_VERSION = "v1alpha2"
KYVERNO_CRDS = [
    ("policyreports", True, "PolicyReport"),
    ("clusterpolicyreports", False, "ClusterPolicyReport"),
]


# ── Kubernetes helpers ────────────────────────────────────────

def load_k8s_config(kubeconfig: str | None, in_cluster: bool):
    """Load Kubernetes client configuration."""
    if in_cluster:
        config.load_incluster_config()
        print("Using in-cluster ServiceAccount config")
    elif kubeconfig:
        config.load_kube_config(config_file=kubeconfig)
        print(f"Using kubeconfig: {kubeconfig}")
    else:
        config.load_kube_config()
        print("Using default kubeconfig (~/.kube/config)")


def list_crds(
    api: client.CustomObjectsApi,
    group: str,
    version: str,
    plural: str,
    namespaced: bool,
    kind: str,
) -> list[dict]:
    """List CRD items from the cluster. Returns empty list on 404 (CRD not installed).

    Injects `kind` on each item — the Kubernetes list API omits it on individual
    items (only the list wrapper has kind: FooList), but the ingest parser requires it.
    """
    try:
        result = api.list_cluster_custom_object(
            group=group,
            version=version,
            plural=plural,
        )
        items = result.get("items", [])
        for item in items:
            item.setdefault("kind", kind)
        return items
    except client.ApiException as e:
        if e.status == 404:
            print(f"    CRD {group}/{plural} not found (not installed)", file=sys.stderr)
        else:
            print(f"    Error listing {plural}: {e.reason}", file=sys.stderr)
        return []


# ── Cluster metadata auto-detection ─────────────────────────────

_AWS_PROVIDER_PREFIXES = ("aws://",)
_GCP_PROVIDER_PREFIXES = ("gce://",)
_AZURE_PROVIDER_PREFIXES = ("azure://",)


def _classify_provider(provider_id: str, node_labels: dict) -> str:
    """Map K8s node .spec.provider_id + labels to a short provider name."""
    pid = (provider_id or "").lower()
    if any(pid.startswith(p) for p in _AWS_PROVIDER_PREFIXES):
        if any(k.startswith("eks.amazonaws.com/") for k in node_labels):
            return "eks"
        return "aws"
    if any(pid.startswith(p) for p in _GCP_PROVIDER_PREFIXES):
        if any(k.startswith("cloud.google.com/gke-") for k in node_labels):
            return "gke"
        return "gcp"
    if any(pid.startswith(p) for p in _AZURE_PROVIDER_PREFIXES):
        if any(k.startswith("kubernetes.azure.com/") for k in node_labels):
            return "aks"
        return "azure"
    return "onprem"


def discover_cluster_metadata(core_api, net_api) -> dict:
    """Return a single dict describing the cluster for /cluster-metadata/sync/.

    Auto-detects:
      - k8s_version from VersionApi
      - provider / region from the first node
      - per-namespace exposure from Services (LB/NodePort) + Ingresses

    Defaults to safe values when K8s API calls fail; never aborts.
    """
    # complete_snapshot=False until we confirm every discovery step that
    # feeds deactivation on the server succeeded. If list_namespace() fails
    # we must not let the server treat this as a full snapshot, or it would
    # deactivate surviving namespaces.
    meta = {
        "k8s_version": "",
        "provider": "onprem",
        "region": "",
        "namespaces": [],
        "complete_snapshot": False,
    }

    # K8s version
    try:
        meta["k8s_version"] = (client.VersionApi().get_code().git_version or "")
    except Exception as e:
        print(f"Warning: could not fetch K8s version: {e}", file=sys.stderr)

    # Provider + region from the first node
    try:
        nodes = core_api.list_node(limit=1)
        if nodes.items:
            node = nodes.items[0]
            labels = node.metadata.labels or {}
            meta["provider"] = _classify_provider(node.spec.provider_id or "", labels)
            meta["region"] = (
                labels.get("topology.kubernetes.io/region")
                or labels.get("failure-domain.beta.kubernetes.io/region")
                or ""
            )
    except Exception as e:
        print(f"Warning: could not inspect nodes: {e}", file=sys.stderr)

    # Per-namespace exposure
    ns_list = []
    try:
        ns_list = core_api.list_namespace().items
    except Exception as e:
        print(f"Warning: could not list namespaces: {e}", file=sys.stderr)
        return meta

    # Bucket services by namespace — LB/NodePort means exposed
    exposed_by_ns = {}
    try:
        for svc in core_api.list_service_for_all_namespaces().items:
            if svc.spec and svc.spec.type in ("LoadBalancer", "NodePort"):
                exposed_by_ns[svc.metadata.namespace] = True
    except Exception as e:
        print(f"Warning: could not list services: {e}", file=sys.stderr)

    # Any Ingress in a namespace also means exposed
    try:
        for ing in net_api.list_ingress_for_all_namespaces().items:
            exposed_by_ns[ing.metadata.namespace] = True
    except client.ApiException as e:
        if e.status != 404:
            print(f"Warning: could not list ingresses: {e.reason}", file=sys.stderr)
    except Exception as e:
        print(f"Warning: could not list ingresses: {e}", file=sys.stderr)

    for ns in ns_list:
        meta["namespaces"].append({
            "name": ns.metadata.name,
            "internet_exposed": exposed_by_ns.get(ns.metadata.name, False),
            "labels": dict(ns.metadata.labels or {}),
            "annotations": dict(ns.metadata.annotations or {}),
        })

    # Namespace listing succeeded above; safe to assert this is the
    # authoritative snapshot the server can act on for deactivation.
    meta["complete_snapshot"] = True
    return meta


def post_cluster_metadata_sync(
    base_url: str, token: str, cluster: str, meta: dict
) -> tuple[bool, str]:
    """POST auto-detected metadata to /api/v1/cluster-metadata/sync/."""
    url = f"{base_url.rstrip('/')}/api/v1/cluster-metadata/sync/"
    body = json.dumps({"cluster_name": cluster, **meta}).encode()
    headers = {
        "Authorization": f"Token {token}",
        "Content-Type": "application/json",
    }
    req = Request(url, data=body, headers=headers, method="POST")
    try:
        with urlopen(req, timeout=30) as resp:
            return True, resp.read().decode()[:200]
    except HTTPError as e:
        return False, f"HTTP {e.code}: {e.read().decode()[:100]}"
    except URLError as e:
        return False, f"connection error: {e.reason}"


# ── KubePosture API ─────────────────────────────────────────────

def post_crd(item: dict, url: str, token: str, cluster: str) -> tuple[bool, str]:
    """Post a single CRD to KubePosture ingest API."""
    body = json.dumps(item).encode()
    headers = {
        "Authorization": f"Token {token}",
        "Content-Type": "application/json",
        "X-Cluster-Name": cluster,
    }
    req = Request(url, data=body, headers=headers, method="POST")
    try:
        with urlopen(req, timeout=30) as resp:
            data = json.loads(resp.read())
            status = data.get("status", "unknown")
            return status in ("success", "queued", "stored_raw"), status
    except HTTPError as e:
        return False, f"HTTP {e.code}: {e.read().decode()[:100]}"
    except URLError as e:
        return False, f"connection error: {e.reason}"


def import_crds(
    api: client.CustomObjectsApi,
    group: str,
    version: str,
    crds: list[tuple[str, bool, str]],
    ingest_url: str,
    token: str,
    cluster: str,
    source_name: str,
) -> tuple[int, int]:
    """Import a set of CRD types. Returns (ok_count, err_count)."""
    total_ok = 0
    total_err = 0

    for plural, namespaced, kind in crds:
        items = list_crds(api, group, version, plural, namespaced, kind)
        print(f"  {plural}: {len(items)} items")

        for item in items:
            meta = item.get("metadata", {})
            name = meta.get("name", "?")
            ns = meta.get("namespace", "")
            label = f"{ns}/{name}" if ns else name

            ok, detail = post_crd(item, ingest_url, token, cluster)
            if ok:
                print(f"    + {label}: {detail}")
                total_ok += 1
            else:
                print(f"    x {label}: {detail}")
                total_err += 1

    return total_ok, total_err


# ── Main ──────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Import security data from a K8s cluster into KubePosture.",
        epilog="By default imports both Trivy and Kyverno. Use --trivy or --kyverno to import only one.",
    )
    parser.add_argument(
        "cluster_name",
        help="Cluster name for KubePosture (e.g., cluster-name-1)",
    )
    parser.add_argument(
        "token",
        help="KubePosture API service token",
    )
    parser.add_argument(
        "--kubeconfig",
        default=None,
        help="Path to kubeconfig file (default: ~/.kube/config)",
    )
    parser.add_argument(
        "--in-cluster",
        action="store_true",
        help="Use in-cluster ServiceAccount config (for CronJob pods)",
    )
    parser.add_argument(
        "--trivy",
        action="store_true",
        help="Import Trivy CRDs only",
    )
    parser.add_argument(
        "--kyverno",
        action="store_true",
        help="Import Kyverno PolicyReports only",
    )

    args = parser.parse_args()

    cluster = args.cluster_name
    token = args.token
    base_url = os.environ.get("KUBEPOSTURE_URL", "http://localhost:8000")
    ingest_url = f"{base_url.rstrip('/')}/api/v1/ingest/"

    # If neither --trivy nor --kyverno specified, import both
    import_trivy = args.trivy or (not args.trivy and not args.kyverno)
    import_kyverno = args.kyverno or (not args.trivy and not args.kyverno)

    # Load K8s config
    load_k8s_config(args.kubeconfig, args.in_cluster)
    custom_api = client.CustomObjectsApi()
    core_api = client.CoreV1Api()
    net_api = client.NetworkingV1Api()

    # Auto-detect k8s version, provider, region, and per-namespace exposure,
    # then push everything to /api/v1/cluster-metadata/sync/ in one call.
    # Failure here is non-fatal — findings ingest still proceeds.
    print("\n== Cluster metadata auto-detect ==")
    meta = discover_cluster_metadata(core_api, net_api)
    print(
        f"  k8s_version={meta['k8s_version']}  provider={meta['provider']}  "
        f"region={meta['region'] or '—'}  namespaces={len(meta['namespaces'])}  "
        f"complete_snapshot={meta['complete_snapshot']}"
    )
    ok, detail = post_cluster_metadata_sync(base_url, token, cluster, meta)
    if ok:
        print(f"  sync: {detail}")
    else:
        print(f"  sync FAILED: {detail} (continuing with findings ingest)", file=sys.stderr)

    total_ok = 0
    total_err = 0

    if import_trivy:
        print(f"\n== Trivy ({len(TRIVY_CRDS)} CRD types) ==")
        ok, err = import_crds(
            custom_api, TRIVY_GROUP, TRIVY_VERSION, TRIVY_CRDS,
            ingest_url, token, cluster, "Trivy",
        )
        total_ok += ok
        total_err += err

    if import_kyverno:
        print(f"\n== Kyverno ({len(KYVERNO_CRDS)} CRD types) ==")
        ok, err = import_crds(
            custom_api, KYVERNO_GROUP, KYVERNO_VERSION, KYVERNO_CRDS,
            ingest_url, token, cluster, "Kyverno",
        )
        total_ok += ok
        total_err += err

    print(f"\nDone: {total_ok} succeeded, {total_err} failed")
    sys.exit(1 if total_err > 0 else 0)


if __name__ == "__main__":
    main()
