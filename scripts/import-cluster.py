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
    ("vulnerabilityreports", True),       # namespaced
    ("configauditreports", True),
    ("exposedsecretreports", True),
    ("rbacassessmentreports", True),
    ("infraassessmentreports", True),
    ("clustercompliancereports", False),  # cluster-scoped
    ("sbomreports", True),
]

# ── Kyverno CRD types ────────────────────────────────────────

KYVERNO_GROUP = "wgpolicyk8s.io"
KYVERNO_VERSION = "v1alpha2"
KYVERNO_CRDS = [
    ("policyreports", True),              # namespaced
    ("clusterpolicyreports", False),      # cluster-scoped
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
) -> list[dict]:
    """List CRD items from the cluster. Returns empty list on 404 (CRD not installed)."""
    try:
        result = api.list_cluster_custom_object(
            group=group,
            version=version,
            plural=plural,
        )
        return result.get("items", [])
    except client.ApiException as e:
        if e.status == 404:
            print(f"    CRD {group}/{plural} not found (not installed)", file=sys.stderr)
        else:
            print(f"    Error listing {plural}: {e.reason}", file=sys.stderr)
        return []


# ── KubePosture API ─────────────────────────────────────────────

def post_crd(item: dict, url: str, token: str, cluster: str) -> tuple[bool, str]:
    """Post a single CRD to KubePosture ingest API."""
    body = json.dumps(item).encode()
    req = Request(
        url,
        data=body,
        headers={
            "Authorization": f"Token {token}",
            "Content-Type": "application/json",
            "X-Cluster-Name": cluster,
        },
        method="POST",
    )
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
    crds: list[tuple[str, bool]],
    ingest_url: str,
    token: str,
    cluster: str,
    source_name: str,
) -> tuple[int, int]:
    """Import a set of CRD types. Returns (ok_count, err_count)."""
    total_ok = 0
    total_err = 0

    for plural, namespaced in crds:
        items = list_crds(api, group, version, plural, namespaced)
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
    api = client.CustomObjectsApi()

    total_ok = 0
    total_err = 0

    if import_trivy:
        print(f"\n== Trivy ({len(TRIVY_CRDS)} CRD types) ==")
        ok, err = import_crds(
            api, TRIVY_GROUP, TRIVY_VERSION, TRIVY_CRDS,
            ingest_url, token, cluster, "Trivy",
        )
        total_ok += ok
        total_err += err

    if import_kyverno:
        print(f"\n== Kyverno ({len(KYVERNO_CRDS)} CRD types) ==")
        ok, err = import_crds(
            api, KYVERNO_GROUP, KYVERNO_VERSION, KYVERNO_CRDS,
            ingest_url, token, cluster, "Kyverno",
        )
        total_ok += ok
        total_err += err

    print(f"\nDone: {total_ok} succeeded, {total_err} failed")
    sys.exit(1 if total_err > 0 else 0)


if __name__ == "__main__":
    main()
