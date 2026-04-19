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
import socket
import sys
import time
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


# ── Network tunables ─────────────────────────────────────────
# K8s calls: (connect, read) tuple — fail fast on unreachable apiserver,
# allow more time for large CRD list responses.
K8S_TIMEOUT: tuple[int, int] = (10, 60)
# KubePosture POSTs: each attempt caps at HTTP_TIMEOUT; we retry on
# transient URLError/5xx/timeout with exponential backoff.
HTTP_TIMEOUT: int = 30
HTTP_MAX_ATTEMPTS: int = 3
HTTP_RETRY_BASE_DELAY: float = 1.5  # seconds; doubles each attempt


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
            _request_timeout=K8S_TIMEOUT,
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
    except Exception as e:
        # Covers urllib3.ReadTimeoutError, ConnectionError, DNS failures —
        # none of which inherit from ApiException. Skip this CRD type so
        # one hang doesn't abort the entire import run.
        print(f"    Network error listing {plural}: {e}", file=sys.stderr)
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


# Canonical K8s topology labels, in preference order.
_REGION_LABELS = (
    "topology.kubernetes.io/region",           # K8s 1.17+ standard, set by cloud CCMs
    "failure-domain.beta.kubernetes.io/region",  # deprecated but still seen on older clusters
)
_ZONE_LABELS = (
    "topology.kubernetes.io/zone",
    "failure-domain.beta.kubernetes.io/zone",
)


def _zone_to_region(zone: str) -> str:
    """Infer region from a zone label when the region label is absent.

    Covers the three major conventions:
      - AWS  / DO:     us-east-1a    → us-east-1   (strip trailing letter)
      - GCP  / GKE:    us-central1-a → us-central1 (strip '-<letter>' suffix)
      - Azure / AKS:   westeurope-1  → westeurope  (strip '-<digit>' suffix)
    Returns the input unchanged when no pattern matches — better a noisy
    string than empty, lets admins correct it manually in the UI.
    """
    if not zone:
        return ""
    if "-" in zone:
        head, _, tail = zone.rpartition("-")
        if head:
            # Azure: trailing 1–2 digit zone number (westeurope-1, eastus2-2)
            if tail.isdigit() and len(tail) <= 2:
                return head
            # GCP: trailing single letter, head has digits (us-central1-a)
            if tail.isalpha() and len(tail) == 1 and any(c.isdigit() for c in head):
                return head
    # AWS: trailing single letter immediately after a digit (us-east-1a)
    if len(zone) >= 2 and zone[-1].isalpha() and zone[-2].isdigit():
        return zone[:-1]
    return zone


def _detect_region(nodes: list) -> str:
    """Pick the first node with a usable region signal.

    Iterates all provided nodes because control-plane nodes often lack
    topology labels — we want to reach a worker. Region label wins;
    zone-derived region is the fallback.
    """
    # Pass 1: explicit region labels on any node
    for node in nodes:
        labels = (node.metadata.labels if node and node.metadata else None) or {}
        for key in _REGION_LABELS:
            if labels.get(key):
                return labels[key]
    # Pass 2: derive from zone label
    for node in nodes:
        labels = (node.metadata.labels if node and node.metadata else None) or {}
        for key in _ZONE_LABELS:
            zone = labels.get(key, "")
            if zone:
                return _zone_to_region(zone)
    return ""


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

    # K8s version — VersionApi.get_code() accepts _request_timeout like the
    # other client methods (passes through to the underlying REST call).
    try:
        meta["k8s_version"] = (
            client.VersionApi().get_code(_request_timeout=K8S_TIMEOUT).git_version or ""
        )
    except Exception as e:
        print(f"Warning: could not fetch K8s version: {e}", file=sys.stderr)

    # Provider from the first node's provider_id; region scans all nodes
    # because control-plane nodes frequently lack topology labels while
    # worker nodes carry them. `limit=20` caps the response on huge clusters.
    try:
        nodes = core_api.list_node(limit=20, _request_timeout=K8S_TIMEOUT)
        if nodes.items:
            first = nodes.items[0]
            first_labels = (first.metadata.labels if first.metadata else None) or {}
            provider_id = (first.spec.provider_id if first.spec else "") or ""
            meta["provider"] = _classify_provider(provider_id, first_labels)
            meta["region"] = _detect_region(nodes.items)
    except Exception as e:
        print(f"Warning: could not inspect nodes: {e}", file=sys.stderr)

    # Per-namespace exposure. If this call fails we return early — without
    # the namespace list there's nothing to describe (and complete_snapshot
    # correctly stays False so the server skips deactivation).
    ns_list = []
    try:
        ns_list = core_api.list_namespace(_request_timeout=K8S_TIMEOUT).items
    except Exception as e:
        print(f"Warning: could not list namespaces: {e}", file=sys.stderr)
        return meta

    # Bucket services by namespace — LB/NodePort means exposed
    exposed_by_ns = {}
    try:
        svcs = core_api.list_service_for_all_namespaces(_request_timeout=K8S_TIMEOUT)
        for svc in svcs.items:
            if svc.spec and svc.spec.type in ("LoadBalancer", "NodePort"):
                exposed_by_ns[svc.metadata.namespace] = True
    except Exception as e:
        print(f"Warning: could not list services: {e}", file=sys.stderr)

    # Any Ingress in a namespace also means exposed
    try:
        ings = net_api.list_ingress_for_all_namespaces(_request_timeout=K8S_TIMEOUT)
        for ing in ings.items:
            exposed_by_ns[ing.metadata.namespace] = True
    except client.ApiException as e:
        if e.status != 404:
            print(f"Warning: could not list ingresses: {e.reason}", file=sys.stderr)
    except Exception as e:
        print(f"Warning: could not list ingresses: {e}", file=sys.stderr)

    # NetworkPolicy count per namespace — 0 means wide blast radius.
    # Counts all policies regardless of selector; a namespace with at least
    # one NetworkPolicy is assumed to be thinking about network scope.
    netpol_by_ns: dict[str, int] = {}
    try:
        nps = net_api.list_network_policy_for_all_namespaces(_request_timeout=K8S_TIMEOUT)
        for np in nps.items:
            ns_name = np.metadata.namespace
            netpol_by_ns[ns_name] = netpol_by_ns.get(ns_name, 0) + 1
    except client.ApiException as e:
        if e.status != 404:
            print(f"Warning: could not list networkpolicies: {e.reason}", file=sys.stderr)
    except Exception as e:
        print(f"Warning: could not list networkpolicies: {e}", file=sys.stderr)

    for ns in ns_list:
        meta["namespaces"].append({
            "name": ns.metadata.name,
            "internet_exposed": exposed_by_ns.get(ns.metadata.name, False),
            "network_policy_count": netpol_by_ns.get(ns.metadata.name, 0),
            "labels": dict(ns.metadata.labels or {}),
            "annotations": dict(ns.metadata.annotations or {}),
        })

    # Namespace listing succeeded above; safe to assert this is the
    # authoritative snapshot the server can act on for deactivation.
    meta["complete_snapshot"] = True
    return meta


def _urlopen_with_retry(req: Request) -> tuple[bool, str, bytes]:
    """Send a POST with retries on transient failures.

    Retries on: URLError (DNS/connect), socket.timeout, and 5xx HTTPError.
    Does NOT retry: 4xx HTTPError — those won't succeed on retry
    (bad token, validation, etc.).

    Returns (ok, error_detail_on_failure, response_body_on_success).
    """
    last_error = "no attempts"
    for attempt in range(1, HTTP_MAX_ATTEMPTS + 1):
        try:
            with urlopen(req, timeout=HTTP_TIMEOUT) as resp:
                return True, "", resp.read()
        except HTTPError as e:
            try:
                body = e.read().decode(errors="replace")[:200]
            except Exception:
                body = ""
            if 400 <= e.code < 500:
                return False, f"HTTP {e.code}: {body}", b""
            last_error = f"HTTP {e.code}: {body}"
        except URLError as e:
            last_error = f"connection error: {e.reason}"
        except socket.timeout:
            last_error = f"timeout after {HTTP_TIMEOUT}s"

        if attempt < HTTP_MAX_ATTEMPTS:
            delay = HTTP_RETRY_BASE_DELAY * (2 ** (attempt - 1))
            time.sleep(delay)
    return False, f"{last_error} (after {HTTP_MAX_ATTEMPTS} attempts)", b""


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
    ok, err, resp_body = _urlopen_with_retry(req)
    if ok:
        return True, resp_body.decode(errors="replace")[:200]
    return False, err


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
    ok, err, resp_body = _urlopen_with_retry(req)
    if not ok:
        return False, err
    try:
        data = json.loads(resp_body)
        status = data.get("status", "unknown")
    except json.JSONDecodeError:
        return False, "invalid JSON response"
    return status in ("success", "queued", "stored_raw"), status


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
    exposed_count = sum(1 for ns in meta["namespaces"] if ns["internet_exposed"])
    print(
        f"  k8s_version={meta['k8s_version']}  provider={meta['provider']}  "
        f"region={meta['region'] or '—'}  namespaces={len(meta['namespaces'])}  "
        f"exposed={exposed_count}  complete_snapshot={meta['complete_snapshot']}"
    )
    if not meta["complete_snapshot"]:
        print(
            "  WARN: complete_snapshot=False — server will NOT deactivate "
            "missing namespaces. Likely cause: missing RBAC on core "
            "namespaces/services/ingresses. Check earlier warnings.",
            file=sys.stderr,
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
