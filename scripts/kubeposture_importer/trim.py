"""Manifest trimming and cluster-meta extraction (unchanged behaviour)."""
from __future__ import annotations

import json

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
