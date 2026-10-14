"""Relevance filter — drop scan CRDs the server would skip or hide anyway.

Per envelope kind:

- cluster-level kinds (RBAC, Infra, Compliance, ClusterPolicyReport):
  always kept;
- image-anchored kinds (Vulnerability / Sbom / ExposedSecret report):
  kept iff `report.artifact.digest` is a currently-deployed digest
  (see snapshot_index.SnapshotIndex.deployed_digests). Trivy keeps a
  report for every historical ReplicaSet; those images are not running
  and the server hides their findings via
  `restrict_to_currently_deployed_images` — shipping them is pure cost;
- workload-anchored kinds (ConfigAuditReport, kyverno.PolicyReport):
  kept iff the subject resolves through the snapshot's ownerReference
  chain to a top-level workload (the server returns
  `workload_not_resolved` otherwise). A PolicyReport whose results are
  all `pass` is still kept: the server's reap only clears stale
  Kyverno signals when `observed_count > 0`.

With the filter disabled every item is kept but the stats are still
computed, so coverage and the log lines stay meaningful.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from .digests import normalize_digest
from .kinds import CLUSTER_LEVEL_KINDS, IMAGE_KINDS
from .snapshot_index import Key, SnapshotIndex, resolve_subject


@dataclass
class FilterStats:
    kind: str
    total: int = 0
    kept: int = 0
    dropped_no_subject: int = 0
    dropped_image_not_deployed: int = 0
    matched_digests: set[str] = field(default_factory=set)
    unmatched_digests: set[str] = field(default_factory=set)
    resolved_subjects: set[Key] = field(default_factory=set)

    def as_dict(self) -> dict:
        return {
            "total": self.total,
            "kept": self.kept,
            "dropped_no_subject": self.dropped_no_subject,
            "dropped_image_not_deployed": self.dropped_image_not_deployed,
        }


def _meta(item: dict) -> dict:
    return item.get("metadata") or {}


def subject_of_trivy(item: dict) -> Key:
    """Mirrors core/parsers/trivy.py::_resource_identity."""
    labels = _meta(item).get("labels") or {}
    namespace = labels.get("trivy-operator.resource.namespace") or _meta(item).get("namespace") or ""
    kind = labels.get("trivy-operator.resource.kind") or ""
    name = labels.get("trivy-operator.resource.name") or ""
    return (namespace, kind, name)


def subjects_of_kyverno(item: dict) -> list[Key]:
    """Every subject any result names (`subjects` or `resources`), with
    the report-level `scope` as the fallback — mirrors
    core/parsers/kyverno.py. Pass results count too (see module doc)."""
    report_ns = _meta(item).get("namespace") or ""
    scope = item.get("scope") or {}
    out: list[Key] = []
    for result in item.get("results") or []:
        if not isinstance(result, dict):
            continue
        subjects = result.get("subjects") or result.get("resources") or []
        if not subjects and scope.get("kind") and scope.get("name"):
            subjects = [scope]
        for subj in subjects:
            if not isinstance(subj, dict):
                continue
            out.append((subj.get("namespace") or report_ns, subj.get("kind") or "", subj.get("name") or ""))
    if not out and scope.get("kind") and scope.get("name"):
        out.append((scope.get("namespace") or report_ns, scope.get("kind") or "", scope.get("name") or ""))
    return out


def artifact_digest(item: dict) -> str:
    artifact = (item.get("report") or {}).get("artifact") or {}
    return normalize_digest(artifact.get("digest") or "")


def filter_kind(kind: str, items: list[dict], idx: SnapshotIndex, *, enabled: bool) -> tuple[list[dict], FilterStats]:
    stats = FilterStats(kind=kind, total=len(items))
    if kind in CLUSTER_LEVEL_KINDS:
        stats.kept = len(items)
        return list(items), stats

    kept: list[dict] = []
    for item in items:
        keep = False
        if kind in IMAGE_KINDS:
            digest = artifact_digest(item)
            if digest and digest in idx.deployed_digests:
                keep = True
                stats.matched_digests.add(digest)
            else:
                stats.dropped_image_not_deployed += 1
                if digest:
                    stats.unmatched_digests.add(digest)
        elif kind == "trivy.ConfigAuditReport":
            resolved = resolve_subject(idx, *subject_of_trivy(item))
            if resolved is not None:
                keep = True
                stats.resolved_subjects.add(resolved)
            else:
                stats.dropped_no_subject += 1
        elif kind == "kyverno.PolicyReport":
            resolved_any = [r for r in (resolve_subject(idx, *s) for s in subjects_of_kyverno(item)) if r]
            if resolved_any:
                keep = True
                stats.resolved_subjects.update(resolved_any)
            else:
                stats.dropped_no_subject += 1
        else:
            # Unknown kind: never filter what we don't understand.
            keep = True
        if keep:
            stats.kept += 1
            kept.append(item)

    if not enabled:
        return list(items), stats
    return kept, stats


def apply_relevance_filter(
    scan_items: dict[str, list[dict]], idx: SnapshotIndex, *, enabled: bool,
) -> tuple[dict[str, list[dict]], dict[str, FilterStats]]:
    filtered: dict[str, list[dict]] = {}
    stats: dict[str, FilterStats] = {}
    for kind, items in scan_items.items():
        filtered[kind], stats[kind] = filter_kind(kind, items, idx, enabled=enabled)
    return filtered, stats
