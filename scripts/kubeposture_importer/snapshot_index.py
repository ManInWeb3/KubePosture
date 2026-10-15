"""Index of one inventory snapshot: which image digests are currently
deployed, which objects are top-level workloads, and the ownerReference
graph used to resolve scan subjects.

Deployed-digest set D deliberately mirrors — and is a superset of — the
server's notion in `core/parsers/inventory.py`:

- every digest in every Pod's `status.containerStatuses[].imageID` /
  `initContainerStatuses[].imageID` (any phase, any owner, terminating
  pods included — the server records them too);
- every digest-pinned `containers[].image` / `initContainers[].image` in
  a controller's pod template (Deployment, StatefulSet, DaemonSet,
  CronJob via `spec.jobTemplate.spec.template`, Job) or a standalone
  Pod's spec. ReplicaSet templates are NOT read — the server never
  reads them either, and including them would resurrect every
  historical ReplicaSet's image, which is exactly what the relevance
  filter exists to drop.

No `replicas != 0` check and no owner resolution for digests: over-
inclusion costs a few kilobytes, under-inclusion hides findings.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from .digests import digest_from_image_id, digest_from_ref
from .kinds import ALIAS_KINDS, TOP_LEVEL_CONTROLLER_KINDS

Key = tuple[str, str, str]  # (namespace, kind, name)

_GRAPH_KINDS = ("Deployment", "StatefulSet", "DaemonSet", "CronJob", "Job", "ReplicaSet", "Pod")
_MAX_HOPS = 8


@dataclass
class SnapshotIndex:
    deployed_digests: set[str] = field(default_factory=set)
    controllers: set[Key] = field(default_factory=set)
    owners: dict[Key, Key] = field(default_factory=dict)
    present: set[Key] = field(default_factory=set)
    # digest → ["Pod ns/name:ctr", "Deployment ns/name:ctr"] (debug output only)
    digest_sources: dict[str, list[str]] = field(default_factory=dict)

    def add_digest(self, digest: str, source: str) -> None:
        if not digest:
            return
        self.deployed_digests.add(digest)
        self.digest_sources.setdefault(digest, []).append(source)


def _meta(item: dict) -> dict:
    return item.get("metadata") or {}


def controller_owner(item: dict) -> dict | None:
    """First ownerReference flagged `controller: true` (mirrors the server)."""
    for ref in _meta(item).get("ownerReferences") or []:
        if isinstance(ref, dict) and ref.get("controller") is True:
            return ref
    return None


def pod_spec_of(kind: str, item: dict) -> dict | None:
    spec = item.get("spec") or {}
    if kind == "Pod":
        return spec
    if kind == "CronJob":
        spec = (spec.get("jobTemplate") or {}).get("spec") or {}
    template = spec.get("template") or {}
    return template.get("spec")


def _containers(pod_spec: dict | None):
    if not pod_spec:
        return []
    out = []
    for c in pod_spec.get("containers") or []:
        out.append(c)
    for c in pod_spec.get("initContainers") or []:
        out.append(c)
    return out


def build_index(by_kind: dict[str, list[dict] | None]) -> SnapshotIndex:
    idx = SnapshotIndex()
    for kind in _GRAPH_KINDS:
        for item in by_kind.get(kind) or []:
            if not isinstance(item, dict):
                continue
            md = _meta(item)
            ns = md.get("namespace") or ""
            name = md.get("name") or ""
            if not name:
                continue
            key: Key = (ns, kind, name)
            idx.present.add(key)

            owner = controller_owner(item)
            if kind in ALIAS_KINDS and owner is not None:
                idx.owners[key] = (ns, owner.get("kind") or "", owner.get("name") or "")
            if kind in TOP_LEVEL_CONTROLLER_KINDS or (kind in ("Job", "Pod") and owner is None):
                idx.controllers.add(key)

            if kind != "ReplicaSet":
                for c in _containers(pod_spec_of(kind, item)):
                    digest = digest_from_ref(c.get("image") or "")
                    if digest:
                        idx.add_digest(digest, f"{kind} {ns}/{name}:{c.get('name', '')}")

            if kind == "Pod":
                status = item.get("status") or {}
                for cs in (status.get("containerStatuses") or []) + (status.get("initContainerStatuses") or []):
                    digest = digest_from_image_id((cs or {}).get("imageID") or "")
                    if digest:
                        idx.add_digest(digest, f"Pod {ns}/{name}:{(cs or {}).get('name', '')}")
    return idx


def resolve_subject(idx: SnapshotIndex, namespace: str, kind: str, name: str,
                    *, max_hops: int = _MAX_HOPS) -> Key | None:
    """Follow controller ownerReferences present in the snapshot up to a
    top-level workload (Pod → ReplicaSet → Deployment, Pod → Job →
    CronJob, standalone Pod/Job → itself). None when the chain leaves
    the snapshot."""
    if not kind or not name:
        return None
    cur: Key = (namespace or "", kind, name)
    seen: set[Key] = set()
    for _ in range(max_hops):
        if cur in idx.controllers:
            return cur
        nxt = idx.owners.get(cur)
        if nxt is None or nxt in seen:
            return None
        seen.add(cur)
        cur = nxt
    return None
