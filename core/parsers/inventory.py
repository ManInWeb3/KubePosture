"""Inventory parser — navigates raw K8s manifests in the ingest envelope.

Pod-ownership rule: a Pod is a standalone Workload iff its
ownerReferences is empty. Owned Pods resolve to their controller via
the alias chain (ReplicaSet → Deployment, Job → CronJob).

Container scope: primary + init containers; ephemeral containers are
skipped.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field

from django.conf import settings
from django.db import transaction
from django.utils import timezone

from core.constants import AliasKind, WorkloadKind
from core.models import (
    Cluster,
    Image,
    Namespace,
    Workload,
    WorkloadAlias,
    WorkloadImageObservation,
    WorkloadSignal,
)
from core.signals import SIGNALS

log = logging.getLogger("core.inventory_parser")

# Progress breadcrumb interval for persist()'s workload loop — see
# ingest._process_inventory's "persist_starting" log for the sizes going
# in. persist() is one @transaction.atomic for the whole snapshot; for a
# large/busy cluster this is the only trace of how far it got if a pod
# dies mid-loop with nothing else logged until the call returns.

CONTROLLER_KINDS_TO_WORKLOAD = {
    "Deployment": WorkloadKind.DEPLOYMENT.value,
    "StatefulSet": WorkloadKind.STATEFULSET.value,
    "DaemonSet": WorkloadKind.DAEMONSET.value,
    "CronJob": WorkloadKind.CRONJOB.value,
    "Job": WorkloadKind.JOB.value,
    "Pod": WorkloadKind.POD.value,
}


@dataclass
class _InventoryStaging:
    """Holds parsed-but-not-yet-persisted inventory state for one cycle.

    Built up in two passes (controllers/aliases first, then pods +
    services/ingresses) before a single transactional commit.
    """

    cluster: Cluster
    namespaces: dict[str, Namespace] = field(default_factory=dict)
    namespace_labels: dict[str, dict] = field(default_factory=dict)
    namespace_annotations: dict[str, dict] = field(default_factory=dict)
    namespaces_with_netpol: set[str] = field(default_factory=set)

    # Workload identity → upserted Workload (post-save).
    # key = (namespace, kind, name)
    workloads: dict[tuple[str, str, str], Workload] = field(default_factory=dict)
    # (namespace, alias_kind, alias_name) → (target_kind, target_name)
    aliases: dict[tuple[str, str, str], tuple[str, str]] = field(default_factory=dict)

    # Previous cycle's WorkloadAlias rows, preloaded once by persist():
    # (namespace, alias_kind, alias_name) → (target_ns, target_kind, target_name).
    # The fallback for `_resolve_alias` when an owner aged out mid-cycle.
    db_aliases: dict[tuple[str, str, str], tuple[str, str, str]] = field(default_factory=dict)

    # Owned Pods, keyed by (namespace, owner_kind, owner_name) — resolved
    # to their top-level workload in the persist pass, once the alias
    # chain is complete.
    _pending_pod_observations: dict[tuple[str, str, str], list] = field(default_factory=dict)
    _pending_pod_signals: dict[tuple[str, str, str], set[str]] = field(default_factory=dict)

    # Service / Ingress data for exposure derivation.
    services: list[dict] = field(default_factory=list)
    ingresses: list[dict] = field(default_factory=list)

    # Workload-keyed signals discovered from manifests:
    # (namespace, kind, name) → set[signal_id]
    derived_signals: dict[tuple[str, str, str], set[str]] = field(default_factory=dict)

    # (namespace, kind, name) → list[(image_ref, image_digest, container_name, init_container)]
    image_observations: dict[
        tuple[str, str, str], list[tuple[str, str, str, bool]]
    ] = field(default_factory=dict)

    # cluster-meta dict from the envelope (k8s_version, provider, region).
    cluster_meta: dict = field(default_factory=dict)

    # Items in the envelope whose `kind` field was missing/empty/unknown
    # — these were silently skipped by the dispatch table. A non-zero
    # count signals an upstream bug (e.g., importer didn't stamp kind
    # on serialized typed objects). Surfaced via `persist()` counters
    # so the worker can log a WARNING.
    unknown_kind_skipped: int = 0


# ── Helpers --------------------------------------------------------

def _meta(item: dict) -> dict:
    return item.get("metadata") or {}


def _name(item: dict) -> str:
    return _meta(item).get("name") or ""


def _namespace(item: dict) -> str:
    return _meta(item).get("namespace") or ""


def _owner_refs(item: dict) -> list[dict]:
    return list(_meta(item).get("ownerReferences") or [])


def _controller_owner(item: dict) -> dict | None:
    for ref in _owner_refs(item):
        if ref.get("controller") is True:
            return ref
    return None


def _pod_template_spec(controller_kind: str, item: dict) -> dict | None:
    # CronJob nests its PodSpec one level deeper than the other controllers.
    spec = item.get("spec") or {}
    if controller_kind == "CronJob":
        spec = (spec.get("jobTemplate") or {}).get("spec") or {}
    template = spec.get("template") or {}
    return template.get("spec")


def _pod_template_meta(controller_kind: str, item: dict) -> dict:
    spec = item.get("spec") or {}
    if controller_kind == "CronJob":
        spec = (spec.get("jobTemplate") or {}).get("spec") or {}
    template = spec.get("template") or {}
    return template.get("metadata") or {}


def _containers(pod_spec: dict | None) -> list[tuple[dict, bool]]:
    """Yield (container_spec, init_container) for every container in
    the pod spec, runtime first then init. The init_container flag
    lets callers distinguish initContainers without a second walk.
    """
    if not pod_spec:
        return []
    out: list[tuple[dict, bool]] = []
    for c in pod_spec.get("containers") or []:
        out.append((c, False))
    for c in pod_spec.get("initContainers") or []:
        out.append((c, True))
    return out


def _digest_from_ref(ref: str) -> str:
    if "@" in ref:
        _, _, tail = ref.partition("@")
        if tail.startswith("sha256:"):
            return tail
    return ""


def _digest_from_pod_status(pod: dict, container_name: str) -> str:
    status = pod.get("status") or {}
    statuses = status.get("containerStatuses") or []
    for cs in statuses:
        if cs.get("name") != container_name:
            continue
        image_id = cs.get("imageID") or ""
        if "@" in image_id:
            _, _, tail = image_id.partition("@")
            if tail.startswith("sha256:"):
                return tail
        if image_id.startswith("sha256:"):
            return image_id
    # Init containers live in initContainerStatuses.
    for cs in status.get("initContainerStatuses") or []:
        if cs.get("name") != container_name:
            continue
        image_id = cs.get("imageID") or ""
        if "@" in image_id:
            _, _, tail = image_id.partition("@")
            if tail.startswith("sha256:"):
                return tail
        if image_id.startswith("sha256:"):
            return image_id
    return ""


def _registry_repo(ref: str) -> tuple[str, str]:
    body = ref.split("@", 1)[0]
    body = body.rsplit(":", 1)[0]
    if "/" in body:
        head, _, tail = body.partition("/")
        if "." in head or ":" in head:
            return head, tail
        return "", body
    return "", body


def _pod_security_signals(pod_spec: dict | None) -> set[str]:
    found: set[str] = set()
    if not pod_spec:
        return found
    if pod_spec.get("hostNetwork") or pod_spec.get("hostPID") or pod_spec.get("hostIPC"):
        found.add("kyverno:disallow-host-namespaces")
    # Kyverno semantics (and the registry text): the three "require"
    # checks fail when the field is false OR unset — a container with no
    # securityContext at all is the common case and must still signal.
    # `runAsNonRoot` may be set at pod level and inherited.
    pod_ctx = pod_spec.get("securityContext") or {}
    for c, _init_container in _containers(pod_spec):
        ctx = c.get("securityContext") or {}
        if ctx.get("privileged") is True:
            found.add("kyverno:disallow-privileged-containers")
        if ctx.get("allowPrivilegeEscalation") is not False:
            found.add("kyverno:disallow-privilege-escalation")
        run_as_non_root = ctx.get("runAsNonRoot")
        if run_as_non_root is None:
            run_as_non_root = pod_ctx.get("runAsNonRoot")
        if run_as_non_root is not True:
            found.add("kyverno:require-run-as-nonroot")
        if ctx.get("readOnlyRootFilesystem") is not True:
            found.add("kyverno:require-ro-rootfs")
    for v in pod_spec.get("volumes") or []:
        if v.get("hostPath"):
            found.add("kyverno:disallow-host-path")
            break
    return {sid for sid in found if sid in SIGNALS}


# ── Service / Ingress → publicly_exposed derivation ---------------

_INTERNAL_LB_ANNOTATIONS = {
    # Legacy in-tree AWS controller.
    "service.beta.kubernetes.io/aws-load-balancer-internal": "true",
    # AWS Load Balancer Controller (the current EKS default).
    "service.beta.kubernetes.io/aws-load-balancer-scheme": "internal",
    "networking.gke.io/load-balancer-type": "Internal",
    "service.beta.kubernetes.io/azure-load-balancer-internal": "true",
}


def _is_internal_lb(svc_meta: dict) -> bool:
    annotations = svc_meta.get("annotations") or {}
    for k, v in _INTERNAL_LB_ANNOTATIONS.items():
        ann = annotations.get(k)
        if ann is None:
            continue
        if str(ann).lower() == str(v).lower():
            return True
    return False


def _selector_subset(selector: dict, labels: dict) -> bool:
    if not selector:
        return False
    for k, v in selector.items():
        if labels.get(k) != v:
            return False
    return True


def _configured_internal_ingress_classes() -> frozenset[str]:
    raw = getattr(settings, "INTERNAL_INGRESS_CLASSES", []) or []
    return frozenset(s.strip().lower() for s in raw if s and s.strip())


def _is_internal_ingress(ing: dict) -> bool:
    spec = ing.get("spec") or {}
    cls = (spec.get("ingressClassName") or "").lower()
    configured = _configured_internal_ingress_classes()
    if cls and cls in configured:
        return True
    if "internal" in cls or "private" in cls:
        return True
    annotations = (ing.get("metadata") or {}).get("annotations") or {}
    if str(annotations.get("alb.ingress.kubernetes.io/scheme", "")).lower() == "internal":
        return True
    cls_ann = str(annotations.get("kubernetes.io/ingress.class", "")).lower()
    if cls_ann and cls_ann in configured:
        return True
    if cls_ann.endswith("-internal") or "internal" in cls_ann:
        return True
    return False


def _ingress_backend_service_names(ing: dict) -> set[str]:
    out: set[str] = set()
    spec = ing.get("spec") or {}
    default = (spec.get("defaultBackend") or {}).get("service") or {}
    if default.get("name"):
        out.add(default["name"])
    for rule in spec.get("rules") or []:
        http = rule.get("http") or {}
        for path in http.get("paths") or []:
            be = (path.get("backend") or {}).get("service") or {}
            if be.get("name"):
                out.add(be["name"])
    return out


# ── Item dispatch --------------------------------------------------

_ENV_DETECTION_REGEX = [
    (r"(^|[-_])prod([-_]|$)", "prod"),
    (r"(^|[-_])production([-_]|$)", "prod"),
    (r"(^|[-_])prd([-_]|$)", "prod"),
    (r"(^|[-_])stag(e|ing)?([-_]|$)", "staging"),
    (r"(^|[-_])stg([-_]|$)", "staging"),
    (r"(^|[-_])(dev|development|test|sandbox|qa)([-_]|$)", "dev"),
]


def _detect_environment_from_name(cluster_name: str) -> str:
    import re
    for pattern, env in _ENV_DETECTION_REGEX:
        if re.search(pattern, cluster_name):
            return env
    return "dev"


def _ingest_namespace(item: dict, st: _InventoryStaging) -> None:
    name = _name(item)
    if not name:
        return
    md = _meta(item)
    st.namespace_labels[name] = dict(md.get("labels") or {})
    st.namespace_annotations[name] = dict(md.get("annotations") or {})


def _ingest_controller(item: dict, st: _InventoryStaging) -> None:
    """Upsert a top-level Workload from a controller manifest."""
    api_kind = item.get("kind") or ""
    # `_DISPATCH` routes ReplicaSets, Pods and owned Jobs elsewhere; only
    # top-level controllers reach this point.
    if api_kind not in CONTROLLER_KINDS_TO_WORKLOAD:
        return

    name = _name(item)
    namespace = _namespace(item)
    if not name or not namespace:
        return

    pod_meta = _pod_template_meta(api_kind, item)
    pod_spec = _pod_template_spec(api_kind, item)
    spec = item.get("spec") or {}

    workload_kind = CONTROLLER_KINDS_TO_WORKLOAD[api_kind]
    key = (namespace, workload_kind, name)

    labels = dict(pod_meta.get("labels") or {})
    service_account = (pod_spec or {}).get("serviceAccountName") or "default"
    replicas = spec.get("replicas")

    workload = Workload(
        cluster=st.cluster,
        namespace=None,  # set later when Namespace rows exist
        kind=workload_kind,
        name=name,
        service_account=service_account,
        replicas=int(replicas) if replicas is not None else None,
        labels=labels,
    )
    # Stash the namespace string for the persist-pass.
    st.workloads[key] = workload

    sigs = _pod_security_signals(pod_spec)
    if sigs:
        st.derived_signals.setdefault(key, set()).update(sigs)

    # Declared-image observations from the controller's own podSpec.
    obs = st.image_observations.setdefault(key, [])
    for c, init_container in _containers(pod_spec):
        cname = c.get("name") or ""
        ref = c.get("image") or ""
        if not cname or not ref:
            continue
        digest = _digest_from_ref(ref)
        obs.append((ref, digest, cname, init_container))


def _ingest_pod(item: dict, st: _InventoryStaging) -> None:
    """Pods carry the ground-truth image set + per-container digests.

    Standalone Pod (no controller owner) → upserts a Workload of kind
    Pod. Owned Pod → resolves via alias chain (later) to update the
    parent's image-observation set with actual digests.
    """
    name = _name(item)
    namespace = _namespace(item)
    if not name or not namespace:
        return

    spec = item.get("spec") or {}
    owner_ref = _controller_owner(item)

    # Pod→owner hint lets Kyverno PolicyReports with scope.kind=Pod
    # resolve to a top-level workload via the alias chain.
    if owner_ref is not None:
        st.aliases[(namespace, "Pod", name)] = (
            owner_ref.get("kind") or "",
            owner_ref.get("name") or "",
        )

    if owner_ref is None:
        labels = dict((_meta(item).get("labels")) or {})
        sa = spec.get("serviceAccountName") or "default"

        workload = Workload(
            cluster=st.cluster,
            namespace=None,
            kind=WorkloadKind.POD.value,
            name=name,
            service_account=sa,
            replicas=None,
            labels=labels,
        )
        key = (namespace, WorkloadKind.POD.value, name)
        st.workloads[key] = workload

        sigs = _pod_security_signals(spec)
        if sigs:
            st.derived_signals.setdefault(key, set()).update(sigs)

        obs = st.image_observations.setdefault(key, [])
        for c, init_container in _containers(spec):
            cname = c.get("name") or ""
            ref = c.get("image") or ""
            if not cname or not ref:
                continue
            digest = _digest_from_ref(ref) or _digest_from_pod_status(item, cname)
            obs.append((ref, digest, cname, init_container))
        return

    # Owned Pod — defer resolution to the persist pass (alias chain may
    # not be fully built yet).
    spec_signals = _pod_security_signals(spec)

    pending = st._pending_pod_observations.setdefault(
        (namespace, owner_ref.get("kind"), owner_ref.get("name")),
        [],
    )
    for c, init_container in _containers(spec):
        cname = c.get("name") or ""
        ref = c.get("image") or ""
        if not cname or not ref:
            continue
        digest = _digest_from_ref(ref) or _digest_from_pod_status(item, cname)
        pending.append((ref, digest, cname, init_container))

    # PodSpec-level signals attach to the owning workload too.
    if spec_signals:
        st._pending_pod_signals.setdefault(
            (namespace, owner_ref.get("kind"), owner_ref.get("name")),
            set(),
        ).update(spec_signals)


def _ingest_alias_object(item: dict, st: _InventoryStaging) -> None:
    """ReplicaSet / Job → record its (alias_kind, alias_name) → controller mapping."""
    api_kind = item.get("kind")
    if api_kind not in (AliasKind.REPLICASET.value, AliasKind.JOB.value):
        return
    name = _name(item)
    namespace = _namespace(item)
    owner = _controller_owner(item)
    if not name or not namespace or owner is None:
        return
    target_kind = owner.get("kind")
    target_name = owner.get("name")
    if not target_kind or not target_name:
        return
    st.aliases[(namespace, api_kind, name)] = (target_kind, target_name)


def _ingest_service(item: dict, st: _InventoryStaging) -> None:
    spec = item.get("spec") or {}
    md = _meta(item)
    selector = dict(spec.get("selector") or {})
    if not selector:
        return  # selectorless Services don't bind to any workload labels
    st.services.append({
        "namespace": _namespace(item),
        "name": _name(item),
        "type": spec.get("type") or "ClusterIP",
        "selector": selector,
        "annotations": dict(md.get("annotations") or {}),
    })


def _ingest_ingress(item: dict, st: _InventoryStaging) -> None:
    md = _meta(item)
    st.ingresses.append({
        "namespace": _namespace(item),
        "name": _name(item),
        "spec": item.get("spec") or {},
        "metadata": md,
    })


def _ingest_networkpolicy(item: dict, st: _InventoryStaging) -> None:
    namespace = _namespace(item)
    if namespace:
        st.namespaces_with_netpol.add(namespace)


# ── Entry point: parse one envelope item ---------------------------

_DISPATCH = {
    "Namespace": _ingest_namespace,
    "Deployment": _ingest_controller,
    "StatefulSet": _ingest_controller,
    "DaemonSet": _ingest_controller,
    "CronJob": _ingest_controller,
    "Job": lambda item, st: (_ingest_controller(item, st) if not _controller_owner(item) else _ingest_alias_object(item, st)),
    "ReplicaSet": _ingest_alias_object,
    "Pod": _ingest_pod,
    "Service": _ingest_service,
    "Ingress": _ingest_ingress,
    "NetworkPolicy": _ingest_networkpolicy,
}


def parse_envelope(payload: dict, cluster: Cluster) -> _InventoryStaging:
    """Parse one inventory payload (envelope) into a staging object."""
    st = _InventoryStaging(cluster=cluster)
    st.cluster_meta = dict(payload.get("cluster_meta") or {})

    items = payload.get("items") or []
    for item in items:
        kind = item.get("kind")
        handler = _DISPATCH.get(kind)
        if handler:
            handler(item, st)
        else:
            # An item with a non-trivial structure but no recognised
            # `kind` is almost certainly an upstream bug (e.g., the
            # importer didn't stamp `kind` on serialized K8s typed
            # objects). Count it so the worker can WARN.
            if isinstance(item, dict) and (
                item.get("metadata") or item.get("spec") or item.get("apiVersion")
            ):
                st.unknown_kind_skipped += 1
    return st


# ── Persist pass --------------------------------------------------

def _resolve_alias(
    st: _InventoryStaging, namespace: str, kind: str, name: str
) -> tuple[str, str] | None:
    """Walk the alias chain (this cycle's staging, then the previous
    cycle's rows in `st.db_aliases`) to a top-level Workload.

    The previous-cycle fallback handles the case where a Pod's owning
    Job has aged out of the inventory mid-cycle but the alias row from
    the previous cycle still resolves to the parent CronJob.
    """
    known_namespace = namespace in st.namespaces
    seen: set[tuple[str, str, str]] = set()
    cur_ns, cur_kind, cur_name = namespace, kind, name
    while True:
        cur = (cur_ns, cur_kind, cur_name)
        if cur in seen:
            return None
        seen.add(cur)

        wk_self = CONTROLLER_KINDS_TO_WORKLOAD.get(cur_kind)
        if wk_self and (cur_ns, wk_self, cur_name) in st.workloads:
            return wk_self, cur_name

        target = st.aliases.get(cur)
        if target is None and known_namespace:
            previous = st.db_aliases.get(cur)
            if previous is not None:
                target_ns, target_kind, target_name = previous
                if (target_ns, target_kind, target_name) in st.workloads:
                    return target_kind, target_name
                target = (target_kind, target_name)

        if target is None:
            return None
        target_kind, target_name = target
        wk = CONTROLLER_KINDS_TO_WORKLOAD.get(target_kind)
        if wk and (cur_ns, wk, target_name) in st.workloads:
            return wk, target_name
        cur_kind, cur_name = target_kind, target_name


def _compute_exposure_breakdown(
    workload_labels: dict, namespace: str, st: _InventoryStaging
) -> tuple[bool, bool]:
    """Return (has_external_lb, has_external_ingress).

    The two are kept separate so the per-source signals
    (kp:has-external-lb / kp:has-external-ingress) can be written.
    `Workload.publicly_exposed` is just the OR of these.
    """
    has_lb = False
    has_ing = False
    for svc in st.services:
        if svc["namespace"] != namespace:
            continue
        if svc["type"] != "LoadBalancer":
            continue
        if _is_internal_lb({"annotations": svc["annotations"]}):
            continue
        if _selector_subset(svc["selector"], workload_labels):
            has_lb = True
            break
    # External Ingress (via backend Services)
    for ing in st.ingresses:
        if ing["namespace"] != namespace:
            continue
        if _is_internal_ingress(ing):
            continue
        backends = _ingress_backend_service_names(ing)
        if not backends:
            continue
        for svc in st.services:
            if svc["namespace"] != namespace:
                continue
            if svc["name"] not in backends:
                continue
            if _selector_subset(svc["selector"], workload_labels):
                has_ing = True
                break
        if has_ing:
            break
    return has_lb, has_ing


def _compute_nodeport(
    workload_labels: dict, namespace: str, st: _InventoryStaging
) -> bool:
    for svc in st.services:
        if svc["namespace"] != namespace:
            continue
        if svc["type"] != "NodePort":
            continue
        if _selector_subset(svc["selector"], workload_labels):
            return True
    return False


_SENSITIVE_KEY = "posture.io/contains-sensitive-data"
_MISSING_NETPOL = "kp:missing-networkpolicy"
# Rows per bulk INSERT / UPDATE statement.
_BULK_BATCH = 500


@transaction.atomic
def persist(st: _InventoryStaging, mark_started_at) -> dict:
    """Write the staged inventory to the DB, return summary counters.

    `mark_started_at` is the ImportMark.started_at for this cycle's
    inventory kind. Used to bump `Workload.last_inventory_at` so the
    reap's diff fires correctly.

    One transaction, one pass per model: each phase loads the cluster's
    existing rows for its model in a single query, diffs them against
    the staging in memory, then writes with `bulk_create` /
    `bulk_update` — so the cost is a fixed ~20 statements rather than
    one lookup plus one save per namespace, workload, alias, image,
    observation and signal (core/tests/parsers/test_inventory_persist_bulk.py
    pins that). The row-level contract of the old per-row saves is kept:
    `last_seen_at` is bumped on every row the snapshot touched (and only
    those), `first_seen_at` never changes, manual admin flags win.

    The cluster row is written first, as the reaper does, so the two
    never take the `core_cluster` / `core_workload` locks in opposite
    orders; with `update_fields` it only ever writes the columns the
    inventory owns.
    """
    cluster = st.cluster
    _persist_cluster_meta(st)
    seen_namespaces = _persist_namespaces(st)
    st.workloads = _persist_workloads(st, mark_started_at)
    _persist_aliases(st)
    _persist_images_and_observations(st)
    _persist_signals(st)
    _rollup_namespace_exposure(st)

    if st.unknown_kind_skipped > 0:
        logging.getLogger("core.inventory").warning(
            "inventory.unknown_kind_skipped count=%d cluster=%s — items "
            "had no `kind` field; likely an importer bug "
            "(e.g., kubernetes Python client typed-list serialization).",
            st.unknown_kind_skipped, cluster.name,
        )

    return {
        "namespaces": len(seen_namespaces),
        "workloads": len(st.workloads),
        "aliases": len(st.aliases),
        "unknown_kind_skipped": st.unknown_kind_skipped,
    }


def _persist_cluster_meta(st: _InventoryStaging) -> None:
    """Cluster columns the inventory owns, written with `update_fields`:
    the worker loaded this Cluster before parsing, and a reap
    (`last_complete_inventory_at`) or an admin (re-import request, manual
    flags) may have committed to the row since — a full-row save would
    silently roll those back."""
    meta = st.cluster_meta or {}
    cluster = st.cluster
    fields = ["last_seen_at"]
    if (v := meta.get("k8s_version")) and cluster.k8s_version != v:
        cluster.k8s_version = v
        fields.append("k8s_version")
    if (p := meta.get("provider")) and not cluster.provider_is_manual and cluster.provider != p:
        cluster.provider = p
        fields.append("provider")
    if (r := meta.get("region")) is not None and not cluster.region_is_manual and cluster.region != r:
        cluster.region = r
        fields.append("region")
    if not cluster.environment_is_manual:
        env = _detect_environment_from_name(cluster.name)
        if env and cluster.environment != env:
            cluster.environment = env
            fields.append("environment")
    cluster.last_seen_at = timezone.now()
    cluster.save(update_fields=fields)


def _persist_namespaces(st: _InventoryStaging) -> set[str]:
    """Upsert the listed namespaces, create implicit ones (referenced by a
    workload but not listed), deactivate the rest. Every committed
    inventory is a complete snapshot (the bundle protocol guarantees it),
    so "absent" means "gone". Fills `st.namespaces`; returns the listed
    names."""
    cluster = st.cluster
    now = timezone.now()
    existing = {ns.name: ns for ns in Namespace.objects.filter(cluster=cluster)}
    seen = set(st.namespace_labels)
    to_create: list[Namespace] = []
    to_update: list[Namespace] = []
    for ns_name, labels in st.namespace_labels.items():
        annotations = st.namespace_annotations.get(ns_name, {})
        sens_label = labels.get(_SENSITIVE_KEY) or annotations.get(_SENSITIVE_KEY)
        ns = existing.get(ns_name)
        if ns is None:
            ns = Namespace(cluster=cluster, name=ns_name, labels=labels, annotations=annotations)
            if sens_label is not None:
                ns.contains_sensitive_data = str(sens_label).lower() == "true"
            to_create.append(ns)
        else:
            ns.labels = labels
            ns.annotations = annotations
            ns.active = True
            ns.deactivated_at = None
            # Auto-derive contains_sensitive_data from the label, unless
            # the admin has manually set the flag on the existing row.
            if sens_label is not None and not ns.sensitive_is_manual:
                ns.contains_sensitive_data = str(sens_label).lower() == "true"
            ns.last_seen_at = now
            to_update.append(ns)
        st.namespaces[ns_name] = ns

    for (ns_name, _, _) in st.workloads:
        if ns_name in st.namespaces:
            continue
        ns = existing.get(ns_name)
        if ns is None:
            ns = Namespace(cluster=cluster, name=ns_name)
            to_create.append(ns)
        st.namespaces[ns_name] = ns

    # A deactivation is not a sighting: `last_seen_at` stays put.
    to_deactivate = [ns for name, ns in existing.items() if ns.active and name not in seen]
    for ns in to_deactivate:
        ns.active = False
        ns.deactivated_at = now

    Namespace.objects.bulk_create(to_create, batch_size=_BULK_BATCH)
    Namespace.objects.bulk_update(
        to_update,
        ["labels", "annotations", "active", "deactivated_at", "contains_sensitive_data", "last_seen_at"],
        batch_size=_BULK_BATCH,
    )
    Namespace.objects.bulk_update(to_deactivate, ["active", "deactivated_at"], batch_size=_BULK_BATCH)
    return seen


def _persist_workloads(st: _InventoryStaging, mark_started_at) -> dict[tuple[str, str, str], Workload]:
    """Upsert one row per staged workload and derive its exposure from
    the staged Services / Ingresses (recording the per-source signals in
    `st.derived_signals`). Returns identity → persisted row."""
    cluster = st.cluster
    now = timezone.now()
    existing = {(w.namespace_id, w.kind, w.name): w for w in Workload.objects.filter(cluster=cluster)}
    out: dict[tuple[str, str, str], Workload] = {}
    to_create: list[Workload] = []
    to_update: list[Workload] = []
    for key, staged in st.workloads.items():
        ns_name, wkind, wname = key
        ns = st.namespaces.get(ns_name)
        if ns is None:
            continue

        labels = staged.labels or {}
        has_lb, has_ing = _compute_exposure_breakdown(labels, ns_name, st)
        if has_lb:
            st.derived_signals.setdefault(key, set()).add("kp:has-external-lb")
        if has_ing:
            st.derived_signals.setdefault(key, set()).add("kp:has-external-ingress")
        if _compute_nodeport(labels, ns_name, st):
            st.derived_signals.setdefault(key, set()).add("kp:has-nodeport-service")
        publicly_exposed = has_lb or has_ing

        fields = {
            "service_account": staged.service_account or "default",
            "replicas": staged.replicas,
            "labels": labels,
            # A workload scaled to zero (Deployment/StatefulSet with
            # replicas==0) is in inventory but runs no pods — not
            # deployed. replicas is None for DaemonSets/Pods/CronJobs/
            # Jobs (no replica count) and None != 0, so those stay
            # deployed. The reap re-applies the same rule as the final
            # authority (reap_inventory_diff).
            "deployed": staged.replicas != 0,
            "last_inventory_at": mark_started_at,
        }
        row = existing.get((ns.id, wkind, wname))
        if row is None:
            row = Workload(cluster=cluster, namespace=ns, kind=wkind, name=wname,
                           publicly_exposed=publicly_exposed, **fields)
            to_create.append(row)
        else:
            # Reuses the row even if it had gone deployed=False for a
            # while (deleted then redeployed later) — `first_seen_at` is
            # untouched so it survives the gap. Intentional: see
            # Workload.first_seen_at's help_text.
            for k, v in fields.items():
                setattr(row, k, v)
            if not row.publicly_exposed_is_manual:
                row.publicly_exposed = publicly_exposed
            row.last_seen_at = now
            to_update.append(row)
        out[key] = row

    Workload.objects.bulk_create(to_create, batch_size=_BULK_BATCH)
    Workload.objects.bulk_update(
        to_update,
        ["service_account", "replicas", "labels", "deployed", "last_inventory_at", "publicly_exposed",
         "last_seen_at"],
        batch_size=_BULK_BATCH,
    )
    return out


def _persist_aliases(st: _InventoryStaging) -> None:
    """Persist a DIRECT (alias_kind, alias_name) → top-level-workload
    mapping, resolving the full ownership chain (Pod→ReplicaSet→Deployment,
    Pod→Job→CronJob) via `_resolve_alias`. Recording only the immediate
    owner would be useless for `ingest._resolve_workload`, which does one
    lookup with no chain-walking of its own.

    Pending pod observations / signals are resolved here too, BEFORE the
    stale-alias prune, so resolution can use both this cycle's staging and
    the previous cycle's rows (a Pod whose owning ReplicaSet/Job aged out
    of `kubectl get` mid-cycle).
    """
    cluster = st.cluster
    now = timezone.now()
    existing: dict[tuple[int, str, str], tuple[int, int]] = {}   # (ns_id, kind, name) → (row id, target id)
    st.db_aliases = {}
    for row_id, ns_id, ns_name, ak, an, tw_id, t_ns, t_kind, t_name in (
        WorkloadAlias.objects.filter(cluster=cluster).values_list(
            "id", "namespace_id", "namespace__name", "alias_kind", "alias_name",
            "target_workload_id", "target_workload__namespace__name", "target_workload__kind",
            "target_workload__name",
        )
    ):
        existing[(ns_id, ak, an)] = (row_id, tw_id)
        st.db_aliases[(ns_name, ak, an)] = (t_ns, t_kind, t_name)

    to_create: list[WorkloadAlias] = []
    to_update: list[WorkloadAlias] = []
    kept: set[int] = set()
    for (ns_name, alias_kind, alias_name) in list(st.aliases):
        ns = st.namespaces.get(ns_name)
        if ns is None:
            continue
        resolved = _resolve_alias(st, ns_name, alias_kind, alias_name)
        if resolved is None:
            continue
        target = st.workloads.get((ns_name, *resolved))
        if target is None:
            continue
        found = existing.get((ns.id, alias_kind, alias_name))
        if found is None:
            to_create.append(WorkloadAlias(cluster=cluster, namespace=ns, alias_kind=alias_kind,
                                           alias_name=alias_name, target_workload=target))
        else:
            row_id, _ = found
            to_update.append(WorkloadAlias(id=row_id, target_workload=target, last_seen_at=now))
            kept.add(row_id)

    for (ns_name, owner_kind, owner_name), obs in st._pending_pod_observations.items():
        resolved = _resolve_alias(st, ns_name, owner_kind, owner_name)
        if resolved is not None:
            st.image_observations.setdefault((ns_name, *resolved), []).extend(obs)
    for (ns_name, owner_kind, owner_name), sigs in st._pending_pod_signals.items():
        resolved = _resolve_alias(st, ns_name, owner_kind, owner_name)
        if resolved is not None:
            st.derived_signals.setdefault((ns_name, *resolved), set()).update(sigs)

    WorkloadAlias.objects.bulk_create(to_create, batch_size=_BULK_BATCH)
    WorkloadAlias.objects.bulk_update(to_update, ["target_workload", "last_seen_at"], batch_size=_BULK_BATCH)
    stale = [row_id for row_id, _ in existing.values() if row_id not in kept]
    if stale:
        WorkloadAlias.objects.filter(id__in=stale).delete()


def _persist_images_and_observations(st: _InventoryStaging) -> None:
    """Images by digest (the first ref seen for a digest this cycle wins)
    and one WorkloadImageObservation per (workload, image, container).
    `init_container` and `last_seen_at` refresh every cycle;
    `currently_deployed` is deliberately not written — only the inventory
    reaper flips it, at the end of a complete cycle."""
    now = timezone.now()
    refs: dict[str, str] = {}                               # digest → ref
    wanted: dict[tuple[int, str, str], bool] = {}           # (workload id, digest, container) → init
    for key, obs_list in st.image_observations.items():
        wl = st.workloads.get(key)
        if wl is None:
            continue
        for ref, digest, cname, init_container in obs_list:
            if not digest:
                continue   # the schema requires a digest; skip unanchored observations
            refs.setdefault(digest, ref)
            wanted[(wl.id, digest, cname)] = init_container
    if not refs:
        return

    images = {img.digest: img for img in Image.objects.filter(digest__in=list(refs))}
    to_create: list[Image] = []
    to_update: list[Image] = []
    for digest, ref in refs.items():
        registry, repo = _registry_repo(ref) if ref else ("", "")
        img = images.get(digest)
        if img is None:
            img = Image(digest=digest, ref=ref or "", registry=registry, repository=repo)
            images[digest] = img
            to_create.append(img)
        else:
            img.ref = ref or ""
            img.registry = registry
            img.repository = repo
            img.last_seen_at = now
            to_update.append(img)
    Image.objects.bulk_create(to_create, batch_size=_BULK_BATCH)
    Image.objects.bulk_update(to_update, ["ref", "registry", "repository", "last_seen_at"], batch_size=_BULK_BATCH)

    existing = {
        (o.workload_id, o.image_id, o.container_name): o
        for o in WorkloadImageObservation.objects.filter(workload__cluster=st.cluster)
    }
    new_obs: list[WorkloadImageObservation] = []
    seen_obs: list[WorkloadImageObservation] = []
    for (wl_id, digest, cname), init_container in wanted.items():
        img = images[digest]
        obs = existing.get((wl_id, img.id, cname))
        if obs is None:
            new_obs.append(WorkloadImageObservation(workload_id=wl_id, image=img, container_name=cname,
                                                    init_container=init_container))
        else:
            obs.init_container = init_container
            obs.last_seen_at = now
            seen_obs.append(obs)
    WorkloadImageObservation.objects.bulk_create(new_obs, batch_size=_BULK_BATCH)
    WorkloadImageObservation.objects.bulk_update(seen_obs, ["init_container", "last_seen_at"], batch_size=_BULK_BATCH)


def _persist_signals(st: _InventoryStaging) -> None:
    """Manifest-derived signals (active) plus `kp:missing-networkpolicy`
    on every workload of a namespace with no NetworkPolicy this cycle
    (cleared where one exists). Same contract as
    `WorkloadSignal.objects.upsert`: an active sighting creates or bumps
    the row, a clearing one writes only when it flips the flag, a signal
    never seen active has no row."""
    now = timezone.now()
    desired: dict[tuple[int, str], bool] = {}
    for key, signal_ids in st.derived_signals.items():
        wl = st.workloads.get(key)
        if wl is None:
            continue
        for sig in signal_ids:
            if sig in SIGNALS:
                desired[(wl.id, sig)] = True
    for (ns_name, _, _), wl in st.workloads.items():
        desired[(wl.id, _MISSING_NETPOL)] = ns_name not in st.namespaces_with_netpol
    if not desired:
        return

    existing = {
        (s.workload_id, s.signal_id): s
        for s in WorkloadSignal.objects.filter(
            workload__cluster=st.cluster, signal_id__in={sig for _, sig in desired},
        )
    }
    to_create: list[WorkloadSignal] = []
    to_update: list[WorkloadSignal] = []
    for (wl_id, sig), active in desired.items():
        row = existing.get((wl_id, sig))
        if row is None:
            if active:
                to_create.append(WorkloadSignal(workload_id=wl_id, signal_id=sig, currently_active=True))
        elif active or row.currently_active:
            row.currently_active = active
            row.last_seen_at = now
            to_update.append(row)
    WorkloadSignal.objects.bulk_create(to_create, batch_size=_BULK_BATCH)
    WorkloadSignal.objects.bulk_update(to_update, ["currently_active", "last_seen_at"], batch_size=_BULK_BATCH)


def _rollup_namespace_exposure(st: _InventoryStaging) -> None:
    """`Namespace.internet_exposed` = any deployed workload in it is
    publicly exposed. Scaled-to-zero workloads (deployed=False) have no
    endpoints behind their LB/Ingress, so they don't count. Manual
    overrides win."""
    exposed = {ns_name for (ns_name, _, _), wl in st.workloads.items() if wl.deployed and wl.publicly_exposed}
    changed = []
    for ns_name, ns in st.namespaces.items():
        if ns.exposure_is_manual:
            continue
        rollup = ns_name in exposed
        if ns.internet_exposed != rollup:
            ns.internet_exposed = rollup
            changed.append(ns)
    Namespace.objects.bulk_update(changed, ["internet_exposed"], batch_size=_BULK_BATCH)


# ── Inventory reap diff (deployed-flag) ---------------------------

@transaction.atomic
def reap_inventory_diff(cluster: Cluster, mark_started_at) -> dict:
    """Maintain `Workload.deployed` after a complete inventory cycle.

    Image deployment is no longer a stored flag — it's derived on
    read via `Image.objects.currently_running()`. The reap only
    needs to update the workload-level truth; the image side falls
    out automatically because the manager joins through
    WorkloadImageObservation.

    Returns a counter dict for logging.
    """
    qs = Workload.objects.filter(cluster=cluster)
    seen = qs.filter(last_inventory_at__gte=mark_started_at)
    # Deployed iff seen this cycle AND not scaled to zero. A Deployment/
    # StatefulSet with replicas==0 is in inventory but runs no pods, so
    # it's not deployed. replicas is NULL for DaemonSets/Pods/CronJobs/
    # Jobs (NULL is not matched by =0), so those stay deployed when seen.
    running = seen.exclude(replicas=0)
    scaled_to_zero = seen.filter(replicas=0).count()
    deployed_true = running.count()
    total = qs.count()

    running.update(deployed=True)
    seen.filter(replicas=0).update(deployed=False)
    qs.exclude(last_inventory_at__gte=mark_started_at).update(deployed=False)

    return {
        "workloads_deployed_true": deployed_true,
        "workloads_deployed_false": total - deployed_true,
        "workloads_scaled_to_zero": scaled_to_zero,
    }
