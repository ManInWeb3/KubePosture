"""Inventory parser — navigates raw K8s manifests in the ingest envelope.

Pod-ownership rule: a Pod is a standalone Workload iff its
ownerReferences is empty. Owned Pods resolve to their controller via
the alias chain (ReplicaSet → Deployment, Job → CronJob).

Container scope: primary + init containers; ephemeral containers are
skipped.
"""
from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any

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

    # `complete_snapshot` from the payload that carries items we just parsed.
    complete_snapshot: bool = False

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
    for c, _init_container in _containers(pod_spec):
        ctx = c.get("securityContext") or {}
        if ctx.get("privileged") is True:
            found.add("kyverno:disallow-privileged-containers")
        if ctx.get("allowPrivilegeEscalation") is True:
            found.add("kyverno:disallow-privilege-escalation")
        run_as_non_root = ctx.get("runAsNonRoot")
        if run_as_non_root is False:
            found.add("kyverno:require-run-as-nonroot")
        if ctx.get("readOnlyRootFilesystem") is False:
            found.add("kyverno:require-ro-rootfs")
    for v in pod_spec.get("volumes") or []:
        if v.get("hostPath"):
            found.add("kyverno:disallow-host-path")
            break
    return {sid for sid in found if sid in SIGNALS}


# ── Service / Ingress → publicly_exposed derivation ---------------

_INTERNAL_LB_ANNOTATIONS = {
    "service.beta.kubernetes.io/aws-load-balancer-internal": "true",
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


def _is_internal_ingress(ing: dict) -> bool:
    spec = ing.get("spec") or {}
    cls = (spec.get("ingressClassName") or "").lower()
    if "internal" in cls or "private" in cls:
        return True
    annotations = (ing.get("metadata") or {}).get("annotations") or {}
    if str(annotations.get("alb.ingress.kubernetes.io/scheme", "")).lower() == "internal":
        return True
    cls_ann = str(annotations.get("kubernetes.io/ingress.class", "")).lower()
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
    (r"(^|[-_])stag(e|ing)?([-_]|$)", "staging"),
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
    if api_kind not in CONTROLLER_KINDS_TO_WORKLOAD:
        return
    if api_kind == "ReplicaSet":
        # ReplicaSets are alias targets, not workloads.
        return
    if api_kind == "Pod":
        # Pod handling is gated on ownerReferences — done in _ingest_pod.
        return
    if api_kind == "Job" and _controller_owner(item) is not None:
        # Owned Jobs (CronJob children) are aliases, not workloads.
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
    workload._namespace_name = namespace  # type: ignore[attr-defined]
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
        workload._namespace_name = namespace  # type: ignore[attr-defined]
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

    pending = st._pending_pod_observations.setdefault(  # type: ignore[attr-defined]
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
        st._pending_pod_signals.setdefault(  # type: ignore[attr-defined]
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
    st._pending_pod_observations = {}  # type: ignore[attr-defined]
    st._pending_pod_signals = {}  # type: ignore[attr-defined]
    st.cluster_meta = dict(payload.get("cluster_meta") or {})
    st.complete_snapshot = bool(payload.get("complete_snapshot"))

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
    """Walk the alias chain (in-memory + DB) to a top-level Workload.

    The DB fallback handles the case where a Pod's owning Job has aged
    out of the inventory mid-cycle but the alias row from the previous
    cycle still resolves to the parent CronJob.
    """
    cluster = st.cluster
    ns_obj = st.namespaces.get(namespace)
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

        target = st.aliases.get((cur_ns, cur_kind, cur_name))
        if target is None and ns_obj is not None:
            row = (
                WorkloadAlias.objects
                .filter(
                    cluster=cluster,
                    namespace=ns_obj,
                    alias_kind=cur_kind,
                    alias_name=cur_name,
                )
                .select_related("target_workload")
                .first()
            )
            if row is not None:
                tw = row.target_workload
                if tw and (tw.namespace.name, tw.kind, tw.name) in st.workloads:
                    return tw.kind, tw.name
                target = (tw.kind, tw.name) if tw else None

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


@transaction.atomic
def persist(st: _InventoryStaging, mark_started_at) -> dict:
    """Write the staged inventory to the DB, return summary counters.

    `mark_started_at` is the ImportMark.started_at for this cycle's
    inventory kind. Used to bump `Workload.last_inventory_at` so the
    reap's diff fires correctly.
    """
    # 1. Cluster metadata --------------------------------------------------
    meta = st.cluster_meta or {}
    cluster = st.cluster
    if (v := meta.get("k8s_version")) and cluster.k8s_version != v:
        cluster.k8s_version = v
    if (p := meta.get("provider")) and not cluster.provider_is_manual and cluster.provider != p:
        cluster.provider = p
    if (r := meta.get("region")) is not None and not cluster.region_is_manual and cluster.region != r:
        cluster.region = r
    if not cluster.environment_is_manual:
        env = _detect_environment_from_name(cluster.name)
        if env and cluster.environment != env:
            cluster.environment = env
    cluster.last_seen_at = timezone.now()
    cluster.save()

    # 2. Namespaces -------------------------------------------------------
    seen_namespaces: set[str] = set()
    for ns_name, labels in st.namespace_labels.items():
        seen_namespaces.add(ns_name)
        annotations = st.namespace_annotations.get(ns_name, {})
        defaults = {
            "labels": labels,
            "annotations": annotations,
            "active": True,
            "deactivated_at": None,
        }
        # Auto-derive contains_sensitive_data from a label, but skip
        # when the admin has manually set the flag on an existing row.
        existing = Namespace.objects.filter(cluster=cluster, name=ns_name).first()
        sens_label = (
            labels.get("posture.io/contains-sensitive-data")
            or annotations.get("posture.io/contains-sensitive-data")
        )
        if sens_label is not None and not (existing and existing.sensitive_is_manual):
            defaults["contains_sensitive_data"] = str(sens_label).lower() == "true"
        ns, _ = Namespace.objects.update_or_create(
            cluster=cluster,
            name=ns_name,
            defaults=defaults,
        )
        st.namespaces[ns_name] = ns

    # Inactive any namespace not seen in this snapshot (only if complete).
    if st.complete_snapshot:
        for ns in Namespace.objects.filter(cluster=cluster, active=True).exclude(name__in=seen_namespaces):
            ns.active = False
            ns.deactivated_at = timezone.now()
            ns.save(update_fields=["active", "deactivated_at"])

    # 3. Implicit Namespaces (referenced by workloads but no Namespace item).
    for (ns_name, _, _) in list(st.workloads.keys()):
        if ns_name not in st.namespaces:
            ns, _ = Namespace.objects.get_or_create(cluster=cluster, name=ns_name)
            st.namespaces[ns_name] = ns

    # 4. Workloads -------------------------------------------------------
    persisted_workloads: dict[tuple[str, str, str], Workload] = {}
    for key, w in st.workloads.items():
        ns_name, wkind, wname = key
        ns = st.namespaces.get(ns_name)
        if ns is None:
            continue

        # Derive publicly_exposed from Services/Ingresses.
        labels = w.labels or {}
        has_lb, has_ing = _compute_exposure_breakdown(labels, ns_name, st)
        publicly_exposed = has_lb or has_ing
        if has_lb:
            st.derived_signals.setdefault(key, set()).add("kp:has-external-lb")
        if has_ing:
            st.derived_signals.setdefault(key, set()).add("kp:has-external-ingress")
        nodeport = _compute_nodeport(labels, ns_name, st)
        if nodeport:
            st.derived_signals.setdefault(key, set()).add("kp:has-nodeport-service")

        existing = Workload.objects.filter(
            cluster=cluster, namespace=ns, kind=wkind, name=wname
        ).first()
        defaults = {
            "service_account": w.service_account or "default",
            "replicas": w.replicas,
            "labels": labels,
            "deployed": True,
            "last_inventory_at": mark_started_at,
        }
        # Honour manual override.
        if existing and existing.publicly_exposed_is_manual:
            pass
        else:
            defaults["publicly_exposed"] = publicly_exposed

        if existing:
            for k, v in defaults.items():
                setattr(existing, k, v)
            existing.save()
            persisted_workloads[key] = existing
        else:
            new = Workload.objects.create(
                cluster=cluster,
                namespace=ns,
                kind=wkind,
                name=wname,
                **defaults,
            )
            persisted_workloads[key] = new
    st.workloads = persisted_workloads

    # 5. WorkloadAlias ---------------------------------------------------
    seen_alias_keys: set[tuple[int, int, str, str]] = set()
    for (ns_name, alias_kind, alias_name), (target_kind, target_name) in st.aliases.items():
        ns = st.namespaces.get(ns_name)
        if ns is None:
            continue
        wk = CONTROLLER_KINDS_TO_WORKLOAD.get(target_kind)
        if not wk:
            continue
        target = persisted_workloads.get((ns_name, wk, target_name))
        if target is None:
            continue
        WorkloadAlias.objects.update_or_create(
            cluster=cluster,
            namespace=ns,
            alias_kind=alias_kind,
            alias_name=alias_name,
            defaults={"target_workload": target},
        )
        seen_alias_keys.add((cluster.id, ns.id, alias_kind, alias_name))

    # 6. Pending pod observations / signals — resolve via alias chain.
    # Done BEFORE alias deletion so resolution can use both the
    # current-cycle staging dict AND the previous-cycle alias rows
    # still in the DB (real clusters can have a Pod whose owning
    # ReplicaSet/Job ages out of `kubectl get` mid-cycle).
    pending_obs = getattr(st, "_pending_pod_observations", {})
    for (ns_name, owner_kind, owner_name), obs in pending_obs.items():
        resolved = _resolve_alias(st, ns_name, owner_kind, owner_name)
        if resolved is None:
            continue
        wk, wname = resolved
        target_key = (ns_name, wk, wname)
        st.image_observations.setdefault(target_key, []).extend(obs)

    pending_sigs = getattr(st, "_pending_pod_signals", {})
    for (ns_name, owner_kind, owner_name), sigs in pending_sigs.items():
        resolved = _resolve_alias(st, ns_name, owner_kind, owner_name)
        if resolved is None:
            continue
        wk, wname = resolved
        st.derived_signals.setdefault((ns_name, wk, wname), set()).update(sigs)

    # Now that pod-obs resolution is done, prune stale aliases.
    if st.complete_snapshot:
        existing = WorkloadAlias.objects.filter(cluster=cluster).values_list(
            "id", "namespace_id", "alias_kind", "alias_name"
        )
        to_delete = [
            row_id for (row_id, ns_id, ak, an) in existing
            if (cluster.id, ns_id, ak, an) not in seen_alias_keys
        ]
        if to_delete:
            WorkloadAlias.objects.filter(id__in=to_delete).delete()

    # 7. Images + WorkloadImageObservation -------------------------------
    image_cache: dict[str, Image] = {}

    def _get_or_make_image(ref: str, digest: str) -> Image | None:
        if not digest:
            # No digest — we can still build an Image keyed by ref if
            # absolutely necessary, but the schema requires a digest.
            # Skip unanchored observations.
            return None
        cached = image_cache.get(digest)
        if cached:
            cached.ref = ref or cached.ref
            return cached
        registry, repo = _registry_repo(ref) if ref else ("", "")
        img, _ = Image.objects.update_or_create(
            digest=digest,
            defaults={
                "ref": ref or "",
                "registry": registry,
                "repository": repo,
            },
        )
        image_cache[digest] = img
        return img

    for key, obs_list in st.image_observations.items():
        wl = persisted_workloads.get(key)
        if wl is None:
            continue
        for ref, digest, cname, init_container in obs_list:
            img = _get_or_make_image(ref, digest)
            if img is None:
                continue
            # update_or_create refreshes init_container + last_seen_at
            # on every cycle. currently_deployed is intentionally NOT
            # in defaults — only the inventory reaper has authority to
            # flip it at end of a complete cycle (mirrors Workload.deployed).
            WorkloadImageObservation.objects.update_or_create(
                workload=wl,
                image=img,
                container_name=cname,
                defaults={
                    "init_container": init_container,
                    "last_seen_at": timezone.now(),
                },
            )

    # 8. WorkloadSignal upserts -----------------------------------------
    for key, signal_ids in st.derived_signals.items():
        wl = persisted_workloads.get(key)
        if wl is None:
            continue
        for sig in signal_ids:
            if sig not in SIGNALS:
                continue
            existing = WorkloadSignal.objects.filter(
                workload=wl, signal_id=sig
            ).first()
            if existing:
                existing.currently_active = True
                existing.save(update_fields=["currently_active", "last_seen_at"])
            else:
                WorkloadSignal.objects.create(
                    workload=wl,
                    signal_id=sig,
                    currently_active=True,
                )

    # 9. `kp:missing-networkpolicy` per namespace.
    # Fired by the inventory parser when a namespace has zero
    # NetworkPolicy resources observed this cycle. The spec
    # (dev_docs/06-signals.md) lists this under Kyverno but for v1 we
    # also derive it from inventory so the signal fires regardless of
    # whether a Kyverno custom policy is installed.
    for ns_name, ns in st.namespaces.items():
        has_netpol = ns_name in st.namespaces_with_netpol
        for key, wl in persisted_workloads.items():
            if key[0] != ns_name:
                continue
            existing = WorkloadSignal.objects.filter(
                workload=wl, signal_id="kp:missing-networkpolicy"
            ).first()
            if not has_netpol:
                if existing:
                    existing.currently_active = True
                    existing.save(update_fields=["currently_active", "last_seen_at"])
                else:
                    WorkloadSignal.objects.create(
                        workload=wl,
                        signal_id="kp:missing-networkpolicy",
                        currently_active=True,
                    )
            else:
                if existing and existing.currently_active:
                    existing.currently_active = False
                    existing.save(update_fields=["currently_active", "last_seen_at"])

    # 10. Namespace internet_exposed rollup ------------------------------
    for ns_name, ns in st.namespaces.items():
        if ns.exposure_is_manual:
            continue
        rollup = any(
            wl.publicly_exposed
            for key, wl in persisted_workloads.items()
            if key[0] == ns_name
        )
        if ns.internet_exposed != rollup:
            ns.internet_exposed = rollup
            ns.save(update_fields=["internet_exposed"])

    if st.unknown_kind_skipped > 0:
        import logging
        logging.getLogger("core.inventory").warning(
            "inventory.unknown_kind_skipped count=%d cluster=%s — items "
            "had no `kind` field; likely an importer bug "
            "(e.g., kubernetes Python client typed-list serialization).",
            st.unknown_kind_skipped, cluster.name,
        )

    return {
        "namespaces": len(seen_namespaces),
        "workloads": len(persisted_workloads),
        "aliases": len(st.aliases),
        "complete_snapshot": st.complete_snapshot,
        "unknown_kind_skipped": st.unknown_kind_skipped,
    }


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
    deployed_true = qs.filter(last_inventory_at__gte=mark_started_at).count()
    deployed_false = qs.exclude(last_inventory_at__gte=mark_started_at).count()
    qs.filter(last_inventory_at__gte=mark_started_at).update(deployed=True)
    qs.exclude(last_inventory_at__gte=mark_started_at).update(deployed=False)

    return {
        "workloads_deployed_true": deployed_true,
        "workloads_deployed_false": deployed_false,
    }
