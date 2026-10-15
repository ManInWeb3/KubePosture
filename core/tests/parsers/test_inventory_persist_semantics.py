"""Inventory `parse_envelope` + `persist()` end to end, asserting the
documented semantics (docs/ssvc-mapping.md §exposure, the complete-snapshot
rule, the workload graph's payload) on the DB rows — not on helpers."""
from __future__ import annotations

import pytest
from django.test import override_settings
from django.utils import timezone

from core.constants import Environment
from core.models import (
    Cluster,
    Namespace,
    Workload,
    WorkloadAlias,
    WorkloadImageObservation,
)
from core.parsers import inventory as inv
from core.tests.parsers.test_inventory_parser import (
    _deployment,
    _envelope,
    _ns,
    _pod,
    _replicaset,
)

DIGEST = "sha256:" + "a" * 64


def _cluster(name="c-sem", env=Environment.PROD.value) -> Cluster:
    return Cluster.objects.create(name=name, environment=env)


def _persist(cluster, *items) -> dict:
    return inv.persist(inv.parse_envelope(_envelope(*items), cluster), mark_started_at=timezone.now())


def _svc(name, namespace, *, type_="ClusterIP", selector=None, annotations=None) -> dict:
    return {
        "apiVersion": "v1", "kind": "Service",
        "metadata": {"name": name, "namespace": namespace, "annotations": annotations or {}},
        "spec": {"type": type_, "selector": selector if selector is not None else {"app": "api"}},
    }


def _ingress(namespace, *, backend="api-svc", class_name=None, annotations=None, default_backend=False) -> dict:
    spec: dict = {}
    if class_name:
        spec["ingressClassName"] = class_name
    if default_backend:
        spec["defaultBackend"] = {"service": {"name": backend}}
    else:
        spec["rules"] = [{"http": {"paths": [{"path": "/", "backend": {"service": {"name": backend}}}]}}]
    return {"apiVersion": "networking.k8s.io/v1", "kind": "Ingress",
            "metadata": {"name": "ing", "namespace": namespace, "annotations": annotations or {}},
            "spec": spec}


def _netpol(namespace) -> dict:
    return {"apiVersion": "networking.k8s.io/v1", "kind": "NetworkPolicy",
            "metadata": {"name": "deny-all", "namespace": namespace}, "spec": {}}


def _signals(workload) -> dict[str, bool]:
    return dict(workload.signals.values_list("signal_id", "currently_active"))


def _api(cluster):
    return Workload.objects.get(cluster=cluster, name="api")


# ── exposure derivation (docs/ssvc-mapping.md) ───────────────────


@pytest.mark.django_db
@pytest.mark.parametrize("default_backend", [False, True], ids=["rules-path", "defaultBackend"])
def test_external_ingress_via_backend_service_exposes_the_workload(default_backend):
    c = _cluster()
    _persist(c, _ns("ns"), _deployment("api", "ns"), _svc("api-svc", "ns"),
             _ingress("ns", class_name="nginx", default_backend=default_backend))

    api = _api(c)
    assert api.publicly_exposed is True
    sigs = _signals(api)
    assert sigs.get("kp:has-external-ingress") is True
    assert "kp:has-external-lb" not in sigs
    assert Namespace.objects.get(cluster=c, name="ns").internet_exposed is True


@pytest.mark.django_db
@pytest.mark.parametrize("ingress_kwargs", [
    {"class_name": "pomerium"},                                          # configured internal class
    {"class_name": "nginx-internal"},                                    # substring heuristic
    {"annotations": {"alb.ingress.kubernetes.io/scheme": "internal"}},  # ALB annotation
    {"annotations": {"kubernetes.io/ingress.class": "nginx-internal"}},  # legacy annotation
], ids=["configured-class", "class-substring", "alb-scheme", "legacy-annotation"])
def test_internal_ingress_does_not_expose(ingress_kwargs):
    c = _cluster()
    with override_settings(INTERNAL_INGRESS_CLASSES=["pomerium"]):
        _persist(c, _ns("ns"), _deployment("api", "ns"), _svc("api-svc", "ns"), _ingress("ns", **ingress_kwargs))

    api = _api(c)
    assert api.publicly_exposed is False
    assert "kp:has-external-ingress" not in _signals(api)
    assert Namespace.objects.get(cluster=c, name="ns").internet_exposed is False


@pytest.mark.django_db
def test_ingress_whose_backend_service_does_not_select_the_workload_does_not_expose():
    c = _cluster()
    _persist(c, _ns("ns"), _deployment("api", "ns"),
             _svc("other-svc", "ns", selector={"app": "other"}), _ingress("ns", backend="other-svc"))
    assert _api(c).publicly_exposed is False


@pytest.mark.django_db
@pytest.mark.parametrize("selector", [{"app": "other"}, {"app": "api", "tier": "web"}],
                         ids=["different-app", "extra-key"])
def test_service_selector_must_be_a_subset_of_the_pod_template_labels(selector):
    c = _cluster()
    _persist(c, _ns("ns"), _deployment("api", "ns"), _svc("lb", "ns", type_="LoadBalancer", selector=selector))
    assert _api(c).publicly_exposed is False


@pytest.mark.django_db
def test_external_load_balancer_exposes_and_internal_annotation_does_not():
    c = _cluster()
    _persist(c, _ns("ns"), _deployment("api", "ns"), _svc("lb", "ns", type_="LoadBalancer"))
    api = _api(c)
    assert api.publicly_exposed is True and _signals(api).get("kp:has-external-lb") is True

    c2 = _cluster("c-int")
    _persist(c2, _ns("ns"), _deployment("api", "ns"), _svc(
        "lb", "ns", type_="LoadBalancer",
        annotations={"service.beta.kubernetes.io/aws-load-balancer-scheme": "internal"},
    ))
    assert _api(c2).publicly_exposed is False


@pytest.mark.django_db
def test_nodeport_is_a_signal_not_exposure():
    c = _cluster()
    _persist(c, _ns("ns"), _deployment("api", "ns"), _svc("np", "ns", type_="NodePort"))
    api = _api(c)
    assert api.publicly_exposed is False
    assert _signals(api).get("kp:has-nodeport-service") is True
    assert Namespace.objects.get(cluster=c, name="ns").internet_exposed is False


@pytest.mark.django_db
def test_manual_exposure_overrides_survive_the_next_inventory():
    c = _cluster()
    _persist(c, _ns("ns"), _deployment("api", "ns"), _svc("lb", "ns", type_="LoadBalancer"))
    Workload.objects.filter(cluster=c, name="api").update(publicly_exposed=False, publicly_exposed_is_manual=True)
    Namespace.objects.filter(cluster=c, name="ns").update(internet_exposed=False, exposure_is_manual=True)

    _persist(c, _ns("ns"), _deployment("api", "ns"), _svc("lb", "ns", type_="LoadBalancer"))

    assert _api(c).publicly_exposed is False
    assert Namespace.objects.get(cluster=c, name="ns").internet_exposed is False


# ── namespace lifecycle (complete-snapshot semantics) ─────────────


@pytest.mark.django_db
def test_absent_namespace_is_deactivated_and_reactivated_when_it_returns():
    c = _cluster()
    _persist(c, _ns("a"), _ns("b"))
    assert set(Namespace.objects.filter(cluster=c, active=True).values_list("name", flat=True)) == {"a", "b"}

    _persist(c, _ns("a"))
    b = Namespace.objects.get(cluster=c, name="b")
    assert b.active is False and b.deactivated_at is not None
    assert Namespace.objects.get(cluster=c, name="a").active is True

    _persist(c, _ns("a"), _ns("b"))
    b.refresh_from_db()
    assert b.active is True and b.deactivated_at is None


@pytest.mark.django_db
def test_sensitive_data_label_sets_the_flag_unless_manually_set():
    c = _cluster()
    ns = _ns("pay")
    ns["metadata"]["labels"] = {"posture.io/contains-sensitive-data": "true"}
    _persist(c, ns)
    assert Namespace.objects.get(cluster=c, name="pay").contains_sensitive_data is True

    Namespace.objects.filter(cluster=c, name="pay").update(contains_sensitive_data=False, sensitive_is_manual=True)
    _persist(c, ns)
    assert Namespace.objects.get(cluster=c, name="pay").contains_sensitive_data is False


@pytest.mark.django_db
def test_missing_networkpolicy_signal_follows_the_namespace_across_cycles():
    c = _cluster()
    _persist(c, _ns("a"), _ns("b"), _deployment("api", "a"), _deployment("web", "b"), _netpol("a"))
    assert _signals(Workload.objects.get(cluster=c, name="api")).get("kp:missing-networkpolicy") is None
    assert _signals(Workload.objects.get(cluster=c, name="web"))["kp:missing-networkpolicy"] is True

    _persist(c, _ns("a"), _ns("b"), _deployment("api", "a"), _deployment("web", "b"), _netpol("a"), _netpol("b"))
    assert _signals(Workload.objects.get(cluster=c, name="web"))["kp:missing-networkpolicy"] is False


# ── cluster metadata ──────────────────────────────────────────────


@pytest.mark.parametrize(("name", "env"), [
    ("prod-east", "prod"), ("eu-production", "prod"), ("prd_1", "prod"),
    ("stg-eu", "staging"), ("staging", "staging"), ("my-stage", "staging"),
    ("reproduction", "dev"), ("payments", "dev"), ("prd1", "dev"), ("qa-2", "dev"),
])
def test_environment_is_detected_from_the_cluster_name(name, env):
    assert inv._detect_environment_from_name(name) == env


@pytest.mark.django_db
def test_manual_environment_is_not_overwritten_by_the_name_heuristic():
    c = Cluster.objects.create(name="prod-east", environment=Environment.DEV.value, environment_is_manual=True)
    _persist(c, _ns("ns"))
    c.refresh_from_db()
    assert c.environment == Environment.DEV.value

    auto = Cluster.objects.create(name="prod-west", environment=Environment.DEV.value)
    _persist(auto, _ns("ns"))
    auto.refresh_from_db()
    assert auto.environment == Environment.PROD.value


# ── workload graph payload: digests reach the owning workload ─────


@pytest.mark.django_db
def test_pod_digest_is_observed_on_the_owning_deployment():
    c = _cluster()
    rs = _replicaset("api-7d9", "ns", owner_deployment="api")
    pod = _pod("api-7d9-x1", "ns", owner={"apiVersion": "apps/v1", "kind": "ReplicaSet", "name": "api-7d9",
                                           "controller": True})
    _persist(c, _ns("ns"), _deployment("api", "ns"), rs, pod)

    obs = WorkloadImageObservation.objects.get(workload__cluster=c, workload__name="api")
    assert (obs.image.digest, obs.container_name, obs.init_container) == (DIGEST, "app", False)
    assert not Workload.objects.filter(cluster=c, kind="Pod").exists()


@pytest.mark.django_db
def test_init_container_digest_is_observed_with_the_init_flag():
    c = _cluster()
    rs = _replicaset("api-7d9", "ns", owner_deployment="api")
    pod = _pod("api-7d9-x1", "ns", owner={"apiVersion": "apps/v1", "kind": "ReplicaSet", "name": "api-7d9",
                                           "controller": True})
    pod["spec"]["initContainers"] = [{"name": "migrate", "image": "registry.x/migrate:1"}]
    pod["status"]["initContainerStatuses"] = [{"name": "migrate", "image": "registry.x/migrate:1",
                                               "imageID": "registry.x/migrate:1@sha256:" + "b" * 64}]
    _persist(c, _ns("ns"), _deployment("api", "ns"), rs, pod)

    init = WorkloadImageObservation.objects.get(workload__name="api", init_container=True)
    assert init.container_name == "migrate" and init.image.digest == "sha256:" + "b" * 64


@pytest.mark.django_db
def test_digest_pinned_template_yields_an_observation_without_a_pod():
    c = _cluster()
    _persist(c, _ns("ns"), _deployment("api", "ns", image="registry.x/app:1@" + DIGEST))
    assert WorkloadImageObservation.objects.get(workload__name="api").image.digest == DIGEST

    c2 = _cluster("c-unpinned")
    _persist(c2, _ns("ns"), _deployment("api", "ns", image="registry.x/app:1"))
    assert not WorkloadImageObservation.objects.filter(workload__cluster=c2).exists()


@pytest.mark.django_db
def test_pod_still_resolves_through_a_previous_cycle_alias_when_its_replicaset_aged_out():
    c = _cluster()
    rs = _replicaset("api-7d9", "ns", owner_deployment="api")
    pod = _pod("api-7d9-x1", "ns", owner={"apiVersion": "apps/v1", "kind": "ReplicaSet", "name": "api-7d9",
                                           "controller": True})
    _persist(c, _ns("ns"), _deployment("api", "ns"), rs, pod)
    first = WorkloadImageObservation.objects.get(workload__name="api").last_seen_at

    _persist(c, _ns("ns"), _deployment("api", "ns"), pod)  # ReplicaSet gone from the listing

    obs = WorkloadImageObservation.objects.get(workload__name="api")
    assert obs.last_seen_at > first, "the pod's image still counts against the Deployment"
    assert WorkloadAlias.objects.filter(cluster=c, alias_kind="Pod", alias_name="api-7d9-x1",
                                        target_workload__name="api").exists()


@pytest.mark.django_db
def test_orphan_pod_with_an_unknown_owner_is_dropped():
    c = _cluster()
    pod = _pod("ghost-x1", "ns", owner={"apiVersion": "apps/v1", "kind": "ReplicaSet", "name": "ghost-7d9",
                                         "controller": True})
    _persist(c, _ns("ns"), _deployment("api", "ns"), pod)

    assert not Workload.objects.filter(cluster=c, kind="Pod").exists()
    assert not WorkloadAlias.objects.filter(cluster=c, alias_name="ghost-x1").exists()
    assert not WorkloadImageObservation.objects.filter(workload__cluster=c).exists()


# ── pod-security signals: every id, positively ────────────────────


@pytest.mark.parametrize(("spec", "expected"), [
    ({"hostNetwork": True}, "kyverno:disallow-host-namespaces"),
    ({"hostPID": True}, "kyverno:disallow-host-namespaces"),
    ({"volumes": [{"name": "h", "hostPath": {"path": "/"}}]}, "kyverno:disallow-host-path"),
    ({"containers": [{"name": "app", "image": "x", "securityContext": {"privileged": True}}]},
     "kyverno:disallow-privileged-containers"),
    ({"containers": [{"name": "app", "image": "x", "securityContext": {"allowPrivilegeEscalation": True}}]},
     "kyverno:disallow-privilege-escalation"),
    ({"containers": [{"name": "app", "image": "x", "securityContext": {"runAsNonRoot": False}}]},
     "kyverno:require-run-as-nonroot"),
    ({"containers": [{"name": "app", "image": "x", "securityContext": {"readOnlyRootFilesystem": False}}]},
     "kyverno:require-ro-rootfs"),
])
def test_each_pod_security_signal_fires_on_its_trigger(spec, expected):
    base = {"containers": [{"name": "app", "image": "x", "securityContext": {
        "allowPrivilegeEscalation": False, "runAsNonRoot": True, "readOnlyRootFilesystem": True}}]}
    assert expected in inv._pod_security_signals({**base, **spec})
    assert expected not in inv._pod_security_signals(base)
