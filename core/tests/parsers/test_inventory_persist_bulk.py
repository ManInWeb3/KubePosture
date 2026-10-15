"""`persist()` as a bulk writer: its query count must not grow with the
cluster, and the row-level side effects the old per-row `save()` /
`update_or_create` loop had — `last_seen_at` bumps, `first_seen_at`
preservation, narrow cluster writes — must survive the rewrite."""
from __future__ import annotations

from datetime import timedelta

import pytest
from django.db import connection
from django.test.utils import CaptureQueriesContext
from django.utils import timezone

from core.constants import Environment
from core.models import (
    Cluster,
    Image,
    Namespace,
    Workload,
    WorkloadAlias,
    WorkloadImageObservation,
    WorkloadSignal,
)
from core.parsers import inventory as inv
from core.tests.parsers.test_inventory_parser import (
    _deployment,
    _envelope,
    _ns,
    _pod,
    _replicaset,
)
from core.tests.parsers.test_inventory_persist_semantics import _netpol, _svc

DIGEST = "sha256:" + "a" * 64


def _cluster(name="c-bulk") -> Cluster:
    return Cluster.objects.create(name=name, environment=Environment.PROD.value)


def _rs_owner(name):
    return {"apiVersion": "apps/v1", "kind": "ReplicaSet", "name": name, "controller": True}


def _app(ns, name, *, image="registry.x/app:1", pods=1):
    """Deployment + ReplicaSet + `pods` owned Pods — the common real shape."""
    items = [_deployment(name, ns, image=image), _replicaset(f"{name}-7d9", ns, owner_deployment=name, image=image)]
    items += [_pod(f"{name}-7d9-x{i}", ns, image=image, owner=_rs_owner(f"{name}-7d9")) for i in range(pods)]
    return items


def _persist(cluster, items, *, started_at=None) -> dict:
    st = inv.parse_envelope(_envelope(*items), cluster)
    return inv.persist(st, mark_started_at=started_at or timezone.now())


def _n_queries(cluster, items) -> int:
    st = inv.parse_envelope(_envelope(*items), cluster)
    with CaptureQueriesContext(connection) as ctx:
        inv.persist(st, mark_started_at=timezone.now())
    return len(ctx.captured_queries)


def _scene(n):
    items = []
    for i in range(n):
        items += [_ns(f"ns{i}"), *_app(f"ns{i}", f"api{i}", pods=2),
                  _svc(f"api{i}-svc", f"ns{i}", type_="LoadBalancer", selector={"app": f"api{i}"})]
    return items


# ── query cost ───────────────────────────────────────────────────


@pytest.mark.django_db
def test_persist_query_count_does_not_grow_with_cluster_size():
    small, large = _cluster("c-small"), _cluster("c-large")

    first_small = _n_queries(small, _scene(2))
    first_large = _n_queries(large, _scene(7))
    assert Workload.objects.filter(cluster=large).count() == 7
    assert WorkloadAlias.objects.filter(cluster=large).count() == 7 * 3, "ReplicaSet + 2 Pods per app"
    assert first_large == first_small, ("create path", first_small, first_large)

    # Second cycle: every row exists and is updated in place, and in both
    # scenes one app's pod set rolls (alias prune + new aliases + a new
    # image and observation) so the fixed-cost branches run in both.
    def rolled(n):
        items = _scene(n)
        items[2:5] = _app("ns0", "api0", image="registry.x/app:2", pods=3)
        return items

    second_small = _n_queries(small, rolled(2))
    second_large = _n_queries(large, rolled(7))
    assert WorkloadAlias.objects.filter(cluster=large).count() == 7 * 3 + 1
    assert second_large == second_small, ("update path", second_small, second_large)


# ── row-level side effects of the old per-row saves ──────────────


@pytest.mark.django_db
def test_second_cycle_bumps_last_seen_on_every_row_it_touches_and_keeps_first_seen():
    c = _cluster()
    items = [_ns("ns"), *_app("ns", "api")]
    _persist(c, items)
    w = Workload.objects.get(cluster=c, name="api")
    ns = Namespace.objects.get(cluster=c, name="ns")
    alias = WorkloadAlias.objects.get(cluster=c, alias_kind="Pod")
    obs = WorkloadImageObservation.objects.get(workload=w)
    img = Image.objects.get(digest=DIGEST)
    sig = WorkloadSignal.objects.get(workload=w, signal_id="kp:missing-networkpolicy")
    before = {k: v for k, v in locals().items() if k in ("w", "ns", "alias", "obs", "img", "sig")}
    stamps = {k: (v.last_seen_at, getattr(v, "first_seen_at", None)) for k, v in before.items()}

    _persist(c, items)

    for name, row in before.items():
        row.refresh_from_db()
        last, first = stamps[name]
        assert row.last_seen_at > last, f"{name}.last_seen_at not bumped"
        if first is not None:
            assert row.first_seen_at == first, f"{name}.first_seen_at changed"
    assert Workload.objects.filter(cluster=c).count() == 1
    assert WorkloadAlias.objects.filter(cluster=c).count() == 2


@pytest.mark.django_db
def test_deactivated_namespace_keeps_its_last_seen_at():
    c = _cluster()
    _persist(c, [_ns("ns"), _ns("old"), *_app("ns", "api")])
    old = Namespace.objects.get(cluster=c, name="old")
    seen = old.last_seen_at

    _persist(c, [_ns("ns"), *_app("ns", "api")])

    old.refresh_from_db()
    assert old.active is False and old.deactivated_at is not None
    assert old.last_seen_at == seen, "'last seen' means last seen, not last deactivated"
    live = Namespace.objects.get(cluster=c, name="ns")
    assert live.active is True and live.last_seen_at > seen


@pytest.mark.django_db
def test_persist_writes_only_the_cluster_columns_it_owns():
    """The worker loads the Cluster before parsing; a reap (anchor) or an
    admin (re-import request) can commit to the same row meanwhile. The
    persist's write must not roll those back."""
    c = _cluster()
    stale = Cluster.objects.get(pk=c.pk)   # what the worker holds
    anchor = timezone.now() - timedelta(hours=1)
    requested = timezone.now()
    Cluster.objects.filter(pk=c.pk).update(last_complete_inventory_at=anchor, reimport_requested_at=requested)
    st = inv.parse_envelope({"cluster_meta": {"name": c.name, "k8s_version": "v1.31.0", "provider": "eks",
                                              "region": "eu-west-1"}, "items": [_ns("ns")]}, stale)

    inv.persist(st, mark_started_at=timezone.now())

    c.refresh_from_db()
    assert (c.k8s_version, c.provider, c.region) == ("v1.31.0", "eks", "eu-west-1")
    assert c.last_complete_inventory_at == anchor, "reap's anchor clobbered by a stale full-row save"
    assert c.reimport_requested_at == requested
    assert c.last_seen_at > requested


@pytest.mark.django_db
def test_alias_retargets_and_stale_aliases_are_pruned():
    c = _cluster()
    pod = _pod("shared-7d9-x0", "ns", owner=_rs_owner("shared-7d9"))
    _persist(c, [_ns("ns"), _deployment("a", "ns"), _deployment("b", "ns"),
                 _replicaset("shared-7d9", "ns", owner_deployment="a"), pod])
    assert WorkloadAlias.objects.get(cluster=c, alias_kind="Pod").target_workload.name == "a"

    _persist(c, [_ns("ns"), _deployment("a", "ns"), _deployment("b", "ns"),
                 _replicaset("shared-7d9", "ns", owner_deployment="b"), pod])

    aliases = {(a.alias_kind, a.alias_name): a.target_workload.name for a in WorkloadAlias.objects.filter(cluster=c)}
    assert aliases == {("ReplicaSet", "shared-7d9"): "b", ("Pod", "shared-7d9-x0"): "b"}

    _persist(c, [_ns("ns"), _deployment("a", "ns"), _deployment("b", "ns")])
    assert not WorkloadAlias.objects.filter(cluster=c).exists(), "aliases absent from the snapshot are gone"


@pytest.mark.django_db
def test_same_digest_seen_under_a_new_ref_refreshes_the_image_row():
    c = _cluster()
    _persist(c, [_ns("ns"), *_app("ns", "api", image="registry.x/app:1")])
    img = Image.objects.get(digest=DIGEST)
    assert (img.ref, img.registry, img.repository) == ("registry.x/app:1", "registry.x", "app")

    _persist(c, [_ns("ns"), *_app("ns", "api", image="ghcr.io/org/app:2")])

    img.refresh_from_db()
    assert (img.ref, img.registry, img.repository) == ("ghcr.io/org/app:2", "ghcr.io", "org/app")
    assert Image.objects.count() == 1


@pytest.mark.django_db
def test_two_pods_of_one_replicaset_share_one_observation_row():
    c = _cluster()
    _persist(c, [_ns("ns"), *_app("ns", "api", pods=3)])
    assert WorkloadImageObservation.objects.filter(workload__name="api").count() == 1


@pytest.mark.django_db
def test_signal_rows_follow_the_upsert_contract_across_cycles():
    """Active sightings bump last_seen_at; a clearing sighting writes only
    when it flips the flag; a signal never seen active has no row."""
    c = _cluster()
    _persist(c, [_ns("ns"), *_app("ns", "api")])
    w = Workload.objects.get(cluster=c, name="api")
    sig = WorkloadSignal.objects.get(workload=w, signal_id="kp:missing-networkpolicy")
    assert sig.currently_active is True
    assert not WorkloadSignal.objects.filter(workload=w, signal_id="kp:has-nodeport-service").exists()

    _persist(c, [_ns("ns"), *_app("ns", "api"), _netpol("ns")])
    sig.refresh_from_db()
    cleared_at = sig.last_seen_at
    assert sig.currently_active is False

    _persist(c, [_ns("ns"), *_app("ns", "api"), _netpol("ns")])
    sig.refresh_from_db()
    assert sig.last_seen_at == cleared_at, "already-inactive signal is not re-written"

    _persist(c, [_ns("ns"), *_app("ns", "api")])
    sig.refresh_from_db()
    assert sig.currently_active is True and sig.last_seen_at > cleared_at
