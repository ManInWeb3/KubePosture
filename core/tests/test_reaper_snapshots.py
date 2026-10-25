"""The observational side of the reaper, which every other reaper test
patches out: the post-reap cluster heartbeat (once, after the LAST mark of
an import session) and the inventory reap's event-path workload snapshots
(`change_kind` / `image_digest_set`)."""
from __future__ import annotations

from datetime import timedelta
from unittest.mock import patch

import pytest
from django.db import connection
from django.test.utils import CaptureQueriesContext
from django.utils import timezone

from core.constants import Environment, ImageSetChangeKind, ImportMarkState, SnapshotScope
from core.models import (
    Cluster,
    Finding,
    Image,
    ImportMark,
    IngestQueue,
    Namespace,
    Snapshot,
    Workload,
    WorkloadImageObservation,
)
from core.services.reaper import (
    _reap_inventory,
    _write_event_path_workload_snapshots,
    maybe_reap,
    reap_all_drainable,
)
from core.services.snapshot import (
    capture_cluster_heartbeat,
    capture_cluster_snapshot,
    capture_daily_heartbeat,
    capture_namespace_snapshot,
)


def _cluster(name="c-snap"):
    return Cluster.objects.create(name=name, environment=Environment.PROD.value)


def _scan_mark(cluster, kind, import_id="imp-1"):
    m = ImportMark.objects.create(cluster=cluster, kind=kind, import_id=import_id,
                                  state=ImportMarkState.DRAINING.value, started_at=timezone.now(),
                                  observed_count=1)
    IngestQueue.objects.create(cluster_name=cluster.name, kind=kind, import_id=import_id, raw_json={},
                               status="done")
    return m


def _cluster_rows(cluster):
    return Snapshot.objects.filter(cluster=cluster, scope_kind=SnapshotScope.CLUSTER.value).count()


# ── heartbeat ─────────────────────────────────────────────────────


@pytest.mark.django_db
def test_heartbeat_fires_once_after_the_last_mark_of_the_session():
    c = _cluster()
    Namespace.objects.create(cluster=c, name="a")
    Namespace.objects.create(cluster=c, name="inactive", active=False)
    first = _scan_mark(c, "trivy.ConfigAuditReport")
    second = _scan_mark(c, "kyverno.PolicyReport")

    assert maybe_reap(first) is not None
    assert _cluster_rows(c) == 0, "no heartbeat while a sibling mark is still draining"

    assert maybe_reap(second) is not None
    assert _cluster_rows(c) == 1
    ns_rows = Snapshot.objects.filter(cluster=c, scope_kind=SnapshotScope.NAMESPACE.value)
    assert [s.namespace.name for s in ns_rows] == ["a"], "one row per ACTIVE namespace"
    assert not Snapshot.objects.filter(scope_kind=SnapshotScope.GLOBAL.value).exists()


@pytest.mark.django_db
def test_sweep_captures_the_heartbeat_once_per_cluster():
    c = _cluster()
    _scan_mark(c, "trivy.ConfigAuditReport")
    _scan_mark(c, "kyverno.PolicyReport")
    other = _cluster("c-other")
    _scan_mark(other, "trivy.ConfigAuditReport")

    assert reap_all_drainable() == 3

    assert _cluster_rows(c) == 1 and _cluster_rows(other) == 1


@pytest.mark.django_db
def test_daily_heartbeat_writes_global_cluster_namespace_and_workload_rows():
    c = _cluster()
    ns = Namespace.objects.create(cluster=c, name="a")
    Workload.objects.create(cluster=c, namespace=ns, kind="Deployment", name="live", deployed=True)
    Workload.objects.create(cluster=c, namespace=ns, kind="Deployment", name="gone", deployed=False)

    assert capture_daily_heartbeat() == 4
    kinds = list(Snapshot.objects.order_by("pk").values_list("scope_kind", flat=True))
    assert kinds == ["global", "cluster", "namespace", "workload"]
    wl_row = Snapshot.objects.get(scope_kind=SnapshotScope.WORKLOAD.value)
    assert wl_row.workload.name == "live" and wl_row.change_kind == ImageSetChangeKind.NONE.value


# ── inventory reap: event-path workload snapshots ─────────────────


def _digest(ch):
    return "sha256:" + ch * 64


def _inventory_scene(current: list[str], previous: list[str] | None):
    """A deployed workload whose currently-running images are `current`;
    `previous` seeds the last workload snapshot's digest set."""
    c = _cluster()
    ns = Namespace.objects.create(cluster=c, name="a")
    w = Workload.objects.create(cluster=c, namespace=ns, kind="Deployment", name="api", deployed=True)
    mark = ImportMark.objects.create(cluster=c, kind="inventory", import_id="imp-ev",
                                     state=ImportMarkState.DRAINING.value, started_at=timezone.now())
    IngestQueue.objects.create(cluster_name=c.name, kind="inventory", import_id="imp-ev", raw_json={},
                               status="done")
    seen = mark.started_at + timedelta(seconds=1)
    Workload.objects.filter(pk=w.pk).update(last_inventory_at=seen)
    for ch in current:
        img = Image.objects.create(digest=_digest(ch), ref=f"img:{ch}")
        obs = WorkloadImageObservation.objects.create(workload=w, image=img, container_name=ch)
        WorkloadImageObservation.objects.filter(pk=obs.pk).update(last_seen_at=seen)
    if previous is not None:
        Snapshot.objects.create(scope_kind=SnapshotScope.WORKLOAD.value, cluster=c, namespace=ns, workload=w,
                                image_digest_set=[_digest(ch) for ch in previous],
                                change_kind=ImageSetChangeKind.FIRST_SEEN.value)
    return mark, w


@pytest.mark.django_db
@pytest.mark.parametrize(("previous", "current", "kind", "changed"), [
    (None, ["a"], ImageSetChangeKind.FIRST_SEEN.value, False),
    (["a"], ["a", "b"], ImageSetChangeKind.ADDED.value, True),
    (["a", "b"], ["a"], ImageSetChangeKind.REMOVED.value, True),
    (["a"], ["b"], ImageSetChangeKind.REPLACED.value, True),
    (["a", "b"], ["c"], ImageSetChangeKind.MIXED.value, True),
], ids=["first-seen", "added", "removed", "replaced", "mixed"])
def test_inventory_reap_writes_an_event_snapshot_per_image_set_change(previous, current, kind, changed):
    mark, w = _inventory_scene(current, previous)
    before = Snapshot.objects.filter(workload=w).count()

    with patch("core.services.reaper._maybe_capture_heartbeat"):
        assert _reap_inventory(mark) is not None

    rows = list(Snapshot.objects.filter(workload=w).order_by("pk"))
    assert len(rows) == before + 1
    new = rows[-1]
    assert new.change_kind == kind
    assert new.image_set_changed_from_previous is changed
    assert new.image_digest_set == sorted(_digest(ch) for ch in current)
    assert new.import_id == "imp-ev"


@pytest.mark.django_db
def test_inventory_reap_writes_nothing_when_the_image_set_is_unchanged():
    mark, w = _inventory_scene(["a"], ["a"])
    # A daily `none` row with an empty digest set must not break the diff.
    Snapshot.objects.create(scope_kind=SnapshotScope.WORKLOAD.value, cluster=w.cluster, namespace=w.namespace,
                            workload=w, image_digest_set=[], change_kind=ImageSetChangeKind.NONE.value)
    before = Snapshot.objects.filter(workload=w).count()

    with patch("core.services.reaper._maybe_capture_heartbeat"):
        _reap_inventory(mark)

    assert Snapshot.objects.filter(workload=w).count() == before


# ── set-based writers: correctness across many workloads, flat query cost ──


def _finding(workload, *, severity, hash_code, image=None, cluster=None):
    return Finding.objects.create(
        cluster=cluster or workload.cluster, workload=workload, image=image, source="trivy",
        category="vulnerability", vuln_id=hash_code, title="t", severity=severity, hash_code=hash_code,
    )


def _deployed_workload(cluster, ns, name, *, images, stale_images=(), deployed=True):
    """A workload whose `images` are currently deployed and whose
    `stale_images` are retained-but-undeployed observations."""
    w = Workload.objects.create(cluster=cluster, namespace=ns, kind="Deployment", name=name, deployed=deployed)
    for ch in images:
        img, _ = Image.objects.get_or_create(digest=_digest(ch), defaults={"ref": f"img:{ch}"})
        WorkloadImageObservation.objects.create(workload=w, image=img, container_name=ch, currently_deployed=True)
    for ch in stale_images:
        img, _ = Image.objects.get_or_create(digest=_digest(ch), defaults={"ref": f"img:{ch}"})
        WorkloadImageObservation.objects.create(workload=w, image=img, container_name=ch, currently_deployed=False)
    return w


def _previous_snapshot(w, digests):
    return Snapshot.objects.create(scope_kind=SnapshotScope.WORKLOAD.value, cluster=w.cluster, namespace=w.namespace,
                                   workload=w, image_digest_set=[_digest(ch) for ch in digests],
                                   change_kind=ImageSetChangeKind.FIRST_SEEN.value)


def _inventory_mark(cluster, import_id="imp-set"):
    return ImportMark.objects.create(cluster=cluster, kind="inventory", import_id=import_id,
                                     state=ImportMarkState.DRAINING.value, started_at=timezone.now())


def _n_queries(fn) -> int:
    with CaptureQueriesContext(connection) as ctx:
        fn()
    return len(ctx.captured_queries)


@pytest.mark.django_db
def test_event_snapshots_cover_every_changed_workload_with_its_own_counts():
    """One reap, four workloads: a first-seen one, an unchanged one, a
    replaced one and an undeployed one. Rows are written only for the two
    that changed, each carrying ITS findings (scoped to currently-deployed
    images, image-less rows included) — not a neighbour's."""
    c = _cluster()
    ns = Namespace.objects.create(cluster=c, name="a")
    mark = _inventory_mark(c)
    first = _deployed_workload(c, ns, "first", images=["a"])
    same = _deployed_workload(c, ns, "same", images=["b"])
    replaced = _deployed_workload(c, ns, "replaced", images=["c"], stale_images=["b"])
    gone = _deployed_workload(c, ns, "gone", images=["d"], deployed=False)
    _previous_snapshot(same, ["b"])
    _previous_snapshot(replaced, ["b"])
    img_a, img_b, img_c = (Image.objects.get(digest=_digest(ch)) for ch in "abc")
    _finding(first, severity="critical", hash_code="f1", image=img_a)
    _finding(first, severity="high", hash_code="f2", image=img_a)
    _finding(replaced, severity="high", hash_code="r1", image=img_c)
    _finding(replaced, severity="medium", hash_code="r2", image=img_b)   # stale image: excluded
    _finding(replaced, severity="low", hash_code="r3")                   # image-less: included
    _finding(gone, severity="critical", hash_code="g1")

    _write_event_path_workload_snapshots(c, mark)

    rows = {s.workload_id: s for s in Snapshot.objects.filter(import_id="imp-set")}
    assert set(rows) == {first.id, replaced.id}
    assert rows[first.id].change_kind == ImageSetChangeKind.FIRST_SEEN.value
    assert rows[first.id].severity_counts == {"critical": 1, "high": 1}
    assert rows[first.id].priority_counts == {"scheduled": 2}
    assert rows[first.id].total_active == 2
    assert rows[first.id].image_digest_set == [_digest("a")]
    assert rows[replaced.id].change_kind == ImageSetChangeKind.REPLACED.value
    assert rows[replaced.id].image_set_changed_from_previous is True
    assert rows[replaced.id].severity_counts == {"high": 1, "low": 1}
    assert rows[replaced.id].total_active == 2
    assert rows[replaced.id].image_digest_set == [_digest("c")]
    assert rows[replaced.id].namespace_id == ns.id and rows[replaced.id].cluster_id == c.id


@pytest.mark.django_db
def test_event_snapshots_use_the_latest_populated_snapshot_per_workload():
    """Several historical rows per workload: the diff is against the
    newest one with a digest set; heartbeat rows (empty set) are skipped
    even when they are newer."""
    c = _cluster()
    ns = Namespace.objects.create(cluster=c, name="a")
    w = _deployed_workload(c, ns, "api", images=["b"])
    old = _previous_snapshot(w, ["a"])
    Snapshot.objects.filter(pk=old.pk).update(captured_at=timezone.now() - timedelta(days=2))
    newer = _previous_snapshot(w, ["b"])
    Snapshot.objects.filter(pk=newer.pk).update(captured_at=timezone.now() - timedelta(days=1))
    Snapshot.objects.create(scope_kind=SnapshotScope.WORKLOAD.value, cluster=c, namespace=ns, workload=w,
                            image_digest_set=[], change_kind=ImageSetChangeKind.NONE.value)

    _write_event_path_workload_snapshots(c, _inventory_mark(c))

    assert not Snapshot.objects.filter(import_id="imp-set").exists(), "newest populated row is [b] == current"


@pytest.mark.django_db
def test_event_snapshot_query_count_does_not_grow_with_workload_count():
    def scene(name, n):
        c = _cluster(name)
        ns = Namespace.objects.create(cluster=c, name="a")
        for i in range(n):
            w = _deployed_workload(c, ns, f"w{i}", images=[chr(ord("a") + i)])
            _previous_snapshot(w, ["z"])
            _finding(w, severity="high", hash_code=f"{name}-{i}", image=Image.objects.get(digest=_digest(chr(ord("a") + i))))
        return c, _inventory_mark(c)

    small = scene("c-small", 2)
    large = scene("c-large", 8)

    n_small = _n_queries(lambda: _write_event_path_workload_snapshots(*small))
    n_large = _n_queries(lambda: _write_event_path_workload_snapshots(*large))

    assert Snapshot.objects.filter(cluster=large[0], import_id="imp-set").count() == 8
    assert n_large == n_small, (n_small, n_large)


@pytest.mark.django_db
def test_daily_heartbeat_counts_every_scope_from_its_own_visible_findings():
    """Two clusters. Scope rows: one global, one per cluster (including the
    empty one), one per ACTIVE namespace, one per DEPLOYED workload. Every
    scope counts visible findings on currently-deployed images (plus
    image-less ones), the same set the findings and workloads pages list;
    cluster-scoped findings count only at cluster and global level."""
    a = _cluster("c-a")
    ns = Namespace.objects.create(cluster=a, name="live")
    inactive = Namespace.objects.create(cluster=a, name="old", active=False)
    w1 = _deployed_workload(a, ns, "w1", images=["x"], stale_images=["y"])
    w2 = _deployed_workload(a, inactive, "w2", images=["x"], deployed=False)
    img_x, img_y = (Image.objects.get(digest=_digest(ch)) for ch in "xy")
    _finding(w1, severity="critical", hash_code="1", image=img_x)
    _finding(w1, severity="high", hash_code="2", image=img_y)      # rolled-out image: counted nowhere
    _finding(w1, severity="low", hash_code="3")                     # image-less
    _finding(w2, severity="critical", hash_code="4")                # undeployed workload: invisible
    _finding(None, severity="critical", hash_code="5", cluster=a)   # cluster-scoped
    _cluster("c-b")

    assert capture_daily_heartbeat() == 5

    by_scope = {}
    for s in Snapshot.objects.all():
        by_scope.setdefault(s.scope_kind, []).append(s)
    g = by_scope["global"][0]
    assert (g.severity_counts, g.total_active) == ({"critical": 2, "low": 1}, 3)
    clusters = {s.cluster.name: s for s in by_scope["cluster"]}
    assert set(clusters) == {"c-a", "c-b"}
    assert (clusters["c-a"].severity_counts, clusters["c-a"].total_active) == ({"critical": 2, "low": 1}, 3)
    assert (clusters["c-b"].severity_counts, clusters["c-b"].priority_counts, clusters["c-b"].total_active) == ({}, {}, 0)
    [n] = by_scope["namespace"]
    assert n.namespace_id == ns.id and n.cluster_id == a.id
    assert (n.severity_counts, n.total_active) == ({"critical": 1, "low": 1}, 2)
    [wl] = by_scope["workload"]
    assert wl.workload_id == w1.id and wl.namespace_id == ns.id and wl.cluster_id == a.id
    assert (wl.severity_counts, wl.priority_counts, wl.total_active) == ({"critical": 1, "low": 1}, {"scheduled": 2}, 2)
    assert wl.change_kind == ImageSetChangeKind.NONE.value and wl.image_digest_set == []


@pytest.mark.django_db
def test_cluster_and_namespace_snapshots_skip_findings_on_rolled_out_images():
    """The snapshots that bracket a flag edit, and the heartbeat that closes
    an import, use the same scope as the daily one: a finding on an image
    the workload no longer runs is not in the trend."""
    c = _cluster("c-roll")
    ns = Namespace.objects.create(cluster=c, name="live")
    w = _deployed_workload(c, ns, "w", images=["x"], stale_images=["y"])
    _finding(w, severity="critical", hash_code="1", image=Image.objects.get(digest=_digest("x")))
    _finding(w, severity="high", hash_code="2", image=Image.objects.get(digest=_digest("y")))

    cluster_row = capture_cluster_snapshot(c)
    namespace_row = capture_namespace_snapshot(ns)
    capture_cluster_heartbeat(c)

    assert (cluster_row.severity_counts, cluster_row.total_active) == ({"critical": 1}, 1)
    assert (namespace_row.severity_counts, namespace_row.total_active) == ({"critical": 1}, 1)
    closing = Snapshot.objects.filter(cluster=c, scope_kind=SnapshotScope.CLUSTER.value).order_by("-id").first()
    assert (closing.severity_counts, closing.total_active) == ({"critical": 1}, 1)


@pytest.mark.django_db
def test_daily_heartbeat_query_count_does_not_grow_with_fleet_size():
    def grow(name, n_ns, n_wl):
        c = _cluster(name)
        for i in range(n_ns):
            ns = Namespace.objects.create(cluster=c, name=f"ns{i}")
            for j in range(n_wl):
                w = _deployed_workload(c, ns, f"w{j}", images=["a"])
                _finding(w, severity="high", hash_code=f"{name}-{i}-{j}", image=Image.objects.get(digest=_digest("a")))

    grow("c-1", 1, 1)
    n_small = _n_queries(capture_daily_heartbeat)
    grow("c-2", 3, 3)
    grow("c-3", 2, 2)
    n_large = _n_queries(capture_daily_heartbeat)

    assert n_large == n_small, (n_small, n_large)


@pytest.mark.django_db
def test_cluster_heartbeat_query_count_does_not_grow_with_namespace_count():
    one = _cluster("c-one")
    Namespace.objects.create(cluster=one, name="a")
    many = _cluster("c-many")
    for i in range(6):
        Namespace.objects.create(cluster=many, name=f"ns{i}")
    Namespace.objects.create(cluster=many, name="inactive", active=False)

    n_one = _n_queries(lambda: capture_cluster_heartbeat(one))
    n_many = _n_queries(lambda: capture_cluster_heartbeat(many))

    assert Snapshot.objects.filter(cluster=many, scope_kind=SnapshotScope.NAMESPACE.value).count() == 6
    assert n_many == n_one, (n_one, n_many)


@pytest.mark.django_db
def test_workload_with_no_image_digests_gets_one_first_seen_row_not_one_per_reap():
    """A deployed workload whose pods have no imageID yet (Pending /
    ImagePullBackOff with an unpinned template) has an empty image set.
    The diff must find its own earlier empty `first_seen` row and stay
    quiet until an image appears — it used to look only at rows with a
    populated digest set, so every reap wrote another `first_seen`."""
    c = _cluster()
    ns = Namespace.objects.create(cluster=c, name="a")
    w = _deployed_workload(c, ns, "pending", images=[])

    _write_event_path_workload_snapshots(c, _inventory_mark(c, "imp-1"))
    _write_event_path_workload_snapshots(c, _inventory_mark(c, "imp-2"))

    rows = list(Snapshot.objects.filter(workload=w).order_by("pk"))
    assert [(r.change_kind, r.image_digest_set, r.import_id) for r in rows] == [
        (ImageSetChangeKind.FIRST_SEEN.value, [], "imp-1")]

    Snapshot.objects.create(scope_kind=SnapshotScope.WORKLOAD.value, cluster=c, namespace=ns, workload=w,
                            image_digest_set=[], change_kind=ImageSetChangeKind.NONE.value)  # daily heartbeat
    img = Image.objects.create(digest=_digest("a"), ref="img:a")
    WorkloadImageObservation.objects.create(workload=w, image=img, container_name="app", currently_deployed=True)
    _write_event_path_workload_snapshots(c, _inventory_mark(c, "imp-3"))

    new = Snapshot.objects.filter(workload=w, import_id="imp-3").get()
    assert (new.change_kind, new.image_digest_set, new.image_set_changed_from_previous) == (
        ImageSetChangeKind.ADDED.value, [_digest("a")], True)
