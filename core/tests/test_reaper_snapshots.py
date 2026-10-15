"""The observational side of the reaper, which every other reaper test
patches out: the post-reap cluster heartbeat (once, after the LAST mark of
an import session) and the inventory reap's event-path workload snapshots
(`change_kind` / `image_digest_set`)."""
from __future__ import annotations

from datetime import timedelta
from unittest.mock import patch

import pytest
from django.utils import timezone

from core.constants import Environment, ImageSetChangeKind, ImportMarkState, SnapshotScope
from core.models import (
    Cluster,
    Image,
    ImportMark,
    IngestQueue,
    Namespace,
    Snapshot,
    Workload,
    WorkloadImageObservation,
)
from core.services.reaper import _reap_inventory, maybe_reap, reap_all_drainable
from core.services.snapshot import capture_daily_heartbeat


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
