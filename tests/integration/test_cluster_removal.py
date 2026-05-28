"""Complete cluster removal — service, management command, and UI view.

Removing a cluster must take down its entire FK-linked subtree
(namespaces, workloads, findings, finding actions, signals, image
observations, import marks, snapshots, aliases, scan inconsistencies)
plus the `IngestQueue` rows that reference it only by string name —
while leaving other clusters and globally-shared data (Image, tokens,
enrichment) untouched.

Covered by `core/services/cluster_removal.py`, the `remove_cluster`
management command, and `ClusterDeleteView`.
"""
from __future__ import annotations

from datetime import timedelta
from io import StringIO

import pytest
from django.contrib.auth.models import Group, User
from django.core.management import call_command
from django.core.management.base import CommandError
from django.urls import reverse
from django.utils import timezone

from core.constants import (
    AliasKind,
    Category,
    FindingActionType,
    IngestQueueStatus,
    ImportMarkState,
    Severity,
    SnapshotScope,
    Source,
)
from core.models import (
    Cluster,
    Finding,
    FindingAction,
    Image,
    IngestQueue,
    ImportMark,
    Namespace,
    ScanInconsistency,
    Snapshot,
    Workload,
    WorkloadAlias,
    WorkloadImageObservation,
    WorkloadSignal,
)
from core.services.cluster_removal import remove_cluster


# ── Fixtures ──────────────────────────────────────────────────────


@pytest.fixture
def admin_user(db):
    u = User.objects.create_user(username="admin1", password="x")
    g, _ = Group.objects.get_or_create(name="admin")
    u.groups.add(g)
    return u


@pytest.fixture
def viewer_user(db):
    u = User.objects.create_user(username="viewer1", password="x")
    g, _ = Group.objects.get_or_create(name="viewer")
    u.groups.add(g)
    return u


@pytest.fixture
def shared_image(db):
    return Image.objects.create(
        digest="sha256:" + "a" * 64,
        ref="registry/api:v1",
        repository="api",
    )


def _populate(cluster, image, *, n_offset=0):
    """Create one row in every table tied to `cluster`, returning a dict
    of the created objects. `n_offset` keeps unique fields distinct when
    two clusters are populated in the same test.
    """
    now = timezone.now()
    ns = Namespace.objects.create(cluster=cluster, name="payments")
    workload = Workload.objects.create(
        cluster=cluster, namespace=ns, kind="Deployment", name="api",
        deployed=True, last_inventory_at=now,
    )
    obs = WorkloadImageObservation.objects.create(
        workload=workload, image=image, container_name="app",
        currently_deployed=True,
    )
    signal = WorkloadSignal.objects.create(
        workload=workload, signal_id=f"sig-{cluster.name}",
    )
    finding = Finding.objects.create(
        cluster=cluster, workload=workload, image=image,
        source=Source.TRIVY, category=Category.VULNERABILITY,
        vuln_id="CVE-2024-0001", title="boom", severity=Severity.HIGH,
        hash_code=f"hash-{cluster.name}",
    )
    action = FindingAction.objects.create(
        finding=finding, action_type=FindingActionType.ACKNOWLEDGE,
        reason="looking into it",
    )
    alias = WorkloadAlias.objects.create(
        cluster=cluster, namespace=ns, alias_kind=AliasKind.REPLICASET,
        alias_name="api-abc123", target_workload=workload,
    )
    incon = ScanInconsistency.objects.create(cluster=cluster, workload=workload)
    mark = ImportMark.objects.create(
        cluster=cluster, kind="vulnerabilityreports",
        import_id=f"imp{n_offset:03d}", state=ImportMarkState.OPEN,
        started_at=now,
    )
    snap_cluster = Snapshot.objects.create(
        scope_kind=SnapshotScope.CLUSTER, cluster=cluster,
    )
    snap_ns = Snapshot.objects.create(
        scope_kind=SnapshotScope.NAMESPACE, cluster=cluster, namespace=ns,
    )
    queue = IngestQueue.objects.create(
        cluster_name=cluster.name, kind="vulnerabilityreports",
        import_id=f"imp{n_offset:03d}", raw_json={},
        status=IngestQueueStatus.PENDING,
    )
    return {
        "ns": ns, "workload": workload, "obs": obs, "signal": signal,
        "finding": finding, "action": action, "alias": alias,
        "incon": incon, "mark": mark, "snap_cluster": snap_cluster,
        "snap_ns": snap_ns, "queue": queue,
    }


@pytest.fixture
def two_clusters(db, shared_image):
    """Two fully-populated clusters sharing one Image."""
    ca = Cluster.objects.create(name="cluster-a", environment="prod")
    cb = Cluster.objects.create(name="cluster-b", environment="staging")
    a = _populate(ca, shared_image, n_offset=0)
    b = _populate(cb, shared_image, n_offset=1)
    return {"ca": ca, "cb": cb, "a": a, "b": b}


# ── Service ───────────────────────────────────────────────────────


def test_service_deletes_entire_subtree(two_clusters):
    ca = two_clusters["ca"]
    ca_pk = ca.pk  # `delete()` nulls the instance pk — capture it first.
    result = remove_cluster(ca)

    assert result.dry_run is False
    assert result.cluster_name == "cluster-a"
    # Cluster row itself is gone.
    assert not Cluster.objects.filter(pk=ca_pk).exists()
    # Every FK-linked child for A is gone.
    assert Namespace.objects.filter(cluster_id=ca_pk).count() == 0
    assert Workload.objects.filter(cluster_id=ca_pk).count() == 0
    assert Finding.objects.filter(cluster_id=ca_pk).count() == 0
    assert FindingAction.objects.filter(finding__cluster_id=ca_pk).count() == 0
    assert WorkloadSignal.objects.filter(workload__cluster_id=ca_pk).count() == 0
    assert WorkloadImageObservation.objects.filter(workload__cluster_id=ca_pk).count() == 0
    assert WorkloadAlias.objects.filter(cluster_id=ca_pk).count() == 0
    assert ScanInconsistency.objects.filter(cluster_id=ca_pk).count() == 0
    assert ImportMark.objects.filter(cluster_id=ca_pk).count() == 0
    assert Snapshot.objects.filter(cluster_id=ca_pk).count() == 0
    # IngestQueue (no FK — matched by name) is also gone.
    assert IngestQueue.objects.filter(cluster_name="cluster-a").count() == 0


def test_service_preserves_other_cluster_and_shared_image(two_clusters):
    cb = two_clusters["cb"]
    remove_cluster(two_clusters["ca"])

    # Cluster B is fully intact.
    assert Cluster.objects.filter(pk=cb.pk).exists()
    assert Namespace.objects.filter(cluster=cb).count() == 1
    assert Workload.objects.filter(cluster=cb).count() == 1
    assert Finding.objects.filter(cluster=cb).count() == 1
    assert IngestQueue.objects.filter(cluster_name="cluster-b").count() == 1
    # The shared Image is append-only — never deleted by a cluster removal.
    assert Image.objects.count() == 1


def test_service_dry_run_counts_without_deleting(two_clusters):
    ca = two_clusters["ca"]
    result = remove_cluster(ca, dry_run=True)

    assert result.dry_run is True
    # Nothing was actually deleted.
    assert Cluster.objects.filter(pk=ca.pk).exists()
    assert Finding.objects.filter(cluster=ca).count() == 1
    # Counts reflect what a real run would delete.
    assert result.deleted["core.Finding"] == 1
    assert result.deleted["core.Namespace"] == 1
    assert result.deleted["core.IngestQueue"] == 1
    assert result.deleted["core.Snapshot"] == 2  # cluster- + namespace-scope
    assert result.total > 0


# ── Management command ────────────────────────────────────────────


def test_command_dry_run_does_not_delete(two_clusters):
    out = StringIO()
    call_command("remove_cluster", "--cluster", "cluster-a", "--dry-run", stdout=out)

    assert Cluster.objects.filter(name="cluster-a").exists()
    body = out.getvalue()
    assert "Dry run" in body
    assert "core.Finding" in body


def test_command_yes_deletes(two_clusters):
    out = StringIO()
    call_command("remove_cluster", "--cluster", "cluster-a", "--yes", stdout=out)

    assert not Cluster.objects.filter(name="cluster-a").exists()
    assert Cluster.objects.filter(name="cluster-b").exists()
    assert "Removed cluster 'cluster-a'" in out.getvalue()


def test_command_unknown_cluster_raises(db):
    with pytest.raises(CommandError, match="No cluster named"):
        call_command("remove_cluster", "--cluster", "ghost", "--yes")


# ── UI view ───────────────────────────────────────────────────────


def _delete_url(cluster):
    return reverse("cluster-delete", args=[cluster.pk])


def test_view_admin_matching_name_deletes(client, admin_user, two_clusters):
    client.force_login(admin_user)
    ca = two_clusters["ca"]

    resp = client.post(_delete_url(ca), {"confirm_name": "cluster-a"})
    assert resp.status_code == 302
    assert resp.url == reverse("cluster-list")
    assert not Cluster.objects.filter(pk=ca.pk).exists()
    assert Cluster.objects.filter(name="cluster-b").exists()


def test_view_wrong_name_does_not_delete(client, admin_user, two_clusters):
    client.force_login(admin_user)
    ca = two_clusters["ca"]

    resp = client.post(_delete_url(ca), {"confirm_name": "typo"})
    assert resp.status_code == 302
    assert resp.url == reverse("cluster-detail", args=[ca.pk])
    # Still there.
    assert Cluster.objects.filter(pk=ca.pk).exists()


def test_view_non_admin_forbidden(client, viewer_user, two_clusters):
    client.force_login(viewer_user)
    ca = two_clusters["ca"]

    resp = client.post(_delete_url(ca), {"confirm_name": "cluster-a"})
    assert resp.status_code == 403
    assert Cluster.objects.filter(pk=ca.pk).exists()


def test_detail_shows_danger_zone_for_admin_only(client, admin_user, viewer_user, two_clusters):
    ca = two_clusters["ca"]
    detail_url = reverse("cluster-detail", args=[ca.pk])

    client.force_login(admin_user)
    admin_body = client.get(detail_url).content.decode()
    assert "Danger zone" in admin_body
    assert _delete_url(ca) in admin_body

    client.force_login(viewer_user)
    viewer_body = client.get(detail_url).content.decode()
    assert "Danger zone" not in viewer_body
    assert _delete_url(ca) not in viewer_body
