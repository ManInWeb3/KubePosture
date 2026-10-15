"""The two HTMX namespace-row endpoints on the cluster page: flipping a
flag (and pinning it manual) and resetting the manual flags. Both are
bracketed by pre/post snapshots and return the re-rendered row with a
fresh active-finding count."""
from __future__ import annotations

import pytest
from django.contrib.auth.models import Group, User
from django.urls import reverse

from core.constants import Environment, Severity, SnapshotScope
from core.models import Cluster, Finding, Namespace, Snapshot, Workload


@pytest.fixture
def admin(db):
    Group.objects.get_or_create(name="admin")
    u = User.objects.create_user(username="ns-admin", password="x")
    u.groups.add(Group.objects.get(name="admin"))
    return u


@pytest.fixture
def authed(client, admin):
    client.force_login(admin)
    return client


@pytest.fixture
def ns(db):
    c = Cluster.objects.create(name="c-ns", environment=Environment.PROD.value)
    ns = Namespace.objects.create(cluster=c, name="edge")
    w = Workload.objects.create(cluster=c, namespace=ns, kind="Deployment", name="api", deployed=True)
    for i in range(2):
        Finding.objects.create(cluster=c, workload=w, source="trivy", category="vulnerability",
                               vuln_id=f"CVE-{i}", title="t", severity=Severity.HIGH.value, hash_code=f"h{i}")
    return ns


def _toggle(ns):
    return reverse("namespace-toggle", kwargs={"cluster_pk": ns.cluster_id, "ns_pk": ns.pk})


def _reset(ns):
    return reverse("namespace-reset-auto", kwargs={"cluster_pk": ns.cluster_id, "ns_pk": ns.pk})


def _snapshot_rows(ns) -> tuple[int, int]:
    return (
        Snapshot.objects.filter(cluster=ns.cluster, scope_kind=SnapshotScope.CLUSTER.value).count(),
        Snapshot.objects.filter(namespace=ns, scope_kind=SnapshotScope.NAMESPACE.value).count(),
    )


@pytest.mark.parametrize(("field", "manual"), [
    ("internet_exposed", "exposure_is_manual"),
    ("contains_sensitive_data", "sensitive_is_manual"),
])
def test_toggle_flips_the_flag_pins_it_manual_and_returns_the_row(authed, ns, field, manual):
    resp = authed.post(_toggle(ns), {"field": field})

    assert resp.status_code == 200
    ns.refresh_from_db()
    assert getattr(ns, field) is True and getattr(ns, manual) is True
    assert _snapshot_rows(ns) == (2, 2), "pre + post rows at both scopes"
    assert resp.context["ns"].finding_count == 2
    assert resp.context["is_admin"] is True and resp.context["cluster"] == ns.cluster
    body = resp.content.decode()
    assert body.lstrip().startswith("<tr") and f'id="ns-row-{ns.pk}"' in body

    authed.post(_toggle(ns), {"field": field})
    ns.refresh_from_db()
    assert getattr(ns, field) is False and getattr(ns, manual) is True, "a second flip clears it, still manual"


def test_toggle_rejects_unknown_fields_and_inactive_namespaces_without_writing(authed, ns):
    assert authed.post(_toggle(ns), {"field": "active"}).status_code == 400
    assert authed.post(_toggle(ns), {}).status_code == 400

    Namespace.objects.filter(pk=ns.pk).update(active=False)
    assert authed.post(_toggle(ns), {"field": "internet_exposed"}).status_code == 409

    ns.refresh_from_db()
    assert (ns.internet_exposed, ns.exposure_is_manual) == (False, False)
    assert _snapshot_rows(ns) == (0, 0)


def test_namespace_must_belong_to_the_cluster_in_the_url(authed, ns):
    other = Cluster.objects.create(name="c-other", environment=Environment.PROD.value)
    url = reverse("namespace-toggle", kwargs={"cluster_pk": other.pk, "ns_pk": ns.pk})
    assert authed.post(url, {"field": "internet_exposed"}).status_code == 404
    url = reverse("namespace-reset-auto", kwargs={"cluster_pk": other.pk, "ns_pk": ns.pk})
    assert authed.post(url).status_code == 404


def test_reset_auto_clears_both_manual_flags_and_returns_the_row(authed, ns):
    Namespace.objects.filter(pk=ns.pk).update(internet_exposed=True, exposure_is_manual=True,
                                              sensitive_is_manual=True)

    resp = authed.post(_reset(ns))

    assert resp.status_code == 200
    ns.refresh_from_db()
    assert (ns.exposure_is_manual, ns.sensitive_is_manual) == (False, False)
    assert ns.internet_exposed is True, "the value is left for the next inventory to re-derive"
    assert _snapshot_rows(ns) == (2, 2)
    assert resp.context["ns"].finding_count == 2
    assert f'id="ns-row-{ns.pk}"' in resp.content.decode()
