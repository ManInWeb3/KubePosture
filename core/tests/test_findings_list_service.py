"""Tests for `core.services.inventory.list_findings`.

Locks the contract: triage-signal filters narrow correctly, exposure
excludes cluster-scoped findings, default sort is priority desc then
last_seen desc.
"""
from __future__ import annotations

from datetime import timedelta

import pytest
from django.utils import timezone

from core.constants import (
    Category,
    Environment,
    PriorityBand,
    Severity,
    Source,
)
from core.models import Cluster, Finding, Namespace, Workload
from core.services.inventory import list_findings


# ── Fixture builders ─────────────────────────────────────────────


def _cluster(name: str = "c1") -> Cluster:
    # last_complete_inventory_at left NULL so default_finding_qs accepts
    # findings via its NULL-branch predicate.
    return Cluster.objects.create(name=name, environment=Environment.PROD.value)


def _ns(c: Cluster, name: str, *, exposed: bool = False, sensitive: bool = False) -> Namespace:
    return Namespace.objects.create(
        cluster=c, name=name,
        internet_exposed=exposed, contains_sensitive_data=sensitive,
    )


def _workload(c: Cluster, ns: Namespace, name: str = "api") -> Workload:
    return Workload.objects.create(
        cluster=c, namespace=ns, kind="Deployment", name=name, deployed=True,
    )


def _finding(
    *,
    workload: Workload | None = None,
    cluster: Cluster | None = None,
    source: str = Source.TRIVY.value,
    severity: str = Severity.HIGH.value,
    priority: str = PriorityBand.SCHEDULED.value,
    title: str = "test finding",
    vuln_id: str = "CVE-2024-0001",
    kev: bool = False,
    epss: float | None = None,
    first_seen=None,
    last_seen=None,
    hash_code: str = "h",
) -> Finding:
    if workload is not None and cluster is None:
        cluster = workload.cluster
    assert cluster is not None
    return Finding.objects.create(
        cluster=cluster,
        workload=workload,
        source=source,
        category=Category.VULNERABILITY.value,
        vuln_id=vuln_id,
        title=title,
        severity=severity,
        effective_priority=priority,
        kev_listed=kev,
        epss_score=epss,
        first_seen=first_seen or timezone.now(),
        last_seen=last_seen or timezone.now(),
        hash_code=hash_code,
    )


# ── Tests ────────────────────────────────────────────────────────


@pytest.mark.django_db
def test_empty_filters_returns_all_active_findings():
    c = _cluster()
    ns = _ns(c, "default")
    w = _workload(c, ns)
    _finding(workload=w, hash_code="h1")
    _finding(workload=w, hash_code="h2", vuln_id="CVE-2024-0002")

    rows = list(list_findings())

    assert len(rows) == 2


@pytest.mark.django_db
def test_name_contains_matches_title_or_vuln_id():
    c = _cluster()
    ns = _ns(c, "default")
    w = _workload(c, ns)
    f1 = _finding(workload=w, hash_code="h1", title="openssl heap overflow", vuln_id="CVE-2024-1111")
    f2 = _finding(workload=w, hash_code="h2", title="curl integer wrap",       vuln_id="CVE-2025-2222")
    f3 = _finding(workload=w, hash_code="h3", title="something else",          vuln_id="GHSA-aaaa")

    by_title = {f.pk for f in list_findings(name_contains="openssl")}
    by_vuln = {f.pk for f in list_findings(name_contains="2025")}

    assert by_title == {f1.pk}
    assert by_vuln == {f2.pk}


@pytest.mark.django_db
def test_priority_filter():
    c = _cluster()
    ns = _ns(c, "default")
    w = _workload(c, ns)
    imm = _finding(workload=w, hash_code="hi", priority=PriorityBand.IMMEDIATE.value)
    _finding(workload=w, hash_code="hd", priority=PriorityBand.DEFER.value)

    rows = list(list_findings(priority=PriorityBand.IMMEDIATE.value))

    assert [f.pk for f in rows] == [imm.pk]


@pytest.mark.django_db
def test_source_filter():
    c = _cluster()
    ns = _ns(c, "default")
    w = _workload(c, ns)
    trivy = _finding(workload=w, hash_code="ht", source=Source.TRIVY.value)
    _finding(workload=w, hash_code="hk", source=Source.KYVERNO.value)

    rows = list(list_findings(source=Source.TRIVY.value))

    assert [f.pk for f in rows] == [trivy.pk]


@pytest.mark.django_db
def test_kev_filter():
    c = _cluster()
    ns = _ns(c, "default")
    w = _workload(c, ns)
    kev_f = _finding(workload=w, hash_code="hk", kev=True)
    _finding(workload=w, hash_code="hn", kev=False)

    rows = list(list_findings(kev=True))

    assert [f.pk for f in rows] == [kev_f.pk]


@pytest.mark.django_db
def test_epss_min_filter():
    c = _cluster()
    ns = _ns(c, "default")
    w = _workload(c, ns)
    high = _finding(workload=w, hash_code="hh", epss=0.7)
    _finding(workload=w, hash_code="hl", epss=0.05)

    rows = list(list_findings(epss_min=0.5))

    assert [f.pk for f in rows] == [high.pk]


@pytest.mark.django_db
def test_age_days_filter_keeps_only_recent_first_seen():
    c = _cluster()
    ns = _ns(c, "default")
    w = _workload(c, ns)
    now = timezone.now()
    new_f = _finding(workload=w, hash_code="hn", first_seen=now - timedelta(days=2))
    _finding(workload=w, hash_code="ho", first_seen=now - timedelta(days=30))

    rows = list(list_findings(age_days=7))

    assert [f.pk for f in rows] == [new_f.pk]


@pytest.mark.django_db
def test_exposure_internet_includes_only_exposed_namespace_workload_findings():
    c = _cluster()
    ns_exposed = _ns(c, "edge", exposed=True)
    ns_internal = _ns(c, "internal", exposed=False)
    w_exposed = _workload(c, ns_exposed, name="frontend")
    w_internal = _workload(c, ns_internal, name="backend")

    f_exposed = _finding(workload=w_exposed, hash_code="he")
    _finding(workload=w_internal, hash_code="hi")
    # cluster-scoped finding (workload IS NULL) — must be excluded by exposure filter
    _finding(cluster=c, workload=None, hash_code="hc")

    rows = list(list_findings(exposure="internet"))

    assert [f.pk for f in rows] == [f_exposed.pk]


@pytest.mark.django_db
def test_exposure_either_combines_internet_and_sensitive():
    c = _cluster()
    ns_exp = _ns(c, "edge", exposed=True, sensitive=False)
    ns_sen = _ns(c, "phi",  exposed=False, sensitive=True)
    ns_neither = _ns(c, "internal", exposed=False, sensitive=False)
    w_exp = _workload(c, ns_exp, name="a")
    w_sen = _workload(c, ns_sen, name="b")
    w_n = _workload(c, ns_neither, name="c")

    f_exp = _finding(workload=w_exp, hash_code="h1")
    f_sen = _finding(workload=w_sen, hash_code="h2")
    _finding(workload=w_n, hash_code="h3")

    rows = list(list_findings(exposure="either"))

    assert {f.pk for f in rows} == {f_exp.pk, f_sen.pk}


@pytest.mark.django_db
def test_default_sort_is_priority_desc_then_last_seen_desc():
    c = _cluster()
    ns = _ns(c, "default")
    w = _workload(c, ns)
    now = timezone.now()
    older_imm = _finding(workload=w, hash_code="h_imm_old",
                         priority=PriorityBand.IMMEDIATE.value,
                         last_seen=now - timedelta(hours=2))
    newer_imm = _finding(workload=w, hash_code="h_imm_new",
                         priority=PriorityBand.IMMEDIATE.value,
                         last_seen=now)
    defer = _finding(workload=w, hash_code="h_defer",
                     priority=PriorityBand.DEFER.value, last_seen=now)

    pks = [f.pk for f in list_findings()]

    # Both immediates outrank defer; within immediate, newer last_seen first.
    assert pks == [newer_imm.pk, older_imm.pk, defer.pk]


@pytest.mark.django_db
def test_excludes_findings_on_undeployed_workloads():
    """Workload-scoped findings on undeployed workloads must not appear
    in the list, even if other filters match. Cluster-scoped findings
    (workload IS NULL) are unaffected."""
    c = _cluster()
    ns = _ns(c, "default")
    deployed_w = Workload.objects.create(
        cluster=c, namespace=ns, kind="Deployment", name="live", deployed=True,
    )
    undeployed_w = Workload.objects.create(
        cluster=c, namespace=ns, kind="Deployment", name="ghost", deployed=False,
    )
    f_live = _finding(workload=deployed_w, hash_code="h_live", vuln_id="CVE-LIVE")
    _finding(workload=undeployed_w, hash_code="h_ghost", vuln_id="CVE-GHOST")
    f_cluster = _finding(cluster=c, workload=None, hash_code="h_cluster", vuln_id="CVE-CLUSTER")

    pks = {f.pk for f in list_findings()}

    assert pks == {f_live.pk, f_cluster.pk}


@pytest.mark.django_db
def test_filters_compose_with_and():
    c = _cluster()
    ns = _ns(c, "edge", exposed=True)
    w = _workload(c, ns)
    match = _finding(workload=w, hash_code="hm",
                     priority=PriorityBand.IMMEDIATE.value, kev=True,
                     source=Source.TRIVY.value, vuln_id="CVE-2024-9999")
    # Same priority+source but no KEV → excluded
    _finding(workload=w, hash_code="h_no_kev",
             priority=PriorityBand.IMMEDIATE.value, kev=False,
             source=Source.TRIVY.value, vuln_id="CVE-2024-8888")
    # KEV but wrong priority → excluded
    _finding(workload=w, hash_code="h_low_prio",
             priority=PriorityBand.DEFER.value, kev=True,
             source=Source.TRIVY.value, vuln_id="CVE-2024-7777")

    rows = list(list_findings(
        priority=PriorityBand.IMMEDIATE.value,
        source=Source.TRIVY.value,
        kev=True,
        exposure="internet",
    ))

    assert [f.pk for f in rows] == [match.pk]
