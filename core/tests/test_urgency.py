"""Unit tests for core.urgency.score().

Locks the SSVC-aligned behaviour after `has_fix` was removed from the
decision tree: priority must depend only on KEV/EPSS/severity/exposure/
escalation/environment/sensitivity — never on `Finding.fixed_version`.
"""
from __future__ import annotations

import pytest

from core.constants import Environment, PriorityBand, Severity
from core.models import (
    Cluster,
    Finding,
    Namespace,
    Workload,
    WorkloadSignal,
)
from core.urgency import score


# ── Fixture builders ─────────────────────────────────────────────


def _cluster(name: str, env: str = Environment.PROD.value) -> Cluster:
    return Cluster.objects.create(name=name, environment=env)


def _ns(cluster: Cluster, name: str, sensitive: bool = False) -> Namespace:
    return Namespace.objects.create(
        cluster=cluster, name=name, contains_sensitive_data=sensitive,
    )


def _workload(cluster: Cluster, ns: Namespace, name: str, exposed: bool = False) -> Workload:
    return Workload.objects.create(
        cluster=cluster, namespace=ns,
        kind="Deployment", name=name,
        publicly_exposed=exposed, deployed=True,
    )


def _finding(
    *,
    workload: Workload,
    severity: str,
    fixed_version: str = "",
    epss_percentile: float = 0.0,
    kev_listed: bool = False,
    hash_code: str,
) -> Finding:
    return Finding.objects.create(
        cluster=workload.cluster,
        workload=workload,
        source="trivy",
        category="vulnerability",
        vuln_id=f"CVE-TEST-{hash_code}",
        title=f"{severity} test finding",
        severity=severity,
        fixed_version=fixed_version,
        epss_percentile=epss_percentile,
        kev_listed=kev_listed,
        hash_code=hash_code,
    )


# ── Branch coverage ──────────────────────────────────────────────


@pytest.mark.django_db
def test_sensitive_namespace_bumps_high_with_fix_to_scheduled():
    """Branch A — sensitive-ns bump fires regardless of fix availability."""
    c = _cluster("dev-1", env=Environment.DEV.value)
    ns = _ns(c, "phi", sensitive=True)
    w = _workload(c, ns, "api")
    f = _finding(
        workload=w, severity=Severity.HIGH.value,
        fixed_version="1.2.3", hash_code="sens-fix",
    )

    result = score(f)

    assert result.band == PriorityBand.SCHEDULED.value
    assert "sensitive-ns" in result.reasons
    assert "no-fix" not in result.reasons


@pytest.mark.django_db
def test_critical_non_prod_no_context_no_fix_is_scheduled_not_defer():
    """Branch B removal — pre-change this DEFERed via the no-fix short-circuit;
    post-change the critical-non-prod branch correctly fires."""
    c = _cluster("dev-2", env=Environment.DEV.value)
    ns = _ns(c, "default")
    w = _workload(c, ns, "batch", exposed=False)
    f = _finding(
        workload=w, severity=Severity.CRITICAL.value,
        fixed_version="",  # no fix
        hash_code="crit-nonprod",
    )

    result = score(f)

    assert result.band == PriorityBand.SCHEDULED.value
    assert result.reasons == ("critical", "non-prod")


@pytest.mark.django_db
def test_high_non_prod_exposed_with_fix_is_scheduled():
    """Branch C — fires regardless of fix availability now."""
    c = _cluster("staging-1", env=Environment.STAGING.value)
    ns = _ns(c, "default")
    w = _workload(c, ns, "api", exposed=True)
    f = _finding(
        workload=w, severity=Severity.HIGH.value,
        fixed_version="9.9.9",  # has fix
        hash_code="high-staging-exposed",
    )

    result = score(f)

    assert result.band == PriorityBand.SCHEDULED.value
    assert "exposed-or-escalation" in result.reasons


@pytest.mark.django_db
def test_low_dev_no_context_defers():
    """Default-tail branch still defers."""
    c = _cluster("dev-3", env=Environment.DEV.value)
    ns = _ns(c, "default")
    w = _workload(c, ns, "noop")
    f = _finding(
        workload=w, severity=Severity.LOW.value,
        hash_code="low-dev",
    )

    result = score(f)

    assert result.band == PriorityBand.DEFER.value
    assert result.reasons == ("default",)


# ── has_fix is invariant under scoring ───────────────────────────


@pytest.mark.django_db
def test_fix_availability_does_not_change_outcome():
    """Same input twice — once with a fix, once without — produces the same band.

    Sweeps a representative grid: severity × exposure × env. KEV is held
    off (KEV short-circuits everything else). Sensitive-ns is held off
    (covered separately in Branch A test).
    """
    seen: list[tuple] = []

    severities = [Severity.LOW.value, Severity.MEDIUM.value, Severity.HIGH.value, Severity.CRITICAL.value]
    envs = [Environment.PROD.value, Environment.DEV.value]
    exposures = [True, False]

    for env in envs:
        c = _cluster(f"c-{env}", env=env)
        ns = _ns(c, "ns")
        for exposed in exposures:
            w = _workload(c, ns, f"w-{env}-{exposed}", exposed=exposed)
            for sev in severities:
                key = f"{env}-{exposed}-{sev}"
                f_unfixed = _finding(
                    workload=w, severity=sev, fixed_version="",
                    epss_percentile=0.5,
                    hash_code=f"{key}-unfixed",
                )
                f_fixed = _finding(
                    workload=w, severity=sev, fixed_version="1.0.0",
                    epss_percentile=0.5,
                    hash_code=f"{key}-fixed",
                )

                r_unfixed = score(f_unfixed)
                r_fixed = score(f_fixed)

                assert r_unfixed.band == r_fixed.band, (
                    f"fix availability altered band for {key}: "
                    f"unfixed={r_unfixed.band} fixed={r_fixed.band}"
                )
                seen.append((key, r_unfixed.band))

    # Sanity: we actually exercised the grid
    assert len(seen) == len(severities) * len(envs) * len(exposures)
