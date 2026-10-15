"""Every lane of the urgency decision tree pinned by its *band value*
(docs/urgency-decision-tree.md). test_urgency.py's grid only asserts
fixed == unfixed, which would still pass if score() returned DEFER for
everything."""
from __future__ import annotations

import pytest

from core.constants import Category, Environment, PriorityBand, Severity
from core.models import Cluster, Finding, Namespace, Workload, WorkloadSignal
from core.urgency import score

IMM, OOB, SCH, DEF = (PriorityBand.IMMEDIATE.value, PriorityBand.OUT_OF_BAND.value,
                      PriorityBand.SCHEDULED.value, PriorityBand.DEFER.value)
C, H, M, L = Severity.CRITICAL.value, Severity.HIGH.value, Severity.MEDIUM.value, Severity.LOW.value


def _scored(*, env=Environment.PROD.value, severity=H, exposed=False, sensitive=False, epss=0.0,
            kev=False, fixed="", escalation_signal=None, cluster_scoped=False, category="vulnerability"):
    c = Cluster.objects.create(name=f"c-{env}", environment=env)
    f_kwargs = dict(cluster=c, source="trivy", category=category, vuln_id="CVE-1", title="t",
                    severity=severity, epss_percentile=epss, kev_listed=kev, fixed_version=fixed, hash_code="h")
    if cluster_scoped:
        f = Finding.objects.create(workload=None, **f_kwargs)
    else:
        ns = Namespace.objects.create(cluster=c, name="ns", contains_sensitive_data=sensitive)
        w = Workload.objects.create(cluster=c, namespace=ns, kind="Deployment", name="api",
                                    deployed=True, publicly_exposed=exposed)
        if escalation_signal:
            WorkloadSignal.objects.create(workload=w, signal_id=escalation_signal, currently_active=True)
        f = Finding.objects.create(workload=w, **f_kwargs)
    f = Finding.objects.select_related("workload__namespace", "workload__cluster", "cluster").get(pk=f.pk)
    return score(f)


LANES = [
    ("supply-chain short-circuit", dict(category=Category.SUPPLY_CHAIN.value, severity=L, env="dev"), IMM, "supply-chain"),
    ("KEV short-circuit", dict(kev=True, severity=L, env="dev"), IMM, "KEV"),
    ("C/H + EPSS>=0.9 + exposed + prod", dict(severity=H, epss=0.95, exposed=True), IMM, "EPSS>=0.9"),
    ("critical + exposed + prod", dict(severity=C, exposed=True), IMM, "critical"),
    ("critical + sensitive ns (any env)", dict(severity=C, sensitive=True, env="dev"), OOB, "sensitive-ns"),
    ("C/H + prod + escalation signal", dict(severity=H, escalation_signal="kyverno:disallow-privileged-containers"), OOB, "escalation-signal"),
    ("EPSS>=0.9 + prod", dict(severity=M, epss=0.95), OOB, "EPSS>=0.9"),
    ("EPSS>=0.9 + C/H outside prod", dict(severity=H, epss=0.95, env="dev"), SCH, "EPSS>=0.9"),
    ("critical + prod", dict(severity=C), OOB, "critical"),
    ("high + exposed + prod", dict(severity=H, exposed=True), OOB, "high"),
    ("high + sensitive ns", dict(severity=H, sensitive=True, env="dev"), SCH, "sensitive-ns"),
    ("medium + sensitive ns + no fix", dict(severity=M, sensitive=True, env="dev"), SCH, "no-fix"),
    ("medium + sensitive ns + fix available", dict(severity=M, sensitive=True, env="dev", fixed="1.1"), DEF, "default"),
    ("C/H + exposed outside prod", dict(severity=H, exposed=True, env="dev"), SCH, "exposed-or-escalation"),
    ("critical outside prod", dict(severity=C, env="dev"), SCH, "non-prod"),
    ("high + prod", dict(severity=H), SCH, "high"),
    ("medium + prod + escalation", dict(severity=M, escalation_signal="kyverno:disallow-privileged-containers"), OOB, "escalation-signal"),
    ("medium + prod, nothing else", dict(severity=M), DEF, "default"),
    ("low anywhere", dict(severity=L, exposed=True, sensitive=True), DEF, "default"),
    ("cluster-scoped critical", dict(cluster_scoped=True, severity=C, env="dev"), OOB, "cluster-scoped"),
    ("cluster-scoped high + prod", dict(cluster_scoped=True, severity=H), OOB, "cluster-scoped"),
    ("cluster-scoped high outside prod", dict(cluster_scoped=True, severity=H, env="dev"), SCH, "cluster-scoped"),
]


@pytest.mark.django_db
@pytest.mark.parametrize(("label", "kwargs", "band", "reason"), LANES, ids=[lane[0] for lane in LANES])
def test_lane_band_and_reason(label, kwargs, band, reason):
    result = _scored(**kwargs)
    assert result.band == band
    assert reason in result.reasons
