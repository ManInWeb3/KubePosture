"""recalculate_priorities must recompute every Finding in bounded chunks
(one unbounded load of the whole table OOMKilled the CronJob)."""
from __future__ import annotations

import io
from unittest.mock import patch

import pytest
from django.core.management import call_command

from core.constants import Environment, Severity
from core.management.commands import recalculate_priorities as cmd
from core.models import Cluster, Finding, Namespace, Workload


def _findings(cluster_name, n):
    c = Cluster.objects.create(name=cluster_name, environment=Environment.PROD.value)
    ns = Namespace.objects.create(cluster=c, name="default")
    w = Workload.objects.create(cluster=c, namespace=ns, kind="Deployment", name="api", deployed=True)
    return [
        Finding.objects.create(
            cluster=c, workload=w, source="trivy", category="vulnerability",
            vuln_id=f"CVE-2024-{cluster_name}-{i}", title="t",
            severity=Severity.HIGH.value, hash_code=f"{cluster_name}-{i}",
        )
        for i in range(n)
    ]


def _run(monkeypatch, *args):
    monkeypatch.setattr(cmd, "_CHUNK_SIZE", 2)
    seen: list[set[int]] = []
    real = cmd.recompute_batch

    def _spy(findings):
        findings = list(findings)
        seen.append({f.pk for f in findings})
        return real(findings)

    out = io.StringIO()
    with patch.object(cmd, "recompute_batch", side_effect=_spy):
        call_command("recalculate_priorities", *args, stdout=out)
    return seen, out.getvalue()


@pytest.mark.django_db
def test_recomputes_every_finding_in_bounded_chunks(monkeypatch):
    findings = _findings("a", 5)

    seen, out = _run(monkeypatch)

    assert [len(s) for s in seen] == [2, 2, 1]
    assert set().union(*seen) == {f.pk for f in findings}
    assert "scanned=5" in out


@pytest.mark.django_db
def test_cluster_filter_limits_scope(monkeypatch):
    a = _findings("a", 3)
    _findings("b", 2)

    seen, out = _run(monkeypatch, "--cluster", "a")

    assert set().union(*seen) == {f.pk for f in a}
    assert "scanned=3" in out


@pytest.mark.django_db
def test_no_findings_makes_no_calls(monkeypatch):
    seen, out = _run(monkeypatch)

    assert seen == []
    assert "scanned=0 updated=0" in out
