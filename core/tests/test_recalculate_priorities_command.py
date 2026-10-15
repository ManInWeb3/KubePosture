"""Priority recompute must run in bounded chunks: whole-table / whole-cluster
loads OOMKilled the recalculate CronJob and the queue workers' reaper."""
from __future__ import annotations

import io
from unittest.mock import patch

import pytest
from django.core.management import call_command

from core import urgency
from core.constants import Environment, Severity
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


@pytest.fixture
def chunks(monkeypatch):
    """Chunk size 2; records the pk set of every chunk actually loaded."""
    monkeypatch.setattr(urgency, "RECOMPUTE_CHUNK_SIZE", 2)
    seen: list[set[int]] = []
    real = urgency._recompute_chunk

    def _spy(pks):
        seen.append(set(pks))
        return real(pks)

    with patch.object(urgency, "_recompute_chunk", side_effect=_spy):
        yield seen


@pytest.mark.django_db
def test_recompute_ids_chunks_and_covers_every_id(chunks):
    findings = _findings("a", 5)

    urgency.recompute_ids(f.pk for f in findings)

    assert [len(c) for c in chunks] == [2, 2, 1]
    assert set().union(*chunks) == {f.pk for f in findings}


@pytest.mark.django_db
def test_recompute_batch_delegates_to_chunks(chunks):
    findings = _findings("a", 3)

    urgency.recompute_batch(findings)

    assert [len(c) for c in chunks] == [2, 1]


@pytest.mark.django_db
def test_recompute_ids_empty_makes_no_calls(chunks):
    assert urgency.recompute_ids([]) == 0
    assert chunks == []


@pytest.mark.django_db
def test_command_recomputes_every_finding(chunks):
    findings = _findings("a", 5)
    out = io.StringIO()

    call_command("recalculate_priorities", stdout=out)

    assert set().union(*chunks) == {f.pk for f in findings}
    assert "scanned=5" in out.getvalue()


@pytest.mark.django_db
def test_command_cluster_filter_limits_scope(chunks):
    a = _findings("a", 3)
    _findings("b", 2)
    out = io.StringIO()

    call_command("recalculate_priorities", "--cluster", "a", stdout=out)

    assert set().union(*chunks) == {f.pk for f in a}
    assert "scanned=3" in out.getvalue()
