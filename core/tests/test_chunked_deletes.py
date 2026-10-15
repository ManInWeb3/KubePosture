"""`Finding` has an incoming CASCADE FK (`FindingAction.finding`), so a
plain `qs.delete()` materialises every matching Finding in Python before
deleting. Cluster removal (a web request) and the findings prune now
delete in pk slices instead."""
from __future__ import annotations

import pytest
from django.utils import timezone

from core.constants import Environment, FindingActionType, Severity
from core.models import Cluster, Finding, FindingAction, Namespace, Workload
from core.services import pruning
from core.services.cluster_removal import remove_cluster
from core.services.pruning import delete_in_chunks, prune_stale_findings


def _cluster_with_findings(n: int, *, name: str = "c-chunks") -> tuple[Cluster, list[Finding]]:
    c = Cluster.objects.create(name=name, environment=Environment.PROD.value)
    ns = Namespace.objects.create(cluster=c, name="ns")
    w = Workload.objects.create(cluster=c, namespace=ns, kind="Deployment", name="api", deployed=False)
    findings = []
    for i in range(n):
        f = Finding.objects.create(
            cluster=c, workload=w, source="trivy", category="vulnerability",
            vuln_id=f"CVE-2024-{i}", title="t", severity=Severity.HIGH.value, hash_code=f"h{i}",
        )
        FindingAction.objects.create(finding=f, action_type=FindingActionType.ACKNOWLEDGE)
        findings.append(f)
    return c, findings


@pytest.mark.django_db
def test_delete_in_chunks_deletes_every_row_and_sums_cascade_counts(monkeypatch):
    monkeypatch.setattr(pruning, "DELETE_CHUNK_SIZE", 2)
    c, findings = _cluster_with_findings(5)
    chunks = _spy_chunks(monkeypatch)
    counts = delete_in_chunks(Finding.objects.filter(cluster=c))

    assert chunks == [2, 2, 1]
    assert counts == {"core.Finding": 5, "core.FindingAction": 5}
    assert not Finding.objects.filter(cluster=c).exists()


def _spy_chunks(monkeypatch) -> list[int]:
    """Record the size of every pk slice `delete_in_chunks` deletes."""
    chunks: list[int] = []
    real = Finding._base_manager.filter

    def spy(*args, **kwargs):
        if "pk__in" in kwargs:
            chunks.append(len(kwargs["pk__in"]))
        return real(*args, **kwargs)

    monkeypatch.setattr(Finding._base_manager, "filter", spy)
    return chunks


@pytest.mark.django_db
def test_remove_cluster_reports_chunk_deleted_findings_in_its_counts(monkeypatch):
    monkeypatch.setattr(pruning, "DELETE_CHUNK_SIZE", 2)
    c, _ = _cluster_with_findings(3)
    chunks = _spy_chunks(monkeypatch)

    result = remove_cluster(c)

    assert chunks == [2, 1], "cluster removal must go through delete_in_chunks"

    assert result.deleted["core.Finding"] == 3
    assert result.deleted["core.FindingAction"] == 3
    assert result.deleted["core.Cluster"] == 1
    assert not Cluster.objects.filter(name="c-chunks").exists()


@pytest.mark.django_db
def test_prune_stale_findings_deletes_in_chunks(monkeypatch):
    monkeypatch.setattr(pruning, "DELETE_CHUNK_SIZE", 2)
    c, findings = _cluster_with_findings(5)
    Finding.objects.filter(cluster=c).update(last_seen=timezone.now() - timezone.timedelta(days=400))
    chunks = _spy_chunks(monkeypatch)

    result = prune_stale_findings(days=180)

    assert chunks == [2, 2, 1], "the prune must go through delete_in_chunks"
    assert (result.scanned, result.deleted) == (5, 5)
    assert not Finding.objects.filter(cluster=c).exists()


# ── KubePostureCommand rc for SystemExit ──────────────────────────


@pytest.mark.parametrize(("code", "expected_rc"), [(0, 0), (None, 0), (2, 2)])
def test_command_logs_the_sys_exit_code_as_rc(code, expected_rc):
    """`sys.exit(0)` is a success (search_sbom uses it for "found"); the
    peak-RSS line the chart sizing reads used to log it as rc=1."""
    from unittest.mock import patch

    from core.management import base

    class Cmd(base.KubePostureCommand):
        def handle(self, *args, **options):
            raise SystemExit(code)

    with patch.object(base, "log") as log, pytest.raises(SystemExit):
        Cmd().execute(no_color=True, force_color=False, skip_checks=True)
    assert log.info.call_args.args[-1] == expected_rc
