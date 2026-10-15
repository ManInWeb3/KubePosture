"""Regression: the DEBUG progress breadcrumb in `upsert_findings` used
`extra={"created": ...}`, which collides with `LogRecord.created` and makes
`logging` raise KeyError("Attempt to overwrite 'created' in LogRecord").
It's raised inside the function's transaction, so every item with >= 250
findings (heavily-vulnerable images) failed outright whenever DEBUG
logging was enabled for `core` — the highest-value reports were the ones
silently dropped.
"""
from __future__ import annotations

import ast
import logging
from pathlib import Path
from unittest.mock import MagicMock

import pytest
from django.utils import timezone

from core.constants import Category, Severity, Source
from core.models import Cluster, Finding, Namespace, Workload
from core.services import dedup

CORE_DIR = Path(__file__).resolve().parents[1]

# Every attribute a LogRecord already has (plus the two keys the
# formatter adds) — none may appear as a key in `extra=`.
_RESERVED = set(vars(logging.makeLogRecord({}))) | {"message", "asctime"}


def _finding(i: int) -> dict:
    return {
        "source": Source.TRIVY.value,
        "category": Category.VULNERABILITY.value,
        "vuln_id": f"CVE-2024-{i:05d}",
        "pkg_name": "pkgx",
        "installed_version": "1.0",
        "title": f"finding {i}",
        "severity": Severity.HIGH.value,
    }


@pytest.mark.django_db
def test_upsert_findings_progress_log_does_not_break_at_debug(caplog):
    from django.utils import timezone

    cluster = Cluster.objects.create(name="c-dedup-logging")
    n = dedup._PROGRESS_LOG_EVERY * 2 + 1  # crosses the breadcrumb twice

    # settings.LOGGING gives the `core` logger propagate=False, so caplog's
    # root handler never sees these records — attach it directly.
    dedup_logger = logging.getLogger("core.dedup")
    dedup_logger.addHandler(caplog.handler)
    try:
        with caplog.at_level(logging.DEBUG, logger="core.dedup"):
            created, updated = dedup.upsert_findings(
                cluster=cluster,
                workload=None,
                image=None,
                findings=[_finding(i) for i in range(n)],
                observation_time=timezone.now(),
            )
    finally:
        dedup_logger.removeHandler(caplog.handler)

    assert (created, updated) == (n, 0)
    assert Finding.objects.filter(cluster=cluster).count() == n
    progress = [r for r in caplog.records if r.msg == "dedup.upsert_findings.progress"]
    assert len(progress) == 2
    assert progress[-1].findings_created == dedup._PROGRESS_LOG_EVERY * 2


def test_no_log_extra_key_shadows_a_logrecord_attribute():
    """DB-free guard for the whole bug class: scan every `extra={...}`
    literal under core/ for keys that collide with LogRecord attributes.
    Such a call only blows up when its level is enabled, so it can sit
    unnoticed until someone turns DEBUG on in production.
    """
    offenders = []
    for path in CORE_DIR.rglob("*.py"):
        if "tests" in path.parts or "migrations" in path.parts:
            continue
        for node in ast.walk(ast.parse(path.read_text())):
            if not isinstance(node, ast.Call):
                continue
            for kw in node.keywords:
                if kw.arg == "extra" and isinstance(kw.value, ast.Dict):
                    keys = {
                        k.value for k in kw.value.keys if isinstance(k, ast.Constant)
                    }
                    if keys & _RESERVED:
                        offenders.append(
                            f"{path.relative_to(CORE_DIR)}:{node.lineno} "
                            f"{sorted(keys & _RESERVED)}"
                        )
    assert not offenders, f"log extra= keys shadow LogRecord attributes: {offenders}"


# ── create/create race, deterministically ─────────────────────────


def _scene():
    c = Cluster.objects.create(name="c-race", environment="prod")
    ns = Namespace.objects.create(cluster=c, name="ns")
    w = Workload.objects.create(cluster=c, namespace=ns, kind="Deployment", name="api", deployed=True)
    return c, w


@pytest.mark.django_db
def test_upsert_retries_once_when_a_concurrent_insert_wins_the_race(monkeypatch):
    """The 8-thread race in test_concurrency.py reaches this branch only by
    luck. Simulate the loser: the first SELECT FOR UPDATE sees nothing, the
    INSERT then collides with a row another transaction committed, and the
    retry must update that row instead of failing the whole queue item."""

    from core.services import dedup

    c, w = _scene()
    f = {"source": "trivy", "category": "vulnerability", "vuln_id": "CVE-1", "pkg_name": "p",
         "installed_version": "1", "fixed_version": "", "title": "t", "severity": "high",
         "cvss_score": None, "cvss_vector": "", "details": {}}
    hc = dedup.compute_hash(source="trivy", category="vulnerability", vuln_id="CVE-1", workload_id=w.id,
                            cluster_name=c.name, image_digest="", pkg_name="p", installed_version="1")
    real_sfu = dedup.Finding.objects.select_for_update
    calls = {"n": 0}

    def flaky_select_for_update(*a, **kw):
        calls["n"] += 1
        if calls["n"] == 1:
            # Attempt 1: nothing visible yet; the other transaction then wins the INSERT.
            qs = MagicMock()
            qs.filter.return_value.first.side_effect = lambda: (
                dedup.Finding.objects.create(cluster=c, workload=w, source="trivy", hash_code=hc,
                                             category="vulnerability", vuln_id="CVE-1", title="other",
                                             severity="high", first_seen=timezone.now(), last_seen=timezone.now())
                and None)
            return qs
        return real_sfu(*a, **kw)

    monkeypatch.setattr(dedup.Finding.objects, "select_for_update", flaky_select_for_update)
    created, updated = dedup.upsert_findings(cluster=c, workload=w, image=None, findings=[f],
                                             observation_time=timezone.now())

    assert (created, updated) == (0, 1)
    assert dedup.Finding.objects.filter(hash_code=hc).count() == 1
    assert dedup.Finding.objects.get(hash_code=hc).title == "t", "the retry updated the winner's row"


@pytest.mark.django_db
def test_upsert_propagates_a_second_consecutive_integrity_error(monkeypatch):
    from django.db import IntegrityError

    from core.services import dedup

    c, w = _scene()
    f = {"source": "trivy", "category": "vulnerability", "vuln_id": "CVE-2", "pkg_name": "p",
         "installed_version": "1", "fixed_version": "", "title": "t", "severity": "high",
         "cvss_score": None, "cvss_vector": "", "details": {}}
    never = MagicMock()
    never.filter.return_value.first.return_value = None
    monkeypatch.setattr(dedup.Finding.objects, "select_for_update", lambda *a, **kw: never)
    monkeypatch.setattr(dedup.Finding, "save", lambda self, *a, **kw: (_ for _ in ()).throw(IntegrityError("dup")))

    with pytest.raises(IntegrityError):
        dedup.upsert_findings(cluster=c, workload=w, image=None, findings=[f], observation_time=timezone.now())
