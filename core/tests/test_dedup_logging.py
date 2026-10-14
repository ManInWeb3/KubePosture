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

import pytest

from core.constants import Category, Severity, Source
from core.models import Cluster, Finding
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
