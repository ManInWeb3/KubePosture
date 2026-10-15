"""Every management command logs its peak RSS and wall time on exit —
the number the chart's memory requests are sized from."""
from __future__ import annotations

import io
import logging
from pathlib import Path

import pytest
from django.core.management import call_command

from core.management import base

COMMANDS_DIR = Path(__file__).resolve().parents[1] / "management/commands"


def _finished_records(caplog, run):
    logger = logging.getLogger("core.management")
    logger.addHandler(caplog.handler)
    try:
        with caplog.at_level(logging.INFO, logger="core.management"):
            run()
    finally:
        logger.removeHandler(caplog.handler)
    return [r for r in caplog.records if r.msg.startswith("command.finished")]


@pytest.mark.django_db
def test_command_logs_peak_rss_and_elapsed_on_success(caplog):
    records = _finished_records(caplog, lambda: call_command("reap_safety_net", stdout=io.StringIO()))
    assert len(records) == 1
    line = records[0].getMessage()
    assert "name=reap_safety_net" in line and "rc=0" in line
    peak = float(line.split("peak_rss_mb=")[1].split()[0])
    assert peak > 1, "a Django process is never under 1 MB resident"


@pytest.mark.django_db
def test_command_logs_rc_1_when_handle_raises(caplog):
    class Boom(Exception):
        pass

    class Cmd(base.KubePostureCommand):
        def handle(self, *a, **kw):
            raise Boom()

    def run():
        with pytest.raises(Boom):
            Cmd().execute(no_color=True, force_color=False, skip_checks=True)

    records = _finished_records(caplog, run)
    assert len(records) == 1 and "rc=1" in records[0].getMessage()


def test_every_command_uses_the_shared_base():
    for path in sorted(COMMANDS_DIR.glob("*.py")):
        if path.name == "__init__.py":
            continue
        text = path.read_text()
        assert "class Command(KubePostureCommand)" in text, path.name
        assert "import BaseCommand" not in text, path.name


def test_peak_rss_is_bytes_on_both_platforms():
    assert base.peak_rss_bytes() > 1024 * 1024
