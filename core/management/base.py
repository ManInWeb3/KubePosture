"""Shared base for KubePosture management commands.

Every batch job (CronJob / one-shot Job) runs through `execute()` here,
which appends one log line with the process's **peak** RSS and wall
time. Memory requests in the chart are set from these lines, not from
guesses: an OOM-killed pod leaves no trace of how much it actually
needed, while a surviving one reports it every run.

    INFO core.management command.finished name=enrich_fetch peak_rss_mb=41.2 elapsed_s=38.4 rc=0
"""
from __future__ import annotations

import logging
import resource
import sys
import time

from django.core.management.base import BaseCommand

log = logging.getLogger("core.management")


def peak_rss_bytes() -> int:
    """Process high-water-mark RSS. `ru_maxrss` is KiB on Linux, bytes on
    macOS (the only two platforms this runs on)."""
    rss = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    return rss if sys.platform == "darwin" else rss * 1024


class KubePostureCommand(BaseCommand):
    """`BaseCommand` that logs peak RSS and elapsed time when it finishes,
    whether `handle()` returned or raised."""

    def execute(self, *args, **options):
        started = time.monotonic()
        rc = 0
        try:
            return super().execute(*args, **options)
        except BaseException:
            rc = 1
            raise
        finally:
            log.info(
                "command.finished name=%s peak_rss_mb=%.1f elapsed_s=%.1f rc=%d",
                self.__class__.__module__.rsplit(".", 1)[-1],
                peak_rss_bytes() / (1024 * 1024),
                time.monotonic() - started,
                rc,
            )
