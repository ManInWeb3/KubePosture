"""Scan-coverage check — "does every deployed thing have a report?"

Record + alert only: a ratio below the threshold prints a WARNING and
is sent to the server in the bundle manifest (which stores it and
exposes a gauge), but the import still proceeds. Trivy lags new pods by
minutes and some images are never scannable; aborting on a mismatch
would leave a cluster unimported until someone intervened.

Kyverno coverage depends on policy scope and background-scan settings
too much for a threshold to mean anything, so it is reported as
informational.
"""
from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass

from . import IMPORTER_VERSION
from .kinds import IMAGE_KINDS
from .relevance import FilterStats
from .snapshot_index import SnapshotIndex

DEFAULT_THRESHOLD = 0.9
ENV_THRESHOLD = "KUBEPOSTURE_COVERAGE_MIN_RATIO"
_INFO_ONLY_KINDS = frozenset({"kyverno.PolicyReport"})


@dataclass(frozen=True)
class CoverageResult:
    kind: str
    expected: int | None
    matched: int | None
    ratio: float | None
    threshold: float | None
    status: str  # "ok" | "warning" | "info" | "n/a"

    def manifest_coverage(self) -> dict | None:
        if self.expected is None or self.matched is None:
            return None
        return {"expected": self.expected, "matched": self.matched}


def read_threshold(env: Mapping[str, str], *, warn=None) -> float:
    raw = env.get(ENV_THRESHOLD)
    if raw is None or raw.strip() == "":
        return DEFAULT_THRESHOLD
    try:
        value = float(raw)
    except ValueError:
        value = -1.0
    if not 0.0 <= value <= 1.0:
        if warn:
            warn(f"{ENV_THRESHOLD}={raw!r} is not a ratio in [0, 1]; using {DEFAULT_THRESHOLD}")
        return DEFAULT_THRESHOLD
    return value


def compute_coverage(kind: str, stats: FilterStats, idx: SnapshotIndex, *, threshold: float) -> CoverageResult:
    if kind in IMAGE_KINDS:
        expected = len(idx.deployed_digests)
        matched = len(stats.matched_digests)
    elif kind in ("trivy.ConfigAuditReport", "kyverno.PolicyReport"):
        expected = len(idx.controllers)
        matched = len(stats.resolved_subjects)
    else:
        return CoverageResult(kind, None, None, None, None, "n/a")

    ratio = 1.0 if expected == 0 else matched / expected
    if kind in _INFO_ONLY_KINDS:
        return CoverageResult(kind, expected, matched, ratio, None, "info")
    status = "warning" if ratio < threshold else "ok"
    return CoverageResult(kind, expected, matched, ratio, threshold, status)


def log_lines(stats: FilterStats, cov: CoverageResult) -> list[tuple[str, str]]:
    """(level, line) pairs — INFO lines go to stdout, WARNING to stderr."""
    lines = [(
        "INFO",
        f"filter kind={stats.kind} total={stats.total} kept={stats.kept} "
        f"dropped_no_subject={stats.dropped_no_subject} "
        f"dropped_image_not_deployed={stats.dropped_image_not_deployed}",
    )]
    if cov.status != "n/a":
        level = "WARNING" if cov.status == "warning" else "INFO"
        threshold = "-" if cov.threshold is None else f"{cov.threshold:.2f}"
        lines.append((
            level,
            f"coverage kind={cov.kind} expected={cov.expected} matched={cov.matched} "
            f"ratio={cov.ratio:.2f} threshold={threshold} status={cov.status}",
        ))
    return lines


def manifest_extra(stats: FilterStats | None, *, relevance_filter: bool) -> dict:
    extra: dict = {"importer_version": IMPORTER_VERSION, "relevance_filter": relevance_filter}
    if stats is not None:
        extra["filter"] = stats.as_dict()
    return extra
