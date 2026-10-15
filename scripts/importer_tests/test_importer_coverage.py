import json

import pytest
from kubeposture_importer import IMPORTER_VERSION
from kubeposture_importer.coverage import (
    ENV_THRESHOLD,
    compute_coverage,
    log_lines,
    manifest_extra,
    read_threshold,
)
from kubeposture_importer.relevance import FilterStats
from kubeposture_importer.snapshot_index import SnapshotIndex

VULN = "trivy.VulnerabilityReport"
CONFIG = "trivy.ConfigAuditReport"
KYVERNO = "kyverno.PolicyReport"


def _idx(digests: int, controllers: int) -> SnapshotIndex:
    idx = SnapshotIndex()
    idx.deployed_digests = {f"sha256:{i:064x}" for i in range(digests)}
    idx.controllers = {("ns", "Deployment", f"d{i}") for i in range(controllers)}
    return idx


def _stats(kind: str, *, digests: int = 0, subjects: int = 0) -> FilterStats:
    s = FilterStats(kind=kind)
    s.matched_digests = {f"sha256:{i:064x}" for i in range(digests)}
    s.resolved_subjects = {("ns", "Deployment", f"d{i}") for i in range(subjects)}
    return s


def test_image_kind_expected_is_distinct_deployed_digests_and_matched_is_distinct_digests():
    cov = compute_coverage(VULN, _stats(VULN, digests=9), _idx(10, 3), threshold=0.9)
    assert (cov.expected, cov.matched, cov.ratio, cov.status) == (10, 9, 0.9, "ok")


def test_config_audit_expected_is_top_level_controllers():
    cov = compute_coverage(CONFIG, _stats(CONFIG, subjects=2), _idx(10, 4), threshold=0.9)
    assert (cov.expected, cov.matched, cov.ratio, cov.status) == (4, 2, 0.5, "warning")


def test_ratio_one_when_nothing_expected():
    cov = compute_coverage(VULN, _stats(VULN), _idx(0, 0), threshold=0.9)
    assert (cov.ratio, cov.status) == (1.0, "ok")


def test_nothing_matched_is_a_warning_not_a_failure():
    """Zero matches is the strongest signal that the filter or the
    scanner is broken — but still only a warning: the import proceeds."""
    cov = compute_coverage(VULN, _stats(VULN, digests=0), _idx(5, 0), threshold=0.9)
    assert (cov.ratio, cov.status) == (0.0, "warning")


def test_kyverno_is_informational():
    cov = compute_coverage(KYVERNO, _stats(KYVERNO, subjects=1), _idx(0, 10), threshold=0.9)
    assert (cov.status, cov.expected, cov.matched, cov.threshold) == ("info", 10, 1, None)
    assert cov.manifest_coverage() == {"expected": 10, "matched": 1}, "numbers still reported"


def test_cluster_level_and_inventory_have_no_coverage():
    for kind in ("trivy.RbacAssessmentReport", "kyverno.ClusterPolicyReport", "inventory"):
        cov = compute_coverage(kind, _stats(kind), _idx(1, 1), threshold=0.9)
        assert cov.status == "n/a" and cov.manifest_coverage() is None


def test_threshold_env_parsing():
    warnings = []
    assert read_threshold({}) == 0.9
    assert read_threshold({ENV_THRESHOLD: "0.75"}) == 0.75
    assert read_threshold({ENV_THRESHOLD: "abc"}, warn=warnings.append) == 0.9
    assert read_threshold({ENV_THRESHOLD: "1.5"}, warn=warnings.append) == 0.9
    assert len(warnings) == 2


def test_log_lines_levels():
    stats = _stats(VULN, digests=1)
    stats.total, stats.kept, stats.dropped_image_not_deployed = 3, 1, 2
    cov = compute_coverage(VULN, stats, _idx(10, 0), threshold=0.9)
    lines = log_lines(stats, cov)
    assert lines[0] == ("INFO", "filter kind=trivy.VulnerabilityReport total=3 kept=1 "
                                "dropped_no_subject=0 dropped_image_not_deployed=2")
    assert lines[1][0] == "WARNING"
    assert "ratio=0.10 threshold=0.90 status=warning" in lines[1][1]
    info = log_lines(_stats(KYVERNO, subjects=1), compute_coverage(KYVERNO, _stats(KYVERNO, subjects=1), _idx(0, 10), threshold=0.9))
    assert info[1][0] == "INFO" and "threshold=- status=info" in info[1][1]


@pytest.mark.parametrize("relevance", [True, False])
def test_manifest_extra_is_small_json(relevance):
    stats = _stats(VULN, digests=1)
    extra = manifest_extra(stats, relevance_filter=relevance)
    assert extra["importer_version"] == IMPORTER_VERSION
    assert extra["relevance_filter"] is relevance
    assert extra["filter"] == stats.as_dict()
    assert len(json.dumps(extra)) < 400
    assert "filter" not in manifest_extra(None, relevance_filter=relevance)
