import copy

import pytest
from kubeposture_importer.kinds import CLUSTER_LEVEL_KINDS
from kubeposture_importer.relevance import apply_relevance_filter, filter_kind
from kubeposture_importer.snapshot_index import build_index

from .fixtures_builders import (
    SHA_A,
    SHA_B,
    SHA_OLD,
    by_kind,
    cronjob,
    deployment_chain,
    job,
    kyverno_result,
    pod,
    policy_report,
    replicaset,
    subject,
    trivy_report,
)

VULN = "trivy.VulnerabilityReport"
SBOM = "trivy.SbomReport"
SECRET = "trivy.ExposedSecretReport"
CONFIG = "trivy.ConfigAuditReport"
KYVERNO = "kyverno.PolicyReport"


@pytest.fixture
def idx():
    return build_index(by_kind(
        *deployment_chain("api", digest=SHA_A),
        replicaset("api-old", owner_name="api", image=f"r/app:0@{SHA_OLD}", replicas=0),
        cronjob("nightly", image="r/cron:1"),
    ))


def test_vuln_report_kept_when_digest_deployed(idx):
    kept, stats = filter_kind(VULN, [trivy_report("VulnerabilityReport", digest=SHA_A)], idx, enabled=True)
    assert len(kept) == 1
    assert (stats.total, stats.kept, stats.dropped_image_not_deployed) == (1, 1, 0)
    assert stats.matched_digests == {SHA_A}


def test_vuln_report_dropped_when_digest_not_deployed(idx):
    kept, stats = filter_kind(VULN, [trivy_report("VulnerabilityReport", digest=SHA_B)], idx, enabled=True)
    assert kept == []
    assert stats.dropped_image_not_deployed == 1
    assert stats.unmatched_digests == {SHA_B}


def test_sbom_for_replicaset_history_image_dropped(idx):
    old = trivy_report("SbomReport", subject_name="api-old", digest=SHA_OLD)
    live = trivy_report("SbomReport", subject_name="api-abc", digest=SHA_A)
    kept, stats = filter_kind(SBOM, [old, live], idx, enabled=True)
    assert kept == [live]
    assert stats.as_dict() == {"total": 2, "kept": 1, "dropped_no_subject": 0, "dropped_image_not_deployed": 1}


def test_cronjob_unpinned_image_without_pods_sbom_dropped_but_kept_with_running_job_pod():
    base = [cronjob("nightly", image="r/cron:1")]
    report = trivy_report("SbomReport", subject_kind="CronJob", subject_name="nightly", digest=SHA_B)
    kept, _ = filter_kind(SBOM, [report], build_index(by_kind(*base)), enabled=True)
    assert kept == []

    with_pod = base + [
        job("nightly-1", owner_ref={"apiVersion": "batch/v1", "kind": "CronJob", "name": "nightly", "controller": True}),
        pod("nightly-1-p", owner_ref={"apiVersion": "batch/v1", "kind": "Job", "name": "nightly-1", "controller": True},
            image="r/cron:1", digest=SHA_B),
    ]
    kept, _ = filter_kind(SBOM, [report], build_index(by_kind(*with_pod)), enabled=True)
    assert kept == [report]


def test_exposed_secret_follows_digest_rule_and_missing_digest_drops(idx):
    kept, stats = filter_kind(SECRET, [
        trivy_report("ExposedSecretReport", digest=SHA_A),
        trivy_report("ExposedSecretReport", digest=None),
    ], idx, enabled=True)
    assert len(kept) == 1
    assert stats.dropped_image_not_deployed == 1
    assert stats.unmatched_digests == set(), "a report with no digest at all is not an 'unmatched digest'"


def test_digest_match_normalises_case(idx):
    report = trivy_report("VulnerabilityReport", digest="SHA256:" + "A" * 64)
    kept, _ = filter_kind(VULN, [report], idx, enabled=True)
    assert kept == [report]


def test_config_audit_subject_resolution(idx):
    via_rs = trivy_report("ConfigAuditReport", subject_kind="ReplicaSet", subject_name="api-abc", digest=None)
    via_old_rs = trivy_report("ConfigAuditReport", subject_kind="ReplicaSet", subject_name="api-old", digest=None)
    service = trivy_report("ConfigAuditReport", subject_kind="Service", subject_name="api", digest=None)
    kept, stats = filter_kind(CONFIG, [via_rs, via_old_rs, service], idx, enabled=True)
    # api-old's RS is in the snapshot and owned by the live Deployment → resolves (harmless duplicate).
    assert kept == [via_rs, via_old_rs]
    assert stats.dropped_no_subject == 1
    assert stats.resolved_subjects == {("ns", "Deployment", "api")}


def test_config_audit_for_standalone_pod_kept():
    idx = build_index(by_kind(pod("standalone")))
    report = trivy_report("ConfigAuditReport", subject_kind="Pod", subject_name="standalone", digest=None)
    kept, _ = filter_kind(CONFIG, [report], idx, enabled=True)
    assert kept == [report]


def test_policy_report_kept_when_any_subject_resolves(idx):
    report = policy_report(results=[
        kyverno_result(subjects=[subject("ConfigMap", "cm")]),
        kyverno_result(subjects=[subject("Pod", "api-abc-x1")]),
    ])
    kept, stats = filter_kind(KYVERNO, [report], idx, enabled=True)
    assert kept == [report]
    assert stats.resolved_subjects == {("ns", "Deployment", "api")}


def test_policy_report_scope_fallback_and_resources_key(idx):
    scoped = policy_report(results=[kyverno_result()], scope=subject("Pod", "api-abc-x1"))
    via_resources = policy_report(results=[kyverno_result(resources=[subject("ReplicaSet", "api-abc", ns=None)])])
    kept, _ = filter_kind(KYVERNO, [scoped, via_resources], idx, enabled=True)
    assert kept == [scoped, via_resources]


def test_policy_report_only_non_workload_subjects_dropped(idx):
    report = policy_report(results=[kyverno_result(subjects=[subject("ConfigMap", "cm"), subject("Role", "r")])])
    kept, stats = filter_kind(KYVERNO, [report], idx, enabled=True)
    assert kept == [] and stats.dropped_no_subject == 1


def test_pass_only_policy_report_is_kept(idx):
    """The server reap clears stale Kyverno signals only when
    observed_count > 0; dropping pass-only reports would push the count
    to 0 and leave cleared-in-cluster signals active forever."""
    report = policy_report(results=[kyverno_result(result="pass", subjects=[subject("Pod", "api-abc-x1")])])
    kept, _ = filter_kind(KYVERNO, [report], idx, enabled=True)
    assert kept == [report]


@pytest.mark.parametrize("kind", sorted(CLUSTER_LEVEL_KINDS))
def test_cluster_level_kinds_always_kept(idx, kind):
    items = [{"kind": "X", "metadata": {"name": "a"}}, {"kind": "X", "metadata": {"name": "b"}}]
    kept, stats = filter_kind(kind, items, idx, enabled=True)
    assert kept == items
    assert stats.as_dict() == {"total": 2, "kept": 2, "dropped_no_subject": 0, "dropped_image_not_deployed": 0}


def test_disabled_filter_keeps_everything_but_still_computes_stats(idx):
    items = [trivy_report("VulnerabilityReport", digest=SHA_A), trivy_report("VulnerabilityReport", digest=SHA_B)]
    kept, stats = filter_kind(VULN, items, idx, enabled=False)
    assert kept == items
    assert (stats.kept, stats.dropped_image_not_deployed) == (1, 1)
    assert stats.matched_digests == {SHA_A}


def test_stats_components_sum_to_total_and_items_not_mutated(idx):
    scan_items = {
        VULN: [trivy_report("VulnerabilityReport", digest=SHA_A), trivy_report("VulnerabilityReport", digest=SHA_B)],
        CONFIG: [trivy_report("ConfigAuditReport", subject_kind="Service", subject_name="s", digest=None)],
        KYVERNO: [policy_report(results=[kyverno_result(subjects=[subject("Pod", "api-abc-x1")])])],
        "trivy.RbacAssessmentReport": [{"kind": "RbacAssessmentReport", "metadata": {"name": "r"}}],
    }
    snapshot = copy.deepcopy(scan_items)
    filtered, stats = apply_relevance_filter(scan_items, idx, enabled=True)
    assert scan_items == snapshot
    for kind, s in stats.items():
        assert s.total == s.kept + s.dropped_no_subject + s.dropped_image_not_deployed
        assert len(filtered[kind]) == s.kept
    assert {k: len(v) for k, v in filtered.items()} == {VULN: 1, CONFIG: 0, KYVERNO: 1, "trivy.RbacAssessmentReport": 1}
