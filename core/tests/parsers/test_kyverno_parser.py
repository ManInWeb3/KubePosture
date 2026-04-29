"""Unit tests for core.parsers.kyverno.

Pure-function tests: no DB, no Django setup beyond the constants
module. Each test exercises `parse_policy_report` against a synthetic
PolicyReport / ClusterPolicyReport CRD.
"""
from __future__ import annotations

from core.constants import Category, Severity, Source
from core.parsers import kyverno


def _policy_report(*, namespace: str = "platform", results: list[dict] | None = None, scope: dict | None = None) -> dict:
    return {
        "apiVersion": "wgpolicyk8s.io/v1alpha2",
        "kind": "PolicyReport",
        "metadata": {"namespace": namespace, "name": "polr-x"},
        "scope": scope or {},
        "results": results or [],
    }


def _cluster_policy_report(*, results: list[dict] | None = None) -> dict:
    return {
        "apiVersion": "wgpolicyk8s.io/v1alpha2",
        "kind": "ClusterPolicyReport",
        "metadata": {"name": "cpolr-x"},
        "results": results or [],
    }


def _result(
    *,
    policy: str = "disallow-host-namespaces",
    rule: str = "host-namespaces",
    result: str = "fail",
    severity: str = "high",
    subject_kind: str = "Pod",
    subject_name: str = "log-collector-x1",
    subject_namespace: str = "platform",
) -> dict:
    return {
        "policy": policy,
        "rule": rule,
        "result": result,
        "severity": severity,
        "message": f"Workload {subject_name} violates {rule}",
        "subjects": [
            {"kind": subject_kind, "name": subject_name, "namespace": subject_namespace}
        ],
    }


# ── Tests ─────────────────────────────────────────────────────────


def test_pass_result_skipped_no_finding_emitted():
    obj = _policy_report(results=[_result(result="pass")])
    parsed = kyverno.parse_policy_report(obj)
    assert parsed["results"] == []


def test_fail_result_creates_finding_and_signal():
    obj = _policy_report(results=[_result(result="fail")])
    parsed = kyverno.parse_policy_report(obj)
    assert len(parsed["results"]) == 1
    out = parsed["results"][0]
    assert out["finding"] is not None
    assert out["finding"]["source"] == Source.KYVERNO.value
    assert out["finding"]["category"] == Category.POLICY.value
    assert out["finding"]["vuln_id"] == "disallow-host-namespaces"


def test_error_and_warn_results_treated_as_failures():
    obj = _policy_report(results=[
        _result(result="error", policy="error-policy"),
        _result(result="warn", policy="warn-policy"),
    ])
    parsed = kyverno.parse_policy_report(obj)
    policies = sorted(r["finding"]["vuln_id"] for r in parsed["results"])
    assert policies == ["error-policy", "warn-policy"]


def test_severity_normalisation():
    obj = _policy_report(results=[
        _result(severity="critical", policy="p1"),
        _result(severity="high", policy="p2"),
        _result(severity="medium", policy="p3"),
        _result(severity="low", policy="p4"),
        _result(severity="info", policy="p5"),
    ])
    parsed = kyverno.parse_policy_report(obj)
    sev_by_policy = {r["finding"]["vuln_id"]: r["finding"]["severity"] for r in parsed["results"]}
    assert sev_by_policy["p1"] == Severity.CRITICAL.value
    assert sev_by_policy["p2"] == Severity.HIGH.value
    assert sev_by_policy["p3"] == Severity.MEDIUM.value
    assert sev_by_policy["p4"] == Severity.LOW.value
    assert sev_by_policy["p5"] == Severity.INFO.value


def test_unknown_severity_defaults_to_medium():
    obj = _policy_report(results=[_result(severity="bogus", policy="p1")])
    parsed = kyverno.parse_policy_report(obj)
    assert parsed["results"][0]["finding"]["severity"] == Severity.MEDIUM.value


def test_pod_subject_carried_through_for_alias_resolution():
    """Subject (kind, name) is preserved for downstream alias resolution
    to a top-level workload."""
    obj = _policy_report(results=[_result(subject_kind="Pod", subject_name="log-collector-aaa11")])
    parsed = kyverno.parse_policy_report(obj)
    assert parsed["results"][0]["subject"] == ("Pod", "log-collector-aaa11")
    assert parsed["results"][0]["namespace_for_subject"] == "platform"


def test_multiple_subjects_yield_one_result_per_subject():
    """A single result with N subjects produces N output rows."""
    obj = _policy_report(results=[
        {
            "policy": "p1",
            "rule": "r1",
            "result": "fail",
            "severity": "high",
            "subjects": [
                {"kind": "Pod", "name": "pod-a", "namespace": "platform"},
                {"kind": "Pod", "name": "pod-b", "namespace": "platform"},
            ],
        }
    ])
    parsed = kyverno.parse_policy_report(obj)
    assert len(parsed["results"]) == 2
    names = sorted(r["subject"][1] for r in parsed["results"])
    assert names == ["pod-a", "pod-b"]


def test_no_subjects_falls_back_to_scope():
    """Result without subjects[] uses the report-level scope block."""
    obj = _policy_report(
        scope={"kind": "Deployment", "name": "log-collector"},
        results=[
            {"policy": "p1", "rule": "r1", "result": "fail", "severity": "high"}
        ],
    )
    parsed = kyverno.parse_policy_report(obj)
    assert len(parsed["results"]) == 1
    assert parsed["results"][0]["subject"] == ("Deployment", "log-collector")


def test_resources_field_used_when_subjects_absent():
    """Some Kyverno versions emit `resources[]` instead of `subjects[]`."""
    obj = _policy_report(results=[
        {
            "policy": "p1",
            "rule": "r1",
            "result": "fail",
            "severity": "high",
            "resources": [
                {"kind": "Deployment", "name": "x", "namespace": "platform"}
            ],
        }
    ])
    parsed = kyverno.parse_policy_report(obj)
    assert parsed["results"][0]["subject"] == ("Deployment", "x")


def test_clusterpolicyreport_kind_distinguished():
    obj = _cluster_policy_report(results=[
        {"policy": "p1", "rule": "r1", "result": "fail", "severity": "high",
         "subjects": [{"kind": "ClusterRole", "name": "admin"}]}
    ])
    parsed = kyverno.parse_policy_report(obj)
    assert parsed["kind"] == "kyverno.ClusterPolicyReport"


def test_empty_results_list_yields_empty_output():
    obj = _policy_report(results=[])
    parsed = kyverno.parse_policy_report(obj)
    assert parsed["results"] == []
    assert parsed["namespace"] == "platform"


def test_finding_carries_rule_and_message_in_details():
    obj = _policy_report(results=[
        _result(rule="host-namespaces", policy="disallow-host-namespaces")
    ])
    parsed = kyverno.parse_policy_report(obj)
    details = parsed["results"][0]["finding"]["details"]
    assert details["rule"] == "host-namespaces"
    assert "violates" in details["message"]
    assert details["result"] == "fail"
