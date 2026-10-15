"""Unit tests for core.parsers.trivy.

Pure-function tests against in-memory CRD fixtures. Each test
exercises a parser entry point and checks the returned dict shape.
"""
from __future__ import annotations

import pytest

from core.constants import Category, Severity, Source
from core.parsers import trivy

# ── Helpers ──────────────────────────────────────────────────────


def _vuln_report(
    *,
    namespace: str = "payments",
    workload_kind: str = "ReplicaSet",
    workload_name: str = "api-server-7d9f5b6c8d",
    container: str = "app",
    image_repo: str = "payments/api",
    image_tag: str = "v1.2.3",
    image_digest: str = "sha256:" + "a" * 64,
    vulns: list[dict] | None = None,
) -> dict:
    """Build a minimal Trivy VulnerabilityReport CRD."""
    return {
        "apiVersion": "aquasecurity.github.io/v1alpha1",
        "kind": "VulnerabilityReport",
        "metadata": {
            "name": f"{workload_kind.lower()}-{workload_name}-{container}",
            "namespace": namespace,
            "labels": {
                "trivy-operator.resource.namespace": namespace,
                "trivy-operator.resource.kind": workload_kind,
                "trivy-operator.resource.name": workload_name,
                "trivy-operator.container.name": container,
            },
        },
        "report": {
            "scanner": {"name": "Trivy", "vendor": "Aqua Security", "version": "0.52.0"},
            "registry": {"server": "registry.internal"},
            "artifact": {
                "repository": image_repo,
                "tag": image_tag,
                "digest": image_digest,
            },
            "os": {"family": "debian", "name": "12"},
            "vulnerabilities": vulns or [],
        },
    }


def _vuln(vid: str, *, pkg: str = "libc6", severity: str = "CRITICAL", score: float = 9.8) -> dict:
    return {
        "vulnerabilityID": vid,
        "resource": pkg,
        "installedVersion": "1.0",
        "fixedVersion": "1.1",
        "severity": severity,
        "score": score,
        "title": f"Test issue {vid}",
        "primaryLink": f"https://avd.aquasec.com/nvd/{vid.lower()}",
        "links": [],
    }


# ── Tests: parse_vulnerability_report ────────────────────────────


def test_vuln_report_extracts_workload_identity_from_labels():
    obj = _vuln_report(vulns=[_vuln("CVE-2024-1234")])
    parsed = trivy.parse_vulnerability_report(obj)

    assert parsed["kind"] == "trivy.VulnerabilityReport"
    assert parsed["namespace"] == "payments"
    assert parsed["resource_kind"] == "ReplicaSet"
    assert parsed["resource_name"] == "api-server-7d9f5b6c8d"
    assert parsed["container_name"] == "app"


def _long_name_report(obj: dict, *, owner_kind: str = "ReplicaSet", owner_name: str | None = None) -> dict:
    """Shape Trivy emits when the scanned resource's name exceeds the
    63-character label-value limit: no `resource.name` label, only
    `resource.name-hash`, the real name in the report's ownerReferences."""
    name = owner_name or ("a-very-long-deployment-name-" + "x" * 40 + "-7d9f5b6c8d")
    assert len(name) > 63
    labels = obj["metadata"]["labels"]
    del labels["trivy-operator.resource.name"]
    labels["trivy-operator.resource.name-hash"] = "85c5b9fbdd"
    obj["metadata"]["ownerReferences"] = [
        {"apiVersion": "apps/v1", "kind": owner_kind, "name": name, "controller": True,
         "blockOwnerDeletion": False, "uid": "u-1"},
    ]
    return obj


def test_identity_falls_back_to_owner_reference_when_name_label_is_missing():
    """Regression found on real data: Trivy drops the name label for
    names over 63 chars; without the fallback the report resolved to no
    workload and every finding on it was silently dropped."""
    long_name = "a-very-long-deployment-name-" + "x" * 40 + "-7d9f5b6c8d"
    obj = _long_name_report(_vuln_report(vulns=[_vuln("CVE-2024-1234")]), owner_name=long_name)

    parsed = trivy.parse_vulnerability_report(obj)

    assert (parsed["namespace"], parsed["resource_kind"], parsed["resource_name"]) == (
        "payments", "ReplicaSet", long_name,
    )
    assert len(parsed["findings"]) == 1


def test_identity_fallback_ignores_an_owner_of_a_different_kind():
    obj = _long_name_report(_vuln_report(), owner_kind="Pod")
    obj["metadata"]["ownerReferences"][0]["kind"] = "Pod"
    # label kind is ReplicaSet; a Pod owner is not the scanned resource.
    parsed = trivy.parse_vulnerability_report(obj)
    assert parsed["resource_name"] == ""


def test_identity_label_wins_over_owner_reference():
    obj = _vuln_report()
    obj["metadata"]["ownerReferences"] = [
        {"kind": "ReplicaSet", "name": "something-else", "controller": True},
    ]
    assert trivy.parse_vulnerability_report(obj)["resource_name"] == "api-server-7d9f5b6c8d"


def test_identity_fallback_covers_every_per_workload_report_kind():
    for parse, obj in (
        (trivy.parse_vulnerability_report, _vuln_report()),
        (trivy.parse_sbom_report, {**_vuln_report(), "kind": "SbomReport",
                                    "report": {"artifact": _vuln_report()["report"]["artifact"], "components": {}}}),
    ):
        parsed = parse(_long_name_report(obj))
        assert parsed["resource_name"].startswith("a-very-long-deployment-name-")


def test_vuln_report_extracts_image_digest_from_artifact():
    digest = "sha256:" + "b" * 64
    obj = _vuln_report(image_digest=digest, vulns=[_vuln("CVE-2024-1234")])
    parsed = trivy.parse_vulnerability_report(obj)
    assert parsed["image_digest"] == digest
    # Registry lives at `report.registry.server` in the real CRD; the ref
    # must be fully qualified so it matches the inventory's.
    assert parsed["image_ref"] == "registry.internal/payments/api:v1.2.3"


def test_vuln_report_without_registry_block_falls_back_to_repo_tag():
    obj = _vuln_report()
    del obj["report"]["registry"]
    assert trivy.parse_vulnerability_report(obj)["image_ref"] == "payments/api:v1.2.3"


def test_vuln_report_creates_one_finding_per_vulnerability():
    obj = _vuln_report(vulns=[
        _vuln("CVE-2024-1234", pkg="libc6"),
        _vuln("CVE-2024-5678", pkg="openssl", severity="HIGH", score=7.5),
        _vuln("CVE-2023-9999", pkg="zlib1g", severity="MEDIUM", score=5.5),
    ])
    parsed = trivy.parse_vulnerability_report(obj)
    assert len(parsed["findings"]) == 3

    vids = sorted(f["vuln_id"] for f in parsed["findings"])
    assert vids == ["CVE-2023-9999", "CVE-2024-1234", "CVE-2024-5678"]


def test_vuln_report_severity_normalisation():
    """Trivy CRITICAL/HIGH/MEDIUM/LOW/UNKNOWN → core.Severity values."""
    obj = _vuln_report(vulns=[
        _vuln("CVE-1", severity="CRITICAL"),
        _vuln("CVE-2", severity="HIGH"),
        _vuln("CVE-3", severity="MEDIUM"),
        _vuln("CVE-4", severity="LOW"),
        _vuln("CVE-5", severity="UNKNOWN"),
    ])
    parsed = trivy.parse_vulnerability_report(obj)
    sevs = [f["severity"] for f in parsed["findings"]]
    assert Severity.CRITICAL.value in sevs
    assert Severity.HIGH.value in sevs
    assert Severity.MEDIUM.value in sevs
    assert Severity.LOW.value in sevs
    # Unknown maps to UNKNOWN
    assert Severity.UNKNOWN.value in sevs


def test_vuln_report_empty_vulnerabilities_yields_empty_findings():
    obj = _vuln_report(vulns=[])
    parsed = trivy.parse_vulnerability_report(obj)
    assert parsed["findings"] == []
    # Identity still extracted
    assert parsed["resource_name"] == "api-server-7d9f5b6c8d"


def test_vuln_report_pkg_name_distinguishes_findings():
    """Same CVE ID, two packages → two finding dicts. Dedup key (in DB)
    will include pkg_name, so they remain separate Finding rows."""
    obj = _vuln_report(vulns=[
        _vuln("CVE-2024-1234", pkg="libc6"),
        _vuln("CVE-2024-1234", pkg="openssl"),
    ])
    parsed = trivy.parse_vulnerability_report(obj)
    pkgs = sorted(f["pkg_name"] for f in parsed["findings"])
    assert pkgs == ["libc6", "openssl"]


def test_vuln_report_missing_metadata_does_not_crash():
    """A malformed CRD (no labels block) parses to empty identity, not raise."""
    obj = {
        "apiVersion": "aquasecurity.github.io/v1alpha1",
        "kind": "VulnerabilityReport",
        "metadata": {"name": "x"},
        "report": {"vulnerabilities": []},
    }
    parsed = trivy.parse_vulnerability_report(obj)
    assert parsed["resource_kind"] == ""
    assert parsed["resource_name"] == ""
    assert parsed["findings"] == []


# ── Tests: parse_config_audit_report ─────────────────────────────


def _config_audit(*, checks: list[dict] | None = None) -> dict:
    return {
        "apiVersion": "aquasecurity.github.io/v1alpha1",
        "kind": "ConfigAuditReport",
        "metadata": {
            "namespace": "platform",
            "labels": {
                "trivy-operator.resource.namespace": "platform",
                "trivy-operator.resource.kind": "DaemonSet",
                "trivy-operator.resource.name": "log-collector",
            },
        },
        "report": {"checks": checks or []},
    }


def test_config_audit_pass_results_skipped():
    obj = _config_audit(checks=[
        {"checkID": "KSV001", "severity": "MEDIUM", "success": True, "title": "passing"},
        {"checkID": "KSV002", "severity": "HIGH", "success": False, "title": "failing"},
    ])
    parsed = trivy.parse_config_audit_report(obj)
    assert len(parsed["findings"]) == 1
    assert parsed["findings"][0]["vuln_id"].endswith("KSV-0002")


def test_config_audit_normalises_avd_check_id():
    obj = _config_audit(checks=[
        {"checkID": "KSV051", "severity": "HIGH", "success": False, "title": "x"},
    ])
    parsed = trivy.parse_config_audit_report(obj)
    # KSV051 → AVD-KSV-0051
    assert parsed["findings"][0]["vuln_id"] == "AVD-KSV-0051"


def test_config_audit_category_is_config():
    obj = _config_audit(checks=[
        {"checkID": "KSV001", "severity": "HIGH", "success": False, "title": "x"},
    ])
    parsed = trivy.parse_config_audit_report(obj)
    assert parsed["findings"][0]["category"] == Category.CONFIG.value


# ── Tests: parse_exposed_secret_report ───────────────────────────


def test_exposed_secret_report_creates_finding_per_secret():
    obj = {
        "metadata": {
            "labels": {
                "trivy-operator.resource.namespace": "payments",
                "trivy-operator.resource.kind": "Deployment",
                "trivy-operator.resource.name": "api-server",
                "trivy-operator.container.name": "app",
            }
        },
        "report": {
            "artifact": {"repository": "payments/api", "tag": "v1", "digest": "sha256:" + "a" * 64},
            "secrets": [
                {"ruleID": "aws-access-key", "severity": "CRITICAL", "title": "AWS key",
                 "category": "AWS", "match": "AKIA...", "target": "/etc/x"},
                {"ruleID": "github-token", "severity": "HIGH", "title": "GH token",
                 "category": "Git", "match": "ghp_...", "target": "/etc/y"},
            ],
        },
    }
    parsed = trivy.parse_exposed_secret_report(obj)
    assert len(parsed["findings"]) == 2
    rule_ids = sorted(f["vuln_id"] for f in parsed["findings"])
    assert rule_ids == ["aws-access-key", "github-token"]
    # Secret presence triggers a workload signal
    assert "kp:exposed-secret-in-image" in parsed["signal_ids"]


def test_exposed_secret_report_no_secrets_yields_no_signal():
    obj = {
        "metadata": {"labels": {}},
        "report": {"artifact": {}, "secrets": []},
    }
    parsed = trivy.parse_exposed_secret_report(obj)
    assert parsed["findings"] == []
    assert parsed["signal_ids"] == set()


# ── Source attribution ──────────────────────────────────────────


def test_all_findings_carry_source_trivy():
    obj = _vuln_report(vulns=[_vuln("CVE-2024-1234")])
    parsed = trivy.parse_vulnerability_report(obj)
    assert parsed["findings"][0]["source"] == Source.TRIVY.value


# ── RBAC / ClusterRBAC / Infra: production kinds with no tests before ──
#
# These three are in PARSERS_BY_KIND, in the importer's CRD_SOURCES and in
# ImportMark.kind; ingest reads `namespace / resource_kind / resource_name
# / cluster_scoped / findings / signal_ids` from them (core/services/ingest.py).


def _check_report(kind: str, *, resource_kind: str, resource_name: str, namespace: str | None,
                  checks: list[dict]) -> dict:
    labels = {"trivy-operator.resource.kind": resource_kind, "trivy-operator.resource.name": resource_name}
    if namespace is not None:
        labels["trivy-operator.resource.namespace"] = namespace
    return {"apiVersion": "aquasecurity.github.io/v1alpha1", "kind": kind,
            "metadata": {"name": "r", "labels": labels}, "report": {"checks": checks}}


def _trivy_signal_ids():
    """(an RBAC-elevation AVD id, a non-RBAC Trivy AVD id) from the registry."""
    from core.signals import SIGNALS, SignalCategory, SignalSource
    rbac = next(sd for sd in SIGNALS.values()
                if sd.source is SignalSource.TRIVY and sd.category is SignalCategory.RBAC_ELEVATION)
    other = next(sd for sd in SIGNALS.values()
                 if sd.source is SignalSource.TRIVY and sd.category is not SignalCategory.RBAC_ELEVATION)
    return rbac, other


def test_rbac_assessment_report_yields_rbac_findings_and_signals():
    rbac_sd, _ = _trivy_signal_ids()
    avd = rbac_sd.matcher  # e.g. "KSV-0041"
    obj = _check_report("RbacAssessmentReport", resource_kind="Role", resource_name="deployer", namespace="payments",
                        checks=[{"checkID": avd.replace("-", ""), "severity": "HIGH",
                                 "success": False, "title": "wildcard verbs"},
                                {"checkID": "KSV999", "severity": "LOW", "success": True, "title": "pass"}])
    parsed = trivy.parse_rbac_assessment_report(obj)

    assert (parsed["namespace"], parsed["resource_kind"], parsed["resource_name"]) == ("payments", "Role", "deployer")
    assert not parsed.get("cluster_scoped")
    assert [f["category"] for f in parsed["findings"]] == [Category.RBAC.value]
    assert parsed["findings"][0]["vuln_id"] == f"AVD-{avd}"
    assert parsed["signal_ids"] == {rbac_sd.id}


def test_cluster_rbac_assessment_report_is_cluster_scoped_and_keeps_the_subject_in_details():
    obj = _check_report("ClusterRbacAssessmentReport", resource_kind="ClusterRole", resource_name="admin",
                        namespace=None,
                        checks=[{"checkID": "KSV-0044", "severity": "CRITICAL", "success": False, "title": "x"}])
    parsed = trivy.parse_cluster_rbac_assessment_report(obj)

    assert parsed["cluster_scoped"] is True and parsed["namespace"] == ""
    f = parsed["findings"][0]
    assert f["vuln_id"] == "AVD-KSV-0044" and f["category"] == Category.RBAC.value
    # With workload=None at upsert time this block is the only place the
    # scanned subject survives.
    assert {k: f["details"][k] for k in ("scope", "resource_kind", "resource_name")} == {
        "scope": "cluster", "resource_kind": "ClusterRole", "resource_name": "admin"}
    assert parsed["signal_ids"] == set()


def test_infra_assessment_report_yields_compliance_findings():
    obj = _check_report("InfraAssessmentReport", resource_kind="Node", resource_name="ip-10-0-0-1", namespace="kube-system",
                        checks=[{"checkID": "KCV0001", "severity": "HIGH", "success": False, "title": "kubelet flag"},
                                {"checkID": "KCV0002", "severity": "LOW", "success": True, "title": "ok"}])
    parsed = trivy.parse_infra_assessment_report(obj)

    assert [f["category"] for f in parsed["findings"]] == [Category.COMPLIANCE.value]
    assert parsed["findings"][0]["vuln_id"] == "KCV0001", "non-KSV ids are kept verbatim"
    assert parsed["findings"][0]["severity"] == Severity.HIGH.value
    assert parsed["signal_ids"] == set()


def test_config_audit_report_emits_registry_signal_ids_for_failed_checks():
    _, other_sd = _trivy_signal_ids()
    compact = other_sd.matcher.replace("-", "")  # "KSV-0017" → "KSV0017"
    obj = _config_audit(checks=[
        {"checkID": compact, "severity": "HIGH", "success": False, "title": "x"},
        {"checkID": "KSV9999", "severity": "LOW", "success": False, "title": "unmapped"},
        {"checkID": other_sd.matcher, "severity": "LOW", "success": True, "title": "passing → no signal"},
    ])
    parsed = trivy.parse_config_audit_report(obj)
    assert parsed["signal_ids"] == {other_sd.id}


@pytest.mark.parametrize(("raw", "expected"), [
    ("KSV051", "AVD-KSV-0051"), ("KSV-0051", "AVD-KSV-0051"), ("KSV-51", "AVD-KSV-0051"),
    ("AVD-KSV-0051", "AVD-KSV-0051"), ("KCV0001", "KCV0001"), ("", ""),
])
def test_normalise_avd_variants(raw, expected):
    assert trivy._normalise_avd(raw) == expected


def test_vuln_report_severity_mapping_is_exact():
    obj = _vuln_report(vulns=[_vuln(f"CVE-{s}", severity=s) for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN", "WEIRD")])
    by_id = {f["vuln_id"]: f["severity"] for f in trivy.parse_vulnerability_report(obj)["findings"]}
    assert by_id == {"CVE-CRITICAL": Severity.CRITICAL.value, "CVE-HIGH": Severity.HIGH.value,
                     "CVE-MEDIUM": Severity.MEDIUM.value, "CVE-LOW": Severity.LOW.value,
                     "CVE-UNKNOWN": Severity.UNKNOWN.value, "CVE-WEIRD": Severity.UNKNOWN.value}
