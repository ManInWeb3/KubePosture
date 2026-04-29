"""Unit tests for core.parsers.trivy.

Pure-function tests against in-memory CRD fixtures. Each test
exercises a parser entry point and checks the returned dict shape.
"""
from __future__ import annotations

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


def test_vuln_report_extracts_image_digest_from_artifact():
    digest = "sha256:" + "b" * 64
    obj = _vuln_report(image_digest=digest, vulns=[_vuln("CVE-2024-1234")])
    parsed = trivy.parse_vulnerability_report(obj)
    assert parsed["image_digest"] == digest
    # _image_ref reads `artifact.registry` (not `report.registry`); fixture
    # places registry at the report level, so the ref is just repo:tag.
    assert parsed["image_ref"] == "payments/api:v1.2.3"


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
