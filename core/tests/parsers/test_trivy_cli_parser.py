"""Unit tests for core.parsers.trivy.parse_trivy_cli_vulnerabilities.

Raw `trivy image --format json` output, as a user produces locally while
hardening a container. PascalCase keys (VulnerabilityID/PkgName/...) vs the
Operator CRD's camelCase keys (vulnerabilityID/resource/...).
"""
from __future__ import annotations

from core.constants import Category, Severity, Source
from core.parsers import trivy


def _cli_doc(artifact: str = "registry.io/app:hardened", results: list[dict] | None = None) -> dict:
    return {
        "SchemaVersion": 2,
        "ArtifactName": artifact,
        "ArtifactType": "container_image",
        "Results": results or [],
    }


def _result(
    target: str = "registry.io/app:hardened (debian 12.4)",
    vulns: list[dict] | None = None,
) -> dict:
    return {
        "Target": target,
        "Class": "os-pkgs",
        "Type": "debian",
        "Vulnerabilities": vulns or [],
    }


def _cli_vuln(
    vid: str,
    *,
    pkg: str = "libc6",
    severity: str = "HIGH",
    installed: str = "2.36-9",
    fixed: str = "2.36-9+deb12u3",
    cvss_v3: float | None = 7.5,
) -> dict:
    out = {
        "VulnerabilityID": vid,
        "PkgName": pkg,
        "InstalledVersion": installed,
        "FixedVersion": fixed,
        "Severity": severity,
        "Title": f"Test issue {vid}",
        "Description": "Test description.",
        "PrimaryURL": f"https://avd.aquasec.com/nvd/{vid.lower()}",
        "References": [f"https://nvd.nist.gov/vuln/detail/{vid}"],
        "PublishedDate": "2024-01-01T00:00:00Z",
    }
    if cvss_v3 is not None:
        vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        out["CVSS"] = {"nvd": {"V3Score": cvss_v3, "V3Vector": vector}}
    return out


def test_cli_parser_extracts_artifact_name():
    parsed = trivy.parse_trivy_cli_vulnerabilities(
        _cli_doc(artifact="my-registry/api:v2-distroless", results=[_result()])
    )
    assert parsed["kind"] == "trivy.CliVulnerability"
    assert parsed["artifact_name"] == "my-registry/api:v2-distroless"


def test_cli_parser_flattens_results_into_one_findings_list():
    parsed = trivy.parse_trivy_cli_vulnerabilities(_cli_doc(results=[
        _result(
            target="os-pkgs",
            vulns=[_cli_vuln("CVE-2024-1111"), _cli_vuln("CVE-2024-2222")],
        ),
        _result(
            target="app-deps",
            vulns=[_cli_vuln("CVE-2024-3333", pkg="lodash", severity="MEDIUM")],
        ),
    ]))
    vids = sorted(f["vuln_id"] for f in parsed["findings"])
    assert vids == ["CVE-2024-1111", "CVE-2024-2222", "CVE-2024-3333"]


def test_cli_parser_maps_pascalcase_to_canonical_dict():
    parsed = trivy.parse_trivy_cli_vulnerabilities(_cli_doc(results=[
        _result(vulns=[_cli_vuln("CVE-2024-9999", pkg="openssl", severity="CRITICAL", cvss_v3=9.8)])
    ]))
    f = parsed["findings"][0]
    assert f["source"] == Source.TRIVY.value
    assert f["category"] == Category.VULNERABILITY.value
    assert f["vuln_id"] == "CVE-2024-9999"
    assert f["pkg_name"] == "openssl"
    assert f["installed_version"] == "2.36-9"
    assert f["fixed_version"] == "2.36-9+deb12u3"
    assert f["severity"] == Severity.CRITICAL.value
    assert f["cvss_score"] == 9.8
    assert f["cvss_vector"].startswith("CVSS:3.1")
    assert f["details"]["primary_link"].endswith("cve-2024-9999")
    assert f["details"]["description"] == "Test description."


def test_cli_parser_handles_missing_vulnerabilities_block():
    parsed = trivy.parse_trivy_cli_vulnerabilities(_cli_doc(results=[
        {"Target": "config", "Class": "config", "Type": "yaml"},
    ]))
    assert parsed["findings"] == []


def test_cli_parser_handles_empty_document():
    parsed = trivy.parse_trivy_cli_vulnerabilities({})
    assert parsed["findings"] == []
    assert parsed["artifact_name"] == ""


def test_cli_parser_severity_normalisation():
    parsed = trivy.parse_trivy_cli_vulnerabilities(_cli_doc(results=[
        _result(vulns=[
            _cli_vuln("CVE-A", severity="CRITICAL"),
            _cli_vuln("CVE-B", severity="HIGH"),
            _cli_vuln("CVE-C", severity="MEDIUM"),
            _cli_vuln("CVE-D", severity="LOW"),
            _cli_vuln("CVE-E", severity="UNKNOWN"),
        ])
    ]))
    sevs = {f["vuln_id"]: f["severity"] for f in parsed["findings"]}
    assert sevs["CVE-A"] == Severity.CRITICAL.value
    assert sevs["CVE-B"] == Severity.HIGH.value
    assert sevs["CVE-C"] == Severity.MEDIUM.value
    assert sevs["CVE-D"] == Severity.LOW.value
