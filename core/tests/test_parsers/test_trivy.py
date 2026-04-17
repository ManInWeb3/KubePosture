import json
from pathlib import Path

from core.constants import Category, Severity, Source
from core.parsers.trivy import (
    parse_trivy_compliance,
    parse_trivy_configaudit,
    parse_trivy_infra,
    parse_trivy_rbac,
    parse_trivy_sbom,
    parse_trivy_secrets,
    parse_trivy_vulnerabilities,
)

FIXTURES = Path(__file__).parent.parent / "fixtures"


def _load_fixture(name: str) -> dict:
    return json.loads((FIXTURES / name).read_text())


class TestParseTrivyVulnerabilities:
    def test_parses_all_vulns(self):
        payload = _load_fixture("vulnerability_report.json")
        findings = parse_trivy_vulnerabilities("test-cluster", payload)
        assert len(findings) == 2

    def test_first_finding_fields(self):
        payload = _load_fixture("vulnerability_report.json")
        findings = parse_trivy_vulnerabilities("test-cluster", payload)
        f = findings[0]

        # Column fields
        assert f["vuln_id"] == "CVE-2024-1234"
        assert f["severity"] == Severity.CRITICAL
        assert f["category"] == Category.VULNERABILITY
        assert f["source"] == Source.TRIVY
        assert f["namespace"] == "prod-app-backend"
        assert f["resource_kind"] == "ReplicaSet"
        assert f["resource_name"] == "backend-6d4cf56db6"

        # JSONB details
        assert f["details"]["component_name"] == "openssl"
        assert f["details"]["installed_version"] == "1.1.1k"
        assert f["details"]["fixed_version"] == "1.1.1l"
        assert f["details"]["score"] == 9.8
        assert f["details"]["image"] == "docker.io/library/nginx:1.25.4"
        assert f["details"]["container"] == "app"

    def test_second_finding_is_high(self):
        payload = _load_fixture("vulnerability_report.json")
        findings = parse_trivy_vulnerabilities("test-cluster", payload)
        assert findings[1]["severity"] == Severity.HIGH
        assert findings[1]["vuln_id"] == "CVE-2024-5678"

    def test_empty_report(self):
        payload = {
            "kind": "VulnerabilityReport",
            "metadata": {"labels": {}},
            "report": {"vulnerabilities": []},
        }
        findings = parse_trivy_vulnerabilities("test-cluster", payload)
        assert findings == []


class TestParseTrivyConfigAudit:
    def test_only_failed_checks(self):
        payload = _load_fixture("configaudit_report.json")
        findings = parse_trivy_configaudit("test-cluster", payload)
        # 3 checks in fixture, 1 passes (KSV012) -> 2 findings
        assert len(findings) == 2

    def test_finding_fields(self):
        payload = _load_fixture("configaudit_report.json")
        findings = parse_trivy_configaudit("test-cluster", payload)
        f = findings[0]

        assert f["vuln_id"] == "KSV001"
        assert f["severity"] == Severity.CRITICAL
        assert f["category"] == Category.MISCONFIGURATION
        assert f["details"]["check_id"] == "KSV001"
        assert "allowPrivilegeEscalation" in f["details"]["messages"][0]


class TestParseTrivySecrets:
    def test_parses_all_secrets(self):
        payload = _load_fixture("exposed_secret_report.json")
        findings = parse_trivy_secrets("test-cluster", payload)
        assert len(findings) == 2

    def test_first_secret_fields(self):
        payload = _load_fixture("exposed_secret_report.json")
        findings = parse_trivy_secrets("test-cluster", payload)
        f = findings[0]

        assert f["title"] == "AWS Access Key ID"
        assert f["severity"] == Severity.CRITICAL
        assert f["vuln_id"] == "aws-access-key-id"
        assert f["category"] == Category.SECRET
        assert f["source"] == Source.TRIVY
        assert f["namespace"] == "prod-app-backend"
        assert f["resource_kind"] == "ReplicaSet"
        assert f["resource_name"] == "api-server-7b9f5d6c4"

        assert f["details"]["rule_id"] == "aws-access-key-id"
        assert f["details"]["secret_category"] == "AWS"
        assert f["details"]["image"] == "ghcr.io/someorg/api-server:v2.1.0"
        assert f["details"]["container"] == "api"

    def test_second_secret_is_high(self):
        payload = _load_fixture("exposed_secret_report.json")
        findings = parse_trivy_secrets("test-cluster", payload)
        assert findings[1]["severity"] == Severity.HIGH
        assert findings[1]["vuln_id"] == "generic-api-key"

    def test_empty_secrets(self):
        payload = {
            "kind": "ExposedSecretReport",
            "metadata": {"labels": {}},
            "report": {"secrets": []},
        }
        assert parse_trivy_secrets("test-cluster", payload) == []


class TestParseTrivyRbac:
    def test_only_failed_checks(self):
        payload = _load_fixture("rbac_assessment_report.json")
        findings = parse_trivy_rbac("test-cluster", payload)
        # 3 checks, 1 passes (KSV050) -> 2 findings
        assert len(findings) == 2

    def test_first_finding_fields(self):
        payload = _load_fixture("rbac_assessment_report.json")
        findings = parse_trivy_rbac("test-cluster", payload)
        f = findings[0]

        assert f["title"] == "Do not allow management of secrets"
        assert f["severity"] == Severity.CRITICAL
        assert f["vuln_id"] == "KSV041"
        assert f["category"] == Category.RBAC
        assert f["source"] == Source.TRIVY
        assert f["namespace"] == "kube-system"
        assert f["resource_kind"] == "Role"
        assert f["resource_name"] == "admin-role"

        assert f["details"]["check_id"] == "KSV041"
        assert "management of secrets" in f["details"]["description"]
        assert len(f["details"]["messages"]) == 1

    def test_second_finding_is_high(self):
        payload = _load_fixture("rbac_assessment_report.json")
        findings = parse_trivy_rbac("test-cluster", payload)
        assert findings[1]["severity"] == Severity.HIGH
        assert findings[1]["vuln_id"] == "KSV044"

    def test_empty_checks(self):
        payload = {
            "kind": "RbacAssessmentReport",
            "metadata": {"labels": {}},
            "report": {"checks": []},
        }
        assert parse_trivy_rbac("test-cluster", payload) == []


class TestParseTrivyInfra:
    def test_only_failed_checks(self):
        payload = _load_fixture("infra_assessment_report.json")
        findings = parse_trivy_infra("test-cluster", payload)
        # 3 checks, 1 passes (KCV0010) -> 2 findings
        assert len(findings) == 2

    def test_first_finding_fields(self):
        payload = _load_fixture("infra_assessment_report.json")
        findings = parse_trivy_infra("test-cluster", payload)
        f = findings[0]

        assert f["title"] == "Ensure that the --profiling argument is set to false"
        assert f["severity"] == Severity.CRITICAL
        assert f["vuln_id"] == "KCV0020"
        assert f["category"] == Category.INFRA
        assert f["source"] == Source.TRIVY
        assert f["namespace"] == "kube-system"
        assert f["resource_kind"] == "Pod"
        assert f["resource_name"] == "kube-apiserver-node01"

        assert f["details"]["check_id"] == "KCV0020"
        assert "profiling" in f["details"]["description"]
        assert f["details"]["remediation"] == ""  # not in CRD

    def test_second_finding_is_medium(self):
        payload = _load_fixture("infra_assessment_report.json")
        findings = parse_trivy_infra("test-cluster", payload)
        assert findings[1]["severity"] == Severity.MEDIUM
        assert findings[1]["vuln_id"] == "KCV0001"

    def test_empty_checks(self):
        payload = {
            "kind": "InfraAssessmentReport",
            "metadata": {"labels": {}},
            "report": {"checks": []},
        }
        assert parse_trivy_infra("test-cluster", payload) == []


class TestParseTrivyComplianceAndSbom:
    def test_compliance_returns_structured_data(self):
        payload = _load_fixture("cluster_compliance_report.json")
        result = parse_trivy_compliance("test-cluster", payload)
        assert len(result) == 1
        assert result[0]["_compliance"] is True
        assert result[0]["framework_id"] == "k8s-cis"

    def test_sbom_returns_structured_data(self):
        payload = _load_fixture("sbom_report.json")
        result = parse_trivy_sbom("test-cluster", payload)
        assert len(result) == 1
        assert result[0]["_sbom"] is True
        assert result[0]["image"] == "docker.io/library/nginx:1.25.4"
        assert len(result[0]["components"]) == 3
