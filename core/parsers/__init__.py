"""
Parser registry — maps CRD kind to parser function.

Each parser: (cluster_name: str, payload: dict) -> list[dict]
Returns finding dicts with columns + details keys.
Special routing flags: _compliance, _sbom, _kyverno_summary.
"""
from core.parsers.kyverno import parse_kyverno_policyreport
from core.parsers.trivy import (
    parse_trivy_compliance,
    parse_trivy_configaudit,
    parse_trivy_infra,
    parse_trivy_rbac,
    parse_trivy_sbom,
    parse_trivy_secrets,
    parse_trivy_vulnerabilities,
)

KIND_ROUTER: dict[str, callable] = {
    # Trivy Operator CRDs
    "VulnerabilityReport": parse_trivy_vulnerabilities,
    "ConfigAuditReport": parse_trivy_configaudit,
    "ExposedSecretReport": parse_trivy_secrets,
    "RbacAssessmentReport": parse_trivy_rbac,
    "ClusterRbacAssessmentReport": parse_trivy_rbac,
    "InfraAssessmentReport": parse_trivy_infra,
    "ClusterInfraAssessmentReport": parse_trivy_infra,
    "ClusterConfigAuditReport": parse_trivy_configaudit,
    "ClusterComplianceReport": parse_trivy_compliance,
    "SbomReport": parse_trivy_sbom,
    # Kyverno PolicyReport CRDs
    "PolicyReport": parse_kyverno_policyreport,
    "ClusterPolicyReport": parse_kyverno_policyreport,
}
