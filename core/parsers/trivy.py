"""
Trivy Operator CRD parsers — 7 functions.

Each parser takes (cluster_name, crd_json) and returns a list of finding dicts.
Finding dicts have two sections:
  - Column fields: title, severity, vuln_id, namespace, resource_kind, resource_name, category, source
  - details dict: all CRD-type-specific fields (JSONB)

Compliance and SBOM parsers return a sentinel dict with _store_raw=True
to signal raw storage in Phase 1 (structured parsing in Phase 2).

Parsers are pure functions — no Django model imports, no DB access.
"""
from core.constants import TRIVY_SEVERITY_MAP, Category, Source

# ── Helpers ─────────────────────────────────────────────────────


def _extract_k8s_identity(payload: dict) -> dict:
    """Extract K8s resource identity from Trivy CRD metadata labels."""
    labels = payload.get("metadata", {}).get("labels", {})
    return {
        "namespace": labels.get("trivy-operator.resource.namespace", ""),
        "resource_kind": labels.get("trivy-operator.resource.kind", ""),
        "resource_name": labels.get("trivy-operator.resource.name", ""),
    }


def _extract_image(payload: dict) -> str:
    """Reconstruct image reference from report.registry + report.artifact."""
    report = payload.get("report", {})
    registry = report.get("registry", {}).get("server", "")
    repo = report.get("artifact", {}).get("repository", "")
    tag = report.get("artifact", {}).get("tag", "")
    if registry and repo:
        return f"{registry}/{repo}:{tag}" if tag else f"{registry}/{repo}"
    if repo:
        return f"{repo}:{tag}" if tag else repo
    return ""


def _map_severity(trivy_severity: str) -> str:
    """Map Trivy uppercase severity to our TextChoices value."""
    return TRIVY_SEVERITY_MAP.get(trivy_severity.upper(), "Low")


# ── VulnerabilityReport ─────────────────────────────────────────


def parse_trivy_vulnerabilities(cluster_name: str, payload: dict) -> list[dict]:
    """Parse VulnerabilityReport -> list of vulnerability finding dicts."""
    identity = _extract_k8s_identity(payload)
    image = _extract_image(payload)
    container = payload.get("metadata", {}).get("labels", {}).get(
        "trivy-operator.container.name", ""
    )
    report = payload.get("report", {})

    findings = []
    for vuln in report.get("vulnerabilities", []):
        severity = _map_severity(vuln.get("severity", "UNKNOWN"))
        findings.append(
            {
                # Columns
                "title": vuln.get("title", vuln.get("vulnerabilityID", "Unknown")),
                "severity": severity,
                "vuln_id": vuln.get("vulnerabilityID", ""),
                "category": Category.VULNERABILITY,
                "source": Source.TRIVY,
                **identity,
                # JSONB details
                "details": {
                    "score": vuln.get("score"),
                    "component_name": vuln.get("resource", ""),
                    "installed_version": vuln.get("installedVersion", ""),
                    "fixed_version": vuln.get("fixedVersion", ""),
                    "advisory_url": vuln.get("primaryLink", ""),
                    "description": vuln.get("description", ""),
                    "image": image,
                    "container": container,
                    "target": vuln.get("target", ""),
                    "pkg_type": vuln.get("packageType", ""),
                    "published_date": vuln.get("publishedDate", ""),
                },
            }
        )
    return findings


# ── ConfigAuditReport ───────────────────────────────────────────


def parse_trivy_configaudit(cluster_name: str, payload: dict) -> list[dict]:
    """Parse ConfigAuditReport -> list of misconfiguration finding dicts."""
    identity = _extract_k8s_identity(payload)
    report = payload.get("report", {})

    findings = []
    for check in report.get("checks", []):
        if check.get("success", False):
            continue  # Only failed checks become findings
        severity = _map_severity(check.get("severity", "UNKNOWN"))
        findings.append(
            {
                "title": check.get("title", check.get("checkID", "Unknown")),
                "severity": severity,
                "vuln_id": check.get("checkID", ""),
                "category": Category.MISCONFIGURATION,
                "source": Source.TRIVY,
                **identity,
                "details": {
                    "check_id": check.get("checkID", ""),
                    "description": check.get("description", ""),
                    "remediation": check.get("remediation", ""),
                    "messages": check.get("messages", []),
                    "scope_type": check.get("scope", {}).get("type", ""),
                    "scope_value": check.get("scope", {}).get("value", ""),
                },
            }
        )
    return findings


# ── ExposedSecretReport ─────────────────────────────────────────


def parse_trivy_secrets(cluster_name: str, payload: dict) -> list[dict]:
    """Parse ExposedSecretReport -> list of secret finding dicts."""
    identity = _extract_k8s_identity(payload)
    image = _extract_image(payload)
    container = payload.get("metadata", {}).get("labels", {}).get(
        "trivy-operator.container.name", ""
    )
    report = payload.get("report", {})

    findings = []
    for secret in report.get("secrets", []):
        severity = _map_severity(secret.get("severity", "UNKNOWN"))
        findings.append(
            {
                "title": secret.get("title", secret.get("ruleID", "Exposed Secret")),
                "severity": severity,
                "vuln_id": secret.get("ruleID", ""),
                "category": Category.SECRET,
                "source": Source.TRIVY,
                **identity,
                "details": {
                    "rule_id": secret.get("ruleID", ""),
                    "secret_category": secret.get("category", ""),
                    "image": image,
                    "container": container,
                },
            }
        )
    return findings


# ── RbacAssessmentReport ────────────────────────────────────────


def parse_trivy_rbac(cluster_name: str, payload: dict) -> list[dict]:
    """Parse RbacAssessmentReport -> list of RBAC finding dicts."""
    identity = _extract_k8s_identity(payload)
    report = payload.get("report", {})

    findings = []
    for check in report.get("checks", []):
        if check.get("success", False):
            continue
        severity = _map_severity(check.get("severity", "UNKNOWN"))
        findings.append(
            {
                "title": check.get("title", check.get("checkID", "Unknown")),
                "severity": severity,
                "vuln_id": check.get("checkID", ""),
                "category": Category.RBAC,
                "source": Source.TRIVY,
                **identity,
                "details": {
                    "check_id": check.get("checkID", ""),
                    "description": check.get("description", ""),
                    "remediation": check.get("remediation", ""),
                    "messages": check.get("messages", []),
                },
            }
        )
    return findings


# ── InfraAssessmentReport ───────────────────────────────────────


def parse_trivy_infra(cluster_name: str, payload: dict) -> list[dict]:
    """Parse InfraAssessmentReport -> list of infra finding dicts."""
    identity = _extract_k8s_identity(payload)
    report = payload.get("report", {})

    findings = []
    for check in report.get("checks", []):
        if check.get("success", False):
            continue
        severity = _map_severity(check.get("severity", "UNKNOWN"))
        findings.append(
            {
                "title": check.get("title", check.get("checkID", "Unknown")),
                "severity": severity,
                "vuln_id": check.get("checkID", ""),
                "category": Category.INFRA,
                "source": Source.TRIVY,
                **identity,
                "details": {
                    "check_id": check.get("checkID", ""),
                    "description": check.get("description", ""),
                    "remediation": check.get("remediation", ""),
                    "messages": check.get("messages", []),
                },
            }
        )
    return findings


# ── ClusterComplianceReport ────────────────────────────────────


def parse_trivy_compliance(cluster_name: str, payload: dict) -> list[dict]:
    """Parse ClusterComplianceReport -> compliance snapshot dict.

    Returns a single-element list with a dict tagged _compliance=True
    so the ingest orchestrator routes to compliance processing
    instead of the findings dedup pipeline.

    CRD structure (varies by Trivy Operator version):
      spec.compliance: {id, title, description, version, controls[]}
      status.summaryReport.controlCheck[]: {id, name, severity, totalFail, totalPass?}
      status.totalCounts: {passCount?, failCount?}  — may be empty in some versions
      status.detailReport.results[]: alternative format in some versions

    Real-world: totalCounts is often empty. totalPass may be missing from
    controlCheck entries. Totals are computed from control checks.
    """
    spec = payload.get("spec", {}).get("compliance", {})
    status = payload.get("status", {})
    control_checks = status.get("summaryReport", {}).get("controlCheck", [])

    framework_id = spec.get("id", "")
    if not framework_id:
        # Fall back to metadata.name (e.g. "k8s-cis-1.23")
        framework_id = payload.get("metadata", {}).get("name", "unknown")

    # Build per-control results from status.summaryReport.controlCheck
    # Compute totals from controls (totalCounts is unreliable/empty)
    #
    # Real Trivy CRDs only have {id, name, severity, totalFail} per control.
    # No totalPass key. A control present in the results with totalFail=0 means PASS.
    # MANUAL is reserved for controls defined in spec but absent from results.
    controls = []
    agg_pass = 0
    agg_fail = 0
    for cc in control_checks:
        cf = cc.get("totalFail", 0) or 0
        cp = cc.get("totalPass", 0) or 0

        if cf == 0:
            status_val = "PASS"
            agg_pass += 1
        else:
            status_val = "FAIL"
            agg_fail += 1

        controls.append({
            "control_id": cc.get("id", ""),
            "name": cc.get("name", ""),
            "severity": _map_severity(cc.get("severity", "UNKNOWN")),
            "status": status_val,
            "total_pass": cp,
            "total_fail": cf,
        })

    # Use totalCounts if provided, otherwise use aggregated control-level counts
    total_counts = status.get("totalCounts", {})
    total_pass = total_counts.get("passCount") or agg_pass
    total_fail = total_counts.get("failCount") or agg_fail
    total = total_pass + total_fail
    pass_rate = round((total_pass / total * 100), 2) if total > 0 else 0

    # Build spec-level control definitions (for auto-creating Controls)
    spec_controls = []
    for sc in spec.get("controls", []):
        spec_controls.append({
            "control_id": sc.get("id", ""),
            "name": sc.get("name", ""),
            "description": sc.get("description", ""),
            "severity": _map_severity(sc.get("severity", "UNKNOWN")),
            "check_ids": [c.get("id", "") for c in sc.get("checks", [])],
        })

    return [{
        "_compliance": True,
        "framework_id": framework_id,
        "framework_title": spec.get("title", framework_id),
        "framework_description": spec.get("description", ""),
        "framework_version": spec.get("version", ""),
        "total_pass": total_pass,
        "total_fail": total_fail,
        "pass_rate": pass_rate,
        "controls": controls,
        "spec_controls": spec_controls,
    }]


# ── SbomReport ─────────────────────────────────────────────────


def parse_trivy_sbom(cluster_name: str, payload: dict) -> list[dict]:
    """Parse SbomReport CycloneDX BOM -> SBOM component dict.

    Returns a single-element list with a dict tagged _sbom=True
    so the ingest orchestrator routes to SBOM processing.

    CRD structure:
      metadata.labels: K8s resource identity
      report.registry + report.artifact: image reference
      report.components.components[]: CycloneDX component list
        Each: {name, version, type, purl, licenses[{expression}], properties[]}
    """
    identity = _extract_k8s_identity(payload)
    image = _extract_image(payload)

    bom = payload.get("report", {}).get("components", {})
    raw_components = bom.get("components", [])

    components = []
    for comp in raw_components:
        # Skip the root container component (type=container is the image itself)
        if comp.get("type") == "container":
            continue

        # Extract licenses as flat list of SPDX identifiers
        licenses = []
        for lic in comp.get("licenses", []):
            expr = lic.get("expression", "")
            if expr:
                licenses.append(expr)
            elif lic.get("license", {}).get("id"):
                licenses.append(lic["license"]["id"])

        # Map CycloneDX type to our ComponentType
        comp_type = comp.get("type", "library")
        if comp_type not in ("library", "framework", "os", "container", "application"):
            comp_type = "other"

        components.append({
            "name": comp.get("name", ""),
            "version": comp.get("version", ""),
            "component_type": comp_type,
            "purl": comp.get("purl", ""),
            "licenses": licenses,
        })

    return [{
        "_sbom": True,
        "namespace": identity.get("namespace", ""),
        "resource_name": identity.get("resource_name", ""),
        "image": image,
        "components": components,
    }]
