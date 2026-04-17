"""
Kyverno PolicyReport parsers.

A single PolicyReport CRD contains both individual results (pass/fail per
resource per policy) and a summary (aggregate counts). One parser handles
both: failures become Findings, summary becomes a PolicyComplianceSnapshot.

CRD structure (wgpolicyk8s.io/v1alpha2):
  kind: PolicyReport | ClusterPolicyReport
  scope: {apiVersion, kind, name, namespace, uid}  — the evaluated resource
  results[]: {policy, rule, result, severity, message, source, timestamp, ...}
  summary: {pass, fail, warn, error, skip}

Kyverno uses lowercase severity (critical, high, medium, low).
Result values: pass, fail, warn, error, skip.

Ingestion approach: CronJob posts individual PolicyReport CRDs one by one
(not the List wrapper). Each CRD = one resource evaluated against all policies.
"""
from core.constants import Category, Source

KYVERNO_SEVERITY_MAP = {
    "critical": "Critical",
    "high": "High",
    "medium": "Medium",
    "low": "Low",
    "info": "Low",
}


def _map_severity(kyverno_severity: str) -> str:
    """Map Kyverno lowercase severity to our TextChoices value."""
    return KYVERNO_SEVERITY_MAP.get(kyverno_severity.lower(), "Medium")


def parse_kyverno_policyreport(cluster_name: str, payload: dict) -> list[dict]:
    """Parse PolicyReport/ClusterPolicyReport -> findings + summary.

    Returns a list with:
    - Finding dicts for each failed/error result (category=policy)
    - A final dict tagged _kyverno_summary=True with aggregate counts

    The ingest orchestrator uses _kyverno_summary to create a
    PolicyComplianceSnapshot alongside the findings.
    """
    scope = payload.get("scope", {})
    resource_ns = scope.get("namespace", "")
    resource_kind = scope.get("kind", "")
    resource_name = scope.get("name", "")

    # For ClusterPolicyReport, scope may be empty — use metadata
    if not resource_kind:
        resource_kind = payload.get("kind", "")
        resource_name = payload.get("metadata", {}).get("name", "")

    results = payload.get("results", [])
    summary = payload.get("summary", {})

    findings = []
    for r in results:
        result_status = r.get("result", "")
        # Only failed and error results become findings
        if result_status not in ("fail", "error"):
            continue

        policy = r.get("policy", "")
        rule = r.get("rule", "")
        severity = _map_severity(r.get("severity", "medium"))
        title = f"{policy}/{rule}" if rule else policy

        # Use result-level resource if available (some reports have per-result resources)
        r_resources = r.get("resources", [])
        if r_resources:
            res = r_resources[0]
            r_ns = res.get("namespace", resource_ns)
            r_kind = res.get("kind", resource_kind)
            r_name = res.get("name", resource_name)
        else:
            r_ns = resource_ns
            r_kind = resource_kind
            r_name = resource_name

        findings.append({
            "title": title,
            "severity": severity,
            "vuln_id": policy,
            "category": Category.POLICY,
            "source": Source.KYVERNO,
            "namespace": r_ns,
            "resource_kind": r_kind,
            "resource_name": r_name,
            "details": {
                "policy": policy,
                "rule": rule,
                "result": result_status,
                "message": r.get("message", ""),
                "category": r.get("category", ""),
                "source": r.get("source", "kyverno"),
            },
        })

    # Collect ALL results (pass + fail) for raw_json storage
    all_results = []
    for r in results:
        all_results.append({
            "policy": r.get("policy", ""),
            "rule": r.get("rule", ""),
            "result": r.get("result", ""),
            "severity": r.get("severity", ""),
            "message": r.get("message", ""),
            "category": r.get("category", ""),
            "namespace": resource_ns,
            "resource_kind": resource_kind,
            "resource_name": resource_name,
        })

    # Append summary dict for PolicyComplianceSnapshot
    total_pass = summary.get("pass", 0) or 0
    total_fail = summary.get("fail", 0) or 0
    total_warn = summary.get("warn", 0) or 0
    total_skip = summary.get("skip", 0) or 0
    total_error = summary.get("error", 0) or 0
    total_fail_combined = total_fail + total_error

    total = total_pass + total_fail_combined
    pass_rate = round((total_pass / total * 100), 2) if total > 0 else 0

    findings.append({
        "_kyverno_summary": True,
        "total_pass": total_pass,
        "total_fail": total_fail_combined,
        "total_warn": total_warn,
        "total_skip": total_skip,
        "pass_rate": pass_rate,
        "results": all_results,
    })

    return findings
