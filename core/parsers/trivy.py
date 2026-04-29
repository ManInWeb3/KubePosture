"""Trivy CRD parsers.

Each function takes one CRD object (raw JSON, as Trivy emits it) plus
context (cluster + alias resolver) and returns a list of dicts ready
for `core.services.dedup.upsert_findings`. Workload resolution is
performed via the alias chain so RS/Job CRDs attach to the parent
controller.

The parsers do not write to the DB themselves — that's the dedup
service. Signal upserts (Trivy KSV → WorkloadSignal) are returned as
a separate list so the caller can sequence them after the workload
has been resolved.
"""
from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from core.constants import Category, Severity, Source, TRIVY_SEVERITY_MAP
from core.signals import signal_for_trivy_avd


def _meta(obj: dict) -> dict:
    return obj.get("metadata") or {}


def _labels(obj: dict) -> dict:
    return _meta(obj).get("labels") or {}


def _resource_identity(obj: dict) -> tuple[str, str, str]:
    """Pull (namespace, kind, name) from a Trivy CRD's labels.

    Trivy stamps `trivy-operator.resource.{namespace,kind,name}` on
    every report; the namespace label is absent for cluster-scoped
    reports.
    """
    lbls = _labels(obj)
    namespace = lbls.get("trivy-operator.resource.namespace") or _meta(obj).get("namespace") or ""
    kind = lbls.get("trivy-operator.resource.kind") or ""
    name = lbls.get("trivy-operator.resource.name") or ""
    return namespace, kind, name


def _container_name(obj: dict) -> str:
    return _labels(obj).get("trivy-operator.container.name") or ""


def _artifact(obj: dict) -> dict:
    """`report.artifact` block — image identity for vuln/secret reports."""
    return (obj.get("report") or {}).get("artifact") or {}


def _image_ref(artifact: dict) -> str:
    """Best-effort `registry/repo:tag` reconstruction from artifact dict.

    Excludes the `@digest` suffix — `Image.ref` is the human-readable
    label; the digest lives on its own column.
    """
    repo = artifact.get("repository") or ""
    registry = artifact.get("registry") or ""
    tag = artifact.get("tag") or ""
    base = repo
    if registry and not repo.startswith(registry + "/"):
        base = f"{registry}/{repo}"
    if tag:
        base = f"{base}:{tag}"
    return base


def _image_digest(artifact: dict) -> str:
    return artifact.get("digest") or ""


def _severity_for(value: str) -> str:
    if not value:
        return Severity.UNKNOWN.value
    return TRIVY_SEVERITY_MAP.get(value.upper(), Severity.UNKNOWN).value


def _normalise_avd(check_id: str) -> str:
    """Normalise Trivy check IDs to the canonical `AVD-KSV-XXXX` form.

    Trivy emits a few variants depending on its version:
      `KSV051` (compact)   → `AVD-KSV-0051`
      `KSV-0051`            → `AVD-KSV-0051`
      `AVD-KSV-0051`        → unchanged
    """
    if not check_id:
        return ""
    if check_id.startswith("AVD-"):
        return check_id
    if check_id.startswith("KSV"):
        rest = check_id[3:].lstrip("-")
        if rest.isdigit():
            return f"AVD-KSV-{int(rest):04d}"
        return f"AVD-{check_id}"
    return check_id


def _os_block(report: dict) -> tuple[str, str, bool]:
    osd = (report.get("os") or {})
    return (
        osd.get("family") or "",
        osd.get("name") or "",
        bool(osd.get("eosl") or False),
    )


# ── VulnerabilityReport ------------------------------------------

def parse_vulnerability_report(obj: dict) -> dict:
    """Returns:
        {
          "kind": "trivy.VulnerabilityReport",
          "namespace", "resource_kind", "resource_name", "container_name",
          "image_ref", "image_digest",
          "os_family", "os_version", "base_eosl",
          "findings": [<finding dicts>],
        }

    Each finding dict carries the column fields needed by `upsert_findings`.
    """
    namespace, kind, name = _resource_identity(obj)
    container = _container_name(obj)
    artifact = _artifact(obj)
    report = obj.get("report") or {}
    os_family, os_version, eosl = _os_block(report)

    findings: list[dict] = []
    for v in report.get("vulnerabilities") or []:
        findings.append({
            "source": Source.TRIVY.value,
            "category": Category.VULNERABILITY.value,
            "vuln_id": v.get("vulnerabilityID") or "",
            "pkg_name": v.get("resource") or "",
            "installed_version": v.get("installedVersion") or "",
            "fixed_version": v.get("fixedVersion") or "",
            "title": v.get("title") or v.get("vulnerabilityID") or "",
            "severity": _severity_for(v.get("severity") or ""),
            "cvss_score": _cvss_score(v),
            "cvss_vector": _cvss_vector(v),
            "details": {
                "description": v.get("description") or "",
                "primary_link": v.get("primaryLink") or "",
                "links": v.get("links") or [],
                "publishedDate": v.get("publishedDate"),
                "lastModifiedDate": v.get("lastModifiedDate"),
                "score": v.get("score"),
                "target": v.get("target"),
            },
        })

    return {
        "kind": "trivy.VulnerabilityReport",
        "namespace": namespace,
        "resource_kind": kind,
        "resource_name": name,
        "container_name": container,
        "image_ref": _image_ref(artifact),
        "image_digest": _image_digest(artifact),
        "os_family": os_family,
        "os_version": os_version,
        "base_eosl": eosl,
        "findings": findings,
    }


def _cvss_score(v: dict) -> float | None:
    cvss = v.get("score")
    if isinstance(cvss, (int, float)):
        return float(cvss)
    cvss_block = v.get("cvss") or {}
    for vendor in ("nvd", "redhat"):
        sub = cvss_block.get(vendor) or {}
        for key in ("V3Score", "V2Score"):
            val = sub.get(key)
            if isinstance(val, (int, float)):
                return float(val)
    return None


def _cvss_vector(v: dict) -> str:
    cvss_block = v.get("cvss") or {}
    for vendor in ("nvd", "redhat"):
        sub = cvss_block.get(vendor) or {}
        for key in ("V3Vector", "V2Vector"):
            val = sub.get(key)
            if val:
                return str(val)
    return ""


# ── ConfigAuditReport (signals + findings) ------------------------

def parse_config_audit_report(obj: dict) -> dict:
    """Returns workload identity + lists of:
       - findings (ConfigAuditReport entries with check_id / severity)
       - signal_ids (KSV checks that map to the registry)
    """
    namespace, kind, name = _resource_identity(obj)
    report = obj.get("report") or {}

    findings: list[dict] = []
    signal_ids: set[str] = set()

    for c in report.get("checks") or []:
        check_id = c.get("checkID") or ""
        success = c.get("success", False)
        if success:
            continue
        sig = signal_for_trivy_avd(check_id)
        if sig:
            signal_ids.add(sig)
        findings.append({
            "source": Source.TRIVY.value,
            "category": Category.CONFIG.value,
            "vuln_id": _normalise_avd(check_id),
            "pkg_name": "",
            "installed_version": "",
            "fixed_version": "",
            "title": c.get("title") or check_id,
            "severity": _severity_for(c.get("severity") or ""),
            "cvss_score": None,
            "cvss_vector": "",
            "details": {
                "description": c.get("description") or "",
                "remediation": c.get("remediation") or "",
                "category": c.get("category") or "",
                "messages": c.get("messages") or [],
            },
        })

    return {
        "kind": "trivy.ConfigAuditReport",
        "namespace": namespace,
        "resource_kind": kind,
        "resource_name": name,
        "container_name": "",
        "image_ref": "",
        "image_digest": "",
        "findings": findings,
        "signal_ids": signal_ids,
    }


# ── ExposedSecretReport -------------------------------------------

def parse_exposed_secret_report(obj: dict) -> dict:
    namespace, kind, name = _resource_identity(obj)
    container = _container_name(obj)
    artifact = _artifact(obj)
    report = obj.get("report") or {}

    findings: list[dict] = []
    secrets = report.get("secrets") or []
    for s in secrets:
        rule_id = s.get("ruleID") or ""
        findings.append({
            "source": Source.TRIVY.value,
            "category": Category.EXPOSED_SECRET.value,
            "vuln_id": rule_id,
            "pkg_name": s.get("target") or "",
            "installed_version": "",
            "fixed_version": "",
            "title": s.get("title") or rule_id,
            "severity": _severity_for(s.get("severity") or ""),
            "cvss_score": None,
            "cvss_vector": "",
            "details": {
                "category": s.get("category") or "",
                "match": s.get("match") or "",
                "target": s.get("target") or "",
            },
        })

    signal_ids: set[str] = set()
    if findings:
        signal_ids.add("kp:exposed-secret-in-image")

    return {
        "kind": "trivy.ExposedSecretReport",
        "namespace": namespace,
        "resource_kind": kind,
        "resource_name": name,
        "container_name": container,
        "image_ref": _image_ref(artifact),
        "image_digest": _image_digest(artifact),
        "findings": findings,
        "signal_ids": signal_ids,
    }


# ── RbacAssessmentReport (per-resource SA / Role) ----------------

def parse_rbac_assessment_report(obj: dict) -> dict:
    namespace, kind, name = _resource_identity(obj)
    report = obj.get("report") or {}

    findings: list[dict] = []
    signal_ids: set[str] = set()
    for c in report.get("checks") or []:
        check_id = c.get("checkID") or ""
        if c.get("success", False):
            continue
        sig = signal_for_trivy_avd(check_id)
        if sig:
            signal_ids.add(sig)
        findings.append({
            "source": Source.TRIVY.value,
            "category": Category.RBAC.value,
            "vuln_id": _normalise_avd(check_id),
            "pkg_name": "",
            "installed_version": "",
            "fixed_version": "",
            "title": c.get("title") or check_id,
            "severity": _severity_for(c.get("severity") or ""),
            "cvss_score": None,
            "cvss_vector": "",
            "details": {
                "description": c.get("description") or "",
                "remediation": c.get("remediation") or "",
                "messages": c.get("messages") or [],
            },
        })

    return {
        "kind": "trivy.RbacAssessmentReport",
        "namespace": namespace,
        "resource_kind": kind,
        "resource_name": name,
        "container_name": "",
        "image_ref": "",
        "image_digest": "",
        "findings": findings,
        "signal_ids": signal_ids,
    }


# ── ClusterRbacAssessmentReport (cluster-scoped) ------------------

def parse_cluster_rbac_assessment_report(obj: dict) -> dict:
    """Cluster-scoped — `namespace` will be empty; findings have no
    workload (workload_id null at upsert time).
    """
    _, kind, name = _resource_identity(obj)
    report = obj.get("report") or {}

    findings: list[dict] = []
    for c in report.get("checks") or []:
        check_id = c.get("checkID") or ""
        if c.get("success", False):
            continue
        findings.append({
            "source": Source.TRIVY.value,
            "category": Category.RBAC.value,
            "vuln_id": _normalise_avd(check_id),
            "pkg_name": "",
            "installed_version": "",
            "fixed_version": "",
            "title": c.get("title") or check_id,
            "severity": _severity_for(c.get("severity") or ""),
            "cvss_score": None,
            "cvss_vector": "",
            "details": {
                "description": c.get("description") or "",
                "remediation": c.get("remediation") or "",
                "messages": c.get("messages") or [],
                "scope": "cluster",
                "resource_kind": kind,
                "resource_name": name,
            },
        })

    return {
        "kind": "trivy.ClusterRbacAssessmentReport",
        "namespace": "",
        "resource_kind": kind,
        "resource_name": name,
        "container_name": "",
        "image_ref": "",
        "image_digest": "",
        "findings": findings,
        "signal_ids": set(),
        "cluster_scoped": True,
    }


# ── InfraAssessmentReport / ClusterComplianceReport (skeletal) ----

def parse_infra_assessment_report(obj: dict) -> dict:
    namespace, kind, name = _resource_identity(obj)
    report = obj.get("report") or {}
    findings: list[dict] = []
    for c in report.get("checks") or []:
        if c.get("success", False):
            continue
        findings.append({
            "source": Source.TRIVY.value,
            "category": Category.COMPLIANCE.value,
            "vuln_id": c.get("checkID") or "",
            "pkg_name": "",
            "installed_version": "",
            "fixed_version": "",
            "title": c.get("title") or c.get("checkID") or "",
            "severity": _severity_for(c.get("severity") or ""),
            "cvss_score": None,
            "cvss_vector": "",
            "details": {
                "description": c.get("description") or "",
                "remediation": c.get("remediation") or "",
                "messages": c.get("messages") or [],
            },
        })
    return {
        "kind": "trivy.InfraAssessmentReport",
        "namespace": namespace,
        "resource_kind": kind,
        "resource_name": name,
        "container_name": "",
        "image_ref": "",
        "image_digest": "",
        "findings": findings,
        "signal_ids": set(),
    }


# ── Dispatch -------------------------------------------------------

PARSERS_BY_KIND = {
    "trivy.VulnerabilityReport": parse_vulnerability_report,
    "trivy.ConfigAuditReport": parse_config_audit_report,
    "trivy.ExposedSecretReport": parse_exposed_secret_report,
    "trivy.RbacAssessmentReport": parse_rbac_assessment_report,
    "trivy.ClusterRbacAssessmentReport": parse_cluster_rbac_assessment_report,
    "trivy.InfraAssessmentReport": parse_infra_assessment_report,
    "trivy.ClusterComplianceReport": parse_infra_assessment_report,  # similar shape
}
