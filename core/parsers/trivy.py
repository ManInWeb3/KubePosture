"""Trivy CRD parsers.

Each function takes one CRD object (raw JSON, as Trivy emits it) and
returns one dict: the scanned resource's identity (`_report` skeleton —
namespace / resource_kind / resource_name, plus container and image for
image-anchored kinds) and `findings`, a list of dicts ready for
`core.services.dedup.upsert_findings`. Workload resolution against the
alias chain happens in `core.services.ingest`, so RS/Job CRDs attach to
the parent controller there.

The parsers do not write to the DB themselves — that's the dedup
service. Signal ids (Trivy KSV → WorkloadSignal) are returned as a
separate set so the caller can sequence them after the workload has
been resolved.
"""
from __future__ import annotations

from core.constants import TRIVY_SEVERITY_MAP, Category, Severity, Source
from core.purl import normalize_purl, purl_ecosystem
from core.signals import signal_for_trivy_avd


def _meta(obj: dict) -> dict:
    return obj.get("metadata") or {}


def _labels(obj: dict) -> dict:
    return _meta(obj).get("labels") or {}


def _owner_reference(obj: dict, kind: str) -> dict | None:
    """The report's ownerReference that names the scanned resource.
    Trivy sets exactly one, `controller: true`, pointing at it."""
    refs = [r for r in (_meta(obj).get("ownerReferences") or []) if isinstance(r, dict)]
    for ref in refs:
        if ref.get("controller") is True and (not kind or ref.get("kind") == kind):
            return ref
    for ref in refs:
        if not kind or ref.get("kind") == kind:
            return ref
    return None


def _resource_identity(obj: dict) -> tuple[str, str, str]:
    """Pull (namespace, kind, name) from a Trivy CRD's labels.

    Trivy stamps `trivy-operator.resource.{namespace,kind,name}` on
    every report; the namespace label is absent for cluster-scoped
    reports.

    Label values are capped at 63 characters, so for a resource with a
    longer name (long Deployment → ReplicaSet → Pod chains, static Pods
    named after their node) Trivy omits `resource.name` and sets only
    `resource.name-hash`. The scanned resource's real name is then only
    in the report's `ownerReferences`; fall back to it, otherwise every
    finding on such a workload is silently dropped as unresolvable.
    """
    lbls = _labels(obj)
    namespace = lbls.get("trivy-operator.resource.namespace") or _meta(obj).get("namespace") or ""
    kind = lbls.get("trivy-operator.resource.kind") or ""
    name = lbls.get("trivy-operator.resource.name") or ""
    if not name:
        ref = _owner_reference(obj, kind)
        if ref is not None:
            name = ref.get("name") or ""
            kind = kind or ref.get("kind") or ""
    return namespace, kind, name


def _container_name(obj: dict) -> str:
    return _labels(obj).get("trivy-operator.container.name") or ""


def _artifact(obj: dict) -> dict:
    """`report.artifact` block — image identity for vuln/secret reports."""
    return (obj.get("report") or {}).get("artifact") or {}


def _image_ref(obj: dict) -> str:
    """`registry/repo:tag` reconstruction from the report. Trivy Operator
    puts the registry at `report.registry.server` and repo/tag/digest
    under `report.artifact`.

    Excludes the `@digest` suffix — `Image.ref` is the human-readable
    label; the digest lives on its own column.
    """
    report = obj.get("report") or {}
    artifact = report.get("artifact") or {}
    repo = artifact.get("repository") or ""
    registry = (report.get("registry") or {}).get("server") or ""
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


def _report(obj: dict, kind: str, *, image: bool = False, **extra) -> dict:
    """The dict skeleton every parser returns: `kind` plus the scanned
    resource's identity. Image-anchored kinds (`image=True`) also carry
    the container name and the image ref / digest; the rest leave those
    empty. `extra` adds the kind's own keys (`findings`, `signal_ids`,
    `components`, ...) and may override a skeleton key."""
    namespace, resource_kind, resource_name = _resource_identity(obj)
    out = {
        "kind": kind,
        "namespace": namespace,
        "resource_kind": resource_kind,
        "resource_name": resource_name,
        "container_name": _container_name(obj) if image else "",
        "image_ref": _image_ref(obj) if image else "",
        "image_digest": _image_digest(_artifact(obj)) if image else "",
    }
    out.update(extra)
    return out


def _finding(category: str, *, vuln_id: str, title: str, severity: str, details: dict,
             pkg_name: str = "") -> dict:
    """A finding dict for the kinds without version / CVSS columns
    (checks, secrets). Vulnerabilities fill those in `_vuln_to_finding_dict`."""
    return {
        "source": Source.TRIVY.value,
        "category": category,
        "vuln_id": vuln_id,
        "pkg_name": pkg_name,
        "installed_version": "",
        "fixed_version": "",
        "title": title,
        "severity": _severity_for(severity or ""),
        "cvss_score": None,
        "cvss_vector": "",
        "details": details,
    }


def _check_findings(
    report: dict,
    category: str,
    *,
    detail_keys: tuple[str, ...] = (),
    extra_details: dict | None = None,
    signal_ids: set[str] | None = None,
) -> list[dict]:
    """One finding per FAILED entry of `report.checks` — the shape shared
    by ConfigAudit / Rbac / ClusterRbac / Infra reports. `detail_keys`
    names further per-check fields to copy into `details` (besides
    description / remediation / messages); `extra_details` is merged in
    as-is. When `signal_ids` is given, failed checks that map to the
    signal registry are added to it."""
    findings: list[dict] = []
    for c in report.get("checks") or []:
        if c.get("success", False):
            continue
        check_id = c.get("checkID") or ""
        if signal_ids is not None:
            sig = signal_for_trivy_avd(check_id)
            if sig:
                signal_ids.add(sig)
        details = {
            "description": c.get("description") or "",
            "remediation": c.get("remediation") or "",
            **{k: c.get(k) or "" for k in detail_keys},
            "messages": c.get("messages") or [],
            **(extra_details or {}),
        }
        findings.append(_finding(
            category,
            vuln_id=_normalise_avd(check_id),
            title=c.get("title") or check_id,
            severity=c.get("severity"),
            details=details,
        ))
    return findings


# ── VulnerabilityReport ------------------------------------------

def parse_vulnerability_report(obj: dict) -> dict:
    """Returns the `_report` skeleton (image-anchored) plus
    `os_family` / `os_version` / `base_eosl` and one finding per
    vulnerability. Each finding dict carries the column fields needed
    by `upsert_findings`."""
    report = obj.get("report") or {}
    os_family, os_version, eosl = _os_block(report)
    return _report(
        obj, "trivy.VulnerabilityReport", image=True,
        os_family=os_family,
        os_version=os_version,
        base_eosl=eosl,
        findings=[_vuln_to_finding_dict(v) for v in (report.get("vulnerabilities") or [])],
    )


def _vuln_to_finding_dict(v: dict) -> dict:
    """Map one Trivy vulnerability entry to the canonical finding dict.

    Accepts either the Operator CRD shape (camelCase keys: vulnerabilityID,
    resource, installedVersion, fixedVersion, primaryLink) or the raw Trivy
    CLI shape (PascalCase keys: VulnerabilityID, PkgName, InstalledVersion,
    FixedVersion, PrimaryURL). Whichever side is present wins.
    """
    vuln_id = v.get("vulnerabilityID") or v.get("VulnerabilityID") or ""
    pkg_name = v.get("resource") or v.get("PkgName") or ""
    installed = v.get("installedVersion") or v.get("InstalledVersion") or ""
    fixed = v.get("fixedVersion") or v.get("FixedVersion") or ""
    title = v.get("title") or v.get("Title") or vuln_id
    severity = v.get("severity") or v.get("Severity") or ""
    description = v.get("description") or v.get("Description") or ""
    primary_link = v.get("primaryLink") or v.get("PrimaryURL") or ""
    links = v.get("links") or v.get("References") or []
    published = v.get("publishedDate") or v.get("PublishedDate")
    last_mod = v.get("lastModifiedDate") or v.get("LastModifiedDate")
    return {
        "source": Source.TRIVY.value,
        "category": Category.VULNERABILITY.value,
        "vuln_id": vuln_id,
        "pkg_name": pkg_name,
        "installed_version": installed,
        "fixed_version": fixed,
        "title": title,
        "severity": _severity_for(severity),
        "cvss_score": _cvss_score(v),
        "cvss_vector": _cvss_vector(v),
        "details": {
            "description": description,
            "primary_link": primary_link,
            "links": links,
            "publishedDate": published,
            "lastModifiedDate": last_mod,
            "score": v.get("score"),
            "target": v.get("target") or v.get("Target"),
        },
    }


def parse_trivy_cli_vulnerabilities(obj: dict) -> dict:
    """Parse a raw `trivy image --format json` document.

    The CLI shape is `{ArtifactName, Results: [{Target, Vulnerabilities: [...]}, ...]}`
    rather than the Operator CRD's `{report: {vulnerabilities: [...]}}`. Returns the
    same canonical finding-dict shape that `parse_vulnerability_report` produces,
    plus the artifact name for display (no workload/namespace identity — those
    come from the workload the caller binds findings to).
    """
    findings: list[dict] = []
    for result in obj.get("Results") or []:
        for v in result.get("Vulnerabilities") or []:
            findings.append(_vuln_to_finding_dict(v))
    return {
        "kind": "trivy.CliVulnerability",
        "artifact_name": obj.get("ArtifactName") or "",
        "findings": findings,
    }


def _cvss_score(v: dict) -> float | None:
    cvss = v.get("score")
    if isinstance(cvss, (int, float)):
        return float(cvss)
    cvss_block = v.get("cvss") or v.get("CVSS") or {}
    for vendor in ("nvd", "redhat"):
        sub = cvss_block.get(vendor) or {}
        for key in ("V3Score", "V2Score"):
            val = sub.get(key)
            if isinstance(val, (int, float)):
                return float(val)
    return None


def _cvss_vector(v: dict) -> str:
    cvss_block = v.get("cvss") or v.get("CVSS") or {}
    for vendor in ("nvd", "redhat"):
        sub = cvss_block.get(vendor) or {}
        for key in ("V3Vector", "V2Vector"):
            val = sub.get(key)
            if val:
                return str(val)
    return ""


# ── Check-list reports (ConfigAudit / Rbac / ClusterRbac / Infra) --

def parse_config_audit_report(obj: dict) -> dict:
    """Config findings per failed KSV check, plus the `signal_ids` of
    the checks that map to the registry."""
    signal_ids: set[str] = set()
    findings = _check_findings(
        obj.get("report") or {}, Category.CONFIG.value,
        detail_keys=("category",), signal_ids=signal_ids,
    )
    return _report(obj, "trivy.ConfigAuditReport", findings=findings, signal_ids=signal_ids)


def parse_rbac_assessment_report(obj: dict) -> dict:
    """Per-resource (ServiceAccount / Role) RBAC findings + signals."""
    signal_ids: set[str] = set()
    findings = _check_findings(obj.get("report") or {}, Category.RBAC.value, signal_ids=signal_ids)
    return _report(obj, "trivy.RbacAssessmentReport", findings=findings, signal_ids=signal_ids)


def parse_cluster_rbac_assessment_report(obj: dict) -> dict:
    """Cluster-scoped — `namespace` is empty and findings have no
    workload (workload_id null at upsert time), so the scanned subject
    is kept in `details`.
    """
    _, kind, name = _resource_identity(obj)
    findings = _check_findings(
        obj.get("report") or {}, Category.RBAC.value,
        extra_details={"scope": "cluster", "resource_kind": kind, "resource_name": name},
    )
    return _report(
        obj, "trivy.ClusterRbacAssessmentReport", namespace="",
        findings=findings, signal_ids=set(), cluster_scoped=True,
    )


def parse_infra_assessment_report(obj: dict) -> dict:
    """InfraAssessmentReport / ClusterComplianceReport: compliance
    findings per failed check, no signals."""
    findings = _check_findings(obj.get("report") or {}, Category.COMPLIANCE.value)
    return _report(obj, "trivy.InfraAssessmentReport", findings=findings, signal_ids=set())


# ── ExposedSecretReport -------------------------------------------

def parse_exposed_secret_report(obj: dict) -> dict:
    report = obj.get("report") or {}
    findings: list[dict] = []
    for s in report.get("secrets") or []:
        rule_id = s.get("ruleID") or ""
        findings.append(_finding(
            Category.EXPOSED_SECRET.value,
            vuln_id=rule_id,
            pkg_name=s.get("target") or "",
            title=s.get("title") or rule_id,
            severity=s.get("severity"),
            details={
                "category": s.get("category") or "",
                "match": s.get("match") or "",
                "target": s.get("target") or "",
            },
        ))
    signal_ids = {"kp:exposed-secret-in-image"} if findings else set()
    return _report(obj, "trivy.ExposedSecretReport", image=True, findings=findings, signal_ids=signal_ids)


# ── SbomReport ----------------------------------------------------


def _component_property(comp: dict, name: str) -> str:
    """Pull a value from CycloneDX `properties[]` by name."""
    for p in comp.get("properties") or []:
        if p.get("name") == name:
            return p.get("value") or ""
    return ""


def _component_license(comp: dict) -> str:
    """CycloneDX `licenses[].license.{id,name}` — first one wins."""
    for lic in comp.get("licenses") or []:
        sub = lic.get("license") or {}
        val = sub.get("id") or sub.get("name") or ""
        if val:
            return val
    return ""


def _component_supplier(comp: dict) -> str:
    sup = comp.get("supplier") or {}
    return sup.get("name") or ""


def parse_sbom_report(obj: dict) -> dict:
    """Returns:
        {
          "kind": "trivy.SbomReport",
          "namespace", "resource_kind", "resource_name", "container_name",
          "image_ref", "image_digest",
          "components": [<component dicts ready for SbomComponent upsert>],
        }

    Components without a `purl` (e.g. the root container/operating-system
    metadata entry) are skipped. Trivy emits a top-level `metadata.component`
    that describes the image itself and a `components[]` list that includes
    OS packages and application dependencies — we only persist the latter.
    """
    report = obj.get("report") or {}

    bom = report.get("components") or {}
    raw_components = bom.get("components") or []

    components: list[dict] = []
    for c in raw_components:
        purl = normalize_purl(c.get("purl") or "")
        if not purl:
            continue
        name_ = c.get("name") or ""
        version = c.get("version") or ""
        ecosystem = (
            purl_ecosystem(purl)
            or _component_property(c, "aquasecurity:trivy:PkgType")
        )
        components.append({
            "purl": purl,
            "name": name_,
            "version": version,
            "ecosystem": ecosystem,
            "component_type": c.get("type") or "",
            "supplier": _component_supplier(c),
            "license": _component_license(c),
            "layer_digest": _component_property(
                c, "aquasecurity:trivy:LayerDigest"
            ),
            "raw": c,
        })

    return _report(obj, "trivy.SbomReport", image=True, components=components)


# ── Dispatch -------------------------------------------------------

PARSERS_BY_KIND = {
    "trivy.VulnerabilityReport": parse_vulnerability_report,
    "trivy.ConfigAuditReport": parse_config_audit_report,
    "trivy.ExposedSecretReport": parse_exposed_secret_report,
    "trivy.RbacAssessmentReport": parse_rbac_assessment_report,
    "trivy.ClusterRbacAssessmentReport": parse_cluster_rbac_assessment_report,
    "trivy.InfraAssessmentReport": parse_infra_assessment_report,
    "trivy.ClusterComplianceReport": parse_infra_assessment_report,  # similar shape
    "trivy.SbomReport": parse_sbom_report,
}
