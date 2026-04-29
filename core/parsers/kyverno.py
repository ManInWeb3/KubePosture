"""Kyverno PolicyReport / ClusterPolicyReport parsers.

Each report carries a list of policy results; failing results emit
both a Finding (for the dashboard) AND a WorkloadSignal upsert
(scored by urgency.py via the registry's HOST_ESCAPE / RBAC sets).

`subjects[]` per result identifies the K8s resource the rule fired
against — this is what we resolve to a Workload via the alias chain.
"""
from __future__ import annotations

from typing import Any

from core.constants import Category, Severity, Source
from core.signals import signal_for_kyverno_policy


def _meta(obj: dict) -> dict:
    return obj.get("metadata") or {}


def _to_severity(s: str) -> str:
    return {
        "critical": Severity.CRITICAL.value,
        "high": Severity.HIGH.value,
        "medium": Severity.MEDIUM.value,
        "low": Severity.LOW.value,
        "info": Severity.INFO.value,
    }.get((s or "").lower(), Severity.MEDIUM.value)


def parse_policy_report(obj: dict) -> dict:
    """Returns:
        {
          "kind": "kyverno.PolicyReport" | "kyverno.ClusterPolicyReport",
          "namespace": "...",
          "results": [
            {
              "subject": (kind, name),
              "namespace_for_subject": "...",
              "finding": {...} | None,
              "signal_id": "kyverno:..." | None,
            },
            ...
          ],
        }

    Pass-result rows are dropped — only failures produce findings/signals.

    Subject resolution: each result may carry `resources[]` or
    `subjects[]`. When neither is populated, we fall back to the
    report's `scope` block (the resource the report is about). For
    PolicyReports we also walk owner-references via the alias chain
    (handled at upsert time).
    """
    api_kind = obj.get("kind") or ""
    md = _meta(obj)
    namespace = md.get("namespace") or ""
    scope = obj.get("scope") or {}
    results_out: list[dict] = []

    for r in obj.get("results") or []:
        if (r.get("result") or "").lower() not in ("fail", "error", "warn"):
            continue
        policy = r.get("policy") or ""
        rule = r.get("rule") or ""
        msg = r.get("message") or ""
        sev = _to_severity(r.get("severity") or "medium")
        subjects = r.get("subjects") or r.get("resources") or []
        if not subjects:
            # Fall back to the report-level scope.
            if scope.get("kind") and scope.get("name"):
                subjects = [scope]
            else:
                subjects = [{}]
        for subj in subjects:
            sub_kind = subj.get("kind") or ""
            sub_name = subj.get("name") or ""
            sub_ns = subj.get("namespace") or namespace

            sig_id = signal_for_kyverno_policy(policy)

            finding = {
                "source": Source.KYVERNO.value,
                "category": Category.POLICY.value,
                "vuln_id": policy,
                "pkg_name": "",
                "installed_version": "",
                "fixed_version": "",
                "title": f"{policy}/{rule}" if rule else policy,
                "severity": sev,
                "cvss_score": None,
                "cvss_vector": "",
                "details": {
                    "rule": rule,
                    "message": msg,
                    "category": r.get("category") or "",
                    "result": r.get("result"),
                },
            }

            results_out.append({
                "subject": (sub_kind, sub_name),
                "namespace_for_subject": sub_ns,
                "finding": finding,
                "signal_id": sig_id,
            })

    return {
        "kind": f"kyverno.{api_kind}" if api_kind else "kyverno.PolicyReport",
        "namespace": namespace,
        "results": results_out,
    }


PARSERS_BY_KIND = {
    "kyverno.PolicyReport": parse_policy_report,
    "kyverno.ClusterPolicyReport": parse_policy_report,
}
