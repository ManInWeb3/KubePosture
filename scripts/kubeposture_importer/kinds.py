"""Kind tables — the single source of truth for what the importer
collects, filters and uploads."""
from __future__ import annotations

# K8s object kinds that go into the inventory envelope (Node is only
# used for cluster_meta, never shipped as an item).
INVENTORY_ITEM_KINDS: frozenset[str] = frozenset({
    "Namespace", "Deployment", "StatefulSet", "DaemonSet", "CronJob",
    "Job", "ReplicaSet", "Pod", "Service", "Ingress", "NetworkPolicy",
})

# (CRD kind as kubectl reports it, envelope kind the server dispatches on).
# This is also the upload order after the inventory bundle; SbomReport is
# last because it is by far the largest.
SCAN_KINDS: tuple[tuple[str, str], ...] = (
    ("VulnerabilityReport", "trivy.VulnerabilityReport"),
    ("ConfigAuditReport", "trivy.ConfigAuditReport"),
    ("ExposedSecretReport", "trivy.ExposedSecretReport"),
    ("RbacAssessmentReport", "trivy.RbacAssessmentReport"),
    ("ClusterRbacAssessmentReport", "trivy.ClusterRbacAssessmentReport"),
    ("InfraAssessmentReport", "trivy.InfraAssessmentReport"),
    ("ClusterComplianceReport", "trivy.ClusterComplianceReport"),
    ("PolicyReport", "kyverno.PolicyReport"),
    ("ClusterPolicyReport", "kyverno.ClusterPolicyReport"),
    ("SbomReport", "trivy.SbomReport"),
)
ENVELOPE_KIND_FOR_CRD: dict[str, str] = dict(SCAN_KINDS)
INVENTORY_KIND = "inventory"

# Relevance-filter classes (see relevance.py).
IMAGE_KINDS: frozenset[str] = frozenset({
    "trivy.VulnerabilityReport", "trivy.SbomReport", "trivy.ExposedSecretReport",
})
SUBJECT_KINDS: frozenset[str] = frozenset({
    "trivy.ConfigAuditReport", "kyverno.PolicyReport",
})
CLUSTER_LEVEL_KINDS: frozenset[str] = frozenset({
    "trivy.RbacAssessmentReport", "trivy.ClusterRbacAssessmentReport",
    "trivy.InfraAssessmentReport", "trivy.ClusterComplianceReport",
    "kyverno.ClusterPolicyReport",
})

# Workload graph (mirrors core/parsers/inventory.py).
TOP_LEVEL_CONTROLLER_KINDS: frozenset[str] = frozenset({
    "Deployment", "StatefulSet", "DaemonSet", "CronJob",
})
ALIAS_KINDS: frozenset[str] = frozenset({"ReplicaSet", "Job", "Pod"})

# CRDs to list live: (group, version, plural, kind, cluster_scoped).
CRD_SOURCES: tuple[tuple[str, str, str, str, bool], ...] = (
    ("aquasecurity.github.io", "v1alpha1", "vulnerabilityreports", "VulnerabilityReport", False),
    ("aquasecurity.github.io", "v1alpha1", "configauditreports", "ConfigAuditReport", False),
    ("aquasecurity.github.io", "v1alpha1", "exposedsecretreports", "ExposedSecretReport", False),
    ("aquasecurity.github.io", "v1alpha1", "rbacassessmentreports", "RbacAssessmentReport", False),
    ("aquasecurity.github.io", "v1alpha1", "clusterrbacassessmentreports", "ClusterRbacAssessmentReport", True),
    ("aquasecurity.github.io", "v1alpha1", "infraassessmentreports", "InfraAssessmentReport", False),
    ("aquasecurity.github.io", "v1alpha1", "clustercompliancereports", "ClusterComplianceReport", True),
    ("aquasecurity.github.io", "v1alpha1", "sbomreports", "SbomReport", False),
    ("wgpolicyk8s.io", "v1alpha2", "policyreports", "PolicyReport", False),
    ("wgpolicyk8s.io", "v1alpha2", "clusterpolicyreports", "ClusterPolicyReport", True),
)
KIND_FOR_PLURAL: dict[str, str] = {plural: kind for _, _, plural, kind, _ in CRD_SOURCES}

# Captured-folder layout (`kubectl get <plural> -A -o json` per file).
FROM_FOLDER_KUBEAPI: dict[str, str] = {
    "namespaces.json": "Namespace",
    "deployments.json": "Deployment",
    "statefulsets.json": "StatefulSet",
    "daemonsets.json": "DaemonSet",
    "cronjobs.json": "CronJob",
    "jobs.json": "Job",
    "replicasets.json": "ReplicaSet",
    "pods.json": "Pod",
    "services.json": "Service",
    "ingresses.json": "Ingress",
    "networkpolicies.json": "NetworkPolicy",
    "nodes.json": "Node",
}
FROM_FOLDER_TRIVY: dict[str, str] = {
    "vulnerabilityreports.json": "VulnerabilityReport",
    "configauditreports.json": "ConfigAuditReport",
    "exposedsecretreports.json": "ExposedSecretReport",
    "rbacassessmentreports.json": "RbacAssessmentReport",
    "clusterrbacassessmentreports.json": "ClusterRbacAssessmentReport",
    "infraassessmentreports.json": "InfraAssessmentReport",
    "clustercompliancereports.json": "ClusterComplianceReport",
    "sbomreports.json": "SbomReport",
}
FROM_FOLDER_KYVERNO: dict[str, str] = {
    "policyreports.json": "PolicyReport",
    "clusterpolicyreports.json": "ClusterPolicyReport",
}
