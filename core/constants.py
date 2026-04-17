"""
Preset enumerations (Convention D5).

These values are hardcoded. No configuration UI, no custom values.
Used by models, parsers, API, and admin throughout the codebase.
"""
from django.db import models


class Severity(models.TextChoices):
    CRITICAL = "Critical", "Critical"
    HIGH = "High", "High"
    MEDIUM = "Medium", "Medium"
    LOW = "Low", "Low"


class Status(models.TextChoices):
    ACTIVE = "active", "Active"
    ACKNOWLEDGED = "acknowledged", "Acknowledged"
    RISK_ACCEPTED = "risk_accepted", "Risk Accepted"
    FALSE_POSITIVE = "false_positive", "False Positive"
    RESOLVED = "resolved", "Resolved"


class Category(models.TextChoices):
    VULNERABILITY = "vulnerability", "Vulnerability"
    MISCONFIGURATION = "misconfiguration", "Misconfiguration"
    SECRET = "secret", "Secret"
    RBAC = "rbac", "RBAC"
    INFRA = "infra", "Infrastructure"
    POLICY = "policy", "Policy"  # Kyverno (Phase 2)


class Source(models.TextChoices):
    TRIVY = "trivy", "Trivy"
    KYVERNO = "kyverno", "Kyverno"


class Priority(models.TextChoices):
    IMMEDIATE = "immediate", "Immediate"
    OUT_OF_CYCLE = "out_of_cycle", "Out-of-Cycle"
    SCHEDULED = "scheduled", "Scheduled"
    DEFER = "defer", "Defer"


class Origin(models.TextChoices):
    CLUSTER = "cluster", "Cluster"
    CI = "ci", "CI Pipeline"  # Future CI scanning


# EPSS threshold for "high exploit probability" in priority decision tree
EPSS_HIGH_THRESHOLD = 0.1  # 10% — findings above this are considered high-risk

# Severity mapping from Trivy (uppercase) to our TextChoices
TRIVY_SEVERITY_MAP = {
    "CRITICAL": Severity.CRITICAL,
    "HIGH": Severity.HIGH,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
    "UNKNOWN": Severity.LOW,  # Map UNKNOWN to Low
}

# Known Trivy compliance framework IDs (from trivy-operator specs)
TRIVY_FRAMEWORK_IDS = {
    "k8s-cis-1.23",
    "eks-cis-1.4",
    "k8s-nsa-1.0",
    "k8s-pss-baseline-0.1",
    "k8s-pss-restricted-0.1",
}
