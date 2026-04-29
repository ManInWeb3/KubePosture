"""Preset enumerations for KubePostureNG.

These values are hardcoded by design (Convention D5). Used by models,
parsers, scoring, API, and admin throughout the codebase.
"""
from django.db import models


class Severity(models.TextChoices):
    CRITICAL = "critical", "Critical"
    HIGH = "high", "High"
    MEDIUM = "medium", "Medium"
    LOW = "low", "Low"
    INFO = "info", "Info"
    UNKNOWN = "unknown", "Unknown"


class Category(models.TextChoices):
    VULNERABILITY = "vulnerability", "Vulnerability"
    CONFIG = "config", "Configuration"
    EXPOSED_SECRET = "exposed-secret", "Exposed Secret"
    RBAC = "rbac", "RBAC"
    COMPLIANCE = "compliance", "Compliance"
    POLICY = "policy", "Policy"


class Source(models.TextChoices):
    TRIVY = "trivy", "Trivy"
    KYVERNO = "kyverno", "Kyverno"
    KUBEPOSTURE = "kubepostureng-policy", "KubePostureNG"


class PriorityBand(models.TextChoices):
    IMMEDIATE = "immediate", "Immediate"
    OUT_OF_CYCLE = "out_of_cycle", "Out-of-Cycle"
    SCHEDULED = "scheduled", "Scheduled"
    DEFER = "defer", "Defer"


class Environment(models.TextChoices):
    PROD = "prod", "Production"
    STAGING = "staging", "Staging"
    DEV = "dev", "Development"


class WorkloadKind(models.TextChoices):
    DEPLOYMENT = "Deployment", "Deployment"
    STATEFULSET = "StatefulSet", "StatefulSet"
    DAEMONSET = "DaemonSet", "DaemonSet"
    CRONJOB = "CronJob", "CronJob"
    JOB = "Job", "Job"
    POD = "Pod", "Pod"


class AliasKind(models.TextChoices):
    REPLICASET = "ReplicaSet", "ReplicaSet"
    JOB = "Job", "Job"
    POD = "Pod", "Pod"


class ImportMarkState(models.TextChoices):
    OPEN = "open", "Open"
    DRAINING = "draining", "Draining"
    REAPED = "reaped", "Reaped"


class IngestQueueStatus(models.TextChoices):
    PENDING = "pending", "Pending"
    PROCESSING = "processing", "Processing"
    DONE = "done", "Done"
    FAILED = "failed", "Failed"


class FindingActionType(models.TextChoices):
    ACKNOWLEDGE = "acknowledge", "Acknowledge"
    ACCEPT = "accept", "Accept"
    FALSE_POSITIVE = "false_positive", "False Positive"
    SCHEDULED = "scheduled", "Scheduled"


class FindingActionScope(models.TextChoices):
    PER_FINDING = "per-finding", "Per Finding"
    PER_VULN_IMAGE = "per-vuln-image", "Per (Vuln, Image)"
    PER_VULN = "per-vuln", "Per Vuln"


class SnapshotScope(models.TextChoices):
    GLOBAL = "global", "Global"
    CLUSTER = "cluster", "Cluster"
    NAMESPACE = "namespace", "Namespace"
    WORKLOAD = "workload", "Workload"


class ImageSetChangeKind(models.TextChoices):
    NONE = "none", "No change"
    ADDED = "added", "Added"
    REMOVED = "removed", "Removed"
    REPLACED = "replaced", "Replaced"
    MIXED = "mixed", "Mixed"
    FIRST_SEEN = "first_seen", "First seen"


# Retention for WorkloadImageObservation rows that have flipped to
# currently_deployed=False. The inventory reaper sweeps stale rows
# older than this on every complete cycle. Keeps recent history for
# audit ("this slot used to run X") without unbounded growth.
WORKLOAD_OBSERVATION_RETENTION_DAYS = 30


# Mapping from Trivy CRD severity strings to Severity enum.
TRIVY_SEVERITY_MAP = {
    "CRITICAL": Severity.CRITICAL,
    "HIGH": Severity.HIGH,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
    "INFO": Severity.INFO,
    "UNKNOWN": Severity.UNKNOWN,
}
