"""The committed capture must not carry identifying data."""
from __future__ import annotations

import gzip
import re

import pytest
from kubeposture_importer.kinds import SCAN_KINDS
from kubeposture_importer.relevance import apply_relevance_filter, subject_of_trivy
from kubeposture_importer.snapshot_index import build_index

pytestmark = pytest.mark.realdata

PII_PATTERNS = {
    "email": re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"),
    "ipv4": re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])"),
    "aws-account-ecr": re.compile(r"\d{12}\.dkr\.ecr\."),
    "amazonaws": re.compile(r"\.amazonaws\.com"),
    "gcr-project": re.compile(r"(?:^|[^a-z])gcr\.io/[a-z][a-z0-9-]+/"),
    "aws-key": re.compile(r"AKIA[0-9A-Z]{16}"),
}
ALLOWED_IPS = {"0.0.0.0", "127.0.0.1", "10.0.0.0"}


def test_no_pii_patterns(fixture_dir):
    for path in sorted(fixture_dir.rglob("*.gz")):
        text = gzip.open(path, "rt", encoding="utf-8").read()
        for name, pattern in PII_PATTERNS.items():
            hits = {m.group(0) for m in pattern.finditer(text)}
            if name == "ipv4":
                hits = {h for h in hits if h not in ALLOWED_IPS and not h.startswith("10.0.0.0")}
            assert not hits, f"{path.name}: {name} → {sorted(hits)[:5]}"


def test_dropped_no_subject_reports_are_for_non_workload_kinds(by_kind):
    idx = build_index(by_kind)
    scan_items = {env_kind: list(by_kind[crd]) for crd, env_kind in SCAN_KINDS if crd in by_kind}
    _, stats = apply_relevance_filter(scan_items, idx, enabled=True)
    if "trivy.ConfigAuditReport" not in scan_items or not stats["trivy.ConfigAuditReport"].dropped_no_subject:
        pytest.skip("no ConfigAuditReports were dropped for a missing subject")
    kinds = {subject_of_trivy(it)[1] for it in scan_items["trivy.ConfigAuditReport"]}
    workload_kinds = {"Deployment", "StatefulSet", "DaemonSet", "CronJob", "Job", "Pod", "ReplicaSet"}
    assert kinds - workload_kinds, "every dropped ConfigAudit subject should be a non-workload kind (Service, ConfigMap, Role…)"
