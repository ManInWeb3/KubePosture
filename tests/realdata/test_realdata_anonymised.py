"""The committed capture must not carry identifying data."""
from __future__ import annotations

import gzip
import ipaddress
import re

import pytest
from kubeposture_importer.kinds import SCAN_KINDS
from kubeposture_importer.relevance import apply_relevance_filter, subject_of_trivy
from kubeposture_importer.snapshot_index import build_index

pytestmark = pytest.mark.realdata

PII_PATTERNS = {
    "email": re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"),
    "aws-account-ecr": re.compile(r"\d{12}\.dkr\.ecr\."),
    # Identifying AWS hostnames have at least two labels before
    # amazonaws.com (bucket / account / endpoint-id + service/region).
    # One label — `eks.amazonaws.com/nodegroup`, `ec2.amazonaws.com` — is
    # a public API name or the well-known label-key domain, not PII.
    "amazonaws-host": re.compile(r"(?<![A-Za-z0-9-])(?:[A-Za-z0-9-]+\.){2,}amazonaws\.com"),
    "gcr-project": re.compile(r"(?:^|[^a-z])gcr\.io/[a-z][a-z0-9-]+/"),
    "aws-key": re.compile(r"AKIA[0-9A-Z]{16}"),
}
# Public AWS key domains used in labels / tolerations (EKS Pod Identity).
_PUBLIC_AWS_DOMAINS = frozenset({"pods.eks.amazonaws.com"})
_IPV4 = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
# Report files carry package / image version strings (1.2.3.4) that parse
# as IPv4 addresses and public package-maintainer emails in SBOM
# `supplier` fields; cluster IPs and team contacts can only live in the
# object inventory.
_INVENTORY_DIRS = ("kubeapi", "kyverno")


def _identifying_ips(text: str) -> set[str]:
    """IPv4 literals that could identify a network. Link-local
    (169.254/16 — NodeLocal DNS, IMDS), loopback and unspecified
    addresses are the same on every cluster and fine to keep."""
    out = set()
    for candidate in _IPV4.findall(text):
        try:
            ip = ipaddress.ip_address(candidate)
        except ValueError:
            continue  # 999.1.1.1-style version noise
        if ip.is_link_local or ip.is_loopback or ip.is_unspecified or ip.is_multicast:
            continue
        out.add(candidate)
    return out


def test_no_pii_patterns(fixture_dir):
    for path in sorted(fixture_dir.rglob("*.gz")):
        text = gzip.open(path, "rt", encoding="utf-8").read()
        for name, pattern in PII_PATTERNS.items():
            if name == "email" and path.parent.name not in _INVENTORY_DIRS:
                continue
            hits = {m.group(0) for m in pattern.finditer(text)} - _PUBLIC_AWS_DOMAINS
            assert not hits, f"{path.name}: {name} → {sorted(hits)[:5]}"
        if path.parent.name in _INVENTORY_DIRS:
            ips = _identifying_ips(text)
            assert not ips, f"{path.name}: ipv4 → {sorted(ips)[:5]}"


@pytest.mark.parametrize(
    ("text", "flagged"),
    [
        ('"eks.amazonaws.com/nodegroup"', False),
        ('"eks.amazonaws.com/component":"x"', False),
        ("https://ec2.amazonaws.com", False),
        ("mybucket.s3.eu-west-1.amazonaws.com", True),
        ("db.abc123.eu-west-1.rds.amazonaws.com", True),
    ],
)
def test_amazonaws_pattern_flags_hosts_not_label_keys(text, flagged):
    assert bool(PII_PATTERNS["amazonaws-host"].search(text)) is flagged


def test_ip_check_allows_link_local_and_flags_private_addresses():
    assert _identifying_ips('"host":"169.254.25.10","a":"127.0.0.1","b":"0.0.0.0"') == set()
    assert _identifying_ips('"ip":"10.1.2.3","x":"192.168.0.7","y":"172.16.4.4"') == {
        "10.1.2.3", "192.168.0.7", "172.16.4.4",
    }
    assert _identifying_ips("version 999.1.1.1 and 1.2.3.4") == {"1.2.3.4"}


def test_dropped_no_subject_reports_are_for_non_workload_kinds(by_kind):
    idx = build_index(by_kind)
    scan_items = {env_kind: list(by_kind[crd]) for crd, env_kind in SCAN_KINDS if crd in by_kind}
    _, stats = apply_relevance_filter(scan_items, idx, enabled=True)
    if "trivy.ConfigAuditReport" not in scan_items or not stats["trivy.ConfigAuditReport"].dropped_no_subject:
        pytest.skip("no ConfigAuditReports were dropped for a missing subject")
    kinds = {subject_of_trivy(it)[1] for it in scan_items["trivy.ConfigAuditReport"]}
    workload_kinds = {"Deployment", "StatefulSet", "DaemonSet", "CronJob", "Job", "Pod", "ReplicaSet"}
    assert kinds - workload_kinds, "every dropped ConfigAudit subject should be a non-workload kind (Service, ConfigMap, Role…)"
