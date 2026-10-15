"""Run the real `scripts/import-cluster.py` as a subprocess against a URL
and parse its SUMMARY line; plus a synthetic capture folder so the
script path is exercised even without a real-data fixture."""
from __future__ import annotations

import json
import os
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

from importer_tests.fixtures_builders import (
    SHA_A,
    SHA_B,
    SHA_OLD,
    cronjob,
    deployment_chain,
    kyverno_result,
    namespace,
    policy_report,
    replicaset,
    subject,
    trivy_report,
)

REPO = Path(__file__).resolve().parents[2]
SCRIPT = REPO / "scripts" / "import-cluster.py"


@dataclass
class ScriptRun:
    returncode: int
    stdout: str
    stderr: str
    summary: dict | None


def run_import(*, cluster: str, folder: Path, url: str, token: str, tmp_dir: Path,
               extra_args: list[str] | None = None, env: dict[str, str] | None = None,
               timeout: float = 120) -> ScriptRun:
    cmd = [sys.executable, str(SCRIPT), cluster, "--from-folder", str(folder), *(extra_args or [])]
    full_env = {
        **os.environ,
        "KUBEPOSTURE_URL": url,
        "KUBEPOSTURE_TOKEN": token,
        "KUBEPOSTURE_TMP": str(tmp_dir),
        "KUBEPOSTURE_HTTP_TIMEOUT": "30",
        "KUBEPOSTURE_HTTP_RETRY_BASE_DELAY": "0.05",
        "PYTHONUNBUFFERED": "1",
        **(env or {}),
    }
    proc = subprocess.run(cmd, env=full_env, capture_output=True, text=True, timeout=timeout, cwd=REPO)
    return ScriptRun(proc.returncode, proc.stdout, proc.stderr, parse_summary(proc.stdout))


def start_import(*, cluster: str, folder: Path, url: str, token: str, tmp_dir: Path,
                 env: dict[str, str] | None = None) -> subprocess.Popen:
    cmd = [sys.executable, str(SCRIPT), cluster, "--from-folder", str(folder)]
    full_env = {**os.environ, "KUBEPOSTURE_URL": url, "KUBEPOSTURE_TOKEN": token,
                "KUBEPOSTURE_TMP": str(tmp_dir), "KUBEPOSTURE_HTTP_TIMEOUT": "30",
                "KUBEPOSTURE_HTTP_RETRY_BASE_DELAY": "0.05", "PYTHONUNBUFFERED": "1", **(env or {})}
    return subprocess.Popen(cmd, env=full_env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, cwd=REPO)


def parse_summary(stdout: str) -> dict | None:
    for line in stdout.splitlines():
        if line.startswith("SUMMARY "):
            return json.loads(line[len("SUMMARY "):])
    return None


# ── synthetic capture ──────────────────────────────────────────────

API_IMAGE = "registry.x/app:1"
CRON_IMAGE = "registry.x/cron:1"


def _write(root: Path, rel: str, items: list[dict]) -> None:
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps({"kind": "List", "items": items}))


def write_synthetic_capture(root: Path, *, cluster: str, with_api: bool = True) -> Path:
    """A Deployment→RS→Pod chain with ReplicaSet history, a CronJob with
    no pods, Trivy Vulnerability/SBOM reports for the live and the old
    image, and a Kyverno PolicyReport on the Pod. `with_api=False` drops
    the Deployment chain (simulating its removal on a later cycle)."""
    items_ns = [namespace("ns")]
    deployments, replicasets, pods, vulns, sboms, polrs = [], [], [], [], [], []
    if with_api:
        dep, rs, pod_ = deployment_chain("api", "ns", digest=SHA_A, image=API_IMAGE)
        old_rs = replicaset("api-old", "ns", owner_name="api", image="registry.x/app:0", replicas=0)
        deployments.append(dep)
        replicasets += [rs, old_rs]
        pods.append(pod_)
        vulns += [
            trivy_report("VulnerabilityReport", ns="ns", subject_name="api-abc", digest=SHA_A)
            | {"report": {"artifact": {"repository": "registry.x/app", "tag": "1", "digest": SHA_A},
                          "os": {"family": "debian", "name": "12"},
                          "vulnerabilities": [{"vulnerabilityID": "CVE-2024-100", "resource": "libc6",
                                               "installedVersion": "1.0", "fixedVersion": "1.1",
                                               "severity": "CRITICAL", "score": 9.8, "title": "t", "links": []}]}},
            trivy_report("VulnerabilityReport", ns="ns", subject_name="api-old", digest=SHA_OLD),
        ]
        sboms += [
            trivy_report("SbomReport", ns="ns", subject_name="api-abc", digest=SHA_A)
            | {"report": {"artifact": {"repository": "registry.x/app", "tag": "1", "digest": SHA_A},
                          "components": {"bomFormat": "CycloneDX", "specVersion": "1.4",
                                         "metadata": {"component": {"type": "container", "name": "registry.x/app:1"}},
                                         "components": [{"type": "library", "name": "openssl", "version": "3.0.1",
                                                         "purl": "pkg:deb/debian/openssl@3.0.1", "properties": []}]}}},
            trivy_report("SbomReport", ns="ns", subject_name="api-old", digest=SHA_OLD),
        ]
        polrs.append(policy_report(ns="ns", results=[kyverno_result(subjects=[subject("Pod", "api-abc-x1", "ns")])]))
    cron = cronjob("nightly", "ns", image=CRON_IMAGE)
    sboms.append(trivy_report("SbomReport", ns="ns", subject_kind="CronJob", subject_name="nightly", digest=SHA_B))

    _write(root, "kubeapi/namespaces.json", items_ns)
    _write(root, "kubeapi/deployments.json", deployments)
    _write(root, "kubeapi/replicasets.json", replicasets)
    _write(root, "kubeapi/pods.json", pods)
    _write(root, "kubeapi/cronjobs.json", [cron])
    _write(root, "trivy/vulnerabilityreports.json", vulns)
    _write(root, "trivy/sbomreports.json", sboms)
    _write(root, "trivy/configauditreports.json", [])
    _write(root, "kyverno/policyreports.json", polrs)
    (root / "kubeapi/version.json").write_text(json.dumps({"serverVersion": {"gitVersion": "v1.30.2"}}))
    return root
