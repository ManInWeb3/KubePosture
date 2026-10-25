"""Renders the central chart with `helm template` and checks what only a
render can show. Skipped where helm is not installed (CI's unit job installs it)."""
from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

CHART = Path(__file__).resolve().parents[1] / "deploy/charts/kubeposture"

pytestmark = pytest.mark.skipif(shutil.which("helm") is None, reason="helm is not installed")


def _setup_job(*sets: str) -> dict:
    cmd = ["helm", "template", "ci", str(CHART), "--show-only", "templates/job-setup.yaml"]
    for value in sets:
        cmd += ["--set-string", value]
    return yaml.safe_load(subprocess.run(cmd, check=True, capture_output=True, text=True).stdout)


def _name(*sets: str) -> str:
    return _setup_job(*sets)["metadata"]["name"]


def test_setup_job_name_is_stable_for_unchanged_values():
    assert _name() == _name()


@pytest.mark.parametrize("change", [
    "image.tag=9.9.9",
    "setupJob.resources.limits.memory=3Gi",
    "adminUser.email=ops@example.test",
])
def test_setup_job_name_changes_with_anything_that_changes_the_job(change):
    """A Job's pod template is immutable, so a changed Job must be a new
    object: Helm then creates it and deletes the old one, ArgoCD prunes
    the old one. No `--force`, `Replace=true` or hook is needed."""
    assert _name(change) != _name()


def test_setup_job_name_can_be_pinned():
    pinned = _name("setupJob.nameSuffixOverride=pinned")
    assert pinned.endswith("-setup-pinned")
    assert _name("setupJob.nameSuffixOverride=pinned", "image.tag=9.9.9") == pinned


def test_setup_job_name_fits_a_kubernetes_name_even_with_a_long_release_name():
    name = _name("fullnameOverride=" + "a" * 63)
    assert len(name) <= 63
    assert re.search(r"-setup-[0-9a-f]{7}$", name), name


def test_setup_job_carries_no_deploy_tool_annotations_by_default():
    annotations = _setup_job()["metadata"].get("annotations") or {}
    assert not [k for k in annotations if "argocd" in k or k.startswith("helm.sh/")], annotations
