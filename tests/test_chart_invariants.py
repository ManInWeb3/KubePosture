"""Cross-component timing and packaging invariants that no single file
can assert on its own: the central's import lock vs the importer Job's
deadline vs the reaper's stuck-open TTL, the importer's upload budget,
and repo hygiene the charts/CI rely on."""
from __future__ import annotations

from pathlib import Path

import yaml

from core.services.reaper import STUCK_OPEN_TIMEOUT_SECONDS

REPO = Path(__file__).resolve().parents[1]
CENTRAL = REPO / "deploy/charts/kubeposture"
IMPORTER = REPO / "deploy/charts/kubeposture-import"


def _values(chart: Path) -> dict:
    return yaml.safe_load((chart / "values.yaml").read_text())


def test_import_lock_covers_the_importer_job_and_expires_before_stuck_open_discard():
    lock = int(_values(CENTRAL)["app"]["env"]["IMPORT_LOCK_TIMEOUT_SECONDS"])
    importer = _values(IMPORTER)
    job_deadline = int(importer["activeDeadlineSeconds"])
    trigger_deadline = int(importer["trigger"]["activeDeadlineSeconds"])

    assert lock >= job_deadline, "a slow-but-alive import must not be raced by a second one"
    assert lock >= trigger_deadline
    assert lock < STUCK_OPEN_TIMEOUT_SECONDS, (
        "an abandoned import must stop gating new ones before the reaper discards it"
    )


def test_upload_deadline_leaves_room_for_a_clean_abort():
    importer = _values(IMPORTER)
    assert int(importer["uploadDeadlineSeconds"]) < int(importer["activeDeadlineSeconds"])


def test_every_importer_pod_template_gets_the_shared_env_and_tmp_volume():
    helpers = (IMPORTER / "templates/_helpers.tpl").read_text()
    for var in ("KUBEPOSTURE_RELEVANCE_FILTER", "KUBEPOSTURE_COVERAGE_MIN_RATIO",
                "KUBEPOSTURE_UPLOAD_DEADLINE_SECONDS", "KUBEPOSTURE_LOG_LEVEL", "KUBEPOSTURE_TMP"):
        assert var in helpers
    assert "sizeLimit" in helpers
    for name in ("cronjob.yaml", "cronjob-trigger.yaml", "job-initial.yaml"):
        text = (IMPORTER / "templates" / name).read_text()
        assert 'include "kubeposture-import.containerEnv"' in text, name
        assert 'include "kubeposture-import.tmpVolume"' in text, name
        assert "mountPath: /tmp" in text, name


def test_central_chart_carries_the_bundle_settings():
    env = _values(CENTRAL)["app"]["env"]
    for key in (
        "IMPORT_BUNDLE_MAX_COMPRESSED_BYTES", "IMPORT_BUNDLE_MAX_UNCOMPRESSED_BYTES",
        "IMPORT_COVERAGE_ALERT_RATIO", "IMPORT_KEEP_FAILED_PAYLOADS", "DATA_UPLOAD_MAX_MEMORY_SIZE",
    ):
        assert key in env, key
    assert "INGEST_QUEUE_MAX_ATTEMPTS" not in env, "dead setting"
    assert env["IMPORT_KEEP_FAILED_PAYLOADS"] == "false", "debug flag must default off"


def test_release_workflow_treats_importer_changes_as_release_relevant():
    """release.yml only cuts a release when 'release-relevant' paths
    changed since the last tag; the importer ships in the same image, so
    scripts/ must be in that filter or an importer fix would silently
    never be released."""
    text = (REPO / ".github/workflows/release.yml").read_text()
    assert "scripts/" in text
    assert "deploy/charts/kubeposture-import/" in text


def test_dockerignore_excludes_tests_and_real_fixtures():
    lines = {ln.strip() for ln in (REPO / ".dockerignore").read_text().splitlines()}
    for entry in ("tests", "core/tests", "scripts/importer_tests", "fixtures/real", ".github"):
        assert entry in lines, entry
