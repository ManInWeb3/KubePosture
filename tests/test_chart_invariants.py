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


def test_every_cronjob_runs_with_guaranteed_qos():
    """Batch jobs set requests == limits so a job is only ever killed for
    exceeding its *own* memory, never evicted because a neighbour spiked.
    Sizes come from the `command.finished peak_rss_mb=` log line."""
    values = _values(CENTRAL)
    jobs = dict(values["cronJobs"], worker=values["worker"])
    for name, job in jobs.items():
        res = job["resources"]
        assert res["requests"] == res["limits"], f"{name}: requests must equal limits"
    # QoS is pod-level: the shared wait-for-db init container must match too.
    helpers = (CENTRAL / "templates/_helpers.tpl").read_text()
    block = helpers.split('define "kubeposture.waitForDb"')[1].split("{{- end }}")[0]
    res = yaml.safe_load(block.split("resources:")[1])
    assert res["requests"] == res["limits"], "wait-for-db init container"


def test_central_tmp_is_a_bounded_disk_backed_emptydir():
    """Every central pod gets its volumes from the shared
    `kubeposture.volumes` helper, and that helper's /tmp is a bounded,
    disk-backed emptyDir."""
    values = _values(CENTRAL)
    assert values["tmp"]["sizeLimit"]

    helpers = (CENTRAL / "templates/_helpers.tpl").read_text()
    volumes = helpers.split('define "kubeposture.volumes"')[1].split("{{- end }}\n\n")[0]
    assert "name: tmp" in volumes and "emptyDir:" in volumes
    assert "sizeLimit: {{ .Values.tmp.sizeLimit }}" in volumes
    mounts = helpers.split('define "kubeposture.volumeMounts"')[1].split("{{- end }}\n\n")[0]
    assert "mountPath: /tmp" in mounts

    for name in ("deployment-web.yaml", "deployment-worker.yaml", "job-setup.yaml",
                 "cronjobs.yaml"):
        text = (CENTRAL / "templates" / name).read_text()
        assert 'include "kubeposture.volumes"' in text, f"{name}: must use the shared volumes helper"
        assert 'include "kubeposture.volumeMounts"' in text, f"{name}: must use the shared mounts helper"
    for path in (CENTRAL / "templates").iterdir():
        assert "medium: Memory" not in path.read_text(), f"{path.name}: /tmp must not count against the memory limit"


def test_values_schema_is_generated_and_referenced():
    """Both charts ship a values.schema.json generated by dadav/helm-schema
    (CI runs `helm-schema -c deploy/charts -n -a --check`; this only guards
    the pieces a careless edit could drop: the file, the editor reference,
    the shared definitions the `$ref`s point at, and the closed root)."""
    import json

    for chart in (CENTRAL, IMPORTER):
        values = (chart / "values.yaml").read_text().splitlines()
        assert values[0] == "# yaml-language-server: $schema=values.schema.json", chart.name
        schema = json.loads((chart / "values.schema.json").read_text())
        assert schema["$schema"] == "http://json-schema.org/draft-07/schema#"
        assert schema["additionalProperties"] is False, f"{chart.name}: typo'd top-level keys must be rejected"
        for name in ("quantity", "resources", "resourceList", "cronSchedule", "stringMap"):
            assert name in schema["definitions"], f"{chart.name}: definition {name}"
        # every $ref in the file resolves to a definition
        text = (chart / "values.schema.json").read_text()
        import re
        for ref in set(re.findall(r'"\$ref": "#/definitions/([A-Za-z]+)"', text)):
            assert ref in schema["definitions"], f"{chart.name}: dangling $ref {ref}"

    central = json.loads((CENTRAL / "values.schema.json").read_text())
    assert central["properties"]["cronJobs"]["additionalProperties"] == {"$ref": "#/definitions/cronJob"}, (
        "extra CronJobs must be allowed and must follow the cronJob shape"
    )
    env = central["properties"]["app"]["properties"]["env"]
    assert env["additionalProperties"]["type"] == ["string", "number", "boolean"] and "properties" not in env, (
        "app.env is a free-form map; --set app.env.X=1 must validate"
    )
    importer = json.loads((IMPORTER / "values.schema.json").read_text())
    assert "clusterName" in importer["required"] and importer["properties"]["clusterName"]["minLength"] == 1


def test_importer_can_delete_jobs_only_in_its_own_namespace():
    """cleanupFailedJobsOnSuccess needs `delete` on Jobs — granted by a
    namespaced Role, never by the ClusterRole (which would allow deleting
    Jobs in every namespace of the cluster)."""
    cluster_role = (IMPORTER / "templates/clusterrole.yaml").read_text()
    verbs = [ln for ln in cluster_role.splitlines() if ln.strip().startswith("verbs:")]
    assert verbs and not any("delete" in ln for ln in verbs), "ClusterRole must stay read-only"
    role = (IMPORTER / "templates/role.yaml").read_text()
    assert "kind: Role\n" in role and "kind: RoleBinding" in role
    assert 'resources: ["jobs"]' in role and 'verbs: ["delete"]' in role
    assert "if .Values.cleanupFailedJobsOnSuccess" in role


def test_worker_time_budget_sits_under_the_job_deadline_and_the_stale_reclaim():
    """--max-seconds must leave headroom under activeDeadlineSeconds (the pass
    in flight still finishes, incl. its reap), and the Job deadline must be
    below STALE_PROCESSING_SECONDS or another pod reclaims an item that a
    still-running worker legitimately holds."""
    from core.services.queue import STALE_PROCESSING_SECONDS

    worker = _values(CENTRAL)["worker"]
    cmd = worker["command"]
    max_seconds = int(cmd[cmd.index("--max-seconds") + 1])
    deadline = int(worker["activeDeadlineSeconds"])

    assert max_seconds + 120 <= deadline, "no headroom for the in-flight item + reap"
    assert deadline < STALE_PROCESSING_SECONDS
