"""CLI: argument / env precedence, exit codes, and a whole cycle from a
captured folder against a fake network."""
from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest
from kubeposture_importer import cli

from .fixtures_builders import SHA_A, SHA_OLD, deployment_chain, namespace, replicaset, trivy_report
from .test_importer_http_upload import FakeNet, _http_error, _Resp

_SCRIPT = Path(__file__).resolve().parents[1] / "import-cluster.py"


def test_hyphenated_shim_exposes_main():
    spec = importlib.util.spec_from_file_location("import_cluster_shim", _SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    sys.modules["import_cluster_shim"] = mod
    spec.loader.exec_module(mod)
    assert mod.main is cli.main


def test_parse_args_env_and_flag_precedence():
    base = ["c", "tok"]
    assert cli.parse_args(base, env={}).relevance_filter is True
    assert cli.parse_args(base, env={"KUBEPOSTURE_RELEVANCE_FILTER": "false"}).relevance_filter is False
    assert cli.parse_args(base + ["--no-relevance-filter"], env={"KUBEPOSTURE_RELEVANCE_FILTER": "true"}).relevance_filter is False
    a = cli.parse_args(base, env={"KUBEPOSTURE_COVERAGE_MIN_RATIO": "0.5", "KUBEPOSTURE_UPLOAD_DEADLINE_SECONDS": "77",
                                  "KUBEPOSTURE_URL": "https://central/", "KUBEPOSTURE_TMP": "/scratch"})
    assert (a.coverage_threshold, a.upload_deadline, a.base_url, str(a.tmp_dir)) == (0.5, 77, "https://central/", "/scratch")
    b = cli.parse_args(base + ["--coverage-min-ratio", "0.8", "--upload-deadline-seconds", "9"], env={})
    assert (b.coverage_threshold, b.upload_deadline) == (0.8, 9)
    assert cli.parse_args(["c"], env={"KUBEPOSTURE_TOKEN": "fromenv"}).token == "fromenv"


def test_missing_token_and_bad_folder_exit_2(tmp_path, monkeypatch, capsys):
    monkeypatch.delenv("KUBEPOSTURE_TOKEN", raising=False)
    assert cli.main(["c"]) == 2
    monkeypatch.setenv("KUBEPOSTURE_TOKEN", "tok")
    assert cli.main(["c", "--from-folder", str(tmp_path / "nope")]) == 2
    err = capsys.readouterr().err
    assert "token required" in err and "not a directory" in err


def test_on_demand_only_exits_0_without_importing_when_nothing_pending(monkeypatch, tmp_path):
    monkeypatch.setenv("KUBEPOSTURE_TOKEN", "tok")
    net = FakeNet([_Resp(200, {"pending": False, "in_flight": False})])
    monkeypatch.setattr(cli, "HttpClient", lambda *a, **k: net.client())
    assert cli.main(["c", "--on-demand-only", "--from-folder", str(tmp_path)]) == 0
    assert net.paths() == ["api/v1/imports/pending/?cluster=c"]

    net = FakeNet([_Resp(200, {"pending": True, "in_flight": True})])
    monkeypatch.setattr(cli, "HttpClient", lambda *a, **k: net.client())
    assert cli.main(["c", "--on-demand-only", "--from-folder", str(tmp_path)]) == 0
    assert len(net.calls) == 1


def _capture(tmp_path: Path) -> Path:
    root = tmp_path / "capture"
    (root / "kubeapi").mkdir(parents=True)
    (root / "trivy").mkdir()
    chain = deployment_chain("api", digest=SHA_A)
    old_rs = replicaset("api-old", owner_name="api", image=f"r/app:0@{SHA_OLD}", replicas=0)
    (root / "kubeapi/namespaces.json").write_text(json.dumps({"items": [namespace("ns")]}))
    (root / "kubeapi/deployments.json").write_text(json.dumps({"items": [chain[0]]}))
    (root / "kubeapi/replicasets.json").write_text(json.dumps({"items": [chain[1], old_rs]}))
    (root / "kubeapi/pods.json").write_text(json.dumps({"items": [chain[2]]}))
    (root / "trivy/vulnerabilityreports.json").write_text(json.dumps({"items": [
        trivy_report("VulnerabilityReport", subject_name="api-abc", digest=SHA_A),
        trivy_report("VulnerabilityReport", subject_name="api-old", digest=SHA_OLD),
    ]}))
    (root / "trivy/sbomreports.json").write_text(json.dumps({"items": []}))
    return root


def test_full_cycle_from_folder_uploads_filters_and_prints_summary(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("KUBEPOSTURE_TOKEN", "tok")
    monkeypatch.setenv("KUBEPOSTURE_TMP", str(tmp_path / "tmp"))
    net = FakeNet([_Resp(201, {"status": "stored"})] * 3 + [_Resp(200, {"status": "committed"})])
    monkeypatch.setattr(cli, "HttpClient", lambda *a, **k: net.client())

    rc = cli.main(["c", "--from-folder", str(_capture(tmp_path))])

    assert rc == 0
    out = capsys.readouterr().out
    assert "filter kind=trivy.VulnerabilityReport total=2 kept=1 dropped_no_subject=0 dropped_image_not_deployed=1" in out
    assert "coverage kind=trivy.VulnerabilityReport expected=1 matched=1 ratio=1.00 threshold=0.90 status=ok" in out
    assert "COMMITTED import_id=" in out
    summary_line = next(ln for ln in out.splitlines() if ln.startswith("SUMMARY "))
    summary = json.loads(summary_line[len("SUMMARY "):])
    assert summary["rc"] == 0 and summary["aborted"] is False
    assert summary["kinds"]["inventory"] == {"count": 1}
    assert summary["kinds"]["trivy.VulnerabilityReport"]["count"] == 1
    assert summary["kinds"]["trivy.SbomReport"]["count"] == 0
    assert "trivy.ConfigAuditReport" not in summary["kinds"], "absent CRD → not part of the import"
    assert summary["deployed_digests"] == 1 and summary["controllers"] == 1

    paths = net.paths()
    import_id = paths[0].split("/")[3]
    assert paths == [
        f"api/v1/imports/{import_id}/bundles/inventory/",
        f"api/v1/imports/{import_id}/bundles/trivy.VulnerabilityReport/",
        f"api/v1/imports/{import_id}/bundles/trivy.SbomReport/",
        f"api/v1/imports/{import_id}/commit/",
    ]
    assert json.loads(net.calls[-1][3])["kinds"] == [
        {"kind": "inventory", "count": 1},
        {"kind": "trivy.VulnerabilityReport", "count": 1},
        {"kind": "trivy.SbomReport", "count": 0},
    ]
    assert list((tmp_path / "tmp").iterdir()) == [], "bundle files cleaned up"


def test_full_cycle_with_filter_disabled_ships_everything(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("KUBEPOSTURE_TOKEN", "tok")
    net = FakeNet([_Resp(201)] * 3 + [_Resp(200)])
    monkeypatch.setattr(cli, "HttpClient", lambda *a, **k: net.client())
    assert cli.main(["c", "--from-folder", str(_capture(tmp_path)), "--no-relevance-filter"]) == 0
    summary = json.loads(next(ln for ln in capsys.readouterr().out.splitlines() if ln.startswith("SUMMARY "))[8:])
    assert summary["relevance_filter"] is False
    assert summary["kinds"]["trivy.VulnerabilityReport"]["count"] == 2
    assert summary["kinds"]["trivy.VulnerabilityReport"]["dropped_image_not_deployed"] == 1, "stats still computed"


def test_upload_failure_aborts_and_exits_1(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("KUBEPOSTURE_TOKEN", "tok")
    net = FakeNet([_Resp(201), _http_error(413, {"error": "bundle_too_large"}), _Resp(200, {"status": "aborted"})])
    monkeypatch.setattr(cli, "HttpClient", lambda *a, **k: net.client())
    rc = cli.main(["c", "--from-folder", str(_capture(tmp_path))])
    captured = capsys.readouterr()
    assert rc == 1
    assert "ABORTED import_id=" in captured.err and "bundle_too_large" in captured.err
    assert net.paths()[-1].endswith("/abort/")
    summary = json.loads(next(ln for ln in captured.out.splitlines() if ln.startswith("SUMMARY "))[8:])
    assert summary["rc"] == 1 and summary["aborted"] is True


@pytest.mark.parametrize("flag", [True, False])
def test_pending_cleared_only_on_success(tmp_path, monkeypatch, flag):
    monkeypatch.setenv("KUBEPOSTURE_TOKEN", "tok")
    script = [_Resp(200, {"pending": True, "in_flight": False, "requested_at": "2026-01-01T00:00:00Z"})]
    if flag:
        script += [_Resp(201)] * 3 + [_Resp(200, {"status": "committed"}), _Resp(200, {"cleared": True})]
    else:
        script += [_http_error(400)] + [_Resp(200)]
    net = FakeNet(script)
    monkeypatch.setattr(cli, "HttpClient", lambda *a, **k: net.client())
    rc = cli.main(["c", "--on-demand-only", "--from-folder", str(_capture(tmp_path))])
    cleared = "api/v1/imports/pending/clear/" in net.paths()
    assert (rc == 0) is flag and cleared is flag


# ── failed-Job cleanup runs after EVERY successful run ─────────────


@pytest.fixture
def cleanup_calls(monkeypatch):
    """Patch the kube side of the cleanup; returns the list of calls."""
    from kubeposture_importer.sources import kube as kube_source

    calls: list[dict] = []
    monkeypatch.setattr(kube_source, "load_kube_config", lambda kubeconfig, in_cluster: "kube-client")
    monkeypatch.setattr(kube_source, "cleanup_failed_sibling_jobs",
                        lambda client, **kw: calls.append({"client": client, **kw}))
    monkeypatch.setenv("KUBEPOSTURE_TOKEN", "tok")
    monkeypatch.setenv("KUBEPOSTURE_CLEANUP_FAILED_JOBS", "true")
    monkeypatch.setenv("KUBEPOSTURE_NAMESPACE", "ns")
    monkeypatch.setenv("KUBEPOSTURE_CRONJOB_NAME", "imp-trigger")
    return calls


@pytest.mark.parametrize("pending", [
    {"pending": False, "in_flight": False},   # the common idle tick
    {"pending": True, "in_flight": True},     # another import already running
])
def test_idle_trigger_tick_cleans_up_its_own_failed_jobs(monkeypatch, cleanup_calls, pending):
    """The trigger's idle ticks used to return before the cleanup (and had
    no kube client loaded), so a failed trigger Job was only cleared on
    the rare tick that actually imported."""
    net = FakeNet([_Resp(200, pending)])
    monkeypatch.setattr(cli, "HttpClient", lambda *a, **k: net.client())
    assert cli.main(["c", "--on-demand-only", "--in-cluster"]) == 0
    assert cleanup_calls == [{"client": "kube-client", "namespace": "ns", "cronjob_name": "imp-trigger"}]


def test_failed_run_does_not_clean_up(monkeypatch, cleanup_calls):
    net = FakeNet([_http_error(503)] * 10)
    monkeypatch.setenv("KUBEPOSTURE_HTTP_RETRY_BASE_DELAY", "0")
    monkeypatch.setattr(cli, "HttpClient", lambda *a, **k: net.client())
    assert cli.main(["c", "--on-demand-only", "--in-cluster"]) == 1
    assert cleanup_calls == []


def test_cleanup_off_or_unconfigured_or_from_folder_is_skipped(monkeypatch, cleanup_calls, tmp_path, capsys):
    def tick(*extra):
        net = FakeNet([_Resp(200, {"pending": False})])
        monkeypatch.setattr(cli, "HttpClient", lambda *a, **k: net.client())
        return cli.main(["c", "--on-demand-only", *extra])

    monkeypatch.setenv("KUBEPOSTURE_CLEANUP_FAILED_JOBS", "false")
    assert tick("--in-cluster") == 0
    monkeypatch.setenv("KUBEPOSTURE_CLEANUP_FAILED_JOBS", "true")
    assert tick("--from-folder", str(tmp_path)) == 0, "a local replay has no CronJob to clean"
    monkeypatch.delenv("KUBEPOSTURE_CRONJOB_NAME")
    assert tick("--in-cluster") == 0
    assert cleanup_calls == []
    assert "KUBEPOSTURE_CRONJOB_NAME not set" in capsys.readouterr().err


def test_cleanup_error_never_changes_the_exit_code(monkeypatch, cleanup_calls, capsys):
    from kubeposture_importer.sources import kube as kube_source

    def boom(*a, **k):
        raise RuntimeError("no in-cluster config")

    monkeypatch.setattr(kube_source, "load_kube_config", boom)
    net = FakeNet([_Resp(200, {"pending": False})])
    monkeypatch.setattr(cli, "HttpClient", lambda *a, **k: net.client())
    assert cli.main(["c", "--on-demand-only", "--in-cluster"]) == 0
    assert "cleanup: skipped: no in-cluster config" in capsys.readouterr().err
