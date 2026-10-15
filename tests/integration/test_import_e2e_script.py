"""The REAL importer process against a live test server.

`scripts/import-cluster.py --from-folder` runs as a subprocess with
KUBEPOSTURE_URL pointing at pytest-django's `live_server` (optionally
through a chaos proxy), then the worker drains in-process and the
resulting DB state is asserted. A synthetic capture keeps this suite
runnable without a real-data fixture; tests/integration/
test_import_e2e_realdata.py repeats the core checks over fixtures/real.
"""
from __future__ import annotations

from datetime import timedelta

import pytest
from django.core.management import call_command
from django.utils import timezone
from kubeposture_importer.bundle import BundleWriter
from kubeposture_importer.http import HttpClient
from kubeposture_importer.upload import UploadError, commit, upload_bundle

from core.api.auth import generate_token
from core.constants import ImportDiscardReason, ImportMarkState
from core.models import (
    Cluster,
    Finding,
    Image,
    ImportMark,
    IngestQueue,
    IngestToken,
    SbomComponent,
    Workload,
    WorkloadSignal,
)
from core.services.inventory import default_finding_qs, restrict_to_currently_deployed_images
from core.services.reaper import STUCK_OPEN_TIMEOUT_SECONDS
from core.services.worker import drain_until_empty

from ._chaos_proxy import ChaosProxy
from ._script_runner import run_import, write_synthetic_capture

pytestmark = [pytest.mark.e2e, pytest.mark.django_db(transaction=True)]

SHA_A = "sha256:" + "a" * 64
SHA_B = "sha256:" + "b" * 64
SHA_OLD = "sha256:" + "0" * 64


@pytest.fixture
def token() -> str:
    plain, hashed = generate_token()
    IngestToken.objects.create(name="e2e-script", token_hash=hashed)
    return plain


@pytest.fixture
def capture(tmp_path):
    return write_synthetic_capture(tmp_path / "capture", cluster="e2e-script")


@pytest.fixture
def scratch(tmp_path):
    d = tmp_path / "scratch"
    d.mkdir()
    return d


def _marks(cluster: str, import_id: str | None = None):
    qs = ImportMark.objects.filter(cluster__name=cluster)
    if import_id:
        qs = qs.filter(import_id=import_id)
    return {m.kind: m for m in qs}


def test_first_cycle_imports_filters_and_leaves_no_queue_rows(live_server, token, capture, scratch):
    run = run_import(cluster="e2e-script", folder=capture, url=live_server.url, token=token, tmp_dir=scratch)
    assert run.returncode == 0, run.stderr
    assert "COMMITTED import_id=" in run.stdout
    assert run.summary and run.summary["rc"] == 0
    # 2 vuln reports in the capture, 1 for the RS-history image → dropped
    assert run.summary["kinds"]["trivy.VulnerabilityReport"] == {
        "total": 2, "kept": 1, "dropped_no_subject": 0, "dropped_image_not_deployed": 1,
        "expected": 1, "matched": 1, "ratio": 1.0, "status": "ok", "count": 1,
    }
    # 3 SBOMs: live api, old api (dropped), CronJob with no pods (dropped)
    assert run.summary["kinds"]["trivy.SbomReport"]["count"] == 1
    assert run.summary["kinds"]["trivy.ConfigAuditReport"]["count"] == 0, "installed-but-empty → count-0 bundle"
    assert run.summary["kinds"]["kyverno.PolicyReport"]["count"] == 1
    assert list(scratch.iterdir()) == [], "bundle files cleaned up"

    totals = drain_until_empty()
    assert totals["failed"] == 0 and totals["ok"] >= 4

    cluster = Cluster.objects.get(name="e2e-script")
    marks = _marks("e2e-script")
    assert set(marks) == {"inventory", "trivy.VulnerabilityReport", "trivy.SbomReport",
                          "trivy.ConfigAuditReport", "kyverno.PolicyReport"}
    assert all(m.state == ImportMarkState.REAPED.value and not m.discard_reason for m in marks.values())
    assert cluster.last_complete_inventory_at == marks["inventory"].started_at
    assert IngestQueue.objects.count() == 0
    assert marks["trivy.VulnerabilityReport"].coverage_expected == 1
    assert marks["trivy.VulnerabilityReport"].coverage_matched == 1
    assert marks["trivy.VulnerabilityReport"].bundle_manifest["relevance_filter"] is True
    assert marks["trivy.VulnerabilityReport"].bundle_manifest["filter"]["dropped_image_not_deployed"] == 1
    assert marks["trivy.ConfigAuditReport"].observed_count == 0

    wl = Workload.objects.get(cluster=cluster, kind="Deployment", name="api")
    assert wl.deployed is True
    assert Workload.objects.get(cluster=cluster, kind="CronJob", name="nightly").deployed is True
    assert Image.objects.currently_running(cluster=cluster).filter(digest=SHA_A).exists()
    finding = Finding.objects.get(vuln_id="CVE-2024-100")
    assert finding.workload_id == wl.id
    assert restrict_to_currently_deployed_images(default_finding_qs()).filter(pk=finding.pk).exists()
    assert not Image.objects.filter(digest=SHA_OLD).exists(), "RS-history image never shipped"
    assert SbomComponent.objects.filter(image__digest=SHA_A, purl="pkg:deb/debian/openssl@3.0.1").exists()
    assert WorkloadSignal.objects.get(workload=wl, signal_id="kyverno:disallow-host-namespaces").currently_active


def test_second_cycle_advances_watermark_and_a_removed_workload_goes_undeployed(live_server, token, capture, scratch, tmp_path):
    first = run_import(cluster="e2e-script", folder=capture, url=live_server.url, token=token, tmp_dir=scratch)
    assert first.returncode == 0, first.stderr
    drain_until_empty()
    cluster = Cluster.objects.get(name="e2e-script")
    anchor_1 = cluster.last_complete_inventory_at

    second = run_import(cluster="e2e-script", folder=capture, url=live_server.url, token=token, tmp_dir=scratch)
    assert second.returncode == 0, second.stderr
    drain_until_empty()
    cluster.refresh_from_db()
    assert cluster.last_complete_inventory_at > anchor_1
    assert ImportMark.objects.filter(cluster=cluster).count() == 10
    assert all(m.state == ImportMarkState.REAPED.value for m in ImportMark.objects.filter(cluster=cluster))
    assert IngestQueue.objects.count() == 0

    # Cycle 3: the api Deployment is gone from the cluster.
    mutated = write_synthetic_capture(tmp_path / "mutated", cluster="e2e-script", with_api=False)
    third = run_import(cluster="e2e-script", folder=mutated, url=live_server.url, token=token, tmp_dir=scratch)
    assert third.returncode == 0, third.stderr
    drain_until_empty()
    wl = Workload.objects.get(cluster=cluster, kind="Deployment", name="api")
    assert wl.deployed is False
    finding = Finding.objects.get(vuln_id="CVE-2024-100")
    assert not restrict_to_currently_deployed_images(default_finding_qs()).filter(pk=finding.pk).exists()


def test_filter_disabled_is_lossless_for_visible_findings(live_server, token, capture, scratch):
    on = run_import(cluster="e2e-on", folder=capture, url=live_server.url, token=token, tmp_dir=scratch)
    off = run_import(cluster="e2e-off", folder=capture, url=live_server.url, token=token, tmp_dir=scratch,
                     extra_args=["--no-relevance-filter"])
    assert on.returncode == 0 and off.returncode == 0, on.stderr + off.stderr
    assert off.summary["kinds"]["trivy.SbomReport"]["count"] == 3 > on.summary["kinds"]["trivy.SbomReport"]["count"]
    drain_until_empty()

    def visible(name):
        c = Cluster.objects.get(name=name)
        return set(restrict_to_currently_deployed_images(default_finding_qs(cluster=c)).values_list("vuln_id", flat=True))

    assert visible("e2e-on") == visible("e2e-off") == {"CVE-2024-100"}
    running = lambda name: set(Image.objects.currently_running(cluster=Cluster.objects.get(name=name)).values_list("digest", flat=True))  # noqa: E731
    assert running("e2e-on") == running("e2e-off") == {SHA_A}
    assert Image.objects.filter(digest=SHA_OLD).exists(), "unfiltered import did ship the RS-history image"


def test_upload_failure_mid_way_aborts_and_leaves_nothing(live_server, token, capture, scratch):
    # Every SBOM bundle upload gets a 500: retried 3×, then the importer
    # aborts the whole import. Earlier bundles were already stored
    # server-side and must vanish with the abort.
    with ChaosProxy(live_server.url, fail_paths={"/bundles/trivy.SbomReport/": 500}) as proxy:
        run = run_import(cluster="e2e-chaos", folder=capture, url=proxy.url, token=token, tmp_dir=scratch)
    assert run.returncode == 1
    assert "ABORTED import_id=" in run.stderr
    assert run.summary and run.summary["aborted"] is True
    assert proxy.count("/bundles/trivy.SbomReport/") == 3, "5xx is retried, then the import is aborted"
    assert proxy.seen[-1].endswith("/abort/")
    assert not any(p.endswith("/commit/") for p in proxy.seen)
    assert drain_until_empty()["claimed"] == 0
    assert not ImportMark.objects.filter(cluster__name="e2e-chaos").exists()
    assert not IngestQueue.objects.filter(cluster_name="e2e-chaos").exists()
    assert not Workload.objects.filter(cluster__name="e2e-chaos").exists()

    clean = run_import(cluster="e2e-chaos", folder=capture, url=live_server.url, token=token, tmp_dir=scratch)
    assert clean.returncode == 0, clean.stderr


def test_commit_with_wrong_count_is_rejected_then_corrected(live_server, token, scratch):
    client = HttpClient(live_server.url, token, timeout=30)
    with BundleWriter(cluster="e2e-count", import_id="IMPCOUNT0000000000000000001", kind="inventory",
                      tmp_dir=scratch) as w:
        w.write_inventory_envelope({"name": "e2e-count"}, [])
        meta = w.finish()
    upload_bundle(client, import_id="IMPCOUNT0000000000000000001", meta=meta)
    with pytest.raises(UploadError) as excinfo:
        commit(client, import_id="IMPCOUNT0000000000000000001", cluster="e2e-count", kinds={"inventory": 3})
    assert excinfo.value.status == 409 and "count_mismatch" in excinfo.value.detail
    assert ImportMark.objects.get(import_id="IMPCOUNT0000000000000000001").state == ImportMarkState.OPEN.value
    resp = commit(client, import_id="IMPCOUNT0000000000000000001", cluster="e2e-count", kinds={"inventory": 1})
    assert resp["status"] == "committed"
    meta.unlink()


def test_uncommitted_import_is_discarded_by_the_safety_net(live_server, token, scratch):
    client = HttpClient(live_server.url, token, timeout=30)
    with BundleWriter(cluster="e2e-stuck", import_id="IMPSTUCK0000000000000000001", kind="inventory",
                      tmp_dir=scratch) as w:
        w.write_inventory_envelope({"name": "e2e-stuck"}, [])
        meta = w.finish()
    upload_bundle(client, import_id="IMPSTUCK0000000000000000001", meta=meta)
    meta.unlink()
    assert drain_until_empty()["claimed"] == 0
    ImportMark.objects.filter(cluster__name="e2e-stuck").update(
        started_at=timezone.now() - timedelta(seconds=STUCK_OPEN_TIMEOUT_SECONDS + 60),
    )
    call_command("reap_safety_net")
    mark = ImportMark.objects.get(cluster__name="e2e-stuck")
    assert mark.state == ImportMarkState.REAPED.value
    assert mark.discard_reason == ImportDiscardReason.STUCK_OPEN.value
    assert IngestQueue.objects.filter(cluster_name="e2e-stuck").count() == 0
    assert Cluster.objects.get(name="e2e-stuck").last_complete_inventory_at is None


def test_on_demand_only_runs_and_clears_the_pending_flag(live_server, token, capture, scratch):
    cluster = Cluster.objects.create(name="e2e-demand", reimport_requested_at=timezone.now())
    run = run_import(cluster="e2e-demand", folder=capture, url=live_server.url, token=token, tmp_dir=scratch,
                     extra_args=["--on-demand-only"])
    assert run.returncode == 0, run.stderr
    assert "running full import" in run.stdout
    cluster.refresh_from_db()
    assert cluster.reimport_requested_at is None

    again = run_import(cluster="e2e-demand", folder=capture, url=live_server.url, token=token, tmp_dir=scratch,
                       extra_args=["--on-demand-only"])
    assert again.returncode == 0 and "no pending request" in again.stdout
    assert again.summary is None, "nothing imported on an idle tick"


def test_request_sequence_on_the_wire(live_server, token, capture, scratch):
    """Through a transparent proxy: inventory first, SBOM last, one
    commit, nothing else."""
    with ChaosProxy(live_server.url) as proxy:
        run = run_import(cluster="e2e-wire", folder=capture, url=proxy.url, token=token, tmp_dir=scratch)
    assert run.returncode == 0, run.stderr
    assert sum(1 for p in proxy.seen if "/bundles/" in p) == 5
    assert proxy.seen[0].endswith("/bundles/inventory/"), "inventory first"
    assert proxy.seen[-2].endswith("/bundles/trivy.SbomReport/"), "SBOM last"
    assert proxy.seen[-1].endswith("/commit/")
    assert len(proxy.seen) == 6
