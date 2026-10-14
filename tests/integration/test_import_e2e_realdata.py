"""The real importer against a live server, over the anonymised
real-cluster captures under fixtures/real/ (skipped when none exist).
Golden expectations (`golden/expectations.yaml`, assertion DSL) are
evaluated after the first cycle when present."""
from __future__ import annotations

import json

import pytest
import yaml
from kubeposture_importer.snapshot_index import build_index
from kubeposture_importer.sources.folder import collect_from_folder

from core.api.auth import generate_token
from core.constants import ImportMarkState
from core.models import Cluster, Finding, ImportMark, IngestQueue, IngestToken, Workload
from core.services.inventory import default_finding_qs, restrict_to_currently_deployed_images
from core.services.test_assertions import evaluate_assertions
from core.services.worker import drain_until_empty

from ..realdata.conftest import real_fixture_dirs
from ._script_runner import run_import

pytestmark = [pytest.mark.e2e, pytest.mark.realdata, pytest.mark.django_db(transaction=True)]


@pytest.fixture(params=real_fixture_dirs() or [None], ids=lambda p: p.name if p else "no-fixtures")
def fixture_dir(request):
    if request.param is None:
        pytest.skip("no anonymised captures under fixtures/real/")
    return request.param


@pytest.fixture
def token() -> str:
    plain, hashed = generate_token()
    IngestToken.objects.create(name="e2e-realdata", token_hash=hashed)
    return plain


def test_first_cycle_matches_golden_and_second_cycle_reaps_cleanly(live_server, token, fixture_dir, tmp_path):
    alias = fixture_dir.name
    scratch = tmp_path / "scratch"
    scratch.mkdir()

    run = run_import(cluster=alias, folder=fixture_dir, url=live_server.url, token=token, tmp_dir=scratch, timeout=600)
    assert run.returncode == 0, run.stderr[-4000:]
    assert run.summary and run.summary["rc"] == 0
    totals = drain_until_empty(limit=200, max_iterations=2000)
    assert totals["failed"] == 0, f"{totals['failed']} items failed; see ImportMark.last_error"

    cluster = Cluster.objects.get(name=alias)
    marks = {m.kind: m for m in ImportMark.objects.filter(cluster=cluster)}
    assert all(m.state == ImportMarkState.REAPED.value and not m.discard_reason for m in marks.values()), {
        k: (m.state, m.discard_reason, m.last_error[:120]) for k, m in marks.items()
    }
    assert cluster.last_complete_inventory_at == marks["inventory"].started_at
    assert IngestQueue.objects.count() == 0

    # Coverage persisted on the server equals what the importer printed.
    for kind, summary in run.summary["kinds"].items():
        if kind == "inventory":
            continue
        assert (marks[kind].coverage_expected, marks[kind].coverage_matched) == (summary["expected"], summary["matched"]), kind
        assert marks[kind].observed_count == summary["count"], kind

    # No finding on an image outside the deployed-digest set.
    idx = build_index(collect_from_folder(fixture_dir))
    stray = Finding.objects.filter(cluster=cluster, image__isnull=False).exclude(image__digest__in=idx.deployed_digests)
    assert stray.count() == 0
    assert Workload.objects.filter(cluster=cluster, deployed=True).exists()

    golden = fixture_dir / "golden" / "expectations.yaml"
    if golden.is_file():
        results = evaluate_assertions(yaml.safe_load(golden.read_text()) or [])
        failed = [r for r in results if not r["pass"]]
        assert not failed, json.dumps(failed, indent=2, default=str)

    visible_before = restrict_to_currently_deployed_images(default_finding_qs(cluster=cluster)).count()
    second = run_import(cluster=alias, folder=fixture_dir, url=live_server.url, token=token, tmp_dir=scratch, timeout=600)
    assert second.returncode == 0, second.stderr[-4000:]
    drain_until_empty(limit=200, max_iterations=2000)
    cluster.refresh_from_db()
    assert cluster.last_complete_inventory_at > marks["inventory"].started_at
    assert IngestQueue.objects.count() == 0
    assert ImportMark.objects.filter(cluster=cluster, state=ImportMarkState.REAPED.value).count() == 2 * len(marks)
    assert restrict_to_currently_deployed_images(default_finding_qs(cluster=cluster)).count() == visible_before
