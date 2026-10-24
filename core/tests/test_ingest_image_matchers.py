"""Matchers at SBOM ingest, and the code they share.

Findings stay in the default views only while `last_seen` is not behind the
cluster's latest complete inventory, so a matcher has to re-observe its
findings every cycle. Every cycle re-posts each image's SbomReport, which is
where `core.services.ingest` runs the image-scoped matchers: the OSV
vulnerability matcher always did, the malicious-package (IoC) matcher only
ran with the hourly feed job — so a still-deployed malicious package dropped
out of view after each inventory until the next tick.
"""
from __future__ import annotations

import time
from datetime import timedelta
from unittest.mock import patch

import pytest
from django.utils import timezone

from core.constants import Environment, Severity, Source
from core.iterutils import chunked
from core.models import (
    Cluster,
    Finding,
    Image,
    IngestQueue,
    Namespace,
    SbomComponent,
    SupplyChainIoc,
    Workload,
    WorkloadImageObservation,
)
from core.services import ingest, matching
from core.services.ingest import _process_sbom
from core.services.inventory import default_finding_qs
from core.services.matching import emit_for_image
from core.services.supply_chain_matcher import match_iocs_to_components

DIGEST = "sha256:" + "a" * 64
EVIL = "pkg:npm/evil@1.0.0"


@pytest.fixture
def cluster(db):
    c = Cluster.objects.create(name="c1", environment=Environment.PROD.value)
    c.last_complete_inventory_at = timezone.now() - timedelta(hours=1)
    c.save()
    return c


def _deployed(cluster, name="api", digest=DIGEST) -> tuple[Workload, Image]:
    ns, _ = Namespace.objects.get_or_create(cluster=cluster, name="payments")
    w = Workload.objects.create(cluster=cluster, namespace=ns, kind="Deployment", name=name,
                                deployed=True)
    img, _ = Image.objects.get_or_create(digest=digest, defaults={"ref": f"reg/{name}:v1"})
    WorkloadImageObservation.objects.create(workload=w, image=img, container_name="app",
                                            currently_deployed=True)
    return w, img


def _component_dict(purl: str) -> dict:
    name, _, version = purl.removeprefix("pkg:npm/").partition("@")
    return {"purl": purl, "name": name, "version": version, "ecosystem": "npm",
            "component_type": "library", "supplier": "", "license": "", "layer_digest": "",
            "raw": {}}


def _sbom_report(purls, *, workload_name="api", digest=DIGEST) -> dict:
    """What `trivy.parse_sbom_report` hands `_process_sbom`."""
    return {"image_ref": "reg/api:v1", "image_digest": digest, "namespace": "payments",
            "resource_kind": "Deployment", "resource_name": workload_name,
            "container_name": "app", "components": [_component_dict(p) for p in purls]}


def _ingest_sbom(cluster, purls, **kw):
    item = IngestQueue.objects.create(cluster_name=cluster.name, kind="trivy.SbomReport",
                                      import_id="imp", raw_json={})
    return _process_sbom(item, lambda _raw: _sbom_report(purls, **kw))


def _ioc(purl=EVIL, advisory_id="MAL-2026-0001"):
    return SupplyChainIoc.objects.create(
        purl=purl, feed_source="osv", advisory_id=advisory_id,
        severity=Severity.CRITICAL.value, advisory_url="https://example.test/adv",
    )


def _visible():
    return default_finding_qs().filter(source=Source.SUPPLY_CHAIN_IOC.value).count()


# ── the reported flicker ─────────────────────────────────────────


def test_sbom_ingest_re_observes_ioc_findings_every_inventory_cycle(cluster):
    """Matched once (the feed tick); a newer inventory completes — the
    finding drops out of the default views; the cycle's SBOM re-post
    brings it back, without waiting for the next feed tick."""
    _deployed(cluster)
    _ioc()
    _ingest_sbom(cluster, [EVIL, "pkg:npm/fine@2.0.0"])
    finding = Finding.objects.get(source=Source.SUPPLY_CHAIN_IOC.value)
    assert _visible() == 1  # ingest alone found it: no feed job involved

    cluster.last_complete_inventory_at = finding.last_seen + timedelta(milliseconds=1)
    cluster.save()
    assert _visible() == 0  # the next cycle completed; nothing re-observed it yet

    time.sleep(0.05)
    _ingest_sbom(cluster, [EVIL, "pkg:npm/fine@2.0.0"])  # that cycle's SbomReport
    assert _visible() == 1
    assert Finding.objects.filter(source=Source.SUPPLY_CHAIN_IOC.value).count() == 1  # bumped


def test_one_matcher_failing_does_not_stop_the_other_or_the_ingest(cluster):
    _deployed(cluster)
    _ioc()

    with patch.object(ingest, "match_osv_vulns", side_effect=RuntimeError("boom")):
        result = _ingest_sbom(cluster, [EVIL])

    assert result["components"] == 1  # the item's own job is done
    assert Finding.objects.filter(source=Source.SUPPLY_CHAIN_IOC.value).count() == 1

    with patch.object(ingest, "match_iocs_to_components", side_effect=RuntimeError("boom")), \
            patch.object(ingest, "match_osv_vulns") as osv:
        _ingest_sbom(cluster, [EVIL])
    osv.assert_called_once()


# ── the IoC matcher scoped to an image ───────────────────────────


def test_ioc_matcher_image_scope_touches_only_that_image(cluster):
    _w1, img1 = _deployed(cluster, "api", DIGEST)
    _w2, img2 = _deployed(cluster, "worker", "sha256:" + "b" * 64)
    for img in (img1, img2):
        SbomComponent.objects.create(image=img, purl=EVIL, name="evil", version="1.0.0",
                                     ecosystem="npm")
    _ioc()

    assert match_iocs_to_components(image=img1) == 1

    assert list(Finding.objects.values_list("image__digest", flat=True)) == [DIGEST]
    assert match_iocs_to_components() == 2  # unscoped: both (img1's finding is updated)


def test_ioc_matcher_image_scope_with_a_name_only_ioc(cluster):
    """A name-only (ranges) IoC resolves per component inside the image."""
    _w, img = _deployed(cluster)
    SbomComponent.objects.create(image=img, purl=EVIL, name="evil", version="1.0.0",
                                 ecosystem="npm")
    SbomComponent.objects.create(image=img, purl="pkg:npm/evil@3.0.0", name="evil",
                                 version="3.0.0", ecosystem="npm")
    SupplyChainIoc.objects.create(
        purl="pkg:npm/evil", feed_source="osv", advisory_id="MAL-2026-0002",
        raw={"affected": [{"package": {"name": "evil"},
                           "ranges": [{"type": "SEMVER",
                                       "events": [{"introduced": "1.0.0"}, {"fixed": "2.0.0"}]}]}]},
    )

    match_iocs_to_components(image=img)

    assert list(Finding.objects.values_list("installed_version", flat=True)) == ["1.0.0"]


# ── the shared step ──────────────────────────────────────────────


def test_ioc_matcher_upserts_once_per_workload_however_many_components_matched(cluster):
    _w1, img = _deployed(cluster, "api")
    _deployed(cluster, "api-canary")  # a second workload running the same image
    for purl in (EVIL, "pkg:npm/also-evil@2.0.0"):
        name, _, version = purl.removeprefix("pkg:npm/").partition("@")
        SbomComponent.objects.create(image=img, purl=purl, name=name, version=version,
                                     ecosystem="npm")
        _ioc(purl, advisory_id=f"MAL-{name}")

    with patch.object(matching, "upsert_findings", wraps=matching.upsert_findings) as upsert:
        touched = match_iocs_to_components()

    assert touched == 4  # 2 components × 2 workloads
    assert upsert.call_count == 2  # one call per workload, each carrying both findings
    assert all(len(call.kwargs["findings"]) == 2 for call in upsert.call_args_list)


def _finding_dict(vuln_id="CVE-1", pkg="evil") -> dict:
    return {"source": Source.OSV.value, "category": "vulnerability", "vuln_id": vuln_id,
            "pkg_name": pkg, "installed_version": "1", "fixed_version": "", "title": "t",
            "severity": Severity.HIGH.value, "cvss_score": None, "cvss_vector": "", "details": {}}


def test_emit_for_image_fans_out_to_deployed_workloads_only(cluster):
    w1, img = _deployed(cluster, "api")
    w2 = Workload.objects.create(cluster=cluster, namespace=w1.namespace, kind="Deployment",
                                 name="gone", deployed=True)
    WorkloadImageObservation.objects.create(workload=w2, image=img, container_name="app",
                                            currently_deployed=False)

    n = emit_for_image(img, [_finding_dict()], timezone.now())

    assert n == 1
    assert list(Finding.objects.values_list("workload__name", flat=True)) == ["api"]


def test_emit_for_image_filter_is_applied_per_workload(cluster):
    w1, img = _deployed(cluster, "api")
    _deployed(cluster, "worker")
    seen = []

    def only_for_api(workload, findings):
        seen.append(workload.name)
        return findings if workload.name == "api" else []

    n = emit_for_image(img, [_finding_dict()], timezone.now(), for_workload=only_for_api)

    assert n == 1
    assert sorted(seen) == ["api", "worker"]  # asked once per deployed workload
    assert list(Finding.objects.values_list("workload__name", flat=True)) == ["api"]


def test_emit_for_image_with_nothing_to_emit_does_no_work(cluster):
    _w, img = _deployed(cluster)
    with patch.object(matching, "upsert_findings") as upsert:
        assert emit_for_image(img, [], timezone.now()) == 0
    upsert.assert_not_called()


def test_chunked_splits_lazily_and_keeps_the_remainder():
    consumed = []

    def source():
        for i in range(7):
            consumed.append(i)
            yield i

    it = chunked(source(), 3)
    assert next(it) == [0, 1, 2] and consumed == [0, 1, 2]  # lazy: nothing read ahead
    assert list(it) == [[3, 4, 5], [6]]
    assert list(chunked([], 3)) == []
