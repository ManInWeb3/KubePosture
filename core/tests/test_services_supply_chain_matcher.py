"""Tests for `core.services.supply_chain_matcher.match_iocs_to_components`."""
from __future__ import annotations

import pytest

from core.constants import (
    Category,
    Environment,
    PriorityBand,
    Severity,
    Source,
)
from core.models import (
    Cluster,
    Finding,
    Image,
    Namespace,
    SbomComponent,
    SupplyChainIoc,
    Workload,
    WorkloadImageObservation,
)
from core.services.dedup import compute_hash
from core.services.supply_chain_matcher import match_iocs_to_components

# ── Fixtures ────────────────────────────────────────────────────


def _cluster(name: str) -> Cluster:
    return Cluster.objects.create(name=name, environment=Environment.PROD.value)


def _ns(c: Cluster, name: str = "payments") -> Namespace:
    return Namespace.objects.create(cluster=c, name=name)


def _workload(c: Cluster, ns: Namespace, name: str) -> Workload:
    return Workload.objects.create(
        cluster=c, namespace=ns, kind="Deployment", name=name, deployed=True,
    )


def _image(digest: str, ref: str = "") -> Image:
    return Image.objects.create(digest=digest, ref=ref or f"img:{digest[:8]}")


def _observation(workload: Workload, image: Image, *, deployed: bool, container: str = "app"):
    return WorkloadImageObservation.objects.create(
        workload=workload, image=image, container_name=container,
        currently_deployed=deployed,
    )


def _component(image: Image, purl: str, *, name: str | None = None, version: str = "1.0", ecosystem: str = "npm"):
    return SbomComponent.objects.create(
        image=image, purl=purl,
        name=name or purl.split("/")[-1].split("@")[0],
        version=version, ecosystem=ecosystem,
    )


def _ioc(
    purl: str, *, feed: str = "osv", advisory_id: str = "MAL-2026-0001",
    severity: str = Severity.CRITICAL.value, url: str = "https://example.test/adv",
):
    return SupplyChainIoc.objects.create(
        purl=purl, feed_source=feed, advisory_id=advisory_id,
        severity=severity, title=f"malicious {purl}", advisory_url=url,
    )


# ── Tests ───────────────────────────────────────────────────────


@pytest.mark.django_db
def test_matcher_creates_finding_with_immediate_priority():
    c = _cluster("c1")
    ns = _ns(c)
    w = _workload(c, ns, "api")
    img = _image("sha256:" + "a" * 64, ref="reg/api:v1")
    _observation(w, img, deployed=True)
    _component(img, "pkg:npm/lodash@4.17.21", name="lodash", version="4.17.21")
    _ioc("pkg:npm/lodash@4.17.21", advisory_id="MAL-2026-0042")

    n = match_iocs_to_components()
    assert n == 1

    f = Finding.objects.get()
    assert f.source == Source.SUPPLY_CHAIN_IOC.value
    assert f.category == Category.SUPPLY_CHAIN.value
    assert f.vuln_id == "MAL-2026-0042"
    assert f.pkg_name == "lodash"
    assert f.installed_version == "4.17.21"
    assert f.effective_priority == PriorityBand.IMMEDIATE.value
    assert f.severity == Severity.CRITICAL.value
    assert f.workload_id == w.id
    assert f.image_id == img.id
    assert f.details["purl"] == "pkg:npm/lodash@4.17.21"
    assert f.details["feed_source"] == "osv"
    assert f.details["advisory_url"] == "https://example.test/adv"


@pytest.mark.django_db
def test_matcher_hash_code_matches_compute_hash():
    c = _cluster("c1")
    ns = _ns(c)
    w = _workload(c, ns, "api")
    img = _image("sha256:" + "a" * 64)
    _observation(w, img, deployed=True)
    _component(img, "pkg:npm/lodash@4.17.21", name="lodash", version="4.17.21")
    _ioc("pkg:npm/lodash@4.17.21", advisory_id="MAL-1")

    match_iocs_to_components()
    f = Finding.objects.get()

    expected = compute_hash(
        source=Source.SUPPLY_CHAIN_IOC.value,
        category=Category.SUPPLY_CHAIN.value,
        vuln_id="MAL-1",
        workload_id=w.id,
        cluster_name=c.name,
        image_digest=img.digest,
        pkg_name="lodash",
        installed_version="4.17.21",
    )
    assert f.hash_code == expected


@pytest.mark.django_db
def test_matcher_is_idempotent_dedup():
    c = _cluster("c1")
    ns = _ns(c)
    w = _workload(c, ns, "api")
    img = _image("sha256:" + "a" * 64)
    _observation(w, img, deployed=True)
    _component(img, "pkg:npm/lodash@4.17.21")
    _ioc("pkg:npm/lodash@4.17.21")

    match_iocs_to_components()
    match_iocs_to_components()
    assert Finding.objects.count() == 1


@pytest.mark.django_db
def test_matcher_cross_feed_produces_separate_findings():
    c = _cluster("c1")
    ns = _ns(c)
    w = _workload(c, ns, "api")
    img = _image("sha256:" + "a" * 64)
    _observation(w, img, deployed=True)
    _component(img, "pkg:npm/lodash@4.17.21")
    _ioc("pkg:npm/lodash@4.17.21", feed="osv", advisory_id="MAL-osv-1")
    _ioc("pkg:npm/lodash@4.17.21", feed="vendor", advisory_id="VENDOR-1")

    match_iocs_to_components()
    findings = list(Finding.objects.order_by("vuln_id"))
    assert len(findings) == 2
    assert {f.vuln_id for f in findings} == {"VENDOR-1", "MAL-osv-1"}


@pytest.mark.django_db
def test_matcher_skips_undeployed_observations():
    c = _cluster("c1")
    ns = _ns(c)
    w = _workload(c, ns, "api")
    img = _image("sha256:" + "a" * 64)
    _observation(w, img, deployed=False)   # undeployed
    _component(img, "pkg:npm/lodash@4.17.21")
    _ioc("pkg:npm/lodash@4.17.21")

    n = match_iocs_to_components()
    assert n == 0
    assert Finding.objects.count() == 0


@pytest.mark.django_db
def test_matcher_multi_image_multi_cluster():
    c1 = _cluster("c1")
    c2 = _cluster("c2")
    ns1 = _ns(c1)
    ns2 = _ns(c2)
    w1 = _workload(c1, ns1, "api")
    w2 = _workload(c2, ns2, "api2")
    img_a = _image("sha256:" + "a" * 64)
    img_b = _image("sha256:" + "b" * 64)
    _observation(w1, img_a, deployed=True)
    _observation(w2, img_b, deployed=True)
    _component(img_a, "pkg:npm/bad@1.0")
    _component(img_b, "pkg:npm/bad@1.0")
    _ioc("pkg:npm/bad@1.0", advisory_id="MAL-multi")

    match_iocs_to_components()
    findings = list(Finding.objects.all())
    assert len(findings) == 2
    workload_ids = {f.workload_id for f in findings}
    assert workload_ids == {w1.id, w2.id}


@pytest.mark.django_db
def test_matcher_touched_purls_scopes_join():
    c = _cluster("c1")
    ns = _ns(c)
    w = _workload(c, ns, "api")
    img = _image("sha256:" + "a" * 64)
    _observation(w, img, deployed=True)
    _component(img, "pkg:npm/lodash@4.17.21")
    _component(img, "pkg:npm/express@4.18.0")
    _ioc("pkg:npm/lodash@4.17.21", advisory_id="MAL-l")
    _ioc("pkg:npm/express@4.18.0", advisory_id="MAL-e")

    # Only scope to lodash purl.
    n = match_iocs_to_components(touched_purls=["pkg:npm/lodash@4.17.21"])
    assert n == 1
    assert Finding.objects.get().vuln_id == "MAL-l"


@pytest.mark.django_db
def test_matcher_empty_touched_purls_short_circuits():
    c = _cluster("c1")
    ns = _ns(c)
    w = _workload(c, ns, "api")
    img = _image("sha256:" + "a" * 64)
    _observation(w, img, deployed=True)
    _component(img, "pkg:npm/lodash@4.17.21")
    _ioc("pkg:npm/lodash@4.17.21")

    n = match_iocs_to_components(touched_purls=[])
    assert n == 0
    assert Finding.objects.count() == 0


@pytest.mark.django_db
def test_matcher_propagates_severity_bump_on_rerun():
    """If an IoC's severity is upgraded on a subsequent fetch, the
    matcher's next pass updates the existing Finding's severity.
    """
    c = _cluster("c1")
    ns = _ns(c)
    w = _workload(c, ns, "api")
    img = _image("sha256:" + "a" * 64)
    _observation(w, img, deployed=True)
    _component(img, "pkg:npm/lodash@4.17.21")
    ioc = _ioc("pkg:npm/lodash@4.17.21", severity=Severity.HIGH.value)

    match_iocs_to_components()
    f = Finding.objects.get()
    assert f.severity == Severity.HIGH.value

    # Feed re-rates to critical on next fetch.
    ioc.severity = Severity.CRITICAL.value
    ioc.save(update_fields=["severity"])

    match_iocs_to_components()
    f.refresh_from_db()
    assert f.severity == Severity.CRITICAL.value
    # And there's still only one finding row.
    assert Finding.objects.count() == 1


@pytest.mark.django_db
def test_matcher_propagates_title_and_details_changes():
    """Feed-side updates to title/url/summary reach the Finding's
    `details` blob on the next match.
    """
    c = _cluster("c1")
    ns = _ns(c)
    w = _workload(c, ns, "api")
    img = _image("sha256:" + "a" * 64)
    _observation(w, img, deployed=True)
    _component(img, "pkg:npm/lodash@4.17.21")
    ioc = _ioc(
        "pkg:npm/lodash@4.17.21",
        feed="osv", advisory_id="MAL-1", url="https://old.example/url",
    )

    match_iocs_to_components()
    f = Finding.objects.get()
    assert f.details["advisory_url"] == "https://old.example/url"

    ioc.advisory_url = "https://new.example/url"
    ioc.summary = "updated summary text"
    ioc.save(update_fields=["advisory_url", "summary"])

    match_iocs_to_components()
    f.refresh_from_db()
    assert f.details["advisory_url"] == "https://new.example/url"
    assert f.details["summary"] == "updated summary text"


@pytest.mark.django_db
def test_matcher_skips_when_workload_undeployed_between_match_runs():
    """Workload flipped to undeployed after first match — second match
    is a no-op (the existing finding is left for the inventory reaper
    to auto-resolve, which is a separate code path).
    """
    c = _cluster("c1")
    ns = _ns(c)
    w = _workload(c, ns, "api")
    img = _image("sha256:" + "a" * 64)
    obs = _observation(w, img, deployed=True)
    _component(img, "pkg:npm/lodash@4.17.21")
    _ioc("pkg:npm/lodash@4.17.21")

    match_iocs_to_components()
    assert Finding.objects.count() == 1

    # Workload undeployed (e.g. scaled to zero).
    obs.currently_deployed = False
    obs.save(update_fields=["currently_deployed"])

    n = match_iocs_to_components()
    assert n == 0
    # Finding row is still there — matcher doesn't delete; the
    # inventory reaper auto-resolves on the next complete cycle.
    assert Finding.objects.count() == 1


@pytest.mark.django_db
def test_matcher_picks_up_redeployed_workload():
    """Re-deploying a workload after an IoC was already in the DB
    causes the next match run to create the finding.
    """
    c = _cluster("c1")
    ns = _ns(c)
    w = _workload(c, ns, "api")
    img = _image("sha256:" + "a" * 64)
    obs = _observation(w, img, deployed=False)  # initially undeployed
    _component(img, "pkg:npm/lodash@4.17.21")
    _ioc("pkg:npm/lodash@4.17.21")

    # First match: no finding because workload isn't deployed.
    assert match_iocs_to_components() == 0
    assert Finding.objects.count() == 0

    # Workload comes back online.
    obs.currently_deployed = True
    obs.save(update_fields=["currently_deployed"])

    n = match_iocs_to_components()
    assert n == 1
    assert Finding.objects.count() == 1


@pytest.mark.django_db
def test_matcher_two_advisory_ids_same_purl():
    """A feed publishes separate IDs for separate disclosures of the
    same compromise → two findings, one per advisory_id.
    """
    c = _cluster("c1")
    ns = _ns(c)
    w = _workload(c, ns, "api")
    img = _image("sha256:" + "a" * 64)
    _observation(w, img, deployed=True)
    _component(img, "pkg:npm/lodash@4.17.21")
    _ioc("pkg:npm/lodash@4.17.21", feed="osv", advisory_id="MAL-disc-1")
    _ioc("pkg:npm/lodash@4.17.21", feed="osv", advisory_id="MAL-disc-2")

    match_iocs_to_components()
    assert Finding.objects.count() == 2
    assert set(Finding.objects.values_list("vuln_id", flat=True)) == {
        "MAL-disc-1", "MAL-disc-2",
    }


@pytest.mark.django_db
def test_matcher_one_workload_two_images_two_findings():
    """Sidecar pattern: one workload runs two distinct images, both
    of which contain the bad purl → two findings (different image FK).
    """
    c = _cluster("c1")
    ns = _ns(c)
    w = _workload(c, ns, "api")
    img_main = _image("sha256:" + "a" * 64, ref="main:v1")
    img_sidecar = _image("sha256:" + "b" * 64, ref="sidecar:v1")
    _observation(w, img_main, deployed=True, container="main")
    _observation(w, img_sidecar, deployed=True, container="logger")
    _component(img_main, "pkg:npm/lodash@4.17.21")
    _component(img_sidecar, "pkg:npm/lodash@4.17.21")
    _ioc("pkg:npm/lodash@4.17.21", advisory_id="MAL-1")

    match_iocs_to_components()
    findings = list(Finding.objects.order_by("image_id"))
    assert len(findings) == 2
    assert {f.image_id for f in findings} == {img_main.id, img_sidecar.id}
    # Both attach to the same workload.
    assert {f.workload_id for f in findings} == {w.id}


@pytest.mark.django_db
def test_matcher_intersects_touched_purls_with_sbom_in_sql_chunks(monkeypatch):
    """`touched ∩ deployed` is computed by Postgres one chunk of touched
    purls at a time — never by loading every SBOM purl into Python. With
    the chunk size forced to 2, five touched purls must still all be
    considered, and only the deployed ones produce Findings."""
    from django.db import connection
    from django.test.utils import CaptureQueriesContext

    from core.services import supply_chain_matcher as scm

    monkeypatch.setattr(scm, "_PURL_CHUNK_SIZE", 2)
    c = _cluster("c1")
    ns = _ns(c)
    w = _workload(c, ns, "api")
    img = _image("sha256:" + "a" * 64)
    _observation(w, img, deployed=True)
    for i in (0, 4):  # only the first and last touched purl are deployed
        _component(img, f"pkg:npm/p{i}@1.0")
    _component(img, "pkg:npm/untouched@1.0")
    for i in range(5):
        _ioc(f"pkg:npm/p{i}@1.0", advisory_id=f"MAL-{i}")
    _ioc("pkg:npm/untouched@1.0", advisory_id="MAL-untouched")

    with CaptureQueriesContext(connection) as ctx:
        n = match_iocs_to_components(touched_purls=[f"pkg:npm/p{i}@1.0" for i in range(5)])

    assert n == 2
    assert set(Finding.objects.values_list("vuln_id", flat=True)) == {"MAL-0", "MAL-4"}
    purl_lookups = [q["sql"] for q in ctx.captured_queries
                    if "core_sbomcomponent" in q["sql"] and '"core_sbomcomponent"."purl" IN' in q["sql"]]
    # 5 touched purls / chunk 2 = 3 intersection queries (+1 for the component fetch).
    assert len(purl_lookups) >= 3
    assert not any(
        'SELECT DISTINCT "core_sbomcomponent"."purl" FROM "core_sbomcomponent"' in q["sql"]
        and "WHERE" not in q["sql"]
        for q in ctx.captured_queries
    ), "must never SELECT every distinct purl of the SBOM table"


@pytest.mark.django_db
def test_matcher_full_scan_walks_ioc_purls_in_indexed_chunks(monkeypatch):
    """A full re-scan looks the IoC purls up in the component table one
    chunk at a time, as the hourly feed run does. It must never join the
    two tables with `purl IN (SELECT …)`: that, OR-ed with its name-purl
    twin, ran for over an hour against ~1.9M stored components."""
    from django.db import connection
    from django.test.utils import CaptureQueriesContext

    from core.services import supply_chain_matcher as scm

    monkeypatch.setattr(scm, "_PURL_CHUNK_SIZE", 2)
    c = _cluster("c1")
    ns = _ns(c)
    w = _workload(c, ns, "api")
    img = _image("sha256:" + "a" * 64)
    _observation(w, img, deployed=True)
    _component(img, "pkg:npm/lodash@4.17.21")
    _component(img, "pkg:npm/evil-pkg@1.2.3")
    _ioc("pkg:npm/lodash@4.17.21", advisory_id="MAL-1")
    _ioc("pkg:npm/evil-pkg", advisory_id="MAL-sentinel")   # name-only: every version
    for i in range(3):
        _ioc(f"pkg:npm/not-deployed{i}@1.0", advisory_id=f"MAL-nd{i}")

    with CaptureQueriesContext(connection) as ctx:
        assert match_iocs_to_components() == 2

    assert set(Finding.objects.values_list("vuln_id", flat=True)) == {"MAL-1", "MAL-sentinel"}
    table_queries = [
        q["sql"] for q in ctx.captured_queries
        if "core_supplychainioc" in q["sql"] or "core_sbomcomponent" in q["sql"]
    ]
    assert not any("IN (SELECT" in sql for sql in table_queries), table_queries
    # 5 IoC purls / chunk 2: the component table is asked about them in chunks.
    chunk_lookups = [sql for sql in table_queries if '"core_sbomcomponent"."purl" IN' in sql]
    assert len(chunk_lookups) >= 2, table_queries


@pytest.mark.django_db
def test_full_rescan_finds_exactly_what_the_incremental_run_finds():
    """The full re-scan and the feed-driven run over every IoC purl are
    the same match: exact and name-only IoCs, other versions of the same
    package, IoCs nobody runs, and images no longer deployed."""
    c = _cluster("c1")
    ns = _ns(c)
    live = _image("sha256:" + "a" * 64)
    gone = _image("sha256:" + "b" * 64)
    _observation(_workload(c, ns, "api"), live, deployed=True)
    _observation(_workload(c, ns, "old"), gone, deployed=False)
    for img in (live, gone):
        _component(img, "pkg:npm/lodash@4.17.21", version="4.17.21")
        _component(img, "pkg:npm/evil-pkg@1.2.3", version="1.2.3")
    _component(live, "pkg:npm/lodash@4.17.20", version="4.17.20")   # another version: not on the IoC
    _ioc("pkg:npm/lodash@4.17.21", advisory_id="MAL-exact")
    _ioc("pkg:npm/evil-pkg", advisory_id="MAL-sentinel")
    _ioc("pkg:npm/nobody-runs-this@9.9.9", advisory_id="MAL-unused")

    def found():
        return {(f.vuln_id, f.installed_version, f.workload.name) for f in Finding.objects.select_related("workload")}

    assert match_iocs_to_components() == 2
    full = found()
    Finding.objects.all().delete()

    every_purl = set(SupplyChainIoc.objects.values_list("purl", flat=True))
    assert match_iocs_to_components(touched_purls=every_purl) == 2

    assert found() == full == {("MAL-exact", "4.17.21", "api"), ("MAL-sentinel", "1.2.3", "api")}


# ── name-only (every-version) IoC purls ─────────────────────────────
#
# The OSV loader stores `pkg:npm/foo` (no version) for an advisory that
# covers every version of a package (`ranges: [{introduced: "0"}]`, the
# standard ossf/malicious-packages shape). Component purls always carry a
# version, so exact equality never matched these — the most common
# malicious-package shape produced no Finding at all.


def _deployed_component(purl: str, *, cluster_name: str = "c1"):
    c = _cluster(cluster_name)
    w = _workload(c, _ns(c), "api")
    img = _image("sha256:" + "d" * 64)
    _observation(w, img, deployed=True)
    return _component(img, purl)


@pytest.mark.django_db
@pytest.mark.parametrize("touched", [True, False], ids=["incremental", "full-rescan"])
def test_sentinel_ioc_matches_every_deployed_version(touched):
    comp = _deployed_component("pkg:npm/evil-pkg@1.2.3")
    ioc = _ioc("pkg:npm/evil-pkg")

    n = match_iocs_to_components(touched_purls={ioc.purl} if touched else None)

    assert n == 1
    f = Finding.objects.get()
    assert f.vuln_id == ioc.advisory_id and f.details["purl"] == comp.purl


@pytest.mark.django_db
def test_sentinel_ioc_matches_scoped_package_names():
    """A literal `@` in a scope must not be mistaken for the version
    separator by the name-purl expression."""
    _deployed_component("pkg:npm/@scope/evil@2.0.0")
    ioc = _ioc("pkg:npm/@scope/evil")

    assert match_iocs_to_components(touched_purls={ioc.purl}) == 1


@pytest.mark.django_db
def test_sentinel_ioc_does_not_match_a_different_package():
    _deployed_component("pkg:npm/evil-pkg-fork@1.0.0")
    ioc = _ioc("pkg:npm/evil-pkg")

    assert match_iocs_to_components(touched_purls={ioc.purl}) == 0
    assert Finding.objects.count() == 0


@pytest.mark.django_db
def test_versioned_ioc_still_requires_an_exact_version():
    _deployed_component("pkg:npm/evil-pkg@1.2.3")
    ioc = _ioc("pkg:npm/evil-pkg@9.9.9")

    assert match_iocs_to_components(touched_purls={ioc.purl}) == 0
