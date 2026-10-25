"""OSV vulnerability lane end to end: real advisories (fixtures/osv) →
loader → OsvAdvisory / OsvAffected → matcher → Finding(source="osv").

Simulates one deployed image whose SBOM carries real purls at versions
chosen from the advisories, plus the negative cases: fixed versions, a
withdrawn advisory, a component Trivy already reports, an unknown
package, and an undeployed workload.
"""
from __future__ import annotations

import io
import os
import tempfile
import zipfile
from datetime import timedelta
from pathlib import Path
from unittest.mock import patch

import pytest
from django.contrib.auth.models import User
from django.urls import reverse
from django.utils import timezone
from django.utils.html import escape

from core.constants import Category, Environment, PriorityBand, Severity, Source
from core.models import (
    Cluster,
    Finding,
    Image,
    Namespace,
    OsvAdvisory,
    OsvAffected,
    SbomComponent,
    SupplyChainIoc,
    Workload,
    WorkloadImageObservation,
)
from core.services import enrichment
from core.services.osv_vuln_matcher import match_osv_vulns

FIXTURES = Path(__file__).resolve().parents[2] / "fixtures" / "osv" / "advisories"


# ── helpers ──────────────────────────────────────────────────────


def _zip_of(eco: str) -> str:
    """Path to a temp `all.zip` for `eco` built from the fixture advisories
    — what `_http_download_conditional` hands the fetcher. Unlinked by it."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for p in sorted((FIXTURES / eco).glob("*.json")):
            zf.writestr(p.name, p.read_bytes())
    fd, path = tempfile.mkstemp(suffix=".zip")
    with os.fdopen(fd, "wb") as f:
        f.write(buf.getvalue())
    return path


def _download_from_fixtures(url, *, state_key, suffix=".bin"):
    eco = url.rsplit("/", 2)[-2]
    return _zip_of(eco) if (FIXTURES / eco).is_dir() else None


# The SBOM of the simulated image: (purl, name, version, ecosystem).
COMPONENTS = [
    # CVE-2021-23337, fixed 4.17.21
    ("pkg:npm/lodash@4.17.20", "lodash", "4.17.20", "npm"),
    # fixed version → no finding
    ("pkg:npm/lodash-es@4.17.21", "lodash-es", "4.17.21", "npm"),
    # last_affected (inclusive)
    ("pkg:npm/lodash.template@4.5.0", "lodash.template", "4.5.0", "npm"),
    # CVE-2022-41723
    ("pkg:golang/golang.org/x/net@v0.6.0", "golang.org/x/net", "v0.6.0", "golang"),
    # CVE-2022-41723, second interval
    ("pkg:golang/stdlib@v1.20.0", "stdlib", "v1.20.0", "golang"),
    # GHSA-m425 (no CVE alias)
    ("pkg:golang/google.golang.org/grpc@v1.57.0", "google.golang.org/grpc", "v1.57.0", "golang"),
    # CVE-2026-41178
    ("pkg:golang/go.opentelemetry.io/otel@v1.43.0", "go.opentelemetry.io/otel", "v1.43.0",
     "golang"),
    # CVE-2026-73500
    ("pkg:golang/go.etcd.io/etcd/v3@v3.6.5", "go.etcd.io/etcd/v3", "v3.6.5", "golang"),
    # CVE-2025-1767, no fix
    ("pkg:golang/k8s.io/kubernetes@v1.33.7", "k8s.io/kubernetes", "v1.33.7", "golang"),
    # withdrawn advisory
    ("pkg:golang/github.com/siyuan-note/siyuan/kernel@v0.0.0-20260101000000-aaaaaaaaaaaa",
     "github.com/siyuan-note/siyuan/kernel", "v0.0.0-20260101000000-aaaaaaaaaaaa", "golang"),
    # %2B purl, no advisory
    ("pkg:golang/github.com/aws/aws-sdk-go@v1.55.5%2Bincompatible",
     "github.com/aws/aws-sdk-go", "v1.55.5+incompatible", "golang"),
    # log4shell
    ("pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
     "org.apache.logging.log4j:log4j-core", "2.14.1", "maven"),
    # CVE-2023-32681 via GHSA + PYSEC
    ("pkg:pypi/requests@2.28.0", "requests", "2.28.0", "pypi"),
    # fixed, odd case
    ("pkg:pypi/Requests@2.31.0", "Requests", "2.31.0", "pypi"),
    # CVE-2023-22466
    ("pkg:cargo/tokio@1.20.2", "tokio", "1.20.2", "cargo"),
]


@pytest.fixture
def scene(db):
    c = Cluster.objects.create(name="c1", environment=Environment.PROD.value)
    c.last_complete_inventory_at = timezone.now() - timedelta(hours=1)
    c.save()
    ns = Namespace.objects.create(cluster=c, name="payments", internet_exposed=True)
    w = Workload.objects.create(cluster=c, namespace=ns, kind="Deployment", name="api",
                                deployed=True, publicly_exposed=True)
    img = Image.objects.create(digest="sha256:" + "a" * 64, ref="reg/api:v1")
    WorkloadImageObservation.objects.create(workload=w, image=img, container_name="app",
                                            currently_deployed=True)
    for purl, name, version, eco in COMPONENTS:
        SbomComponent.objects.create(
            image=img, purl=purl, name=name, version=version, ecosystem=eco,
        )
    return {"cluster": c, "workload": w, "image": img, "namespace": ns}


def _fetch_from_fixtures():
    with patch.object(enrichment, "_http_download_conditional",
                      side_effect=_download_from_fixtures):
        return enrichment.fetch_osv()


@pytest.fixture
def loaded(scene):
    _fetch_from_fixtures()
    return scene


def _osv_findings(**kw):
    return Finding.objects.filter(source=Source.OSV.value, **kw).order_by("pkg_name", "vuln_id")


def _trivy_finding(scene, *, vuln_id, pkg_name, installed_version):
    return Finding.objects.create(
        cluster=scene["cluster"], workload=scene["workload"], image=scene["image"],
        source=Source.TRIVY.value, category=Category.VULNERABILITY.value,
        vuln_id=vuln_id, pkg_name=pkg_name, installed_version=installed_version,
        title=pkg_name, severity=Severity.HIGH.value, hash_code=f"trivy-{pkg_name}",
    )


# ── loader ───────────────────────────────────────────────────────


def test_loader_stores_advisories_and_affected_rows(loaded):
    adv = OsvAdvisory.objects.get(osv_id="GO-2023-1571")
    assert "CVE-2022-41723" in adv.aliases
    assert adv.withdrawn_at is None
    assert adv.published_at.date().isoformat() == "2023-02-16"
    names = set(OsvAffected.objects.filter(advisory=adv).values_list("name", flat=True))
    assert names == {"stdlib", "golang.org/x/net"}
    assert OsvAffected.objects.get(advisory=adv, name="stdlib").purl_type == "golang"

    log4j = OsvAdvisory.objects.get(osv_id="GHSA-jfh8-c2jp-5v3q")
    assert log4j.severity == Severity.CRITICAL.value
    assert log4j.cvss_vector.startswith("CVSS:3.1/")
    core = OsvAffected.objects.filter(advisory=log4j, name="org.apache.logging.log4j:log4j-core")
    assert core.count() == 3 and all(a.versions for a in core)   # enumerated, one row per block

    withdrawn = OsvAdvisory.objects.get(osv_id="GHSA-24r3-p3x6-cqvx")
    assert withdrawn.withdrawn_at is not None


def test_loader_keeps_malicious_entries_in_the_ioc_lane(loaded):
    assert SupplyChainIoc.objects.filter(advisory_id="MAL-2026-18187").exists()
    assert not OsvAdvisory.objects.filter(osv_id="MAL-2026-18187").exists()


def test_loader_only_fetches_ecosystems_present_in_sboms(scene):
    SbomComponent.objects.filter(ecosystem__in=["pypi", "cargo", "maven"]).delete()
    with patch.object(enrichment, "_http_download_conditional",
                      side_effect=_download_from_fixtures) as dl:
        enrichment.fetch_osv()
    fetched = sorted(call.args[0].rsplit("/", 2)[-2] for call in dl.call_args_list)
    assert fetched == ["Go", "npm"]


def test_loader_is_idempotent_and_skips_unmodified(loaded):
    before = OsvAdvisory.objects.count(), OsvAffected.objects.count()
    _fetch_from_fixtures()
    assert (OsvAdvisory.objects.count(), OsvAffected.objects.count()) == before


def test_loader_zero_input_keeps_existing_rows(loaded):
    before = OsvAdvisory.objects.count()
    with patch.object(enrichment, "_http_download_conditional", return_value=None):
        assert enrichment.fetch_osv() == 0
    assert OsvAdvisory.objects.count() == before


# ── matcher: the simulated image ─────────────────────────────────


# pkg_name: (vuln_id, fixed_version, severity). Go vulndb entries carry
# no severity (→ unknown); grpc has no CVE alias (→ the OSV id).
EXPECTED = {
    "lodash": ("CVE-2021-23337", "4.17.21", Severity.HIGH.value),
    "lodash.template": ("CVE-2021-23337", "", Severity.HIGH.value),
    "golang.org/x/net": ("CVE-2022-41723", "0.7.0", Severity.UNKNOWN.value),
    "stdlib": ("CVE-2022-41723", "1.20.1", Severity.UNKNOWN.value),
    "google.golang.org/grpc": ("GHSA-m425-mq94-257g", "1.57.1", Severity.HIGH.value),
    "go.opentelemetry.io/otel": ("CVE-2026-41178", "1.44.0", Severity.UNKNOWN.value),
    "go.etcd.io/etcd/v3": ("CVE-2026-73500", "3.6.14", Severity.HIGH.value),
    "k8s.io/kubernetes": ("CVE-2025-1767", "", Severity.UNKNOWN.value),
    "org.apache.logging.log4j:log4j-core": ("CVE-2021-44228", "2.15.0", Severity.CRITICAL.value),
    "requests": ("CVE-2023-32681", "2.31.0", Severity.MEDIUM.value),
    "tokio": ("CVE-2023-22466", "1.20.3", Severity.UNKNOWN.value),
}


def test_matcher_emits_one_finding_per_vulnerable_component(loaded):
    n = match_osv_vulns()
    assert n == len(EXPECTED)
    rows = {f.pkg_name: f for f in _osv_findings()}
    assert set(rows) == set(EXPECTED)
    for pkg, (vuln_id, fixed, severity) in EXPECTED.items():
        f = rows[pkg]
        assert (f.vuln_id, f.fixed_version, f.severity) == (vuln_id, fixed, severity), pkg
        assert f.category == Category.VULNERABILITY.value
        assert f.workload == loaded["workload"] and f.image == loaded["image"]
        assert f.details["osv_ids"] and f.details["purl"].startswith("pkg:")
    # The two PyPI advisories for the same CVE collapse into one finding.
    assert _osv_findings(pkg_name="requests").count() == 1
    assert set(rows["requests"].details["osv_ids"]) == {"GHSA-j8r2-6x86-q33q", "PYSEC-2023-74"}


def test_matcher_skips_fixed_withdrawn_and_unknown(loaded):
    match_osv_vulns()
    for pkg in ("lodash-es", "Requests", "github.com/siyuan-note/siyuan/kernel",
                "github.com/aws/aws-sdk-go"):
        assert not _osv_findings(pkg_name=pkg).exists(), pkg


def test_matcher_scores_through_the_normal_tree(loaded):
    match_osv_vulns()
    f = _osv_findings(pkg_name="org.apache.logging.log4j:log4j-core").get()
    # critical + exposed + prod → Immediate; no supply-chain short-circuit.
    assert f.effective_priority == PriorityBand.IMMEDIATE.value
    assert _osv_findings(pkg_name="stdlib").get().effective_priority != PriorityBand.IMMEDIATE.value


def test_matcher_does_not_duplicate_a_trivy_finding(loaded):
    """Trivy already reports CVE-2021-23337 on lodash@4.17.20 for this
    workload/image: the OSV lane is gap-fill, so it stays silent there."""
    _trivy_finding(loaded, vuln_id="CVE-2021-23337", pkg_name="lodash", installed_version="4.17.20")
    match_osv_vulns()
    assert not _osv_findings(pkg_name="lodash").exists()
    assert _osv_findings(pkg_name="lodash.template").exists()   # other package, still emitted


def test_matcher_recognises_trivy_findings_by_alias(loaded):
    """Trivy keyed the grpc advisory by its GO id; OSV knows it as GHSA-m425…."""
    _trivy_finding(loaded, vuln_id="GO-2023-2153", pkg_name="google.golang.org/grpc",
                   installed_version="v1.57.0")
    match_osv_vulns()
    assert not _osv_findings(pkg_name="google.golang.org/grpc").exists()


def test_matcher_is_idempotent_and_bumps_last_seen(loaded):
    match_osv_vulns()
    f = _osv_findings(pkg_name="lodash").get()
    first = f.last_seen
    match_osv_vulns()
    assert _osv_findings().count() == len(EXPECTED)
    f.refresh_from_db()
    assert f.last_seen > first


def test_matcher_scoped_to_one_image(loaded):
    other = Image.objects.create(digest="sha256:" + "b" * 64, ref="reg/other:v1")
    WorkloadImageObservation.objects.create(workload=loaded["workload"], image=other,
                                            container_name="side", currently_deployed=True)
    SbomComponent.objects.create(image=other, purl="pkg:npm/lodash@4.17.19", name="lodash",
                                 version="4.17.19", ecosystem="npm")
    assert match_osv_vulns(image=other) == 1
    assert _osv_findings().get().image == other


def test_matcher_ignores_undeployed_and_withdrawn(loaded):
    match_osv_vulns()
    f = _osv_findings(pkg_name="lodash").get()
    seen = f.last_seen
    WorkloadImageObservation.objects.update(currently_deployed=False)
    match_osv_vulns()
    f.refresh_from_db()
    assert f.last_seen == seen            # not bumped → ages out like any other finding
    WorkloadImageObservation.objects.update(currently_deployed=True)
    OsvAdvisory.objects.filter(osv_id="GHSA-35jh-r3h4-6jhm").update(withdrawn_at=timezone.now())
    match_osv_vulns()
    f.refresh_from_db()
    assert f.last_seen == seen


def test_sbom_ingest_runs_the_matcher_for_that_image(loaded):
    """Each inventory cycle re-posts the image's SbomReport; matching at
    ingest keeps OSV findings' last_seen in step with the cycle, exactly
    like Trivy findings."""
    from core.services import ingest

    with patch.object(ingest, "match_osv_vulns") as m:
        ingest._after_sbom_upsert(loaded["image"])
    m.assert_called_once_with(image=loaded["image"])


def test_finding_details_carry_the_affected_ranges(loaded):
    """What the finding panel shows as "Affected versions". An interval says
    it all, so PyPI's 66 enumerated `requests` releases are not stored next
    to it."""
    match_osv_vulns()

    lodash = _osv_findings(pkg_name="lodash").get().details
    assert (lodash["affected_ranges"], lodash["affected_versions"]) == (["< 4.17.21"], [])
    requests = _osv_findings(pkg_name="requests").get().details
    assert requests["affected_ranges"] == [">= 2.3.0, < 2.31.0"]
    assert requests["affected_versions"] == []
    stdlib = _osv_findings(pkg_name="stdlib").get().details
    assert stdlib["affected_ranges"] == ["< 1.19.6", ">= 1.20.0-0, < 1.20.1"]


def test_finding_panel_shows_purl_affected_versions_aliases_and_links(client, loaded):
    match_osv_vulns()
    f = _osv_findings(pkg_name="lodash").get()
    client.force_login(User.objects.create_user(username="osv-panel", password="x"))

    body = client.get(reverse("findings-detail-panel", args=[f.pk])).content.decode()

    assert "Package URL" in body and "pkg:npm/lodash@4.17.20" in body
    assert "Affected versions" in body and "&lt; 4.17.21" in body
    assert "Also known as" in body and "GHSA-35jh-r3h4-6jhm" in body
    # The advisory's references are listed, next to the osv.dev link.
    assert f'href="{f.details["primary_link"]}"' in body
    assert f.details["references"]
    assert f'href="{escape(f.details["references"][0])}"' in body


# ── one compromised release (CVE-2026-33634) ─────────────────────

# Trimmed real records. Go vulndb can only say `introduced 0.69.4` for the
# one compromised Trivy release, which reads as "every later release"; the
# GHSA for the same CVE names the version.
_TRIVY = "github.com/aquasecurity/trivy"
_GO_4919 = {
    "id": "GO-2026-4919", "aliases": ["CVE-2026-33634", "GHSA-69fq-xp46-6x23"],
    "summary": "Trivy ecosystem supply chain briefly compromised",
    "modified": "2026-06-16T13:29:16Z",
    "affected": [{
        "package": {"name": _TRIVY, "ecosystem": "Go"},
        "ranges": [{"type": "SEMVER", "events": [{"introduced": "0.69.4"}]}],
    }],
}
_GHSA_69FQ = {
    "id": "GHSA-69fq-xp46-6x23", "aliases": ["CVE-2026-33634", "GO-2026-4919"],
    "summary": "Trivy ecosystem supply chain briefly compromised",
    "modified": "2026-09-10T03:50:59Z", "database_specific": {"severity": "CRITICAL"},
    "affected": [
        {"package": {"name": _TRIVY, "ecosystem": "Go"}, "versions": ["0.69.4"]},
        {"package": {"name": "aquasecurity/trivy-action", "ecosystem": "GitHub Actions"},
         "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "0.35.0"}]}]},
    ],
}


def _deploy_trivy(scene, version, *advisories):
    enrichment._upsert_advisories([(a, "Go") for a in advisories])
    SbomComponent.objects.create(
        image=scene["image"], name=_TRIVY, version=version, ecosystem="golang",
        purl=f"pkg:golang/{_TRIVY}@{version.replace('+', '%2B')}",
    )
    match_osv_vulns()
    return _osv_findings(pkg_name=_TRIVY)


@pytest.mark.parametrize("version", ["v0.75.0+dirty", "v0.69.5", "v0.69.3"])
def test_later_release_is_not_flagged_by_an_open_range_the_ghsa_contradicts(scene, version):
    assert not _deploy_trivy(scene, version, _GO_4919, _GHSA_69FQ).exists()


def test_the_compromised_release_itself_is_flagged_with_the_exact_version(scene):
    f = _deploy_trivy(scene, "v0.69.4", _GO_4919, _GHSA_69FQ).get()

    assert (f.vuln_id, f.severity) == ("CVE-2026-33634", Severity.CRITICAL.value)
    assert f.details["affected_versions"] == ["0.69.4"]
    assert f.details["affected_ranges"] == []
    assert set(f.details["osv_ids"]) == {"GHSA-69fq-xp46-6x23"}


def test_open_range_stands_when_no_advisory_pins_the_versions(scene):
    """"No fix yet" is what an open range normally means: without a
    sibling listing exact versions it is trusted."""
    f = _deploy_trivy(scene, "v0.75.0+dirty", _GO_4919).get()

    assert f.vuln_id == "CVE-2026-33634"
    assert f.details["affected_ranges"] == [">= 0.69.4"]
