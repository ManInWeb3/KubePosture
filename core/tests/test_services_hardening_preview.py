"""Tests for core.services.hardening_preview.

End-to-end: parse Trivy CLI JSON → enrich with EPSS/KEV → score against the
target workload's urgency context → serialise for the session. The whole
pipeline must produce zero Finding writes (D1/D3).
"""
from __future__ import annotations

import pytest

from core.constants import Environment, PriorityBand
from core.models import (
    Cluster,
    EpssScore,
    Finding,
    KevEntry,
    Namespace,
    Workload,
)
from core.services import hardening_preview


def _cluster(name="c-prev", env=Environment.PROD.value):
    return Cluster.objects.create(name=name, environment=env)


def _ns(cluster, name="default", *, sensitive=False):
    return Namespace.objects.create(
        cluster=cluster, name=name, contains_sensitive_data=sensitive,
    )


def _workload(cluster, ns, *, exposed=False):
    return (
        Workload.objects
        .select_related("cluster", "namespace")
        .prefetch_related("signals")
        .get(pk=Workload.objects.create(
            cluster=cluster, namespace=ns,
            kind="Deployment", name="api",
            publicly_exposed=exposed, deployed=True,
        ).pk)
    )


def _cli_json(*vulns) -> dict:
    return {
        "ArtifactName": "registry/api:hardened",
        "Results": [
            {
                "Target": "registry/api:hardened (debian 12)",
                "Class": "os-pkgs",
                "Vulnerabilities": list(vulns),
            }
        ],
    }


def _v(vid, *, severity, pkg="libc6", cvss=7.5):
    return {
        "VulnerabilityID": vid,
        "PkgName": pkg,
        "InstalledVersion": "1.0",
        "FixedVersion": "1.1",
        "Severity": severity,
        "Title": f"Test {vid}",
        "CVSS": {"nvd": {"V3Score": cvss, "V3Vector": "x"}},
    }


# ── Shape detection ─────────────────────────────────────────────


def test_is_trivy_cli_json_accepts_results_list():
    assert hardening_preview.is_trivy_cli_json({"Results": []}) is True


def test_is_trivy_cli_json_rejects_crd_shape():
    crd = {"report": {"vulnerabilities": []}, "metadata": {}}
    assert hardening_preview.is_trivy_cli_json(crd) is False


def test_is_trivy_cli_json_rejects_non_dict():
    assert hardening_preview.is_trivy_cli_json("not json") is False
    assert hardening_preview.is_trivy_cli_json(None) is False


# ── Preview scoring ─────────────────────────────────────────────


@pytest.mark.django_db
def test_preview_scores_kev_finding_as_immediate(django_assert_max_num_queries):
    c = _cluster()
    ns = _ns(c)
    w = _workload(c, ns)
    KevEntry.objects.create(vuln_id="CVE-2024-0001")

    result = hardening_preview.preview_trivy_cli_scan(
        w, _cli_json(_v("CVE-2024-0001", severity="HIGH")),
    )

    assert len(result.findings) == 1
    f = result.findings[0]
    assert f["vuln_id"] == "CVE-2024-0001"
    assert f["kev_listed"] is True
    assert f["effective_priority"] == PriorityBand.IMMEDIATE.value
    assert result.counts[PriorityBand.IMMEDIATE.value] == 1


@pytest.mark.django_db
def test_preview_uses_workload_exposure_to_promote_priority():
    """Same CVE on an exposed prod workload vs an internal dev workload —
    priority must shift. Locks the contract that preview really plumbs
    workload context through urgency.score()."""
    # Internet-exposed prod workload, EPSS-high critical CVE -> IMMEDIATE.
    c_prod = _cluster(name="prod-exposed", env=Environment.PROD.value)
    ns_prod = _ns(c_prod, name="payments")
    w_prod = _workload(c_prod, ns_prod, exposed=True)
    EpssScore.objects.create(vuln_id="CVE-2024-9999", score=0.97, percentile=0.95)

    prod = hardening_preview.preview_trivy_cli_scan(
        w_prod, _cli_json(_v("CVE-2024-9999", severity="CRITICAL")),
    )

    # Same CVE, non-exposed dev workload -> NOT immediate.
    c_dev = _cluster(name="dev-internal", env=Environment.DEV.value)
    ns_dev = _ns(c_dev, name="default")
    w_dev = _workload(c_dev, ns_dev, exposed=False)

    dev = hardening_preview.preview_trivy_cli_scan(
        w_dev, _cli_json(_v("CVE-2024-9999", severity="CRITICAL")),
    )

    assert prod.findings[0]["effective_priority"] == PriorityBand.IMMEDIATE.value
    assert dev.findings[0]["effective_priority"] != PriorityBand.IMMEDIATE.value


@pytest.mark.django_db
def test_preview_serializes_detail_fields_and_stable_idx():
    """The preview detail offcanvas renders description / references / CVSS
    straight from the serialized dict, and looks the finding up by `idx` —
    which must survive the urgency re-sort (position != idx)."""
    c = _cluster()
    ns = _ns(c)
    w = _workload(c, ns)
    KevEntry.objects.create(vuln_id="CVE-2024-KEV1")  # forces an IMMEDIATE to the top

    vuln = _v("CVE-2024-DESC", severity="HIGH")
    vuln["Description"] = "A nasty bug."
    vuln["PrimaryURL"] = "https://example.com/cve"
    vuln["References"] = ["https://example.com/ref"]

    result = hardening_preview.preview_trivy_cli_scan(w, _cli_json(
        vuln,                                       # idx 0, sorts below the KEV row
        _v("CVE-2024-KEV1", severity="LOW"),        # idx 1, sorts to top via KEV
    ))

    # The KEV row sorted to position 0, so position != idx.
    assert result.findings[0]["vuln_id"] == "CVE-2024-KEV1"
    assert result.findings[0]["idx"] == 1

    found = hardening_preview.find_finding(result, 0)
    assert found is not None
    assert found["vuln_id"] == "CVE-2024-DESC"
    assert found["description"] == "A nasty bug."
    assert found["primary_link"] == "https://example.com/cve"
    assert found["links"] == ["https://example.com/ref"]
    assert found["cvss_score"] == 7.5

    assert hardening_preview.find_finding(result, 99) is None


@pytest.mark.django_db
def test_preview_findings_are_priority_sorted_not_cli_order():
    """Trivy CLI emits in package order — IMMEDIATE rows can land anywhere.
    The findings panel uses a scrollable table; if we preserve CLI order, the
    high-priority rows can be off-screen below DEFER rows. Lock priority sort
    matching the real findings panel (inventory.order_findings)."""
    c = _cluster()
    ns = _ns(c)
    w = _workload(c, ns)
    # KEV short-circuits to IMMEDIATE; without KEV these would be SCHEDULED/DEFER.
    KevEntry.objects.create(vuln_id="CVE-2024-KEV1")
    KevEntry.objects.create(vuln_id="CVE-2024-KEV2")

    # IMMEDIATE rows deliberately in the MIDDLE / END of CLI order.
    result = hardening_preview.preview_trivy_cli_scan(w, _cli_json(
        _v("CVE-2024-LOW1", severity="LOW"),
        _v("CVE-2024-KEV1", severity="HIGH"),     # IMMEDIATE via KEV
        _v("CVE-2024-LOW2", severity="LOW"),
        _v("CVE-2024-KEV2", severity="MEDIUM"),   # IMMEDIATE via KEV
        _v("CVE-2024-LOW3", severity="LOW"),
    ))

    bands = [f["effective_priority"] for f in result.findings]
    # IMMEDIATE rows MUST land at the top, regardless of CLI position.
    assert bands[0] == PriorityBand.IMMEDIATE.value
    assert bands[1] == PriorityBand.IMMEDIATE.value


@pytest.mark.django_db
def test_preview_writes_no_finding_rows():
    """D1/D3 invariant: preview must never persist to Finding."""
    c = _cluster()
    ns = _ns(c)
    w = _workload(c, ns)
    EpssScore.objects.create(vuln_id="CVE-2024-1234", score=0.5, percentile=0.7)
    KevEntry.objects.create(vuln_id="CVE-2024-5678")

    before = Finding.objects.count()
    hardening_preview.preview_trivy_cli_scan(
        w, _cli_json(
            _v("CVE-2024-1234", severity="HIGH"),
            _v("CVE-2024-5678", severity="MEDIUM"),
            _v("CVE-2024-XXXX", severity="LOW"),
        ),
    )
    assert Finding.objects.count() == before


@pytest.mark.django_db
def test_preview_returns_empty_counts_for_empty_scan():
    c = _cluster()
    ns = _ns(c)
    w = _workload(c, ns)

    result = hardening_preview.preview_trivy_cli_scan(w, _cli_json())

    assert result.findings == []
    assert result.total == 0
    # All four bands present with zero counts so the row template renders cleanly.
    assert set(result.counts.keys()) == {b.value for b in PriorityBand}
    assert all(v == 0 for v in result.counts.values())


@pytest.mark.django_db
def test_preview_carries_artifact_name_as_image_ref():
    c = _cluster()
    ns = _ns(c)
    w = _workload(c, ns)

    result = hardening_preview.preview_trivy_cli_scan(
        w,
        {
            "ArtifactName": "myorg/payments:v2-distroless",
            "Results": [{"Vulnerabilities": []}],
        },
    )
    assert result.image_ref == "myorg/payments:v2-distroless"
    assert result.digest.startswith("candidate:")


# ── Batch enrichment ────────────────────────────────────────────


@pytest.mark.django_db
def test_batch_enrichment_returns_map_and_set():
    EpssScore.objects.create(vuln_id="CVE-2024-1", score=0.1, percentile=0.5)
    EpssScore.objects.create(vuln_id="CVE-2024-2", score=0.9, percentile=0.95)
    KevEntry.objects.create(vuln_id="CVE-2024-2")

    epss_map, kev_set = hardening_preview.batch_enrichment(
        ["CVE-2024-1", "CVE-2024-2", "CVE-2024-3", "GHSA-xxxx", ""]
    )

    assert epss_map == {
        "CVE-2024-1": (0.1, 0.5),
        "CVE-2024-2": (0.9, 0.95),
    }
    assert kev_set == {"CVE-2024-2"}


@pytest.mark.django_db
def test_batch_enrichment_skips_non_cve_ids():
    KevEntry.objects.create(vuln_id="CVE-2024-X")
    _, kev_set = hardening_preview.batch_enrichment(["AVD-KSV-0001", "policy/x"])
    assert kev_set == set()


# ── Session helpers ─────────────────────────────────────────────


class _FakeSession(dict):
    """Dict + the `.modified` flag the real SessionStore exposes."""
    modified = False


class _FakeRequest:
    def __init__(self):
        self.session = _FakeSession()


def test_stash_and_load_roundtrip():
    req = _FakeRequest()
    result = hardening_preview.PreviewResult(
        candidate_id="abc",
        digest="candidate:abc",
        image_ref="foo/bar:hardened",
        findings=[{"vuln_id": "CVE-X", "pk": None}],
        counts={b.value: 0 for b in PriorityBand},
        total=1,
    )
    hardening_preview.stash(req, workload_id=42, result=result)

    loaded = hardening_preview.load(req, workload_id=42, candidate_id="abc")
    assert loaded is not None
    assert loaded.image_ref == "foo/bar:hardened"
    assert loaded.findings == [{"vuln_id": "CVE-X", "pk": None}]


def test_load_returns_none_for_unknown_candidate():
    req = _FakeRequest()
    assert hardening_preview.load(req, 1, "missing") is None


def test_clear_removes_session_entry():
    req = _FakeRequest()
    result = hardening_preview.PreviewResult(
        candidate_id="abc",
        digest="candidate:abc",
        image_ref="x",
        findings=[],
        counts={b.value: 0 for b in PriorityBand},
        total=0,
    )
    hardening_preview.stash(req, 1, result)
    hardening_preview.clear(req, 1, "abc")
    assert hardening_preview.load(req, 1, "abc") is None


def test_candidate_digest_helpers():
    assert hardening_preview.is_candidate_digest("candidate:abc") is True
    assert hardening_preview.is_candidate_digest("sha256:abc") is False
    assert hardening_preview.is_candidate_digest(None) is False
    assert hardening_preview.candidate_id_from_digest("candidate:abc") == "abc"
    assert hardening_preview.candidate_id_from_digest("sha256:abc") == ""
