"""Every item in the real capture must go through the server parsers
without raising, and the fields the pipeline keys on must be present."""
from __future__ import annotations

import pytest
from kubeposture_importer.kinds import INVENTORY_ITEM_KINDS, SCAN_KINDS
from kubeposture_importer.trim import trim_manifest

from core.models import Cluster
from core.parsers import inventory as inventory_parser
from core.parsers import kyverno as kyverno_parser
from core.parsers import trivy as trivy_parser

pytestmark = pytest.mark.realdata


def test_every_scan_item_parses(by_kind):
    parsed = 0
    for crd_kind, env_kind in SCAN_KINDS:
        for item in by_kind.get(crd_kind) or []:
            if env_kind in trivy_parser.PARSERS_BY_KIND:
                trivy_parser.PARSERS_BY_KIND[env_kind](item)
            else:
                kyverno_parser.parse_policy_report(item)
            parsed += 1
    assert parsed > 0


def test_image_reports_carry_digest_and_identity(by_kind):
    for crd_kind in ("VulnerabilityReport", "SbomReport", "ExposedSecretReport"):
        for item in by_kind.get(crd_kind) or []:
            parsed = trivy_parser.PARSERS_BY_KIND[f"trivy.{crd_kind}"](item)
            assert parsed["image_digest"].startswith("sha256:"), item["metadata"]["name"]
            assert parsed["resource_kind"] and parsed["resource_name"], item["metadata"]["name"]


def test_sbom_components_have_purl_and_ecosystem(by_kind):
    total = 0
    for item in by_kind.get("SbomReport") or []:
        for comp in trivy_parser.parse_sbom_report(item)["components"]:
            assert comp["purl"].startswith("pkg:")
            assert comp["ecosystem"], comp["purl"]
            total += 1
    if by_kind.get("SbomReport"):
        assert total > 0


def test_inventory_envelope_parses_with_no_unknown_kinds(by_kind):
    items = [trim_manifest(it) for k in sorted(INVENTORY_ITEM_KINDS) for it in by_kind.get(k) or []]
    envelope = {"cluster_meta": {"name": "fixture"}, "items": items}
    staging = inventory_parser.parse_envelope(envelope, Cluster(name="fixture"))
    assert staging.unknown_kind_skipped == 0
    assert staging.workloads, "a capture without a single workload is not useful"
    assert staging.image_observations
