"""
Tests for SBOM models, parser, service, and backfill.

Covers:
- Component model constraints
- parse_trivy_sbom parser output
- save_sbom_components service (upsert + delete stale)
- End-to-end ingest of SbomReport
- backfill_sbom from RawReport
"""
import json
from pathlib import Path

import pytest

from core.constants import Source
from core.models import Cluster, Component, RawReport
from core.parsers.trivy import parse_trivy_sbom
from core.services.ingest import ingest_scan
from core.services.sbom import backfill_raw_sbom, save_sbom_components

FIXTURES = Path(__file__).parent / "fixtures"


def _load_fixture(name: str) -> dict:
    return json.loads((FIXTURES / name).read_text())


# ── Parser tests (no DB) ──────────────────────────────────────


class TestParseTrivySbom:
    def test_returns_sbom_dict(self):
        payload = _load_fixture("sbom_report.json")
        result = parse_trivy_sbom("test-cluster", payload)

        assert len(result) == 1
        data = result[0]
        assert data["_sbom"] is True
        assert data["image"] == "docker.io/library/nginx:1.25.4"
        assert data["namespace"] == "prod-app-backend"
        assert data["resource_name"] == "backend-6d4cf56db6"

    def test_component_count(self):
        payload = _load_fixture("sbom_report.json")
        data = parse_trivy_sbom("test-cluster", payload)[0]
        # 3 library components (container root is skipped)
        assert len(data["components"]) == 3

    def test_component_fields(self):
        payload = _load_fixture("sbom_report.json")
        data = parse_trivy_sbom("test-cluster", payload)[0]
        openssl = data["components"][0]

        assert openssl["name"] == "openssl"
        assert openssl["version"] == "1.1.1k"
        assert openssl["component_type"] == "library"
        assert openssl["purl"] == "pkg:deb/debian/openssl@1.1.1k"
        assert openssl["licenses"] == ["OpenSSL"]

    def test_multi_license(self):
        payload = _load_fixture("sbom_report.json")
        data = parse_trivy_sbom("test-cluster", payload)[0]
        libc = data["components"][2]

        assert libc["name"] == "libc6"
        assert libc["licenses"] == ["GPL-2.0-only", "LGPL-2.1-only"]

    def test_empty_bom(self):
        payload = {
            "kind": "SbomReport",
            "metadata": {"labels": {}},
            "report": {"components": {"components": []}},
        }
        data = parse_trivy_sbom("test-cluster", payload)[0]
        assert data["_sbom"] is True
        assert data["components"] == []

    def test_skips_container_type(self):
        """Root container component (the image itself) is skipped."""
        payload = {
            "kind": "SbomReport",
            "metadata": {"labels": {}},
            "report": {
                "registry": {"server": "docker.io"},
                "artifact": {"repository": "library/nginx", "tag": "1.25"},
                "components": {
                    "components": [
                        {"name": "nginx", "version": "1.25", "type": "container", "purl": "pkg:oci/nginx"},
                        {"name": "openssl", "version": "3.0", "type": "library", "purl": "pkg:deb/openssl@3.0"},
                    ]
                },
            },
        }
        data = parse_trivy_sbom("test-cluster", payload)[0]
        assert len(data["components"]) == 1
        assert data["components"][0]["name"] == "openssl"


# ── Model tests ────────────────────────────────────────────────


@pytest.mark.django_db
class TestComponentModel:
    def test_create(self, cluster):
        c = Component.objects.create(
            cluster=cluster,
            image="docker.io/library/nginx:1.25",
            name="openssl",
            version="1.1.1k",
            purl="pkg:deb/debian/openssl@1.1.1k",
            licenses=["OpenSSL"],
        )
        assert str(c) == "openssl@1.1.1k"

    def test_unique_constraint(self, cluster):
        Component.objects.create(
            cluster=cluster, image="img:1", name="pkg", version="1.0"
        )
        with pytest.raises(Exception):
            Component.objects.create(
                cluster=cluster, image="img:1", name="pkg", version="1.0"
            )

    def test_different_version_ok(self, cluster):
        Component.objects.create(
            cluster=cluster, image="img:1", name="pkg", version="1.0"
        )
        Component.objects.create(
            cluster=cluster, image="img:1", name="pkg", version="2.0"
        )
        assert Component.objects.count() == 2

    def test_different_cluster_ok(self):
        c1 = Cluster.objects.create(name="c1")
        c2 = Cluster.objects.create(name="c2")
        Component.objects.create(cluster=c1, image="img:1", name="pkg", version="1.0")
        Component.objects.create(cluster=c2, image="img:1", name="pkg", version="1.0")
        assert Component.objects.count() == 2


# ── Service tests ──────────────────────────────────────────────


@pytest.mark.django_db
class TestSaveSbomComponents:
    def test_creates_components(self, cluster):
        payload = _load_fixture("sbom_report.json")
        data = parse_trivy_sbom("test-cluster", payload)[0]
        result = save_sbom_components(cluster, data)

        assert result["status"] == "success"
        assert result["components_created"] == 3
        assert Component.objects.filter(cluster=cluster).count() == 3

    def test_component_values(self, cluster):
        payload = _load_fixture("sbom_report.json")
        data = parse_trivy_sbom("test-cluster", payload)[0]
        save_sbom_components(cluster, data)

        openssl = Component.objects.get(name="openssl", cluster=cluster)
        assert openssl.version == "1.1.1k"
        assert openssl.purl == "pkg:deb/debian/openssl@1.1.1k"
        assert openssl.licenses == ["OpenSSL"]
        assert openssl.image == "docker.io/library/nginx:1.25.4"
        assert openssl.namespace == "prod-app-backend"

    def test_upsert_on_rescan(self, cluster):
        payload = _load_fixture("sbom_report.json")
        data = parse_trivy_sbom("test-cluster", payload)[0]
        save_sbom_components(cluster, data)
        result = save_sbom_components(cluster, data)

        assert result["components_created"] == 0
        assert result["components_updated"] == 3
        assert Component.objects.filter(cluster=cluster).count() == 3

    def test_removes_stale_components(self, cluster):
        """Components not in current BOM are deleted (Convention D4)."""
        payload = _load_fixture("sbom_report.json")
        data = parse_trivy_sbom("test-cluster", payload)[0]
        save_sbom_components(cluster, data)
        assert Component.objects.filter(cluster=cluster).count() == 3

        # Second scan has only openssl
        data["components"] = [data["components"][0]]
        result = save_sbom_components(cluster, data)

        assert result["components_updated"] == 1
        assert result["components_removed"] == 2
        assert Component.objects.filter(cluster=cluster).count() == 1
        assert Component.objects.get(cluster=cluster).name == "openssl"

    def test_scoped_to_image(self, cluster):
        """Removing stale components only affects the same cluster+image."""
        payload = _load_fixture("sbom_report.json")
        data = parse_trivy_sbom("test-cluster", payload)[0]
        save_sbom_components(cluster, data)

        # Add a component for a different image
        Component.objects.create(
            cluster=cluster, image="other/image:v1", name="other-pkg", version="1.0"
        )
        assert Component.objects.filter(cluster=cluster).count() == 4

        # Rescan same image — other image's components untouched
        save_sbom_components(cluster, data)
        assert Component.objects.filter(cluster=cluster).count() == 4

    def test_skips_no_image(self, cluster):
        result = save_sbom_components(cluster, {"image": "", "components": []})
        assert result["status"] == "skipped"


# ── Ingest integration ─────────────────────────────────────────


@pytest.mark.django_db
class TestSbomIngestIntegration:
    def test_end_to_end(self):
        payload = _load_fixture("sbom_report.json")
        result = ingest_scan(payload, cluster_name_header="test-cluster")

        assert result["status"] == "success"
        assert result["kind"] == "SbomReport"
        assert result["components_created"] == 3
        assert RawReport.objects.count() == 0
        assert Component.objects.count() == 3

    def test_no_longer_raw(self):
        payload = _load_fixture("sbom_report.json")
        ingest_scan(payload, cluster_name_header="test-cluster")
        assert RawReport.objects.count() == 0


# ── Backfill ───────────────────────────────────────────────────


@pytest.mark.django_db
class TestBackfillSbom:
    def test_backfill_processes_raw_reports(self, cluster):
        payload = _load_fixture("sbom_report.json")
        RawReport.objects.create(
            cluster=cluster,
            kind="SbomReport",
            source=Source.TRIVY,
            raw_json=payload,
        )

        result = backfill_raw_sbom()
        assert result["processed"] == 1
        assert result["errors"] == 0
        assert Component.objects.filter(cluster=cluster).count() == 3

    def test_backfill_filter_by_cluster(self, cluster):
        payload = _load_fixture("sbom_report.json")
        other = Cluster.objects.create(name="other-cluster")
        RawReport.objects.create(cluster=cluster, kind="SbomReport", raw_json=payload)
        RawReport.objects.create(cluster=other, kind="SbomReport", raw_json=payload)

        result = backfill_raw_sbom(cluster_name="test-cluster")
        assert result["processed"] == 1
        assert Component.objects.filter(cluster=cluster).count() == 3
        assert Component.objects.filter(cluster=other).count() == 0
