"""Unit tests for core.parsers.trivy.parse_sbom_report.

Pure-function tests against in-memory CRD fixtures. Checks that
components without purls are skipped, ecosystem is derived from
purl prefix, and per-component properties (LayerDigest, license,
supplier) are extracted correctly.
"""
from __future__ import annotations

from core.parsers import trivy


def _sbom_report(
    *,
    namespace: str = "payments",
    workload_kind: str = "ReplicaSet",
    workload_name: str = "api-server-7d9f5b6c8d",
    container: str = "app",
    image_repo: str = "payments/api",
    image_tag: str = "v1.2.3",
    image_digest: str = "sha256:" + "a" * 64,
    components: list[dict] | None = None,
) -> dict:
    return {
        "apiVersion": "aquasecurity.github.io/v1alpha1",
        "kind": "SbomReport",
        "metadata": {
            "name": f"{workload_kind.lower()}-{workload_name}-{container}",
            "namespace": namespace,
            "labels": {
                "trivy-operator.resource.namespace": namespace,
                "trivy-operator.resource.kind": workload_kind,
                "trivy-operator.resource.name": workload_name,
                "trivy-operator.container.name": container,
            },
        },
        "report": {
            "registry": {"server": "registry.internal"},
            "artifact": {
                "repository": image_repo,
                "tag": image_tag,
                "digest": image_digest,
            },
            "components": {
                "bomFormat": "CycloneDX",
                "specVersion": "1.4",
                "metadata": {
                    "component": {
                        # The root container component has no purl and must be ignored.
                        "type": "container",
                        "name": f"{image_repo}:{image_tag}",
                    },
                },
                "components": components or [],
            },
        },
    }


def _component(
    *,
    purl: str,
    name: str | None = None,
    version: str = "1.0",
    type_: str = "library",
    license_id: str | None = None,
    supplier: str | None = None,
    layer_digest: str | None = None,
    pkg_type: str | None = None,
) -> dict:
    comp: dict = {
        "bom-ref": purl,
        "type": type_,
        "name": name or purl.split("/")[-1].split("@")[0],
        "version": version,
        "purl": purl,
    }
    if license_id:
        comp["licenses"] = [{"license": {"id": license_id}}]
    if supplier:
        comp["supplier"] = {"name": supplier}
    props = []
    if layer_digest:
        props.append({"name": "aquasecurity:trivy:LayerDigest", "value": layer_digest})
    if pkg_type:
        props.append({"name": "aquasecurity:trivy:PkgType", "value": pkg_type})
    if props:
        comp["properties"] = props
    return comp


def test_sbom_report_extracts_workload_identity_and_image():
    obj = _sbom_report(components=[_component(purl="pkg:npm/lodash@4.17.21")])
    parsed = trivy.parse_sbom_report(obj)

    assert parsed["kind"] == "trivy.SbomReport"
    assert parsed["namespace"] == "payments"
    assert parsed["resource_kind"] == "ReplicaSet"
    assert parsed["resource_name"] == "api-server-7d9f5b6c8d"
    assert parsed["container_name"] == "app"
    assert parsed["image_digest"] == "sha256:" + "a" * 64
    assert "payments/api" in parsed["image_ref"]


def test_sbom_report_skips_components_without_purl():
    obj = _sbom_report(components=[
        {"type": "library", "name": "no-purl-pkg", "version": "1.0"},
        _component(purl="pkg:npm/lodash@4.17.21"),
    ])
    parsed = trivy.parse_sbom_report(obj)
    assert len(parsed["components"]) == 1
    assert parsed["components"][0]["purl"] == "pkg:npm/lodash@4.17.21"


def test_sbom_report_derives_ecosystem_from_purl():
    obj = _sbom_report(components=[
        _component(purl="pkg:npm/lodash@4.17.21"),
        _component(purl="pkg:pypi/requests@2.28.0"),
        _component(purl="pkg:golang/github.com/foo/bar@v1.0.0"),
        _component(purl="pkg:deb/debian/libc6@2.36-9?arch=amd64"),
        _component(purl="pkg:rpm/rhel/glibc@2.34-100?arch=x86_64"),
    ])
    parsed = trivy.parse_sbom_report(obj)
    ecosystems = [c["ecosystem"] for c in parsed["components"]]
    assert ecosystems == ["npm", "pypi", "golang", "deb", "rpm"]


def test_sbom_report_falls_back_to_pkg_type_property_when_purl_lacks_type():
    # A purl that doesn't start with `pkg:` (degraded data); falls back to PkgType.
    obj = _sbom_report(components=[
        _component(purl="weird-purl@1.0", pkg_type="npm"),
    ])
    parsed = trivy.parse_sbom_report(obj)
    assert parsed["components"][0]["ecosystem"] == "npm"


def test_sbom_report_extracts_license_supplier_layer_digest():
    obj = _sbom_report(components=[
        _component(
            purl="pkg:npm/lodash@4.17.21",
            license_id="MIT",
            supplier="Example, Inc.",
            layer_digest="sha256:" + "b" * 64,
        ),
    ])
    parsed = trivy.parse_sbom_report(obj)
    comp = parsed["components"][0]
    assert comp["license"] == "MIT"
    assert comp["supplier"] == "Example, Inc."
    assert comp["layer_digest"] == "sha256:" + "b" * 64
    assert comp["component_type"] == "library"


def test_sbom_report_preserves_raw_component():
    raw = _component(purl="pkg:npm/lodash@4.17.21", license_id="MIT")
    obj = _sbom_report(components=[raw])
    parsed = trivy.parse_sbom_report(obj)
    assert parsed["components"][0]["raw"] == raw


def test_sbom_report_empty_components():
    obj = _sbom_report(components=[])
    parsed = trivy.parse_sbom_report(obj)
    assert parsed["components"] == []


def test_parser_registered_in_dispatch():
    assert "trivy.SbomReport" in trivy.PARSERS_BY_KIND
    assert trivy.PARSERS_BY_KIND["trivy.SbomReport"] is trivy.parse_sbom_report
