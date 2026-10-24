"""The finding panel (`/findings/<pk>/panel/`) for findings that don't come
from the matchers that record a purl: a Trivy vulnerability names the package
and version only, so the panel looks the purl up in the image's SBOM.
"""
from __future__ import annotations

import pytest
from django.contrib.auth.models import User
from django.urls import reverse

from core.constants import Category, Environment, Severity, Source
from core.models import (
    Cluster,
    Finding,
    Image,
    Namespace,
    SbomComponent,
    Workload,
)


@pytest.fixture
def scene(db):
    c = Cluster.objects.create(name="c1", environment=Environment.PROD.value)
    ns = Namespace.objects.create(cluster=c, name="payments")
    w = Workload.objects.create(cluster=c, namespace=ns, kind="Deployment", name="api",
                                deployed=True)
    img = Image.objects.create(digest="sha256:" + "a" * 64, ref="reg/api:v1")
    return {"cluster": c, "workload": w, "image": img}


def _component(image, purl, name, version, ecosystem):
    return SbomComponent.objects.create(image=image, purl=purl, name=name, version=version,
                                        ecosystem=ecosystem)


_hash = iter(range(10_000))


def _trivy_finding(scene, *, pkg_name, installed_version, image=True, **details):
    return Finding.objects.create(
        cluster=scene["cluster"], workload=scene["workload"],
        image=scene["image"] if image else None,
        source=Source.TRIVY.value, category=Category.VULNERABILITY.value,
        vuln_id="CVE-2026-0001", pkg_name=pkg_name, installed_version=installed_version,
        severity=Severity.HIGH.value, title="a vulnerability", details=details,
        hash_code=f"h{next(_hash):060d}",
    )


def _panel(client, finding) -> str:
    client.force_login(User.objects.create_user(username=f"panel{finding.pk}", password="x"))
    resp = client.get(reverse("findings-detail-panel", args=[finding.pk]))
    assert resp.status_code == 200
    return resp.content.decode()


def test_trivy_finding_shows_the_purl_of_its_sbom_component(client, scene):
    img = scene["image"]
    # Trivy's `resource` for a scoped package carries the scope; the SBOM
    # `name` doesn't (it is in `group`), the purl does.
    _component(img, "pkg:npm/@tanstack/router-devtools-core@1.168.1", "router-devtools-core",
               "1.168.1", "npm")
    _component(img, "pkg:npm/@tanstack/router-devtools-core@1.167.6", "router-devtools-core",
               "1.167.6", "npm")
    f = _trivy_finding(scene, pkg_name="@tanstack/router-devtools-core",
                       installed_version="1.168.1")

    body = _panel(client, f)

    assert "Package URL" in body
    assert "pkg:npm/@tanstack/router-devtools-core@1.168.1" in body
    assert "router-devtools-core@1.167.6" not in body  # the other version is not this finding


def test_trivy_os_package_matches_the_purl_with_a_namespace(client, scene):
    _component(scene["image"], "pkg:deb/debian/libc6@2.36-9", "libc6", "2.36-9", "deb")
    f = _trivy_finding(scene, pkg_name="libc6", installed_version="2.36-9")

    assert "pkg:deb/debian/libc6@2.36-9" in _panel(client, f)


def test_no_package_url_row_without_a_matching_component(client, scene):
    other = Image.objects.create(digest="sha256:" + "b" * 64, ref="reg/other:v1")
    _component(other, "pkg:npm/lodash@4.17.20", "lodash", "4.17.20", "npm")   # another image
    _component(scene["image"], "pkg:npm/lodash@4.17.21", "lodash", "4.17.21", "npm")  # other ver.
    _component(scene["image"], "pkg:npm/lodash-es@4.17.20", "lodash-es", "4.17.20", "npm")

    assert "Package URL" not in _panel(
        client, _trivy_finding(scene, pkg_name="lodash", installed_version="4.17.20"))


def test_finding_without_an_image_or_package_does_not_look_anything_up(client, scene):
    no_image = _trivy_finding(scene, pkg_name="lodash", installed_version="1", image=False)
    no_package = _trivy_finding(scene, pkg_name="", installed_version="")

    assert "Package URL" not in _panel(client, no_image)
    assert "Package URL" not in _panel(client, no_package)


def test_only_http_links_are_rendered(client, scene):
    f = _trivy_finding(scene, pkg_name="x", installed_version="1",
                       primary_link="https://avd.example.test/CVE-2026-0001",
                       links=["javascript:alert(1)", "https://example.test/advisory",
                              "https://avd.example.test/CVE-2026-0001"])

    body = _panel(client, f).split("Raw details JSON")[0]

    assert 'href="https://example.test/advisory"' in body
    assert "javascript:" not in body
    assert body.count('href="https://avd.example.test/CVE-2026-0001"') == 1  # not repeated
