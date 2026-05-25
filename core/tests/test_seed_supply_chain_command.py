"""Tests for the `manage.py seed_supply_chain_test` command."""
from __future__ import annotations

import io

import pytest
from django.core.management import call_command

from core.constants import Environment
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


@pytest.mark.django_db
def test_seed_creates_full_chain_and_finding():
    out = io.StringIO()
    call_command("seed_supply_chain_test", stdout=out, stderr=io.StringIO())
    body = out.getvalue()

    assert "Seeding full test chain" in body
    assert "findings touched: 1" in body

    assert Cluster.objects.filter(name="test-supply-chain").exists()
    assert SbomComponent.objects.filter(purl="pkg:npm/lodash@4.17.21").exists()
    assert SupplyChainIoc.objects.filter(feed_source="manual-test").exists()
    assert Finding.objects.filter(source="supply_chain_ioc").count() == 1


@pytest.mark.django_db
def test_seed_with_custom_purl():
    out = io.StringIO()
    call_command(
        "seed_supply_chain_test",
        "--purl", "pkg:pypi/ctx@0.1.2",
        stdout=out, stderr=io.StringIO(),
    )
    assert SbomComponent.objects.filter(purl="pkg:pypi/ctx@0.1.2").exists()
    assert SupplyChainIoc.objects.filter(purl="pkg:pypi/ctx@0.1.2").exists()
    f = Finding.objects.get(source="supply_chain_ioc")
    assert f.pkg_name == "ctx"
    assert f.installed_version == "0.1.2"


@pytest.mark.django_db
def test_seed_with_scoped_purl_extracts_name_correctly():
    """Regression: scoped names that start with `@` (npm @types, the
    user's @ctx test case) broke `split("@")[0]` parsing.
    """
    out = io.StringIO()
    call_command(
        "seed_supply_chain_test",
        "--purl", "pkg:pypi/@ctx@0.1.2",
        stdout=out, stderr=io.StringIO(),
    )
    comp = SbomComponent.objects.get(purl="pkg:pypi/@ctx@0.1.2")
    assert comp.name == "@ctx"
    assert comp.version == "0.1.2"
    assert comp.ecosystem == "pypi"

    f = Finding.objects.get(source="supply_chain_ioc")
    assert f.pkg_name == "@ctx"
    assert f.installed_version == "0.1.2"
    # Title shows the full identifier, not just "@0.1.2".
    assert "@ctx@0.1.2" in f.title


@pytest.mark.django_db
def test_seed_with_npm_scoped_purl():
    out = io.StringIO()
    call_command(
        "seed_supply_chain_test",
        "--purl", "pkg:npm/@types/node@20.0.0",
        stdout=out, stderr=io.StringIO(),
    )
    comp = SbomComponent.objects.get(purl="pkg:npm/@types/node@20.0.0")
    assert comp.name == "@types/node"
    assert comp.version == "20.0.0"
    assert comp.ecosystem == "npm"


@pytest.mark.django_db
def test_use_existing_purl_when_present():
    # Pre-seed a "real" deployed component without an IoC.
    c = Cluster.objects.create(name="prod-x", environment=Environment.PROD.value)
    ns = Namespace.objects.create(cluster=c, name="payments")
    w = Workload.objects.create(
        cluster=c, namespace=ns, kind="Deployment", name="api", deployed=True,
    )
    img = Image.objects.create(digest="sha256:" + "b" * 64, ref="reg/api:v1")
    WorkloadImageObservation.objects.create(
        workload=w, image=img, container_name="main", currently_deployed=True,
    )
    SbomComponent.objects.create(
        image=img, purl="pkg:npm/express@4.18.0",
        name="express", version="4.18.0", ecosystem="npm",
    )

    out = io.StringIO()
    call_command(
        "seed_supply_chain_test",
        "--use-existing-purl", "pkg:npm/express@4.18.0",
        stdout=out, stderr=io.StringIO(),
    )
    body = out.getvalue()
    assert "Inserting IoC against existing purl" in body
    assert "deployed observations matching this purl: 1" in body
    # No synthetic cluster was added.
    assert not Cluster.objects.filter(name="test-supply-chain").exists()
    # Finding was created against the real workload.
    f = Finding.objects.get(source="supply_chain_ioc")
    assert f.workload_id == w.id


@pytest.mark.django_db
def test_use_existing_purl_errors_when_not_in_db():
    out = io.StringIO()
    err = io.StringIO()
    call_command(
        "seed_supply_chain_test",
        "--use-existing-purl", "pkg:npm/doesnotexist@1.0",
        stdout=out, stderr=err,
    )
    assert "not found in SbomComponent" in err.getvalue()
    assert not Finding.objects.filter(source="supply_chain_ioc").exists()


@pytest.mark.django_db
def test_cleanup_removes_all_test_rows():
    # First seed everything.
    call_command("seed_supply_chain_test", stdout=io.StringIO(), stderr=io.StringIO())
    assert Finding.objects.filter(source="supply_chain_ioc").exists()
    assert Cluster.objects.filter(name="test-supply-chain").exists()

    # Then clean up.
    call_command(
        "seed_supply_chain_test",
        "--cleanup",
        stdout=io.StringIO(), stderr=io.StringIO(),
    )
    assert not Cluster.objects.filter(name="test-supply-chain").exists()
    assert not SupplyChainIoc.objects.filter(feed_source="manual-test").exists()
    assert not Finding.objects.filter(
        source="supply_chain_ioc", vuln_id__startswith="TEST-",
    ).exists()


@pytest.mark.django_db
def test_cleanup_preserves_real_findings():
    """Cleanup must not touch findings that aren't TEST-*."""
    c = Cluster.objects.create(name="prod-real", environment=Environment.PROD.value)
    ns = Namespace.objects.create(cluster=c, name="payments")
    w = Workload.objects.create(
        cluster=c, namespace=ns, kind="Deployment", name="api", deployed=True,
    )
    img = Image.objects.create(digest="sha256:" + "c" * 64, ref="reg/api:v1")
    real = Finding.objects.create(
        cluster=c, workload=w, image=img,
        source="supply_chain_ioc", category="supply_chain",
        vuln_id="MAL-real-not-test", pkg_name="real", installed_version="1.0",
        title="real", severity="critical", details={},
        hash_code="real-hash",
        first_seen="2026-04-01T00:00:00Z", last_seen="2026-04-01T00:00:00Z",
    )

    call_command(
        "seed_supply_chain_test",
        "--cleanup",
        stdout=io.StringIO(), stderr=io.StringIO(),
    )
    assert Finding.objects.filter(pk=real.pk).exists()
