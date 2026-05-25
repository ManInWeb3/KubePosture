"""Tests for the `manage.py match_supply_chain` management command."""
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


def _seed_matchable(purl: str = "pkg:npm/lodash@4.17.21"):
    c = Cluster.objects.create(name="c-cmd", environment=Environment.PROD.value)
    ns = Namespace.objects.create(cluster=c, name="payments")
    w = Workload.objects.create(
        cluster=c, namespace=ns, kind="Deployment", name="api", deployed=True,
    )
    img = Image.objects.create(digest="sha256:" + "a" * 64, ref="r:1")
    WorkloadImageObservation.objects.create(
        workload=w, image=img, container_name="main", currently_deployed=True,
    )
    SbomComponent.objects.create(
        image=img, purl=purl, name="lodash", version="4.17.21", ecosystem="npm",
    )
    SupplyChainIoc.objects.create(
        purl=purl, feed_source="osv", advisory_id="MAL-cmd",
        severity="critical", title="x",
    )


@pytest.mark.django_db
def test_match_supply_chain_full_scan_creates_findings():
    _seed_matchable()
    out = io.StringIO()
    call_command("match_supply_chain", stdout=out)
    assert "findings_touched=1" in out.getvalue()
    assert "scope=all IoCs" in out.getvalue()
    assert Finding.objects.filter(source="supply_chain_ioc").count() == 1


@pytest.mark.django_db
def test_match_supply_chain_purl_scope():
    _seed_matchable(purl="pkg:npm/lodash@4.17.21")
    out = io.StringIO()
    call_command(
        "match_supply_chain",
        "--purl", "pkg:npm/lodash@4.17.21",
        stdout=out,
    )
    assert "scope=1 purl(s)" in out.getvalue()
    assert "findings_touched=1" in out.getvalue()


@pytest.mark.django_db
def test_match_supply_chain_no_iocs_returns_zero():
    out = io.StringIO()
    call_command("match_supply_chain", stdout=out)
    assert "findings_touched=0" in out.getvalue()


@pytest.mark.django_db
def test_match_supply_chain_purl_scope_normalises_encoded():
    """`%40` in the CLI arg still matches the stored `@` purl."""
    _seed_matchable(purl="pkg:npm/lodash@4.17.21")
    out = io.StringIO()
    call_command(
        "match_supply_chain",
        "--purl", "pkg:npm/lodash%404.17.21",
        stdout=out,
    )
    assert "findings_touched=1" in out.getvalue()
