"""Regression test — supply-chain findings surface in the existing
`/findings/` page through the Source filter dropdown (which auto-picks
up new `Source` enum entries) and the IMMEDIATE priority short-circuit
in `core.urgency.score`.
"""
from __future__ import annotations

import pytest
from django.contrib.auth.models import User
from django.urls import reverse

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
from core.services.supply_chain_matcher import match_iocs_to_components


@pytest.fixture
def viewer(db):
    return User.objects.create_user(username="viewer-sc", password="x")


@pytest.fixture
def seeded_match(db):
    c = Cluster.objects.create(name="c-sc", environment=Environment.PROD.value)
    ns = Namespace.objects.create(cluster=c, name="payments")
    w = Workload.objects.create(
        cluster=c, namespace=ns, kind="Deployment", name="api", deployed=True,
    )
    img = Image.objects.create(digest="sha256:" + "a" * 64, ref="reg/api:v1")
    WorkloadImageObservation.objects.create(
        workload=w, image=img, container_name="app", currently_deployed=True,
    )
    SbomComponent.objects.create(
        image=img, purl="pkg:npm/lodash@4.17.21",
        name="lodash", version="4.17.21", ecosystem="npm",
    )
    SupplyChainIoc.objects.create(
        purl="pkg:npm/lodash@4.17.21",
        feed_source="osv",
        advisory_id="MAL-2026-1",
        severity=Severity.CRITICAL.value,
        title="Malicious lodash",
        advisory_url="https://example.test/MAL-2026-1",
    )
    match_iocs_to_components()
    return c, w, img


def test_finding_lands_with_immediate_priority(seeded_match):
    f = Finding.objects.get(source=Source.SUPPLY_CHAIN_IOC.value)
    assert f.category == Category.SUPPLY_CHAIN.value
    assert f.effective_priority == PriorityBand.IMMEDIATE.value
    assert f.title.startswith("Malicious package:")


def test_source_filter_dropdown_includes_supply_chain(client, viewer, seeded_match):
    client.force_login(viewer)
    resp = client.get(reverse("findings-list"))
    body = resp.content.decode()
    # The dropdown iterates Source.choices, so the new enum entry
    # appears as an <option>.
    assert 'value="supply_chain_ioc"' in body
    assert "Supply-Chain IoC" in body


def test_source_filter_narrows_to_supply_chain(client, viewer, seeded_match):
    client.force_login(viewer)
    resp = client.get(reverse("findings-list") + "?source=supply_chain_ioc")
    body = resp.content.decode()
    assert "Malicious package: lodash@4.17.21" in body
    # The supply-chain finding renders with IMMEDIATE band — find the chip.
    assert "Immediate" in body or "IMMEDIATE" in body.lower()


def test_name_search_finds_supply_chain_by_advisory_id(client, viewer, seeded_match):
    client.force_login(viewer)
    resp = client.get(reverse("findings-list") + "?name=MAL-2026-1")
    body = resp.content.decode()
    assert "Malicious package: lodash" in body
