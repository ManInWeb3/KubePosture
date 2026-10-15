"""Cluster page: when was this cluster last imported, and how did that
import go — the "Imports" card built from `Cluster.last_complete_inventory_at`
and the most recent import's ImportMark rows."""
from __future__ import annotations

from datetime import timedelta

import pytest
from django.contrib.auth.models import User
from django.template.defaultfilters import date as date_filter
from django.urls import reverse
from django.utils import timezone
from django.utils.timesince import timesince

from core.constants import Environment, ImportDiscardReason, ImportMarkState
from core.models import Cluster, ImportMark


@pytest.fixture
def cluster(db):
    return Cluster.objects.create(name="c-imp", environment=Environment.PROD.value)


@pytest.fixture
def authed(client, db):
    client.force_login(User.objects.create_user(username="v", password="x"))
    return client


def _import(cluster, import_id, *, started_at, kinds):
    """`kinds`: {kind: (state, failed_count, discard_reason)}."""
    for kind, (state, failed, reason) in kinds.items():
        ImportMark.objects.create(cluster=cluster, kind=kind, import_id=import_id, state=state,
                                  started_at=started_at, observed_count=3, failed_count=failed,
                                  discard_reason=reason, last_error="boom" if failed else "")


def _page(authed, cluster):
    resp = authed.get(reverse("cluster-detail", args=[cluster.pk]))
    assert resp.status_code == 200
    return resp


def test_never_imported_cluster_says_so(authed, cluster):
    resp = _page(authed, cluster)
    assert resp.context["latest_import"] is None
    assert resp.content.decode().count(">never<") == 2, "both timestamps read 'never'"


def test_complete_import_shows_anchor_and_per_kind_rows(authed, cluster):
    t = timezone.now() - timedelta(hours=2)
    _import(cluster, "01OLD", started_at=t - timedelta(days=1),
            kinds={"inventory": (ImportMarkState.REAPED.value, 0, "")})
    _import(cluster, "01NEW", started_at=t, kinds={
        "inventory": (ImportMarkState.REAPED.value, 0, ""),
        "trivy.VulnerabilityReport": (ImportMarkState.REAPED.value, 0, ""),
    })
    Cluster.objects.filter(pk=cluster.pk).update(last_complete_inventory_at=t)

    resp = _page(authed, cluster)
    li = resp.context["latest_import"]
    assert (li["import_id"], li["status"], li["started_at"], li["reaped"]) == ("01NEW", "complete", t, 2)
    assert [m.kind for m in li["kinds"]] == ["inventory", "trivy.VulnerabilityReport"]
    body = resp.content.decode()
    assert date_filter(timezone.localtime(t), "Y-m-d H:i") in body
    assert f"({timesince(t)} ago)" in body and "<code>01NEW</code>" in body and "01OLD" not in body


@pytest.mark.parametrize(("kinds", "status"), [
    ({"inventory": ("open", 0, ""), "kyverno.PolicyReport": ("open", 0, "")}, "uploading"),
    ({"inventory": ("reaped", 0, ""), "kyverno.PolicyReport": ("draining", 0, "")}, "processing"),
    ({"inventory": ("reaped", 0, ""), "kyverno.PolicyReport": ("reaped", 2, "")}, "failed"),
    ({"inventory": ("reaped", 1, ImportDiscardReason.INVENTORY_FAILED.value),
      "kyverno.PolicyReport": ("reaped", 0, ImportDiscardReason.INVENTORY_FAILED.value)}, "discarded"),
], ids=["uploading", "processing", "failed", "discarded"])
def test_latest_import_status_rolls_up_the_kind_states(authed, cluster, kinds, status):
    _import(cluster, "01X", started_at=timezone.now(), kinds=kinds)
    resp = _page(authed, cluster)
    li = resp.context["latest_import"]
    assert li["status"] == status
    body = resp.content.decode()
    assert f">{status}<" in body
    if status == "failed":
        assert li["failed_count"] == 2 and "boom" in body
    if status == "discarded":
        assert ImportDiscardReason.INVENTORY_FAILED.label in body
