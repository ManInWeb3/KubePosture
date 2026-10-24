"""The namespace dropdown on the list pages follows the selected cluster.

The full page already scoped it server-side; the HTMX filter requests
only swapped the rows, so the dropdown rendered at page load kept every
namespace. The partial now carries the scoped `<select>` as an
out-of-band swap, and a namespace that isn't in the selected cluster is
dropped from the filter instead of emptying the table.
"""
from __future__ import annotations

import re

import pytest
from django.contrib.auth.models import User
from django.urls import reverse
from django.utils import timezone

from core.constants import Environment
from core.models import Cluster, Image, Namespace, Workload, WorkloadImageObservation


@pytest.fixture
def authed(client, db):
    client.force_login(User.objects.create_user(username="nsf", password="x"))
    return client


@pytest.fixture
def two_clusters(db):
    """Cluster `ca` with namespace `ns-alpha`, cluster `cb` with `ns-beta`,
    one deployed workload (and one deployed image) in each."""
    out = {}
    for cname, nsname, digest in (("ca", "ns-alpha", "a"), ("cb", "ns-beta", "b")):
        c = Cluster.objects.create(name=cname, environment=Environment.PROD.value)
        c.last_complete_inventory_at = timezone.now()
        c.save()
        ns = Namespace.objects.create(cluster=c, name=nsname)
        w = Workload.objects.create(
            cluster=c, namespace=ns, kind="Deployment", name=f"api-{cname}",
            deployed=True, last_inventory_at=c.last_complete_inventory_at,
        )
        img = Image.objects.create(digest="sha256:" + digest * 64, ref=f"reg/api-{cname}:v1",
                                   registry="reg", repository=f"api-{cname}")
        WorkloadImageObservation.objects.create(
            workload=w, image=img, container_name="app", currently_deployed=True,
        )
        out[cname] = (c, ns, w, img)
    return out


def _namespace_select(body: str) -> str:
    m = re.search(r'<select[^>]*name="namespace"[^>]*>.*?</select>', body, re.S)
    assert m, "namespace <select> missing from response"
    return m.group(0)


def _options(select_html: str) -> list[str]:
    return re.findall(r'<option value="([^"]*)"', select_html)


# ── full page ──────────────────────────────────────────────────────


def test_full_page_scopes_namespaces_to_cluster(authed, two_clusters):
    body = authed.get(reverse("workloads-list"), {"cluster": "ca"}).content.decode()
    opts = _options(_namespace_select(body))
    assert "ns-alpha" in opts and "ns-beta" not in opts


def test_full_page_without_cluster_lists_every_namespace(authed, two_clusters):
    body = authed.get(reverse("workloads-list")).content.decode()
    opts = _options(_namespace_select(body))
    assert {"ns-alpha", "ns-beta"} <= set(opts)


# ── HTMX partial (what the filter form actually requests) ──────────


@pytest.mark.parametrize("url_name,target", [
    ("workloads-list", "workload-rows"),
    ("images-list", "image-rows"),
])
def test_partial_carries_oob_namespace_select_scoped_to_cluster(
    authed, two_clusters, url_name, target,
):
    resp = authed.get(reverse(url_name), {"cluster": "ca"},
                      HTTP_HX_REQUEST="true", HTTP_HX_TARGET=target)
    assert resp.status_code == 200
    body = resp.content.decode()
    assert "<html" not in body.lower()
    select = _namespace_select(body)
    assert 'hx-swap-oob="true"' in select
    opts = _options(select)
    assert "ns-alpha" in opts and "ns-beta" not in opts


def test_partial_keeps_namespace_selected_when_it_belongs_to_cluster(authed, two_clusters):
    body = authed.get(reverse("workloads-list"), {"cluster": "ca", "namespace": "ns-alpha"},
                      HTTP_HX_REQUEST="true", HTTP_HX_TARGET="workload-rows").content.decode()
    select = _namespace_select(body)
    assert re.search(r'value="ns-alpha"[^>]*selected', select)


def test_partial_drops_namespace_from_another_cluster(authed, two_clusters):
    """Switching cluster while a namespace of the previous cluster is still
    selected: the stale namespace must neither stay selected nor empty the
    table — the rows are those of the cluster alone."""
    body = authed.get(reverse("workloads-list"), {"cluster": "ca", "namespace": "ns-beta"},
                      HTTP_HX_REQUEST="true", HTTP_HX_TARGET="workload-rows").content.decode()
    select = _namespace_select(body)
    assert "selected" not in select
    assert "api-ca" in body
    assert "No workloads match" not in body


def test_partial_without_cluster_lists_every_namespace(authed, two_clusters):
    body = authed.get(reverse("workloads-list"), {"namespace": "ns-beta"},
                      HTTP_HX_REQUEST="true", HTTP_HX_TARGET="workload-rows").content.decode()
    select = _namespace_select(body)
    assert {"ns-alpha", "ns-beta"} <= set(_options(select))
    assert re.search(r'value="ns-beta"[^>]*selected', select)
    assert "api-cb" in body and "api-ca" not in body


# ── response shape (what the browser's HTML parser sees) ───────────


@pytest.mark.parametrize("url_name,target", [
    ("workloads-list", "workload-rows"),
    ("images-list", "image-rows"),
])
def test_partial_puts_rows_before_the_oob_select(authed, two_clusters, url_name, target):
    """htmx parses the partial inside a `<template>`, and the parser picks
    the template's insertion mode from the first start tag: a leading
    `<select>` means "in body", which drops every `<tr>`/`<td>` after it and
    renders the table as one flat run of text. The partial must therefore
    open with a `<tr>` and carry the OOB `<select>` after the last row."""
    body = authed.get(reverse(url_name), {"cluster": "ca"},
                      HTTP_HX_REQUEST="true", HTTP_HX_TARGET=target).content.decode()
    assert body.lstrip().startswith("<tr"), body[:200]
    assert body.rindex("</tr>") < body.index('<select name="namespace"')


@pytest.mark.parametrize("url_name,target", [
    ("workloads-list", "workload-rows"),
    ("images-list", "image-rows"),
])
def test_namespace_select_template_comment_does_not_leak(authed, two_clusters, url_name, target):
    """Django's `{# #}` is single-line only; a multi-line one renders its
    text verbatim — into the filter bar on the full page and into the swapped
    rows on the partial."""
    full = authed.get(reverse(url_name)).content.decode()
    partial = authed.get(reverse(url_name), {"cluster": "ca"},
                         HTTP_HX_REQUEST="true", HTTP_HX_TARGET=target).content.decode()
    for body in (full, partial):
        assert "{#" not in body and "#}" not in body
        assert "Namespace filter dropdown" not in body
