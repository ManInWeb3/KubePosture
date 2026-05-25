"""Tests for the shared pagination widget + `elided_page_range` filter."""
from __future__ import annotations

import pytest
from django.contrib.auth.models import User
from django.core.paginator import Paginator
from django.template import Context, Template
from django.urls import reverse

from core.constants import Environment
from core.models import (
    Cluster,
    Image,
    Namespace,
    SbomComponent,
    Workload,
    WorkloadImageObservation,
)


# ── elided_page_range filter ─────────────────────────────────────


def _render_filter_test(page_number: int, total_items: int, per_page: int) -> list:
    paginator = Paginator(list(range(total_items)), per_page)
    page_obj = paginator.page(page_number)
    template = Template("{% load pagination_tags %}{{ page_obj|elided_page_range|safe }}")
    return template.render(Context({"page_obj": page_obj}))


def test_elided_page_range_small_page_count_shows_all():
    """With only 3 pages, no ellipsis is needed."""
    out = _render_filter_test(page_number=2, total_items=30, per_page=10)
    # 3 pages total → [1, 2, 3], no ellipsis.
    assert "1" in out
    assert "2" in out
    assert "3" in out
    assert "…" not in out


def test_elided_page_range_large_page_count_inserts_ellipsis():
    """With 20 pages and current=10, expect ellipsis on both sides."""
    out = _render_filter_test(page_number=10, total_items=200, per_page=10)
    assert "10" in out
    assert "1" in out and "20" in out   # endpoints
    assert "…" in out                   # ellipsis appears


def test_elided_page_range_page_one():
    """At page 1, only the right-side ellipsis kicks in."""
    out = _render_filter_test(page_number=1, total_items=200, per_page=10)
    assert "1" in out
    assert "20" in out
    assert "…" in out


# ── End-to-end via the components list page ──────────────────────


@pytest.fixture
def viewer(db):
    return User.objects.create_user(username="viewer-pag", password="x")


@pytest.fixture
def many_components(db):
    """Seed enough components to force pagination (page size = 50)."""
    c = Cluster.objects.create(name="c-pag", environment=Environment.PROD.value)
    ns = Namespace.objects.create(cluster=c, name="payments")
    w = Workload.objects.create(
        cluster=c, namespace=ns, kind="Deployment", name="api", deployed=True,
    )
    img = Image.objects.create(digest="sha256:" + "a" * 64, ref="reg/api:v1")
    WorkloadImageObservation.objects.create(
        workload=w, image=img, container_name="main", currently_deployed=True,
    )
    for i in range(75):     # > 1 page, < 100
        SbomComponent.objects.create(
            image=img,
            purl=f"pkg:npm/pkg-{i:03d}@1.0",
            name=f"pkg-{i:03d}", version="1.0", ecosystem="npm",
        )
    return c


def test_components_page_one_renders_numbered_buttons(client, viewer, many_components):
    client.force_login(viewer)
    resp = client.get(reverse("components-list"))
    body = resp.content.decode()
    # 75 components / 50 page size = 2 pages.
    # Both page numbers should appear as clickable buttons.
    assert ">1<" in body                                   # active button
    assert 'aria-current="page"' in body                   # active marker
    assert "page=2" in body                                # link to page 2
    # Prev arrow is disabled on page 1; Next is enabled.
    assert "Previous page" not in body or "disabled" in body


def test_components_page_two_active_state(client, viewer, many_components):
    client.force_login(viewer)
    resp = client.get(reverse("components-list") + "?page=2")
    body = resp.content.decode()
    # Active page marker is on 2 now.
    assert 'aria-current="page"' in body
    assert "page=1" in body                                # back to page 1
    assert ">2<" in body


def test_pagination_shows_in_htmx_partial(client, viewer, many_components):
    """The widget is included in `_rows.html` so it ships with the HTMX
    re-render too (not just the full-page response).
    """
    client.force_login(viewer)
    resp = client.get(
        reverse("components-list"),
        HTTP_HX_REQUEST="true",
        HTTP_HX_TARGET="component-rows",
    )
    body = resp.content.decode()
    assert 'class="pagination' in body
    assert "page=2" in body


def test_pagination_preserves_existing_filters(client, viewer, many_components):
    """`request_qs` excludes the `page` key so pagination links append
    page=N onto the current filter state instead of clobbering it.
    """
    client.force_login(viewer)
    resp = client.get(reverse("components-list") + "?ecosystem=npm")
    body = resp.content.decode()
    # Pagination links should carry ecosystem=npm forward.
    assert "ecosystem=npm" in body
    assert "page=2" in body


def test_widget_does_not_leak_doc_comment(client, viewer, many_components):
    """Regression: multi-line `{# #}` is not valid Django syntax (it's
    single-line only). The widget uses `{% comment %}…{% endcomment %}`;
    if someone reverts to `{# #}` the doc text leaks into the HTML.
    """
    client.force_login(viewer)
    resp = client.get(reverse("components-list"))
    body = resp.content.decode()
    assert "Shared paginator footer" not in body
    assert "Required context vars" not in body
