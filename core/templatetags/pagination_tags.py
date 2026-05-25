"""Template helpers for paginated list views.

The standard Django `Paginator.get_elided_page_range(number)` requires
the current page as an argument — which Django templates can't pass.
This filter wraps it so list templates can just do
`{% for p in page_obj|elided_page_range %}`.
"""
from __future__ import annotations

from django import template

register = template.Library()


@register.filter
def elided_page_range(page_obj):
    """Yield page numbers with `Paginator.ELLIPSIS` markers for gaps.

    Example for current=5 of 20 pages:
        [1, 2, '…', 3, 4, 5, 6, 7, '…', 19, 20]

    Uses Django's built-in defaults (on_each_side=3, on_ends=2).
    """
    return list(page_obj.paginator.get_elided_page_range(page_obj.number))
