"""Tabler badge helpers for severity, priority, EPSS, KEV.

Templates load this with `{% load findings_tags %}`. Each tag returns
safe HTML for a Tabler `bg-*-lt` badge, so callers don't have to repeat
colour mapping in every template.
"""
from __future__ import annotations

from django import template
from django.utils.safestring import mark_safe

register = template.Library()


_SEVERITY_COLOURS = {
    "critical": "bg-red-lt text-red",
    "high": "bg-orange-lt text-orange",
    "medium": "bg-yellow-lt text-yellow",
    "low": "bg-azure-lt text-azure",
    "info": "bg-secondary-lt text-secondary",
    "unknown": "bg-secondary-lt text-secondary",
}

_PRIORITY_COLOURS = {
    "immediate": "bg-red-lt text-red",
    "out_of_cycle": "bg-orange-lt text-orange",
    "scheduled": "bg-yellow-lt text-yellow",
    "defer": "bg-secondary-lt text-secondary",
}

_PRIORITY_LABELS = {
    "immediate": "Immediate",
    "out_of_cycle": "Out-of-Cycle",
    "scheduled": "Scheduled",
    "defer": "Defer",
}


@register.simple_tag
def severity_badge(severity):
    if not severity:
        return mark_safe('<span class="text-muted">—</span>')
    cls = _SEVERITY_COLOURS.get(severity.lower(), "bg-secondary-lt")
    return mark_safe(f'<span class="badge {cls}">{severity.title()}</span>')


# Numeric ranks so kubeposture.js sortable tables order by urgency,
# not alphabetic textContent. Higher = more urgent — pair with sort-desc.
_PRIORITY_RANK = {"immediate": 3, "out_of_cycle": 2, "scheduled": 1, "defer": 0}
_SEVERITY_RANK = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1, "unknown": 0}


@register.filter
def priority_rank(value):
    return _PRIORITY_RANK.get(value, -1)


@register.filter
def severity_rank(value):
    return _SEVERITY_RANK.get((value or "").lower(), -1)


@register.simple_tag
def priority_badge(priority):
    if not priority:
        return mark_safe('<span class="text-muted">—</span>')
    cls = _PRIORITY_COLOURS.get(priority, "bg-secondary-lt")
    label = _PRIORITY_LABELS.get(priority, priority)
    return mark_safe(f'<span class="badge {cls}">{label}</span>')


@register.simple_tag
def epss_badge(score):
    if score is None:
        return mark_safe('<span class="text-muted">—</span>')
    pct = score * 100 if score <= 1 else score
    if pct >= 50:
        cls = "bg-red-lt text-red"
    elif pct >= 10:
        cls = "bg-orange-lt text-orange"
    elif pct >= 1:
        cls = "bg-yellow-lt text-yellow"
    else:
        cls = "bg-secondary-lt text-secondary"
    return mark_safe(f'<span class="badge {cls}">{pct:.1f}%</span>')


@register.simple_tag
def kev_badge(kev_listed):
    if kev_listed:
        return mark_safe('<span class="badge bg-red-lt text-red" title="CISA Known Exploited Vulnerability — actively exploited in the wild">KEV</span>')
    return mark_safe('<span class="text-muted">—</span>')


_PSS_COLOURS = {
    "restricted": "bg-success-lt text-success",
    "baseline": "bg-warning-lt text-warning",
    "privileged": "bg-danger-lt text-danger",
}


@register.simple_tag
def pss_badge(value):
    """Render the Pod Security Standards `enforce` mode as a Tabler badge.

    Empty value renders a muted "—" since the absence of the label means
    PSS is not configured for the namespace.
    """
    v = (value or "").strip().lower()
    if not v:
        return mark_safe('<span class="text-muted">—</span>')
    cls = _PSS_COLOURS.get(v, "bg-secondary-lt text-secondary")
    return mark_safe(f'<span class="badge {cls}" title="pod-security.kubernetes.io/enforce">{v}</span>')


@register.simple_tag
def count_badge(value, band):
    """Render a priority-band count: integer, coloured if non-zero, muted 0 otherwise."""
    if not value:
        return mark_safe('<span class="text-muted">0</span>')
    cls = _PRIORITY_COLOURS.get(band, "bg-secondary-lt")
    return mark_safe(f'<span class="badge {cls}">{value}</span>')
