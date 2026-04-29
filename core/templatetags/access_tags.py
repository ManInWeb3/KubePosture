"""`{{ user|is_admin }}` filter for admin-gated UI affordances.

Mirrors `core.views_ui._is_admin`: superuser or member of the seeded
`admin` group. Cached on the user instance so a navbar that calls it
many times produces one query per request.
"""
from __future__ import annotations

from django import template

register = template.Library()


@register.filter(name="is_admin")
def is_admin(user) -> bool:
    if not getattr(user, "is_authenticated", False):
        return False
    if user.is_superuser:
        return True
    if hasattr(user, "_kv_is_admin"):
        return bool(user._kv_is_admin)
    user._kv_is_admin = user.groups.filter(name="admin").exists()
    return user._kv_is_admin
