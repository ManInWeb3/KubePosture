"""Role-based access control for session-authenticated views.

Three roles, hierarchical: admin ⊃ operator ⊃ viewer. A user with
role X passes any check requiring role Y where Y ≤ X. Django
superusers always pass.

Enforcement comes in two flavours:

  - `@require_role(role)` — function decorator for plain Django views
    (returns 403 PermissionDenied; redirects anonymous to LOGIN_URL).
  - `IsViewer` / `IsOperator` / `IsAdmin` — DRF permission classes
    for `permission_classes = [...]` on API views.

Group seeding lives in `manage.py setup_rbac`. We deliberately do
NOT use Django's per-action Permission objects in v1 — group-name
checks are simpler for the three-tier model. If a future feature
needs custom roles, swap the helper without touching call sites.
"""
from __future__ import annotations

from functools import wraps

from django.contrib.auth.decorators import login_required
from django.core.exceptions import PermissionDenied
from rest_framework.permissions import BasePermission


ROLE_HIERARCHY = ["viewer", "operator", "admin"]


def _has_role(user, required: str) -> bool:
    """True iff `user` has `required` role or a higher one in the hierarchy."""
    if not user or not user.is_authenticated:
        return False
    if user.is_superuser:
        return True
    if required not in ROLE_HIERARCHY:
        raise ValueError(
            f"unknown role: {required!r}; must be one of {ROLE_HIERARCHY}"
        )
    user_groups = set(user.groups.values_list("name", flat=True))
    required_idx = ROLE_HIERARCHY.index(required)
    accepted = ROLE_HIERARCHY[required_idx:]
    return any(role in user_groups for role in accepted)


def require_role(role: str):
    """Decorator: enforce a minimum role on a Django view.

    Anonymous users are redirected to LOGIN_URL (via `@login_required`).
    Authenticated users without the required role get 403.
    """
    def decorator(view_func):
        @wraps(view_func)
        @login_required
        def wrapper(request, *args, **kwargs):
            if not _has_role(request.user, role):
                raise PermissionDenied(
                    f"this action requires the '{role}' role or higher"
                )
            return view_func(request, *args, **kwargs)
        return wrapper
    return decorator


class _IsRoleBase(BasePermission):
    """DRF permission class base. Subclasses set `role`."""

    role: str = "viewer"

    def has_permission(self, request, view):
        return _has_role(request.user, self.role)


class IsViewer(_IsRoleBase):
    role = "viewer"


class IsOperator(_IsRoleBase):
    role = "operator"


class IsAdmin(_IsRoleBase):
    role = "admin"
