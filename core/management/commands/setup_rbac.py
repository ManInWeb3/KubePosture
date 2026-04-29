"""Seed the three RBAC Groups: viewer, SecEngineer, admin.

The role hierarchy is admin ⊃ SecEngineer ⊃ viewer (any user with
role X can do anything X-or-below requires). Enforcement is via
`core.api.permissions.require_role` and `IsViewer`/`IsSecEngineer`/
`IsAdmin` DRF permission classes — both check group membership
on the user, not Django's per-action Permission objects. Keeping
RBAC at the group level matches the v1 three-tier model in
dev_docs/02-architecture.md and dodges the ceremony of seeding
Permission objects.

Usage:
    python manage.py setup_rbac

Idempotent. Re-run after migrations or whenever you reset the DB.
"""
from django.contrib.auth.models import Group
from django.core.management.base import BaseCommand


_ROLES = ["viewer", "SecEngineer", "admin"]


class Command(BaseCommand):
    help = "Create the three RBAC groups (viewer, SecEngineer, admin)."

    def handle(self, *args, **opts):
        for name in _ROLES:
            group, created = Group.objects.get_or_create(name=name)
            if created:
                self.stdout.write(self.style.SUCCESS(f"Created group: {name}"))
            else:
                self.stdout.write(f"Group already exists: {name}")
