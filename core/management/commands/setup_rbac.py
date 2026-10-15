"""Seed the three RBAC Groups: viewer, SecEngineer, admin.

The role hierarchy is admin ⊃ SecEngineer ⊃ viewer. Enforcement is a
group-membership check on the user (`core.templatetags.access_tags.
is_admin`, used by the UI views' `AdminRequiredMixin` / `_is_admin`),
not Django's per-action Permission objects. Keeping RBAC at the group
level matches the v1 three-tier model and dodges the ceremony of
seeding Permission objects.

Usage:
    python manage.py setup_rbac

Idempotent. Re-run after migrations or whenever you reset the DB.
"""
from django.contrib.auth.models import Group

from core.management.base import KubePostureCommand

_ROLES = ["viewer", "SecEngineer", "admin"]


class Command(KubePostureCommand):
    help = "Create the three RBAC groups (viewer, SecEngineer, admin)."

    def handle(self, *args, **opts):
        for name in _ROLES:
            group, created = Group.objects.get_or_create(name=name)
            if created:
                self.stdout.write(self.style.SUCCESS(f"Created group: {name}"))
            else:
                self.stdout.write(f"Group already exists: {name}")
