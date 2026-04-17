"""
Create viewer/operator/admin Django groups with appropriate permissions.
Idempotent — safe to run multiple times.

Usage: python manage.py setup_roles
"""
from django.contrib.auth.models import Group, Permission
from django.contrib.contenttypes.models import ContentType
from django.core.management.base import BaseCommand


class Command(BaseCommand):
    help = "Create viewer/operator/admin groups with model permissions"

    def handle(self, *args, **options):
        # Define role hierarchy (R1, R3)
        roles = {
            "viewer": {
                "finding": ["view_finding"],
                "cluster": ["view_cluster"],
                "scanstatus": ["view_scanstatus"],
                "rawreport": ["view_rawreport"],
            },
            "operator": {
                "finding": ["view_finding", "change_finding"],
                "cluster": ["view_cluster"],
                "scanstatus": ["view_scanstatus"],
                "rawreport": ["view_rawreport"],
            },
            "admin": {
                "finding": ["view_finding", "change_finding", "delete_finding"],
                "cluster": ["view_cluster", "change_cluster"],
                "scanstatus": ["view_scanstatus"],
                "rawreport": ["view_rawreport", "delete_rawreport"],
            },
        }

        for role_name, model_perms in roles.items():
            group, created = Group.objects.get_or_create(name=role_name)
            action = "Created" if created else "Updated"

            group.permissions.clear()
            for model_name, perm_codenames in model_perms.items():
                try:
                    ct = ContentType.objects.get(app_label="core", model=model_name)
                except ContentType.DoesNotExist:
                    self.stderr.write(
                        self.style.WARNING(
                            f"  ContentType core.{model_name} not found — run migrate first"
                        )
                    )
                    continue

                for codename in perm_codenames:
                    try:
                        perm = Permission.objects.get(
                            content_type=ct, codename=codename
                        )
                        group.permissions.add(perm)
                    except Permission.DoesNotExist:
                        self.stderr.write(
                            self.style.WARNING(
                                f"  Permission {codename} not found for {model_name}"
                            )
                        )

            self.stdout.write(
                self.style.SUCCESS(f"{action} group '{role_name}' with permissions")
            )
