"""
Ensure a default admin user exists (idempotent).

Creates the user if missing, assigns to the 'admin' group.
Password is only set on creation — existing users are not modified.

The created user is a plain application admin (admin group, no Django
admin access). To grant Django admin / superuser access to a platform
operator, see: manage.py shell instructions in README § User Management.

Usage:
  python manage.py ensure_adminuser
  python manage.py ensure_adminuser --username ops --password s3cret --email ops@example.com
"""
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group
from django.core.management.base import BaseCommand

User = get_user_model()


class Command(BaseCommand):
    help = "Ensure a default admin user exists (idempotent)."

    def add_arguments(self, parser):
        parser.add_argument("--username", default="admin")
        parser.add_argument("--password", default="admin")
        parser.add_argument("--email", default="admin@kubeposture.local")

    def handle(self, *args, **options):
        username = options["username"]
        user, created = User.objects.get_or_create(
            username=username,
            defaults={
                "email": options["email"],
                "is_staff": False,
                "is_superuser": False,
            },
        )
        if created:
            user.set_password(options["password"])
            user.save(update_fields=["password"])

        # Always ensure the user is in the admin group (idempotent)
        admin_group, _ = Group.objects.get_or_create(name="admin")
        user.groups.add(admin_group)

        if created:
            self.stdout.write(self.style.SUCCESS(f"Created admin user '{username}'"))
        else:
            self.stdout.write(f"Admin user '{username}' already exists, skipping")
