"""Rename the `operator` Django auth Group to `SecEngineer`.

Existing users in `operator` keep their group membership — this is a
plain in-place name update on the Group row, not a recreate. Idempotent
in both directions: if no `operator` row exists (fresh DB), the migration
is a no-op and `setup_rbac` will seed `SecEngineer` directly.
"""
from django.db import migrations


def _rename(apps, _schema_editor, *, frm: str, to: str) -> None:
    Group = apps.get_model("auth", "Group")
    Group.objects.filter(name=frm).update(name=to)


def forward(apps, schema_editor):
    _rename(apps, schema_editor, frm="operator", to="SecEngineer")


def backward(apps, schema_editor):
    _rename(apps, schema_editor, frm="SecEngineer", to="operator")


class Migration(migrations.Migration):

    dependencies = [
        ("auth", "0012_alter_user_first_name_max_length"),
        ("core", "0009_add_observation_currently_deployed_init_container"),
    ]

    operations = [
        migrations.RunPython(forward, backward),
    ]
