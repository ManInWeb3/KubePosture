from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ("core", "0006_ingest_token"),
    ]

    operations = [
        migrations.RemoveField(
            model_name="finding",
            name="vex_status",
        ),
        migrations.DeleteModel(
            name="VexStatement",
        ),
    ]
