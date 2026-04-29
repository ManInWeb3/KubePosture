"""Cluster-less ingest tokens.

Renames `ClusterToken` → `IngestToken`. Drops the `cluster` FK so a
single token can write into any cluster (cluster identity comes from
the request payload). Adds a required + unique `name` field for
human identification.

Existing rows are migrated in-place: each gets `name = legacy-{cluster.name}`,
with a numeric suffix if multiple tokens existed for the same cluster.
The token's hash and `last_used_at` are preserved, so a currently-set
`KUBEPOSTURE_TOKEN` keeps working after the migration.
"""
from django.db import migrations, models


def _backfill_token_names(apps, schema_editor):
    IngestToken = apps.get_model("core", "IngestToken")
    seen: dict[str, int] = {}
    for tok in IngestToken.objects.select_related("cluster").order_by("id"):
        base = f"legacy-{tok.cluster.name}"
        idx = seen.get(base, 0)
        tok.name = base if idx == 0 else f"{base}-{idx}"
        seen[base] = idx + 1
        tok.save(update_fields=["name"])


class Migration(migrations.Migration):
    dependencies = [
        ("core", "0005_cluster_last_complete_inventory_at"),
    ]

    operations = [
        # 1. Rename the model — table renames to core_ingesttoken automatically.
        migrations.RenameModel(old_name="ClusterToken", new_name="IngestToken"),

        # 2. Drop the now-stale cluster-scoped index before backfill so we
        #    don't carry an orphan index forward.
        migrations.RemoveIndex(
            model_name="ingesttoken",
            name="cluster_token_active",
        ),

        # 3. Add `name` nullable so we can backfill existing rows.
        migrations.AddField(
            model_name="ingesttoken",
            name="name",
            field=models.CharField(max_length=120, null=True),
        ),

        # 4. Data migration: copy cluster.name into name with dedup.
        migrations.RunPython(_backfill_token_names, migrations.RunPython.noop),

        # 5. Tighten constraint: required + unique.
        migrations.AlterField(
            model_name="ingesttoken",
            name="name",
            field=models.CharField(max_length=120, unique=True),
        ),

        # 6. Drop the cluster FK.
        migrations.RemoveField(model_name="ingesttoken", name="cluster"),

        # 7. New index that doesn't reference cluster.
        migrations.AddIndex(
            model_name="ingesttoken",
            index=models.Index(fields=["revoked_at"], name="ingest_token_active"),
        ),
    ]
