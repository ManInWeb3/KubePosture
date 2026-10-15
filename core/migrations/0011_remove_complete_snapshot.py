# Every committed inventory is a complete snapshot by construction (one
# bundle, verified whole, committed atomically), so the per-payload flag
# and the "incomplete cycles in a row" counter it fed are dead.

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('core', '0010_importmark_bundle_fields'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='ingestqueue',
            name='complete_snapshot',
        ),
        migrations.RemoveField(
            model_name='cluster',
            name='consecutive_incomplete_inventories',
        ),
        migrations.AlterField(
            model_name='cluster',
            name='last_complete_inventory_at',
            field=models.DateTimeField(
                blank=True,
                help_text=(
                    '`mark.started_at` of the most recent reaped inventory cycle. Every '
                    'committed inventory is a complete snapshot (the bundle protocol '
                    'guarantees it); discarded imports never advance this. Anchor for '
                    '`Image.objects.currently_running()`: an image observation is '
                    'considered current iff its `last_seen_at` is at or after this '
                    'timestamp. NULL until the first inventory cycle reaps.'
                ),
                null=True,
            ),
        ),
    ]
