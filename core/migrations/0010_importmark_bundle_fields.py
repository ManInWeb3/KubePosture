# Bundle import protocol: idempotency key, coverage, discard bookkeeping.

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('core', '0009_alter_workload_first_seen_at'),
    ]

    operations = [
        migrations.AddField(
            model_name='importmark',
            name='bundle_sha256',
            field=models.CharField(blank=True, default='', help_text="sha256 of the uploaded bundle's item lines — idempotency key: a re-upload with the same hash is a no-op, a different hash is a 409.", max_length=64),
        ),
        migrations.AddField(
            model_name='importmark',
            name='coverage_expected',
            field=models.IntegerField(blank=True, help_text='Importer-reported denominator of the scan-coverage check (deployed images for image-anchored kinds, top-level controllers for workload-anchored kinds). NULL when the kind has no coverage notion.', null=True),
        ),
        migrations.AddField(
            model_name='importmark',
            name='coverage_matched',
            field=models.IntegerField(blank=True, help_text='Importer-reported numerator: distinct subjects a kept report covered.', null=True),
        ),
        migrations.AddField(
            model_name='importmark',
            name='bundle_manifest',
            field=models.JSONField(blank=True, default=dict, help_text='Non-core manifest fields the importer sent (relevance-filter stats, importer version, flags). Core fields live in their own columns.'),
        ),
        migrations.AddField(
            model_name='importmark',
            name='discard_reason',
            field=models.CharField(blank=True, choices=[('stuck_open', 'Importer never committed the import'), ('inventory_failed', 'Inventory payload failed to process')], default='', help_text='Empty for a normal reap. Set when the mark was moved to `reaped` by a discard instead — its data was never applied.', max_length=32),
        ),
        migrations.AddField(
            model_name='importmark',
            name='failed_count',
            field=models.PositiveIntegerField(default=0, help_text='IngestQueue rows of this tuple that ended `failed`, captured at reap / discard before the rows are deleted.'),
        ),
        migrations.AddField(
            model_name='importmark',
            name='last_error',
            field=models.TextField(blank=True, default='', help_text='error_message of the newest failed row of this tuple (truncated).'),
        ),
        migrations.AlterField(
            model_name='importmark',
            name='kind',
            field=models.CharField(help_text='inventory | trivy.VulnerabilityReport | trivy.ConfigAuditReport | trivy.ExposedSecretReport | trivy.RbacAssessmentReport | trivy.ClusterRbacAssessmentReport | trivy.InfraAssessmentReport | trivy.ClusterComplianceReport | trivy.SbomReport | kyverno.PolicyReport | kyverno.ClusterPolicyReport', max_length=64),
        ),
        migrations.AlterField(
            model_name='importmark',
            name='observed_count',
            field=models.IntegerField(blank=True, help_text='Set by /imports/<id>/commit/: payloads delivered for this kind. Gates the zero-input no-op rule for scan kinds.', null=True),
        ),
        migrations.AddIndex(
            model_name='importmark',
            index=models.Index(fields=['cluster', 'import_id'], name='import_mark_import'),
        ),
    ]
