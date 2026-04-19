"""
Introduce first-class Namespace model; drop cluster-level exposure fields;
Finding.namespace becomes FK(Namespace).

User-approved: no data migration — users re-import. Existing Finding rows
have their namespace string cleared (namespace_id=NULL) and are treated as
cluster-scoped until the next import populates Namespace rows + re-upserts
findings.

SQL views (created in 0009) reference `c.internet_exposed`; dropped here
first, recreated by 0013 against the new schema.
"""
from django.db import migrations, models


DROP_VIEWS_SQL = """
DROP VIEW IF EXISTS v_vulnerability_findings;
DROP VIEW IF EXISTS v_misconfiguration_findings;
DROP VIEW IF EXISTS v_secret_findings;
DROP VIEW IF EXISTS v_rbac_findings;
DROP VIEW IF EXISTS v_infra_findings;
DROP VIEW IF EXISTS v_policy_findings;
"""


def drop_views(apps, schema_editor):
    if schema_editor.connection.vendor == "postgresql":
        schema_editor.execute(DROP_VIEWS_SQL)


def noop(apps, schema_editor):
    pass


class Migration(migrations.Migration):

    dependencies = [
        ("core", "0011_userpreference"),
    ]

    operations = [
        migrations.RunPython(drop_views, noop),
        migrations.CreateModel(
            name="Namespace",
            fields=[
                (
                    "id",
                    models.BigAutoField(
                        auto_created=True,
                        primary_key=True,
                        serialize=False,
                        verbose_name="ID",
                    ),
                ),
                ("name", models.CharField(max_length=253)),
                (
                    "internet_exposed",
                    models.BooleanField(
                        default=False,
                        help_text=(
                            "Namespace has externally-reachable workloads "
                            "(Services LB/NodePort, Ingresses)."
                        ),
                    ),
                ),
                (
                    "exposure_is_manual",
                    models.BooleanField(
                        default=False,
                        help_text=(
                            "Admin manually set internet_exposed — auto-detect "
                            "skips this record."
                        ),
                    ),
                ),
                (
                    "contains_sensitive_data",
                    models.BooleanField(
                        default=False,
                        help_text=(
                            "Namespace processes PII, financial, or regulated data."
                        ),
                    ),
                ),
                (
                    "sensitive_is_manual",
                    models.BooleanField(
                        default=False,
                        help_text="Admin manually set contains_sensitive_data.",
                    ),
                ),
                (
                    "labels",
                    models.JSONField(
                        blank=True,
                        default=dict,
                        help_text=(
                            "Mirrored from K8s namespace.metadata.labels "
                            "(future: ownership, scope)."
                        ),
                    ),
                ),
                (
                    "annotations",
                    models.JSONField(
                        blank=True,
                        default=dict,
                        help_text="Mirrored from K8s namespace.metadata.annotations.",
                    ),
                ),
                ("first_seen", models.DateTimeField(auto_now_add=True)),
                ("last_seen", models.DateTimeField(auto_now=True)),
                (
                    "cluster",
                    models.ForeignKey(
                        on_delete=models.deletion.CASCADE,
                        related_name="namespaces",
                        to="core.cluster",
                    ),
                ),
            ],
            options={
                "ordering": ["cluster_id", "name"],
            },
        ),
        migrations.AddConstraint(
            model_name="namespace",
            constraint=models.UniqueConstraint(
                fields=("cluster", "name"), name="unique_namespace_per_cluster"
            ),
        ),
        migrations.AddIndex(
            model_name="namespace",
            index=models.Index(
                fields=["cluster", "internet_exposed"],
                name="namespace_cluster_exposed",
            ),
        ),
        # Cluster: drop exposure fields, add _is_manual flags, tweak defaults
        migrations.RemoveField(model_name="cluster", name="internet_exposed"),
        migrations.RemoveField(model_name="cluster", name="contains_sensitive_data"),
        migrations.RemoveField(model_name="cluster", name="namespace_overrides"),
        migrations.AlterField(
            model_name="cluster",
            name="environment",
            field=models.CharField(
                blank=True,
                help_text=(
                    "dev, staging, prod — parsed from cluster name on auto-register."
                ),
                max_length=20,
            ),
        ),
        migrations.AlterField(
            model_name="cluster",
            name="provider",
            field=models.CharField(
                default="onprem",
                help_text=(
                    "aws, eks, gcp, gke, azure, aks, onprem — auto-detected "
                    "from node provider_id."
                ),
                max_length=20,
            ),
        ),
        migrations.AlterField(
            model_name="cluster",
            name="region",
            field=models.CharField(
                blank=True,
                help_text="Auto-detected from node label topology.kubernetes.io/region.",
                max_length=50,
            ),
        ),
        migrations.AddField(
            model_name="cluster",
            name="environment_is_manual",
            field=models.BooleanField(default=False),
        ),
        migrations.AddField(
            model_name="cluster",
            name="provider_is_manual",
            field=models.BooleanField(default=False),
        ),
        migrations.AddField(
            model_name="cluster",
            name="region_is_manual",
            field=models.BooleanField(default=False),
        ),
        # Finding.namespace: CharField → FK(Namespace, null=True)
        # User accepts data loss; we drop + add rather than alter.
        migrations.RemoveField(model_name="finding", name="namespace"),
        migrations.AddField(
            model_name="finding",
            name="namespace",
            field=models.ForeignKey(
                blank=True,
                help_text="NULL for cluster-scoped resources (ClusterRole, etc.).",
                null=True,
                on_delete=models.deletion.SET_NULL,
                related_name="findings",
                to="core.namespace",
            ),
        ),
    ]
