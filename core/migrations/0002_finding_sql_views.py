"""
SQL views per finding category for Grafana.

These views expose JSONB `details` as structured columns so Grafana
SQL datasource queries look like regular table queries.

Only runs on PostgreSQL — noop on SQLite (tests).
"""
from django.db import migrations

VIEWS_SQL = """
CREATE OR REPLACE VIEW v_vulnerability_findings AS
SELECT
    f.id, c.name AS cluster_name, f.severity, f.status, f.vuln_id, f.title,
    f.namespace, f.resource_kind, f.resource_name,
    f.first_seen, f.last_seen, f.resolved_at,
    f.epss_score, f.kev_listed,
    (f.details->>'score')::numeric AS cvss_score,
    f.details->>'component_name' AS component_name,
    f.details->>'installed_version' AS installed_version,
    f.details->>'fixed_version' AS fixed_version,
    f.details->>'advisory_url' AS advisory_url,
    f.details->>'image' AS image,
    f.details->>'container' AS container
FROM core_finding f
LEFT JOIN core_cluster c ON f.cluster_id = c.id
WHERE f.category = 'vulnerability';

CREATE OR REPLACE VIEW v_misconfiguration_findings AS
SELECT
    f.id, c.name AS cluster_name, f.severity, f.status, f.vuln_id, f.title,
    f.namespace, f.resource_kind, f.resource_name,
    f.first_seen, f.last_seen, f.resolved_at,
    f.details->>'check_id' AS check_id,
    f.details->>'description' AS description,
    f.details->>'remediation' AS remediation
FROM core_finding f
LEFT JOIN core_cluster c ON f.cluster_id = c.id
WHERE f.category = 'misconfiguration';

CREATE OR REPLACE VIEW v_secret_findings AS
SELECT
    f.id, c.name AS cluster_name, f.severity, f.status, f.vuln_id, f.title,
    f.namespace, f.resource_kind, f.resource_name,
    f.first_seen, f.last_seen, f.resolved_at,
    f.details->>'rule_id' AS rule_id,
    f.details->>'secret_category' AS secret_category,
    f.details->>'image' AS image
FROM core_finding f
LEFT JOIN core_cluster c ON f.cluster_id = c.id
WHERE f.category = 'secret';

CREATE OR REPLACE VIEW v_rbac_findings AS
SELECT
    f.id, c.name AS cluster_name, f.severity, f.status, f.vuln_id, f.title,
    f.namespace, f.resource_kind, f.resource_name,
    f.first_seen, f.last_seen, f.resolved_at,
    f.details->>'check_id' AS check_id,
    f.details->>'description' AS description,
    f.details->>'remediation' AS remediation
FROM core_finding f
LEFT JOIN core_cluster c ON f.cluster_id = c.id
WHERE f.category = 'rbac';

CREATE OR REPLACE VIEW v_infra_findings AS
SELECT
    f.id, c.name AS cluster_name, f.severity, f.status, f.vuln_id, f.title,
    f.namespace, f.resource_kind, f.resource_name,
    f.first_seen, f.last_seen, f.resolved_at,
    f.details->>'check_id' AS check_id,
    f.details->>'description' AS description,
    f.details->>'remediation' AS remediation
FROM core_finding f
LEFT JOIN core_cluster c ON f.cluster_id = c.id
WHERE f.category = 'infra';
"""

DROP_VIEWS_SQL = """
DROP VIEW IF EXISTS v_vulnerability_findings;
DROP VIEW IF EXISTS v_misconfiguration_findings;
DROP VIEW IF EXISTS v_secret_findings;
DROP VIEW IF EXISTS v_rbac_findings;
DROP VIEW IF EXISTS v_infra_findings;
"""


def create_views(apps, schema_editor):
    if schema_editor.connection.vendor == "postgresql":
        schema_editor.execute(VIEWS_SQL)


def drop_views(apps, schema_editor):
    if schema_editor.connection.vendor == "postgresql":
        schema_editor.execute(DROP_VIEWS_SQL)


class Migration(migrations.Migration):

    dependencies = [
        ("core", "0001_initial"),
    ]

    operations = [
        migrations.RunPython(create_views, drop_views),
    ]
