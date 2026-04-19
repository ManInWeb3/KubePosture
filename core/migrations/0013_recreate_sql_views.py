"""
Recreate Grafana-facing SQL views after the Namespace refactor.

Views dropped by 0012 (which removed the columns they referenced).
Here we re-create them against the new schema:
  - f.namespace (CharField) → n.name (via LEFT JOIN core_namespace n)
  - c.internet_exposed → EXISTS over core_namespace with internet_exposed=true,
    exposed as cluster_has_exposure
"""
from django.db import migrations


VIEWS_SQL = """
CREATE OR REPLACE VIEW v_vulnerability_findings AS
SELECT
    f.id, c.name AS cluster_name, f.severity, f.status, f.effective_priority,
    f.vuln_id, f.title,
    n.name AS namespace, f.resource_kind, f.resource_name,
    f.first_seen, f.last_seen, f.resolved_at,
    f.epss_score, f.kev_listed,
    c.environment AS cluster_environment,
    EXISTS (SELECT 1 FROM core_namespace nx
            WHERE nx.cluster_id = c.id AND nx.internet_exposed) AS cluster_has_exposure,
    (f.details->>'score')::numeric AS cvss_score,
    f.details->>'component_name' AS component_name,
    f.details->>'installed_version' AS installed_version,
    f.details->>'fixed_version' AS fixed_version,
    f.details->>'advisory_url' AS advisory_url,
    f.details->>'image' AS image,
    f.details->>'container' AS container
FROM core_finding f
LEFT JOIN core_cluster c ON f.cluster_id = c.id
LEFT JOIN core_namespace n ON f.namespace_id = n.id
WHERE f.category = 'vulnerability';

CREATE OR REPLACE VIEW v_misconfiguration_findings AS
SELECT
    f.id, c.name AS cluster_name, f.severity, f.status, f.effective_priority,
    f.vuln_id, f.title,
    n.name AS namespace, f.resource_kind, f.resource_name,
    f.first_seen, f.last_seen, f.resolved_at,
    c.environment AS cluster_environment,
    EXISTS (SELECT 1 FROM core_namespace nx
            WHERE nx.cluster_id = c.id AND nx.internet_exposed) AS cluster_has_exposure,
    f.details->>'check_id' AS check_id,
    f.details->>'description' AS description,
    f.details->>'remediation' AS remediation
FROM core_finding f
LEFT JOIN core_cluster c ON f.cluster_id = c.id
LEFT JOIN core_namespace n ON f.namespace_id = n.id
WHERE f.category = 'misconfiguration';

CREATE OR REPLACE VIEW v_secret_findings AS
SELECT
    f.id, c.name AS cluster_name, f.severity, f.status, f.effective_priority,
    f.vuln_id, f.title,
    n.name AS namespace, f.resource_kind, f.resource_name,
    f.first_seen, f.last_seen, f.resolved_at,
    c.environment AS cluster_environment,
    f.details->>'rule_id' AS rule_id,
    f.details->>'secret_category' AS secret_category,
    f.details->>'image' AS image
FROM core_finding f
LEFT JOIN core_cluster c ON f.cluster_id = c.id
LEFT JOIN core_namespace n ON f.namespace_id = n.id
WHERE f.category = 'secret';

CREATE OR REPLACE VIEW v_rbac_findings AS
SELECT
    f.id, c.name AS cluster_name, f.severity, f.status, f.effective_priority,
    f.vuln_id, f.title,
    n.name AS namespace, f.resource_kind, f.resource_name,
    f.first_seen, f.last_seen, f.resolved_at,
    c.environment AS cluster_environment,
    f.details->>'check_id' AS check_id,
    f.details->>'description' AS description,
    f.details->>'remediation' AS remediation
FROM core_finding f
LEFT JOIN core_cluster c ON f.cluster_id = c.id
LEFT JOIN core_namespace n ON f.namespace_id = n.id
WHERE f.category = 'rbac';

CREATE OR REPLACE VIEW v_infra_findings AS
SELECT
    f.id, c.name AS cluster_name, f.severity, f.status, f.effective_priority,
    f.vuln_id, f.title,
    n.name AS namespace, f.resource_kind, f.resource_name,
    f.first_seen, f.last_seen, f.resolved_at,
    c.environment AS cluster_environment,
    f.details->>'check_id' AS check_id,
    f.details->>'description' AS description,
    f.details->>'remediation' AS remediation
FROM core_finding f
LEFT JOIN core_cluster c ON f.cluster_id = c.id
LEFT JOIN core_namespace n ON f.namespace_id = n.id
WHERE f.category = 'infra';

CREATE OR REPLACE VIEW v_policy_findings AS
SELECT
    f.id, c.name AS cluster_name, f.severity, f.status, f.effective_priority,
    f.vuln_id, f.title,
    n.name AS namespace, f.resource_kind, f.resource_name,
    f.first_seen, f.last_seen, f.resolved_at,
    c.environment AS cluster_environment,
    f.details->>'policy' AS policy,
    f.details->>'rule' AS rule,
    f.details->>'message' AS message
FROM core_finding f
LEFT JOIN core_cluster c ON f.cluster_id = c.id
LEFT JOIN core_namespace n ON f.namespace_id = n.id
WHERE f.category = 'policy';
"""


DROP_VIEWS_SQL = """
DROP VIEW IF EXISTS v_vulnerability_findings;
DROP VIEW IF EXISTS v_misconfiguration_findings;
DROP VIEW IF EXISTS v_secret_findings;
DROP VIEW IF EXISTS v_rbac_findings;
DROP VIEW IF EXISTS v_infra_findings;
DROP VIEW IF EXISTS v_policy_findings;
"""


def create_views(apps, schema_editor):
    if schema_editor.connection.vendor == "postgresql":
        schema_editor.execute(VIEWS_SQL)


def drop_views(apps, schema_editor):
    if schema_editor.connection.vendor == "postgresql":
        schema_editor.execute(DROP_VIEWS_SQL)


class Migration(migrations.Migration):

    dependencies = [
        ("core", "0012_namespace_model"),
    ]

    operations = [
        migrations.RunPython(create_views, drop_views),
    ]
