from core.parsers.metadata import (
    parse_cluster_meta,
    parse_image_meta,
    parse_namespace_meta,
)


class TestParseClusterMeta:
    def test_prd_abbreviation(self):
        assert parse_cluster_meta("someapp-prd-usw2-eks")["environment"] == "prod"

    def test_prod_full(self):
        assert parse_cluster_meta("azure-prod-eastus-01")["environment"] == "prod"

    def test_production_full(self):
        assert parse_cluster_meta("production-cluster")["environment"] == "prod"

    def test_staging(self):
        assert parse_cluster_meta("myapp-staging-cluster")["environment"] == "staging"

    def test_stg_abbreviation(self):
        assert parse_cluster_meta("payments-stg-do")["environment"] == "staging"

    def test_stage(self):
        assert parse_cluster_meta("stage-eu-west")["environment"] == "staging"

    def test_uat(self):
        assert parse_cluster_meta("uat-payments-cluster")["environment"] == "staging"

    def test_preprod(self):
        assert parse_cluster_meta("preprod-apps")["environment"] == "staging"

    def test_dev(self):
        assert parse_cluster_meta("dev-sandbox-do")["environment"] == "dev"

    def test_development(self):
        assert parse_cluster_meta("development-cluster")["environment"] == "dev"

    def test_env_anywhere_in_name(self):
        # keyword can appear in any segment position
        assert parse_cluster_meta("apps-fra1-do-prod")["environment"] == "prod"

    def test_unknown(self):
        assert parse_cluster_meta("something-random")["environment"] == "unknown"

    def test_only_returns_environment(self):
        # no provider/region/project guessing
        meta = parse_cluster_meta("someapp-prd-usw2-eks")
        assert set(meta.keys()) == {"environment"}


class TestParseNamespaceMeta:
    def test_convention(self):
        meta = parse_namespace_meta("prod-app-backend")
        assert meta["environment"] == "prod"
        assert meta["project"] == "app"
        assert meta["service"] == "backend"

    def test_override(self):
        meta = parse_namespace_meta("kube-system")
        assert meta["environment"] == "system"
        assert meta["project"] == "kubernetes"

    def test_short_name(self):
        meta = parse_namespace_meta("monitoring")
        assert meta["environment"] == "unknown"


class TestParseImageMeta:
    def test_full_reference(self):
        meta = parse_image_meta("registry.ovh.net/app/backend:v1.2.3")
        assert meta["registry"] == "registry.ovh.net"
        assert meta["project"] == "app"
        assert meta["component"] == "backend"
        assert meta["tag"] == "v1.2.3"

    def test_docker_hub(self):
        meta = parse_image_meta("library/nginx:1.25")
        assert meta["component"] == "nginx"
        assert meta["tag"] == "1.25"

    def test_no_tag(self):
        meta = parse_image_meta("nginx")
        assert meta["component"] == "nginx"
        assert meta["tag"] == "latest"
