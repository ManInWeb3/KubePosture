from core.parsers.metadata import (
    parse_cluster_meta,
    parse_image_meta,
    parse_namespace_meta,
)


class TestParseClusterMeta:
    def test_aws_eks(self):
        meta = parse_cluster_meta("someapp-prd-usw2-eks")
        assert meta["provider"] == "eks"
        assert meta["environment"] == "prod"
        assert meta["region"] == "us-west-2"
        assert meta["project"] == "someapp"

    def test_azure_aks(self):
        meta = parse_cluster_meta("azure-prod-japaneast-001")
        assert meta["provider"] == "aks"
        assert meta["environment"] == "prod"
        assert meta["region"] == "japaneast"

    def test_digitalocean(self):
        meta = parse_cluster_meta("someapps-fra1-do")
        assert meta["provider"] == "do"
        assert meta["region"] == "fra1"

    def test_override(self):
        meta = parse_cluster_meta("central-someorg")
        assert meta["provider"] == "ovh"
        assert meta["environment"] == "prod"
        assert meta["region"] == "eu-west-par"
        assert meta["project"] == "central"

    def test_unknown(self):
        meta = parse_cluster_meta("something-random")
        assert meta["provider"] == "unknown"
        assert meta["environment"] == "unknown"


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
