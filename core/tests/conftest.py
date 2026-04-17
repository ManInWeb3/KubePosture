import pytest
from django.contrib.auth.models import User
from rest_framework.authtoken.models import Token

from core.models import Cluster


@pytest.fixture
def cluster(db):
    return Cluster.objects.create(
        name="test-cluster",
        provider="ovh",
        environment="dev",
        region="eu-west-lim",
        project="test",
    )


@pytest.fixture
def service_user(db):
    return User.objects.create_user(username="svc-test", password="testpass")


@pytest.fixture
def service_token(service_user):
    token, _ = Token.objects.get_or_create(user=service_user)
    return token


@pytest.fixture
def api_client():
    from rest_framework.test import APIClient

    return APIClient()


@pytest.fixture
def auth_client(api_client, service_token):
    api_client.credentials(HTTP_AUTHORIZATION=f"Token {service_token.key}")
    return api_client
