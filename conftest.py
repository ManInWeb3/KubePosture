"""Pytest config: ensure DJANGO_SETTINGS_MODULE + harness flag are set."""
import os

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "kubeposture.settings")
os.environ.setdefault("TESTING_HARNESS_ENABLED", "true")
os.environ.setdefault("LOG_LEVEL", "WARNING")


def pytest_configure(config):
    """Use plain static-files storage in tests so {% static %} works
    without a prior `collectstatic` (the manifest backend used in prod
    raises on missing entries)."""
    from django.conf import settings

    if not settings.configured:
        return
    settings.STORAGES = {
        **getattr(settings, "STORAGES", {}),
        "staticfiles": {"BACKEND": "django.contrib.staticfiles.storage.StaticFilesStorage"},
    }
