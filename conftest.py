"""Pytest config: ensure DJANGO_SETTINGS_MODULE + harness flag are set.

Note: pytest-django may have loaded Django settings before this file
runs, so the env defaults below only take effect when nothing else set
them earlier (CI sets them in the workflow). Tests that need the
testing-harness routes use `core/tests/harness_urls.py` instead of
relying on TESTING_HARNESS_ENABLED.
"""
import os
import sys
from pathlib import Path

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "kubeposture.settings")
os.environ.setdefault("TESTING_HARNESS_ENABLED", "true")
os.environ.setdefault("LOG_LEVEL", "WARNING")

# The importer lives in scripts/kubeposture_importer/ and is run as
# `python scripts/import-cluster.py` in production (scripts/ ends up on
# sys.path[0]); mirror that for the test suite.
_SCRIPTS = str(Path(__file__).resolve().parent / "scripts")
if _SCRIPTS not in sys.path:
    sys.path.insert(0, _SCRIPTS)


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
