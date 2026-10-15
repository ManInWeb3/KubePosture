"""Test-only URLconf exposing the /api/v1/testing/* harness views.

core/api/urls.py registers those routes only when
`settings.TESTING_HARNESS_ENABLED` is true at import time, which under
pytest-django depends on the environment the settings module was first
loaded in. Tests that exercise the harness over HTTP point ROOT_URLCONF
here (with `override_settings(TESTING_HARNESS_ENABLED=True)`) so they
don't depend on that ordering. The views still run their own `_gated()`
check.
"""
from django.urls import path

from core.api import testing_views

urlpatterns = [
    path("api/v1/testing/reset/", testing_views.reset),
    path("api/v1/testing/load_scenario/", testing_views.load_scenario),
]
