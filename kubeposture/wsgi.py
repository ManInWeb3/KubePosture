"""WSGI config for kubeposture project."""
import os

from django.core.wsgi import get_wsgi_application

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "kubeposture.settings")
application = get_wsgi_application()
