"""
KubePosture Django settings.

All configuration via environment variables (django-environ).
See .env.example for available settings.
"""
from pathlib import Path

import environ

env = environ.Env(
    DEBUG=(bool, False),
    ALLOWED_HOSTS=(list, []),
    CSRF_TRUSTED_ORIGINS=(list, []),
    LOG_LEVEL=(str, "INFO"),
)

BASE_DIR = Path(__file__).resolve().parent.parent

# Read .env file if it exists (local dev)
env_file = BASE_DIR / ".env"
if env_file.exists():
    environ.Env.read_env(str(env_file))

# ── Core ────────────────────────────────────────────────────────

SECRET_KEY = env("SECRET_KEY")
DEBUG = env("DEBUG")
ALLOWED_HOSTS = env("ALLOWED_HOSTS")
CSRF_TRUSTED_ORIGINS = env("CSRF_TRUSTED_ORIGINS")

# ── Apps ────────────────────────────────────────────────────────

INSTALLED_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    # Third-party
    "rest_framework",
    "rest_framework.authtoken",
    "django_filters",
    # Local
    "core",
]

# ── Middleware ───────────────────────────────────────────────────

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "core.metrics.middleware.PrometheusMetricsMiddleware",
    "whitenoise.middleware.WhiteNoiseMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "core.middleware.jwt_auth.ProxyJWTAuthMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
]

ROOT_URLCONF = "kubeposture.urls"

# ── Templates ───────────────────────────────────────────────────

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [BASE_DIR / "templates"],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.debug",
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
            ],
        },
    },
]

WSGI_APPLICATION = "kubeposture.wsgi.application"

# ── Database ────────────────────────────────────────────────────

DATABASES = {
    "default": env.db("DATABASE_URL"),
}

DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

# ── Auth ────────────────────────────────────────────────────────

LOGIN_URL = "/accounts/login/"
LOGIN_REDIRECT_URL = "/"
LOGOUT_REDIRECT_URL = "/accounts/login/"

AUTH_PASSWORD_VALIDATORS = [] if DEBUG else [
    {"NAME": "django.contrib.auth.password_validation.MinimumLengthValidator"},
]

# ── Proxy-forwarded JWT auth (optional) ─────────────────────────
# Generic header-JWT auth for reverse-proxy front-ends that
# authenticate users upstream and forward a signed JWT (Pomerium,
# oauth2-proxy JWT mode, Cloudflare Access, Authelia jwt mode,
# Traefik forward-auth + OIDC).
# When enabled, the middleware auto-creates a Django User in the
# `viewer` group on first login. See docs/auth-jwt-proxy.md.

JWT_AUTH_ENABLED = env.bool("JWT_AUTH_ENABLED", default=False)
JWT_AUTH_HEADER = env("JWT_AUTH_HEADER", default="X-Pomerium-Jwt-Assertion")
JWT_AUTH_JWKS_URL = env("JWT_AUTH_JWKS_URL", default="")
JWT_AUTH_AUDIENCE = env("JWT_AUTH_AUDIENCE", default="")
JWT_AUTH_ISSUER = env("JWT_AUTH_ISSUER", default="")
JWT_AUTH_JWKS_CACHE_TTL = env.int("JWT_AUTH_JWKS_CACHE_TTL", default=3600)

# ── Static files ────────────────────────────────────────────────

STATIC_URL = "static/"
STATIC_ROOT = BASE_DIR / "staticfiles"
STATICFILES_DIRS = [BASE_DIR / "static"]
STORAGES = {
    "staticfiles": {
        "BACKEND": "whitenoise.storage.CompressedManifestStaticFilesStorage",
    },
}

# ── DRF ─────────────────────────────────────────────────────────

REST_FRAMEWORK = {
    "DEFAULT_AUTHENTICATION_CLASSES": [
        "rest_framework.authentication.SessionAuthentication",
    ],
    "DEFAULT_PERMISSION_CLASSES": [
        "rest_framework.permissions.IsAuthenticated",
    ],
    "DEFAULT_FILTER_BACKENDS": [
        "django_filters.rest_framework.DjangoFilterBackend",
    ],
    "DEFAULT_PAGINATION_CLASS": "rest_framework.pagination.PageNumberPagination",
    "PAGE_SIZE": 25,
}

# ── KubePostureNG harness flag (Phase 5) ───────────────────────────

TESTING_HARNESS_ENABLED = env.bool("TESTING_HARNESS_ENABLED", default=False)

# ── Logging ─────────────────────────────────────────────────────

LOG_LEVEL = env("LOG_LEVEL")

LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {
        "verbose": {
            "format": "{asctime} {levelname} {name} {message}",
            "style": "{",
        },
    },
    "handlers": {
        "console": {
            "class": "logging.StreamHandler",
            "formatter": "verbose",
        },
    },
    "root": {
        "handlers": ["console"],
        "level": LOG_LEVEL,
    },
    "loggers": {
        "django": {
            "handlers": ["console"],
            "level": LOG_LEVEL,
            "propagate": False,
        },
        "core": {
            "handlers": ["console"],
            "level": "DEBUG" if DEBUG else LOG_LEVEL,
            "propagate": False,
        },
    },
}

# ── Import bundles ─────────────────────────────────────────────
# See core/services/bundle_ingest.py. The upload view streams the body
# itself (DRF parsers are bypassed), so these caps — not Django's
# DATA_UPLOAD_MAX_MEMORY_SIZE — bound a bundle. Sized for a cycle of
# ~20 MB uncompressed today with generous headroom; all env-tunable.

IMPORT_BUNDLE_MAX_COMPRESSED_BYTES = env.int(
    "IMPORT_BUNDLE_MAX_COMPRESSED_BYTES", default=64 * 1024 * 1024,
)
IMPORT_BUNDLE_MAX_UNCOMPRESSED_BYTES = env.int(
    "IMPORT_BUNDLE_MAX_UNCOMPRESSED_BYTES", default=128 * 1024 * 1024,
)
IMPORT_BUNDLE_MAX_ITEMS = env.int("IMPORT_BUNDLE_MAX_ITEMS", default=50_000)
# The inventory envelope is one line (~1 MB today for a mid-size cluster).
IMPORT_BUNDLE_MAX_LINE_BYTES = env.int(
    "IMPORT_BUNDLE_MAX_LINE_BYTES", default=32 * 1024 * 1024,
)
# None → tempfile's default (TMPDIR / /tmp — an emptyDir in the chart).
IMPORT_BUNDLE_TMP_DIR = env("IMPORT_BUNDLE_TMP_DIR", default=None) or None

# commit logs `import.coverage_low` at ERROR when an importer-reported
# coverage ratio (matched / expected) is below this. The import still
# proceeds — partial scanner coverage is a valid snapshot.
IMPORT_COVERAGE_ALERT_RATIO = env.float("IMPORT_COVERAGE_ALERT_RATIO", default=0.9)

# Debugging aid only. The reap deletes a tuple's IngestQueue rows once it
# has recorded failed_count / last_error on the ImportMark; with this on,
# `failed` rows (and their raw payloads) are kept for the 14-day prune so
# a reproducible parse failure can be replayed. Turn on while
# investigating, off afterwards.
IMPORT_KEEP_FAILED_PAYLOADS = env.bool("IMPORT_KEEP_FAILED_PAYLOADS", default=False)

# Plain-JSON endpoints (commit, the testing harness) still go through
# Django's in-memory body limit; the default 2.5 MB is too small for
# harness scenarios that inline an inventory envelope.
DATA_UPLOAD_MAX_MEMORY_SIZE = env.int("DATA_UPLOAD_MAX_MEMORY_SIZE", default=16 * 1024 * 1024)

# ── Inventory exposure ─────────────────────────────────────────

# Ingress class names to treat as non-public when computing
# Workload.publicly_exposed. Adds to the built-in "internal"/"private"
# substring heuristic in core/parsers/inventory.py:_is_internal_ingress.
# Comma-separated, case-insensitive. Example: "pomerium,nginx-internal".
INTERNAL_INGRESS_CLASSES = env.list("INTERNAL_INGRESS_CLASSES", default=[])

# ── Snapshots ──────────────────────────────────────────────────

# Sliding retention window for the Snapshot table. Per
# Architecture/dev_docs/03-data-model.md §Snapshot — Retention.
# `manage.py prune_snapshots` deletes rows older than this.
SNAPSHOT_RETENTION_DAYS = env.int("SNAPSHOT_RETENTION_DAYS", default=365)

# ── Security (production) ───────────────────────────────────────

if not DEBUG:
    SECURE_SSL_REDIRECT = env.bool("SECURE_SSL_REDIRECT", default=False)
    SESSION_COOKIE_SECURE = True
    CSRF_COOKIE_SECURE = True
    SECURE_BROWSER_XSS_FILTER = True
    SECURE_CONTENT_TYPE_NOSNIFF = True
    X_FRAME_OPTIONS = "DENY"
