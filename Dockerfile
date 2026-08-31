# syntax=docker/dockerfile:1

# ---- Builder: installs Python deps into a venv ----
# All current requirements.txt deps ship prebuilt manylinux wheels for cp312
# on both amd64 and arm64 (psycopg[binary] bundles libpq; pyyaml and the
# cryptography package pulled in by PyJWT[crypto] both publish aarch64
# wheels), and Wolfi is glibc-based so those wheels resolve normally. The
# compiler toolchain here is insurance, not a current requirement: the CI
# build is multi-arch via QEMU emulation, and a future dependency lacking an
# aarch64 wheel would otherwise silently fall back to a slow/fragile
# emulated source build.
FROM cgr.dev/chainguard/wolfi-base:latest AS builder

RUN apk add --no-cache \
      python-3.12 \
      py3.12-pip \
      build-base \
      python-3.12-dev

RUN python -m venv /venv
ENV PATH="/venv/bin:${PATH}"

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# ---- Runtime ----
FROM cgr.dev/chainguard/wolfi-base:latest

# UID/GID 1000 matches the Helm charts' hardcoded runAsUser/runAsGroup
# (deploy/charts/kubeposture and deploy/charts/kubeposture-import) so the
# image behaves the same way standalone (e.g. `docker run`) as it does
# under those charts' securityContext. Wolfi has no baked-in nonroot user
# the way Chainguard's distroless images do, so it's created explicitly
# via BusyBox's adduser/addgroup (wolfi-base ships BusyBox for /bin/sh,
# which the charts' wait-for-db/migrate/setup steps rely on).
RUN apk add --no-cache python-3.12 \
 && addgroup -g 1000 app \
 && adduser  -D -u 1000 -G app -h /app -s /bin/sh app

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PROMETHEUS_MULTIPROC_DIR=/tmp/prom_multiproc \
    PATH="/venv/bin:${PATH}"

WORKDIR /app

COPY --from=builder /venv /venv
COPY . .

RUN SECRET_KEY=build-collectstatic \
    DATABASE_URL=sqlite:///placeholder.db \
    python manage.py collectstatic --noinput

USER 1000:1000

EXPOSE 8000

CMD ["gunicorn", "-c", "gunicorn.conf.py", "kubeposture.wsgi:application", \
     "--bind", "0.0.0.0:8000", \
     "--workers", "2", \
     "--access-logfile", "-"]
