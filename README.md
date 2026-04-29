# KubePostureNG

K8s security posture aggregator. Pulls Trivy Operator + Kyverno reports
from each cluster, enriches with EPSS / KEV / VEX, scores each finding
by urgency, and exposes a per-`(workload, image)` view of what to fix
first.

Authoritative design lives in
[`Architecture/dev_docs/`](Architecture/dev_docs/) and the executable
test bundle in
[`Architecture/mock_tests/`](Architecture/mock_tests/).

The current milestone is **data model + ingest + scripts + scenario
tests passing**. UI = Django admin only. Custom UI lands in a later
milestone.

---

## Quick start (local development)

### Prerequisites

- Python 3.12+
- Docker (for PostgreSQL)

### 1. Start postgres

```bash
docker compose up -d db
```

### 2. Install dependencies

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
pip install -r requirements-dev.txt   # pytest, ruff
```

### 3. Configure environment

```bash
cp .env.example .env
```

Defaults work against the docker-compose database. The relevant vars:

| Variable | Notes |
|---|---|
| `SECRET_KEY` | Any non-empty string for dev. |
| `DATABASE_URL` | Defaults to the docker-compose Postgres. |
| `DEBUG` | `True` in dev. |
| `LOG_LEVEL` | `INFO` is fine; bump to `DEBUG` to see queue / reaper traces. |
| `TESTING_HARNESS_ENABLED` | Set to `true` to expose `/api/v1/testing/*` (the scenario harness). Off in prod. |

### 4. Apply migrations

```bash
python manage.py migrate
```

### 5. Create a Django superuser (for the admin UI)

```bash
python manage.py createsuperuser
```

### 6. Run the dev server

```bash
python manage.py runserver
```

Open http://localhost:8000/admin/ and log in with the superuser. The
admin lists every model — Cluster, Workload, Image, Finding,
WorkloadSignal, ImportMark, IngestQueue, Snapshot, FindingAction,
EpssScore, KevEntry, VexStatement, ScanInconsistency.

There is no custom UI in this milestone. Read + act through Django
admin.

### 7. Drain the ingest queue

In another terminal:

```bash
source .venv/bin/activate
python manage.py process_ingest_queue
```

This is one-shot — it drains everything currently `state=draining`
and exits. In production it runs as a 1-min CronJob; locally re-run
it whenever you've ingested new data.

---

## Loading data

Three ways, in order from cheapest to most-realistic:

### Option A — Replay a scenario fixture (no cluster needed)

Useful for sanity-checking the pipeline end-to-end without any K8s
plumbing.

```bash
TESTING_HARNESS_ENABLED=true \
DJANGO_SETTINGS_MODULE=kubeposture.settings \
pytest tests/scenario_runner/   # all 7 scenarios pass
```

That populates a throwaway test DB. To populate your real dev DB
from a fixture, use the harness endpoint:

```bash
curl -X POST http://localhost:8000/api/v1/testing/reset/ \
  -H 'Content-Type: application/json' -d '{}'

curl -X POST http://localhost:8000/api/v1/testing/load_scenario/ \
  -H 'Content-Type: application/json' -d '{
    "cluster": "prod-payments-1",
    "import_id": "01HW000000000000000000HPPY",
    "scenario_dir": "/abs/path/to/Architecture/mock_tests/01-happy-path"
  }'
```

(Server must have been started with `TESTING_HARNESS_ENABLED=true`.)

### Option B — Replay a captured `kubectl get -o json` dump

```bash
# 1. Capture from any cluster you have kubectl access to.
mkdir -p /tmp/kp-snap/{kubeapi,trivy,kyverno}
kubectl get deployments -A -o json   > /tmp/kp-snap/kubeapi/deployments.json
kubectl get statefulsets -A -o json  > /tmp/kp-snap/kubeapi/statefulsets.json
kubectl get daemonsets -A -o json    > /tmp/kp-snap/kubeapi/daemonsets.json
kubectl get cronjobs -A -o json      > /tmp/kp-snap/kubeapi/cronjobs.json
kubectl get jobs -A -o json          > /tmp/kp-snap/kubeapi/jobs.json
kubectl get replicasets -A -o json   > /tmp/kp-snap/kubeapi/replicasets.json
kubectl get pods -A -o json          > /tmp/kp-snap/kubeapi/pods.json
kubectl get services -A -o json      > /tmp/kp-snap/kubeapi/services.json
kubectl get ingresses -A -o json     > /tmp/kp-snap/kubeapi/ingresses.json
kubectl get networkpolicies -A -o json > /tmp/kp-snap/kubeapi/networkpolicies.json
kubectl get namespaces -o json       > /tmp/kp-snap/kubeapi/namespaces.json
kubectl get nodes -o json            > /tmp/kp-snap/kubeapi/nodes.json
kubectl version -o json              > /tmp/kp-snap/kubeapi/version.json

# Trivy CRDs (only if Trivy Operator is installed in the cluster):
kubectl get vulnerabilityreports -A -o json   > /tmp/kp-snap/trivy/vulnerabilityreports.json
kubectl get configauditreports -A -o json     > /tmp/kp-snap/trivy/configauditreports.json
kubectl get exposedsecretreports -A -o json   > /tmp/kp-snap/trivy/exposedsecretreports.json
kubectl get rbacassessmentreports -A -o json  > /tmp/kp-snap/trivy/rbacassessmentreports.json
kubectl get clusterrbacassessmentreports -o json > /tmp/kp-snap/trivy/clusterrbacassessmentreports.json
kubectl get infraassessmentreports -A -o json > /tmp/kp-snap/trivy/infraassessmentreports.json
kubectl get clustercompliancereports -o json  > /tmp/kp-snap/trivy/clustercompliancereports.json

# Kyverno PolicyReports (only if Kyverno is installed):
kubectl get policyreports -A -o json          > /tmp/kp-snap/kyverno/policyreports.json
kubectl get clusterpolicyreports -o json      > /tmp/kp-snap/kyverno/clusterpolicyreports.json

# 2. Mint a bearer token (only the plain token is shown — once).
TOKEN=$(python manage.py create_cluster_token <cluster-name> | tail -1)

# 3. Replay the capture into your local central.
KUBEPOSTURE_URL=http://localhost:8000 KUBEPOSTURE_TOKEN=$TOKEN \
  python scripts/import-cluster.py <cluster-name> --from-folder /tmp/kp-snap

# 4. Drain the queue.
python manage.py process_ingest_queue
```

### Option C — Live cluster import

Same flow, but instead of `--from-folder` point the importer at a
kubeconfig:

```bash
TOKEN=$(python manage.py create_cluster_token <cluster-name> | tail -1)

KUBEPOSTURE_URL=http://localhost:8000 KUBEPOSTURE_TOKEN=$TOKEN \
  python scripts/import-cluster.py <cluster-name> \
  --kubeconfig ~/.kube/config

python manage.py process_ingest_queue
```

`--in-cluster` works too if the script runs as a Pod with a
ServiceAccount.

---

## Enrichment (EPSS + KEV)

Optional but recommended — without these every Finding's
`effective_priority` is a function of severity + workload context only.

```bash
python manage.py enrich_fetch --source kev    # ~1.5k rows, seconds
python manage.py enrich_fetch --source epss   # ~330k rows, ~3 min
```

Failures are non-fatal: the loaders honour the universal zero-input
no-op rule (empty/failed fetch leaves existing rows alone).

In production both run as daily CronJobs. Locally, re-run when you
want fresh threat-intel.

VEX is admin-uploaded — drop OpenVEX / CSAF JSON files anywhere and
load with:

```bash
python manage.py enrich_from_file --source vex /path/to/file.json
```

---

## Daily housekeeping

```bash
python manage.py snapshot_capture          # daily heartbeat snapshots (global / cluster / namespace / workload)
python manage.py prune_snapshots           # delete Snapshot rows older than SNAPSHOT_RETENTION_DAYS (default 365)
python manage.py reap_safety_net           # fire any stuck reaps
python manage.py recalculate_priorities    # bulk recompute (after a scoring tweak)
```

Snapshot rows feed the **CVE Trend** charts on `/workloads/` (fleet-wide
or per-cluster, follows the cluster filter) and on each workload detail
page (per-cluster history with image-set events marked). Per-import
workload-scope snapshots are written automatically by the inventory
reaper; the daily heartbeat above fills in continuity at all four
scopes.

---

## Running the scenario suite

The scenario harness drives the scenarios under
`Architecture/mock_tests/` end-to-end against the testing endpoints.
It's the canonical regression suite for the ingest pipeline.

```bash
TESTING_HARNESS_ENABLED=true LOG_LEVEL=ERROR \
  pytest tests/scenario_runner/
```

Each scenario:

1. Truncates the test DB (`/api/v1/testing/reset/`).
2. Posts the scenario's `imports/*.json` files via
   `/api/v1/testing/load_scenario/`, which drains the queue and fires
   reaps inline.
3. Evaluates `assertions.yaml` via
   `/api/v1/testing/assert_batch/` — ~25 assertion kinds covering
   workloads, findings, signals, snapshots, marks.

---

## Common operations

| Task | Command |
|---|---|
| Reset the dev DB | `docker compose exec db psql -U kubeposture -d postgres -c 'DROP DATABASE IF EXISTS kubeposture' -c 'CREATE DATABASE kubeposture'` then `python manage.py migrate` |
| Mint a cluster bearer token | `python manage.py create_cluster_token <name>` |
| Drain the ingest queue once | `python manage.py process_ingest_queue` |
| Force a priority recompute | `python manage.py recalculate_priorities [--cluster <name>]` |
| Capture a daily snapshot | `python manage.py snapshot_capture` |
| Prune old snapshots | `python manage.py prune_snapshots [--dry-run]` |
| Fetch latest EPSS / KEV | `python manage.py enrich_fetch --source {epss,kev}` |
| Run scenario tests | `TESTING_HARNESS_ENABLED=true pytest tests/scenario_runner/` |
| System check | `python manage.py check` |

---

## Layout

```
core/
  models/                # 16 models (Cluster, Workload, Finding, WorkloadSignal, …)
  parsers/
    inventory.py         # raw K8s manifest → staged upserts
    trivy.py             # Trivy CRDs → Findings + signal IDs
    kyverno.py           # Kyverno PolicyReports → signals
  services/
    ingest.py            # per-kind dispatch
    queue.py             # SKIP LOCKED claim, gated on ImportMark.state='draining'
    reaper.py            # kind-dispatched reap, zero-input no-op rule
    dedup.py             # Finding hash + bulk upsert
    snapshot.py          # daily-heartbeat capture
    enrichment.py        # file + HTTP loaders for EPSS / KEV / VEX
    worker.py            # claim → process → reap loop
    test_assertions.py   # scenario-runner assertion evaluator
  api/
    auth.py              # bearer-token auth + ClusterToken hashing
    views.py             # /api/v1/imports/*  /ingest/  /cluster-metadata/sync/
    testing_views.py     # /api/v1/testing/*  (gated on settings flag)
  signals.py             # signal registry (kyverno: / ksv: / kp: IDs)
  urgency.py             # pure decision tree → effective_priority
  management/commands/   # process_ingest_queue, enrich_fetch, …

scripts/import-cluster.py        # the importer (live and --from-folder modes)
tests/scenario_runner/           # pytest plugin walking Architecture/mock_tests/
```

---

## Tech stack

- Django 5.2 LTS + DRF
- PostgreSQL 16 (JSONB on `Finding.details` + `Snapshot.*`)
- Whitenoise (static), gunicorn (WSGI)
- DB-backed ingest queue — no Redis / Celery
- pytest + pytest-django for unit tests + scenario suite

---

## Known limits in this milestone

- No custom UI. Django admin only.
- No live `--in-cluster` / `--kubeconfig` smoke test against a real
  cluster recorded yet — only `--from-folder` is verified end-to-end.
- VEX auto-fetch deferred. File-driven only.
- Helm chart for the central + importer not yet bumped to the new
  endpoint contract — local dev only for now.
- `reap_safety_net` fires drainable reaps but does not yet delete
  stuck `state=open` marks past 1h. Workaround: clear them via Django
  admin or a SQL DELETE.
