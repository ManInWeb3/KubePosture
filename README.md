# KubePosture

K8s security posture aggregator. Pulls Trivy Operator + Kyverno reports
from each cluster, enriches with EPSS + KEV, scores each finding by
urgency, and exposes a per-`(workload, image)` view of what to fix
first.

Also ingests Trivy `SbomReport` CRDs into a per-image component inventory
(`/components/`), pulls the OSV.dev supply-chain IoC feed, and matches it
against deployed components — malicious-publish events surface as
IMMEDIATE-priority findings alongside CVEs.

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
| `INTERNAL_INGRESS_CLASSES` | Comma-separated ingress class names treated as not publicly exposed (e.g. `pomerium`). Empty = built-in `internal`/`private` substring heuristic only. |

### 4. Apply migrations

```bash
python manage.py migrate
```

### 5. Seed the RBAC groups

```bash
python manage.py setup_rbac
```

Creates the three role Groups — `viewer`, `SecEngineer`, `admin` — that
the Access UI assigns to users. Idempotent; re-run any time.

### 6. Create a Django superuser (for the admin UI)

```bash
python manage.py createsuperuser
```

### 7. Run the dev server

```bash
python manage.py runserver
```

Open http://localhost:8000/admin/ and log in with the superuser. The
admin lists every model — Cluster, Namespace, Workload, WorkloadAlias,
WorkloadImageObservation, WorkloadSignal, Image, Finding, FindingAction,
ImportMark, IngestQueue, IngestToken, Snapshot, EpssScore, KevEntry,
ScanInconsistency, UserPreference.

There is no custom UI in this milestone. Read + act through Django
admin.

### 8. Drain the ingest queue

In another terminal:

```bash
source .venv/bin/activate
python manage.py process_ingest_queue          # loop until empty (default)
python manage.py process_ingest_queue --once   # single batch then exit
python manage.py process_ingest_queue --limit 50
```

Default mode loops `drain_once` batches until the queue is empty, then
exits. In production this runs as a CronJob every few minutes; locally
re-run it whenever you've ingested new data.

---

## Loading data

Three ways, in order from cheapest to most-realistic:

### Option A — Replay the e2e fixtures (no cluster needed)

Useful for sanity-checking the pipeline end-to-end without any K8s
plumbing.

```bash
pytest tests/integration/test_import_e2e.py   # synthetic cycles through the real endpoints
pytest -m realdata                            # anonymised real-cluster capture under fixtures/real/
```

Those populate a throwaway test DB. To populate your real dev DB with
inline payloads, use the harness endpoint — it stores one bundle per
`(import_id, kind)` and commits, exactly like a real upload:

```bash
curl -X POST http://localhost:8000/api/v1/testing/reset/ \
  -H 'Content-Type: application/json' -d '{}'

curl -X POST http://localhost:8000/api/v1/testing/load_scenario/ \
  -H 'Content-Type: application/json' -d '{
    "cluster": "prod-payments-1",
    "import_id": "01HW000000000000000000HPPY",
    "payloads": [{"kind": "inventory",
                  "payload": {"cluster_meta": {"name": "prod-payments-1"}, "items": []}}],
    "finishes": [{"kind": "inventory", "observed_count": 1}]
  }'
```

(Server must have been started with `TESTING_HARNESS_ENABLED=true`.
`observed_count` must equal the number of payloads for that kind — a
real commit is strict about it.)

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
#    Tokens are NOT cluster-bound; the name is just a human label.
TOKEN=$(python manage.py create_ingest_token my-laptop | tail -1)

# 3. Replay the capture into your local central. The importer uploads
#    one gzip bundle per kind, then commits the import atomically —
#    nothing is queued unless every bundle verified.
KUBEPOSTURE_URL=http://localhost:8000 KUBEPOSTURE_TOKEN=$TOKEN \
  python scripts/import-cluster.py <cluster-name> --from-folder /tmp/kp-snap

# 4. Drain the queue.
python manage.py process_ingest_queue
```

`scripts/capture-cluster-fixture.sh /tmp/kp-snap` runs the capture
block above for you (and skips CRDs the cluster doesn't have).

### Option C — Live cluster import

Same flow, but instead of `--from-folder` point the importer at a
kubeconfig:

```bash
TOKEN=$(python manage.py create_ingest_token my-laptop | tail -1)

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

Offline / air-gapped variant — load from a local file instead of
fetching over HTTP:

```bash
python manage.py enrich_from_file --source kev /path/to/known_exploited_vulnerabilities.json
python manage.py enrich_from_file --source epss /path/to/epss_scores.csv
```

---

## Supply-chain detection (OSV)

Layered on top of Trivy SBOM ingest. Each cluster import now POSTs
`SbomReport` CRDs alongside the existing scan kinds, which populate the
`SbomComponent` table — one row per `(image, purl)`. The OSV.dev feed
pulls malicious-publish IoCs and a matcher joins them against currently-
deployed components.

```bash
# Pull the IoC feed (writes SupplyChainIoc rows, runs the matcher inline).
python manage.py enrich_fetch --source osv-supply-chain  # ~hourly in prod

# Run the matcher manually (e.g. after seeding IoCs by hand for testing).
python manage.py match_supply_chain
python manage.py match_supply_chain --purl pkg:npm/lodash@4.17.21

# Manual search of the SBOM inventory.
python manage.py search_sbom --purl pkg:npm/lodash@4.17.21
python manage.py search_sbom --prefix pkg:npm/eslint-config-prettier
python manage.py search_sbom --purls-file /path/to/iocs.txt
```

OSV uses per-ecosystem bulk-zip snapshots
(`osv-vulnerabilities.storage.googleapis.com/<eco>/all.zip`) with
conditional GET. The fetcher only downloads ecosystems we actually
deploy — read from `SbomComponent.ecosystem` distinct. Filtered to
malicious-publish entries (`MAL-*` IDs or
`database_specific.malicious=true`). Each zip is streamed to a temp
file and decompressed one advisory at a time, so peak memory stays
flat even for the multi-hundred-MB npm snapshot. It works out of the
box with no configuration.

Matches become normal `Finding` rows with
`source=supply_chain_ioc`, `category=supply_chain`,
`effective_priority=immediate`, and show up in `/findings/?source=supply_chain_ioc`.

### End-to-end smoke test

Seed a synthetic cluster + workload + image + component + IoC and run
the matcher in one shot:

```bash
python manage.py seed_supply_chain_test               # default purl
python manage.py seed_supply_chain_test --purl pkg:pypi/ctx@0.1.2
python manage.py seed_supply_chain_test --use-existing-purl pkg:npm/lodash@4.17.21
python manage.py seed_supply_chain_test --cleanup     # remove test rows
```

Verify in the UI at `/findings/?source=supply_chain_ioc` and
`/components/?name=<your-purl-substring>`.

---

## Cadence — how often to run each command

The table is what the production CronJobs do. For a local dev setup,
re-run on the same triggers (or just on demand).

| Command | Cadence | Trigger |
|---|---|---|
| `migrate` | once per release | Code/schema change |
| `setup_rbac` | once + idempotent re-run | Install or after RBAC group rename |
| `createsuperuser` | once per env | Initial admin |
| `process_ingest_queue` | every 1–3 min (continuous) | Drains `IngestQueue`; reaps inline as marks finish draining (the reap deletes the tuple's rows — the queue only ever holds in-flight work) |
| `enrich_fetch --source kev` | daily | CISA KEV catalog refresh |
| `enrich_fetch --source epss` | daily | first.org EPSS publishes daily |
| `enrich_fetch --source osv-supply-chain` | hourly | OSV.dev per-ecosystem bulk-zip snapshots; conditional GET keeps off-cycle ticks cheap; streams each zip to disk so memory stays flat; calls the matcher inline |
| `match_supply_chain` | on-demand | Re-run matcher without re-fetching feeds (after seeding test IoCs, or after a matching-logic change) |
| `reap_safety_net` | hourly | Catches stuck `state=draining` ImportMarks the inline reaper missed; discards imports that can never complete — marks abandoned in `state=open` (importer died before `/imports/<id>/commit/`) and imports whose inventory payload failed — deleting their rows and marking them `reaped` with a `discard_reason` |
| `snapshot_capture` | daily (after enrichment + reaper) | End-of-day heartbeat at global / cluster / namespace / workload scopes; feeds trend charts |
| `prune_stale_data` | daily | DB hygiene — prunes `IngestQueue` leftovers (14d; normally empty, see [docs/pruning.md](docs/pruning.md)), `ImportMark` REAPED (90d), `ScanInconsistency` (30d), stale `Finding` rows (180d), `SbomComponent` on long-undeployed images (90d). Configurable per target. |
| `prune_snapshots` | daily or weekly | Deletes Snapshot rows older than `SNAPSHOT_RETENTION_DAYS` (default 365) |
| `recalculate_priorities` | on-demand or weekly | After a scoring tweak in `core/urgency.py`, or after a bulk enrichment refresh |
| `reset_runtime_data --yes` | manual only | Wipe runtime tables (workloads / findings / queue / marks / snapshots) while preserving Cluster + IngestToken + EPSS/KEV |

Quick local cron (one-shot housekeeping pass):

```bash
python manage.py reap_safety_net
python manage.py snapshot_capture
python manage.py prune_snapshots
```

Snapshot rows feed the **CVE Trend** charts on `/workloads/` (fleet-wide
or per-cluster, follows the cluster filter) and on each workload detail
page (per-cluster history with image-set events marked). Per-import
workload-scope snapshots are written automatically by the inventory
reaper; the daily heartbeat above fills in continuity at all four
scopes.

---

## Import API contract

The importer (`scripts/import-cluster.py`, deployed by the
`kubeposture-import` chart) talks to the central over three bearer-
authenticated endpoints. One `import_id` (a ULID minted per cycle)
groups everything; the cluster comes from the manifest / body and is
auto-registered.

| Step | Request | Notes |
|---|---|---|
| upload | `POST /api/v1/imports/<import_id>/bundles/<kind>/` — `Content-Type: application/x-ndjson`, `Content-Encoding: gzip` | Body: line 1 is `{"manifest": {cluster, import_id, kind, count, sha256, coverage?, …}}`; then one CRD JSON object per line (kind `inventory`: exactly one line, the envelope). `sha256` covers the item lines as sent, newlines included. The server verifies size caps, count and hash in a byte pass, then inserts the rows **and** the kind's ImportMark (`open`) in one transaction. `201 stored`; re-upload of identical bytes `200 already_uploaded`; different bytes `409 bundle_conflict`; verification failures `400` with an `error` code; caps `413`. |
| commit | `POST /api/v1/imports/<import_id>/commit/` — `{"cluster", "kinds": [{"kind", "count"}, …]}` | Every listed kind must have a mark whose stored row count equals `count`; every uploaded kind must be listed (`409` otherwise). All marks flip to `draining` together — nothing is claimable before this. `count: 0` is legitimate (CRD installed, no objects) and drives the zero-input / outage rule; absent CRDs are simply not listed. Idempotent for an identical retry. |
| abort | `POST /api/v1/imports/<import_id>/abort/` — `{"cluster"}` | Deletes the import's rows and marks while nothing is committed. The importer calls it when any bundle fails. |

Imports that are never committed are discarded by `reap_safety_net`
after `STUCK_OPEN_TIMEOUT_SECONDS` (30 min); a failed inventory payload
discards its whole import immediately. Discarded marks are `reaped`
with `discard_reason` set and never touch `last_complete_inventory_at`.
Every reap deletes its tuple's queue rows after recording
`failed_count` / `last_error` on the mark.

Side endpoints: `GET /api/v1/imports/pending/?cluster=`,
`POST /api/v1/imports/pending/clear/`, `POST /api/v1/cluster-metadata/sync/`.

---

## Running the tests

```bash
docker compose up -d db                       # Postgres (SKIP LOCKED, TRUNCATE … need the real thing)
pytest -m "not e2e and not realdata"          # unit + service + HTTP contract tests
pytest -m "e2e or realdata"                   # real endpoints → drain → ORM assertions; real-data fixtures
pytest scripts/importer_tests                          # the importer package (no DB, no Django)
```

- `tests/integration/test_import_e2e.py` drives the bundle endpoints
  with synthetic clusters (deploy tracking, image upgrade, alias
  resolution, scanner outage, abort, re-upload, stuck-open discard, …).
- `tests/realdata/` and `tests/integration/test_import_e2e_realdata.py`
  run against the anonymised real-cluster capture under
  `fixtures/real/<alias>/` and the real `scripts/import-cluster.py
  --from-folder`; they skip when no fixture is present.
- `.github/workflows/test.yml` runs lint, unit and e2e jobs on every PR.

---

## Common operations

| Task | Command |
|---|---|
| Reset the dev DB (full schema rebuild) | `docker compose exec db psql -U kubeposture -d postgres -c 'DROP DATABASE IF EXISTS kubeposture' -c 'CREATE DATABASE kubeposture'` then `python manage.py migrate` |
| Reset runtime data only (preserves clusters / tokens / EPSS / KEV) | `python manage.py reset_runtime_data --yes` |
| Mint an ingest bearer token | `python manage.py create_ingest_token <name> [--description "..."]` |
| Drain the ingest queue (loop) | `python manage.py process_ingest_queue` |
| Drain the ingest queue (single batch) | `python manage.py process_ingest_queue --once [--limit 100]` |
| Force a priority recompute | `python manage.py recalculate_priorities [--cluster <name>]` |
| Capture a daily snapshot | `python manage.py snapshot_capture` |
| Prune old snapshots | `python manage.py prune_snapshots [--dry-run]` |
| Daily DB hygiene (all targets) | `python manage.py prune_stale_data [--dry-run]` |
| Dry-run DB hygiene (preview deletions) | `python manage.py prune_stale_data --dry-run` |
| Sweep stuck draining/open marks | `python manage.py reap_safety_net` |
| Fetch latest EPSS / KEV | `python manage.py enrich_fetch --source {epss,kev}` |
| Load EPSS / KEV from file (offline) | `python manage.py enrich_from_file --source {epss,kev} <path>` |
| Pull supply-chain IoC feed (OSV bulk zip) | `python manage.py enrich_fetch --source osv-supply-chain` |
| Re-run the supply-chain matcher | `python manage.py match_supply_chain [--purl <purl>]` |
| Search the SBOM inventory for a purl | `python manage.py search_sbom --purl <purl> \| --prefix <pfx> \| --purls-file <path>` |
| Seed an end-to-end supply-chain test | `python manage.py seed_supply_chain_test [--purl <purl>] [--cleanup]` |
| Seed RBAC groups | `python manage.py setup_rbac` |
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
    enrichment.py        # file + HTTP loaders for EPSS + KEV
    worker.py            # claim → process → reap loop
    bundle_ingest.py     # bundle spool/verify/store, commit, abort
    reaper.py            # claim-first reaps, delete-at-reap, discards
    test_assertions.py   # assertion DSL (harness + real-data e2e)
  api/
    auth.py              # bearer-token auth + IngestToken hashing
    views.py             # /api/v1/imports/pending/*  /cluster-metadata/sync/
    views_bundles.py     # /api/v1/imports/<id>/bundles/<kind>/  commit/  abort/
    testing_views.py     # /api/v1/testing/*  (gated on settings flag)
  signals.py             # signal registry (kyverno: / ksv: / kp: IDs)
  urgency.py             # pure decision tree → effective_priority
  management/commands/   # process_ingest_queue, enrich_fetch, …

scripts/import-cluster.py        # the importer entry point (shim over scripts/kubeposture_importer/)
scripts/kubeposture_importer/    # collect → relevance filter → coverage → bundles → upload/commit
scripts/capture-cluster-fixture.sh, scripts/anonymize-fixture.py   # real-data fixture tooling
fixtures/real/<alias>/           # anonymised real-cluster capture + golden expectations
tests/integration/               # e2e through the real endpoints (+ realdata variant)
tests/realdata/                  # parser / filter / bundle checks over fixtures/real
```

---

## Tech stack

- Django 5.2 LTS + DRF
- PostgreSQL 16 (JSONB on `Finding.details` + `Snapshot.*`)
- Whitenoise (static), gunicorn (WSGI)
- DB-backed ingest queue — no Redis / Celery
- pytest + pytest-django for unit, e2e and real-data suites

---

## Known limits in this milestone

- No custom UI. Django admin only.
- No live `--in-cluster` / `--kubeconfig` smoke test against a real
  cluster recorded yet — `--from-folder` is verified end-to-end (the
  real-data e2e runs the actual script against a live test server).
- VEX ingest deferred. Applicability checks are manual against
  upstream sources; see [docs/operations/handling-vulnerable-images.md](docs/operations/handling-vulnerable-images.md#step-1--applicability-check)
  for the GHSA / OSV.dev / Chainguard recipes. Record applicability
  decisions as `FindingAction.FALSE_POSITIVE` overlays.
