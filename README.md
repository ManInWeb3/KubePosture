# KubePosture

K8s security posture management platform. Aggregates vulnerability and compliance findings from Trivy Operator and Kyverno across all clusters into a single database with lifecycle tracking, effective priority scoring, and compliance reporting.

## Who Uses This

KubePosture is the **security team's tool**. Not everyone involved in fixing security issues needs an account.

### Direct access (create accounts)

| Role | Django group | What they do |
|---|---|---|
| Security lead / CISO | `admin` | Approve risk acceptance, manage cluster config, user management, compliance sign-off |
| DevSecOps engineer | `operator` | Triage findings, acknowledge, bulk actions, propose risk acceptance |
| Compliance officer / auditor | `viewer` | Read compliance matrix, download PDF reports |
| On-call engineer | `viewer` | Look up a CVE or misconfiguration during an incident |

### No direct access needed — sync to Linear instead

| Person | Why no account | How they engage |
|---|---|---|
| Developer | Doesn't need CVSS, EPSS, or compliance context — just needs a ticket | Linear issue synced from the finding |
| Product manager | Schedules security work in sprints, not raw CVE triage | Linear issue as backlog item |
| Engineering manager | Wants team-level security work visible, not a security dashboard | Linear issues in team board |

The sync boundary: KubePosture decides **what** needs fixing and **how urgent** (IMMEDIATE → Urgent, OUT-OF-CYCLE → High, SCHEDULED → Medium, DEFER → Low). Linear is where engineering tracks **when** they'll fix it. Linear integration is planned for Phase 5H.

### Risk acceptance

"Accept Risk" requires admin role — it's a compliance act with an auditable paper trail (reason + expiry date required). A propose/approve workflow (operator proposes, admin approves in one click) is planned for Phase 4.

## Quick Start (Local Development)

### Prerequisites

- Python 3.12+
- Docker (for PostgreSQL)

### 1. Start the database

```bash
docker compose up -d db
```

### 2. Install dependencies

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
pip install -r requirements-dev.txt  # for tests
```

### 3. Configure environment

Copy the example env file:

```bash
cp .env.example .env
```

The defaults work for local development with the docker-compose database.

### 4. Initialize the database

```bash
python manage.py migrate
python manage.py setup_roles              # creates viewer/operator/admin groups
python manage.py load_frameworks fixtures/*.yaml  # loads compliance frameworks
python manage.py createsuperuser          # create your admin account
```

### 5. Start the dev server

```bash
python manage.py runserver
```

Open http://localhost:8000 and log in with your superuser account.

### 6. Start the ingest queue processor

In a separate terminal:

```bash
source .venv/bin/activate
python manage.py process_ingest_queue
```

This continuously processes incoming scanner data. Must be running for ingested data to appear.

## Importing Scanner Data

### Create a service token

```bash
python manage.py create_service_token cluster-name-1
# Output: Token: ac9999bc1aXXXXXXXXXXXc795ca7c2
```

### Import from a cluster

Import everything (Trivy + Kyverno):

```bash
python scripts/import-cluster.py cluster-name-1 <token>
```

Import Trivy only:

```bash
python scripts/import-cluster.py cluster-name-1 <token> --trivy
```

Import Kyverno only:

```bash
python scripts/import-cluster.py cluster-name-1 <token> --kyverno
```

Custom kubeconfig:

```bash
python scripts/import-cluster.py cluster-name-1 <token> --kubeconfig /path/to/kubeconfig
```

In-cluster (for K8s CronJob):

```bash
python scripts/import-cluster.py cluster-name-1 <token> --in-cluster
```

Custom API URL:

```bash
KUBEPOSTURE_URL=https://kubeposture.someorg.xyz \
  python scripts/import-cluster.py cluster-name-1 <token>
```

## How-To: Mitigating CVEs via Findings

Playbook for reducing *Immediate* and *Out-of-Cycle* findings. Work top-down;
ignore *Scheduled* and *Defer* until the top two buckets are empty.

1. **Configure cluster context first.** In Settings → Clusters, set each cluster's
   environment (prod/staging/dev), internet-exposed flag, and sensitive-data flag.
   Without this, effective priority degrades and everything lands in *Defer*.
2. **Triage Immediate findings.** Findings → filter `priority=immediate`, `status=active`.
   This is the KEV + high-EPSS + critical + exposed-prod intersection — the weekly work queue.
3. **Group by image.** Most CVEs cluster in a few base images. Open the Images tab,
   sort by Critical count. One base-image bump (e.g. `python:3.11-slim` → `3.12-slim`)
   typically closes 20–200 findings at once.
4. **Choose the fix per finding.** Click a finding — the `fixed_version` field tells you if a patch exists.
   - **Patch available** → bump the dependency/image, rebuild, redeploy.
   - **No patch, exposed + KEV** → compensate with NetworkPolicy, WAF rule, or disable the feature.
   - **Vendor image, unpatched** → Accept Risk with a short expiry (≤ 90 days) + tracking ticket.
   - **False positive** → mark as False Positive with a reason (audit trail matters).
5. **Ship & verify.** After the new image rolls out, the next scan dedups by hash.
   Fixed findings auto-transition to RESOLVED; unchanged ones stay ACTIVE. Verify by
   filtering `status=resolved` for that cluster/image.
6. **Prevent recurrence (shift left).** Dependabot/Renovate on source repos,
   Trivy in CI to fail builds on new Criticals, pin base images to hardened/distroless.
7. **Measure.** Track *time-to-fix for Immediate* and *open Immediate at week end* — not raw finding counts.

## How-To: Making Clusters Compliant

Goal: pass framework audits (CIS Kubernetes Benchmark, NSA Hardening, SOC2, PCI DSS)
and keep them passing. Core loop: **Trivy detects existing violations → you fix them →
Kyverno prevents new violations**.

1. **Pick a framework.** Compliance → Trivy Frameworks. Start with CIS Kubernetes Benchmark
   (widest coverage). Add SOC2/PCI DSS/HIPAA only if you have a regulatory requirement.
   Frameworks are loaded from fixture YAMLs listed in `frameworkFixtures` in Helm values
   via `manage.py load_frameworks`.
2. **Read the matrix.** Click a framework card → View Matrix. Rows = controls, columns = clusters.
   **FAIL** cells are your work; **MISSING** means no scan data (check the scanner is installed).
3. **Fix the easy wins.** Most CIS failures are config issues in Helm values:
   - Missing `resources.requests`/`resources.limits` → add them.
   - `allowPrivilegeEscalation: true` → set to false.
   - Running as root → set `runAsNonRoot: true` + non-zero `runAsUser`.
   - Writable root filesystem → `readOnlyRootFilesystem: true`, mount writable paths as `emptyDir`.
   - Missing NetworkPolicy → add default-deny per namespace + explicit allows.
   - Wide cluster-admin bindings → scope down to namespaces or specific resources.
   - Default ServiceAccount in use → create per-workload SA, set `automountServiceAccountToken: false` where unused.
4. **Deploy Kyverno policies in audit mode.** Once a control is green, deploy the matching
   Kyverno policy with `validationFailureAction: Audit`. Violations show up on
   Compliance → Kyverno Policies without blocking deployments.
5. **Promote to enforce.** Watch for 1–2 weeks. When the audit-mode policy has zero fails
   across all clusters, flip to `validationFailureAction: Enforce`. New violations get
   blocked at admission — the control is self-enforcing.
6. **Document exceptions.** Legitimate exceptions (e.g. a vendor operator needing cluster-admin)
   get a Risk Acceptance on the finding with reason + expiry. Auditors accept documented
   exceptions; they don't accept undocumented ones.
7. **Prepare for audit.** You need four things:
   detection evidence (matrix PASS/FAIL), enforcement evidence (Kyverno in enforce mode),
   remediation evidence (finding history shows who fixed what, when), documented exceptions.
8. **Stay compliant.** Weekly: no new red cells. Monthly: review risk acceptances.
   Quarterly: reload framework fixtures (`manage.py load_frameworks`) in case CIS/SOC2
   released new versions.

## Daily Cron Jobs

These should run as K8s CronJobs in production:

```bash
# Enrich findings with EPSS exploit probability scores (daily)
python manage.py enrich_epss

# Enrich findings with CISA KEV (Known Exploited Vulnerabilities) flags (daily)
python manage.py enrich_kev

# Expire risk acceptances past their expiry date (daily)
python manage.py expire_risk_acceptances

# Clean up processed ingest queue items older than 7 days
python manage.py cleanup_ingest_queue --days 7

# Recalculate effective priorities (after cluster config changes)
python manage.py recalculate_priorities
```

## Management Commands

| Command | Purpose |
|---------|---------|
| `setup_roles` | Create viewer/operator/admin groups (idempotent) |
| `create_service_token <name>` | Create API token for scanner ingest |
| `load_frameworks <files>` | Load compliance framework fixtures from YAML |
| `process_ingest_queue` | Process incoming scanner data (run continuously) |
| `enrich_epss` | Update EPSS exploit probability scores |
| `enrich_kev` | Update CISA Known Exploited Vulnerabilities flags |
| `expire_risk_acceptances` | Reactivate expired risk acceptances |
| `recalculate_priorities` | Recalculate effective priority for all findings |
| `cleanup_ingest_queue` | Delete old processed queue items |
| `backfill_compliance` | Reprocess raw compliance reports into structured models |
| `backfill_sbom` | Reprocess raw SBOM reports into component models |

## Build & Release

### Docker Image

**Build locally:**

```bash
docker build -t kubeposture:dev .
```

**Release via CI** — push a semver tag:

```bash
git tag v0.1.0
git push origin v0.1.0
```

GitHub Actions builds a multi-platform image (`amd64` + `arm64`) and pushes to GHCR:

```
ghcr.io/<owner>/<repo>:0.1.0
ghcr.io/<owner>/<repo>:0.1
ghcr.io/<owner>/<repo>:latest
ghcr.io/<owner>/<repo>:sha-<short-sha>
```

**Pull a released image:**

```bash
docker pull ghcr.io/<owner>/<repo>:0.1.0
```

---

### Helm Charts

There are two charts under `deploy/charts/`:

| Chart | Purpose |
|---|---|
| `kubeposture` | Main application (web, worker, cronjobs) |
| `kubeposture-import` | CronJob deployed per-cluster to pull scanner data |

**Lint and package locally:**

```bash
helm lint deploy/charts/kubeposture
helm package deploy/charts/kubeposture --version 0.1.0 --app-version 0.1.0
```

**Release via CI** — push a chart release tag using the convention `helm-{chart}-v{version}`:

```bash
# release the main chart
git tag helm-kubeposture-v0.1.0
git push origin helm-kubeposture-v0.1.0

# release the import chart
git tag helm-kubeposture-import-v0.1.0
git push origin helm-kubeposture-import-v0.1.0
```

GitHub Actions lints, packages, and pushes the chart as an OCI artifact to GHCR.

**Install a released chart:**

```bash
helm install kubeposture \
  oci://ghcr.io/<owner>/<repo>/charts/kubeposture \
  --version 0.1.0 \
  -f my-values.yaml
```

> OCI charts do not use `helm repo add` — reference the full OCI URL directly.

---

## User Management

### Default admin user

`manage.py ensure_adminuser` (run by the setup Job on every deploy) creates a plain application admin — in the `admin` group, no Django admin access, no superuser flag. Change the credentials in Helm values:

```yaml
adminUser:
  username: admin
  password: changeme
  email: security@example.com
```

### Assign a role to an existing user

```bash
python manage.py shell -c "
from django.contrib.auth.models import User, Group
u = User.objects.get(username='jane')
u.groups.set([Group.objects.get(name='operator')])  # viewer | operator | admin
"
```

### Grant Django admin access (platform operator / superuser)

Django admin (`/admin/`) is separate from application roles. Only needed for the platform operator who fixes data via Django admin (cluster metadata corrections, framework management, etc.). Keep this to one or two people.

```bash
python manage.py shell -c "
from django.contrib.auth.models import User
u = User.objects.get(username='jane')
u.is_staff = True       # grants /admin/ login
u.is_superuser = True   # bypasses all permission checks in /admin/
u.save()
"
```

To revoke:

```bash
python manage.py shell -c "
from django.contrib.auth.models import User
u = User.objects.get(username='jane')
u.is_staff = False
u.is_superuser = False
u.save()
"
```

> Superusers bypass `has_role()` checks in the application too — they can do everything any role can do.

## Running Tests

```bash
source .venv/bin/activate
python -m pytest core/tests/ -v
```

Note: Tests marked with `@pytest.mark.django_db` require PostgreSQL running via docker-compose.

## Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `SECRET_KEY` | Yes | - | Django secret key |
| `DATABASE_URL` | Yes | - | PostgreSQL connection string |
| `DEBUG` | No | `False` | Enable debug mode |
| `ALLOWED_HOSTS` | No | `[]` | Comma-separated list of allowed hosts |
| `LOG_LEVEL` | No | `INFO` | Logging level |

## Tech Stack

- **Backend:** Django 5.2 LTS + Django REST Framework
- **UI:** Tabler (Bootstrap 5) + HTMX -- server-side rendering, zero JS build pipeline
- **Database:** PostgreSQL 16 (JSONB hybrid model for findings)
- **Static files:** Whitenoise
- **Queue:** PostgreSQL-backed async ingest queue (no Redis/Celery)

