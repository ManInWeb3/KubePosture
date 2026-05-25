# Urgency Decision Tree

Every finding carries an `effective_priority` band:

- **Immediate** — drop current work, fix today.
- **OutOfCycle** — patch this week, before normal release cadence.
- **Scheduled** — include in the next planned release.
- **Defer** — track but don't act.

The band is computed from threat-intel enrichments, namespace/cluster
context, and the workload's [exploitability likelihood signals](06-signals.md).
It is the primary sort key in the UI.

**Implementation: `core/urgency.py`** as a pure Python function. The
decision tree is code — versioned with the app, unit-testable,
tweakable without a schema migration. This module and `core/signals.py`
are the two places where scoring evolves as the tool learns the
deployment's patterns.

## Function signature

A Finding attaches to one Workload (nullable only for cluster-scoped
findings). So scoring takes a Finding and reads `finding.workload.*`
directly — no aggregation, no separate context object:

```python
# core/urgency.py
from dataclasses import dataclass
from enum import Enum

class PriorityBand(str, Enum):
    IMMEDIATE    = "immediate"
    OUT_OF_CYCLE = "out_of_cycle"
    SCHEDULED    = "scheduled"
    DEFER        = "defer"

@dataclass(frozen=True)
class PriorityResult:
    band: PriorityBand
    reasons: tuple[str, ...]     # e.g. ("KEV", "env=prod", "signal:kyverno:disallow-privileged-containers")


def score(finding: Finding) -> PriorityResult:
    """THE EDITABLE FUNCTION.

    Pure: no DB access beyond the already-loaded relations on `finding`,
    no I/O, no globals. Reads `finding.*` and `finding.workload.*`
    directly. Edit this body to tweak the scoring logic.

    Callers must have loaded `finding.workload.namespace.cluster` and
    `finding.workload.signals` (the set of active WorkloadSignal IDs)
    via select_related / prefetch_related before calling.
    """
    ...


def compute_priority(finding: Finding) -> PriorityResult:
    """Public entry point. Ensures relations are loaded, then calls score().
    For bulk paths use recompute_batch() to avoid N+1.
    """
    finding = (Finding.objects
        .select_related("workload__namespace__cluster", "image")
        .prefetch_related("workload__signals")
        .get(pk=finding.pk))
    return score(finding)


def recompute_batch(findings: Iterable[Finding]) -> None:
    """Bulk recompute entry. One query pass to load every finding's
    relations, then loops calling score() in memory. Use from enrichment
    refresh, signal-change fan-out, inventory reap, etc.
    """
    loaded = (Finding.objects
        .filter(pk__in=[f.pk for f in findings])
        .select_related("workload__namespace__cluster", "image")
        .prefetch_related("workload__signals"))
    updated = []
    for f in loaded:
        result = score(f)
        f.effective_priority = result.band
        updated.append(f)
    Finding.objects.bulk_update(updated, ["effective_priority"])
```

**Cluster-scoped findings** (`finding.workload is None` — e.g. RBAC
findings on ClusterRoles) skip the workload reads and score off
finding fields + `finding.cluster` only. `score()` handles this with an
early branch.

The caller always sees `compute_priority(finding)` or
`recompute_batch(findings)`. The editable core is `score(finding)` —
that's the function to edit when tuning the formula.

## Decision tree (v1 reference)

**v1 starter thresholds — "good enough, adjust later."** The table
below is a ship-it default. It lives in `core/urgency.py` and is the
artefact to tweak. Don't over-tune at the start — after the first
month of real production traffic, review the band distribution
(via `finding_count` queries grouped by `effective_priority`) and
adjust EPSS cutoffs + severity-combination rules based on what the
data actually says. Until then, leave the defaults alone.

> **Note:** an earlier draft of this spec included a VEX short-circuit
> at the top of `score()`. VEX ingest was deferred — applicability
> decisions are recorded out-of-band as `FindingAction.FALSE_POSITIVE`
> overlays today. See [operations/handling-vulnerable-images.md](operations/handling-vulnerable-images.md#step-1--applicability-check)
> for the manual applicability-check workflow against GHSA, OSV.dev,
> and Chainguard VEX feeds.

```python
def score(finding: Finding) -> PriorityResult:
    # Supply-chain IoC match short-circuits to Immediate (placed before
    # KEV so the reason chip reads "supply-chain" if both ever combine).
    if finding.category == Category.SUPPLY_CHAIN.value:
        return PriorityResult(PriorityBand.IMMEDIATE, ("supply-chain",))

    # KEV short-circuits to Immediate
    if finding.kev_listed:
        return PriorityResult(PriorityBand.IMMEDIATE, ("KEV",))

    epss    = finding.epss_percentile or 0

    # Cluster-scoped finding (e.g. RBAC on ClusterRole) — no workload
    if finding.workload is None:
        env = finding.cluster.environment
        if finding.severity == "critical":
            return PriorityResult(
                PriorityBand.IMMEDIATE if env == "prod" else PriorityBand.OUT_OF_CYCLE,
                ("critical", f"cluster-scoped", env),
            )
        if finding.severity == "high" and env == "prod":
            return PriorityResult(PriorityBand.OUT_OF_CYCLE, ("high", "cluster-scoped", "prod"))
        return PriorityResult(PriorityBand.SCHEDULED, ("cluster-scoped",))

    # Workload-scoped finding
    w  = finding.workload
    ns = w.namespace
    c  = w.cluster

    # SSVC exposure check. is_exposed=True ≡ `open` (internet-reachable
    # via external LB / non-internal Ingress / namespace rollup).
    # is_exposed=False ≡ `controlled` (cluster-network-reachable, not
    # isolated) — NOT `small`. The tree's non-exposed branches treat
    # False as controlled. A `small` lane is reserved for a future
    # revision that detects deny-all NetPol + no listening port; it
    # would slot in below `controlled` and demote one band. NodePort /
    # hostNetwork / missing-NP remain separate inputs (escalation
    # signals / future weighting), not internet exposure.
    is_exposed = (
        w.has_external_ingress
        or w.has_external_lb
        or ns.internet_exposed  # namespace rollup, same primitives
    )

    signal_ids          = {s.signal_id for s in w.signals.all()}
    has_host_escape     = bool(signal_ids & HOST_ESCAPE_SIGNALS)      # from core/signals.py
    has_rbac_elevation  = bool(signal_ids & RBAC_ELEVATION_SIGNALS)
    has_priv_escalation = bool(signal_ids & PRIV_ESCALATION_SIGNALS)
    has_escalation      = has_host_escape or has_rbac_elevation or has_priv_escalation

    if finding.severity in {"critical", "high"} and epss >= 0.9 \
            and is_exposed and c.environment == "prod":
        return PriorityResult(PriorityBand.IMMEDIATE,
                              ("severity", "EPSS>=0.9", "exposed", "prod"))

    if finding.severity == "critical" and is_exposed and c.environment == "prod":
        return PriorityResult(PriorityBand.IMMEDIATE, ("critical", "exposed", "prod"))

    if finding.severity in {"critical", "high"} and c.environment == "prod" and has_escalation:
        return PriorityResult(PriorityBand.OUT_OF_CYCLE,
                              ("severity", "prod", "escalation-signal"))

    if epss >= 0.9 and c.environment == "prod":
        return PriorityResult(PriorityBand.OUT_OF_CYCLE, ("EPSS>=0.9", "prod"))

    if finding.severity == "critical" and c.environment == "prod":
        return PriorityResult(PriorityBand.OUT_OF_CYCLE, ("critical", "prod"))

    if finding.severity == "high" and is_exposed and c.environment == "prod":
        return PriorityResult(PriorityBand.OUT_OF_CYCLE, ("high", "exposed", "prod"))

    if finding.severity in {"critical", "high"} and (is_exposed or has_escalation):
        return PriorityResult(PriorityBand.SCHEDULED, ("severity", "exposed-or-escalation"))

    if finding.severity == "critical" and c.environment != "prod":
        return PriorityResult(PriorityBand.SCHEDULED, ("critical", "non-prod"))

    if finding.severity == "high" and c.environment == "prod":
        return PriorityResult(PriorityBand.SCHEDULED, ("high", "prod"))

    if finding.severity in {"high", "medium"} and ns.contains_sensitive_data:
        return PriorityResult(PriorityBand.SCHEDULED, ("severity", "sensitive-ns"))

    return PriorityResult(PriorityBand.DEFER, ("default",))
```

Category sets (`HOST_ESCAPE_SIGNALS`, `RBAC_ELEVATION_SIGNALS`,
`PRIV_ESCALATION_SIGNALS`) are built from `core/signals.py` by
filtering `SIGNALS` on `category` — so adding a new signal to the
registry automatically extends the set used here.

## Supply-chain short-circuit

`Category.SUPPLY_CHAIN` findings (source = `supply_chain_ioc`, produced
by `core/services/supply_chain_matcher.py` when a `SbomComponent.purl`
matches a `SupplyChainIoc.purl`) **unconditionally resolve to
`IMMEDIATE`**. The check is the first branch in `score()`, before KEV.

**Rationale.** A match means a feed (Aikido Intel or OSV.dev) has
explicitly flagged this exact `(name, version)` as malicious — a
maintainer-account takeover, attacker-published version, or
intentionally backdoored release. There is no benign middle ground.
The package contains attacker code by design, so neither severity nor
exposure nor EPSS reduces the urgency. The KEV-style short-circuit
applies for the same reason it does to KEV: known exploitation
trumps everything else in the tree.

**What it ignores by design:**

| Input | Why ignored |
|---|---|
| Feed-supplied severity | Most feeds publish "critical"; some omit it. The matcher defaults to `Severity.CRITICAL.value` when absent. The band stays IMMEDIATE regardless. |
| CVSS / EPSS | Malicious-publish events typically have no CVSS or EPSS score; `_enrichment_for` only fires on `CVE-*` IDs anyway. |
| Namespace exposure / cluster environment | A flagged purl in a sealed dev cluster still ranks IMMEDIATE — the deployed artifact contains attacker code regardless of network reachability. |
| Multi-feed confirmation | Aikido + OSV reporting the same compromise produces two findings (different `vuln_id`), both IMMEDIATE. No "confidence boost" sub-band. |

**Reason chip.** The `PriorityResult.reasons` tuple is `("supply-chain",)`
so the UI displays "Immediate · supply-chain" — distinct from "Immediate
· KEV" so triage knows at a glance what fired.

**If you ever want to soften this rule** (e.g. demote internal-only
deployments to OUT_OF_BAND, or respect feed-supplied severity), see
"Tweaking the formula" below — the supply-chain branch is a one-block
edit. The locked v1 decision was unconditional IMMEDIATE because
real-world supply-chain incidents (Shai-Hulud, `ctx`, `ua-parser-js`,
`eslint-config-prettier`) ship credential-stealing payloads on first
import, so the cost of demoting and being wrong is high.

## Tweaking the formula

The formula is code. Treat it accordingly:

- **Changing thresholds** (e.g. `epss_percentile >= 0.9` → `>= 0.95`):
  one-line edit in `core/urgency.py`.
- **Adding a new signal category** (e.g. NetworkPolicy gaps as their own
  weighted bucket): add the category to `SignalCategory`, assign
  affected signals, then reference the new category in
  `compute_priority`.
- **Replacing the decision tree with a weighted-sum scorer**: the
  `PriorityInput` contract stays; only `compute_priority`'s body
  changes. Callers (ingest, signal-change recompute, enrichment
  recompute) are unaffected.

Tests live alongside: `core/tests/test_urgency.py` with fixture inputs
covering every branch. No live DB needed — the function is pure.

## Defaults and null-safety

The formula must **never raise** on missing data, and every input
must have a defined default. Missing data in this system means one
of:

- **Scanner disabled / outage in a cluster** — no VulnerabilityReports
  arrive; Finding rows simply aren't created or refreshed.
- **Kyverno policy not deployed in a cluster** — the corresponding
  signal never appears in `WorkloadSignal`; downstream readers see
  "not fired."
- **Enrichment source empty this cycle** — EPSS/KEV joins return
  no row; the `epss_score` / `kev_listed` columns are `NULL` on the
  Finding.
- **Namespace / cluster context columns not yet populated** —
  autodetect hasn't run, or a new cluster is in its first import.

Column-level rules:

| Input | Default when absent | Why |
|---|---|---|
| `Workload.has_external_ingress` / `has_external_lb` / `has_nodeport_service` | `False` (NOT NULL, default False in schema) | Autodetection not having run is visually the same as "no exposure detected" at the scoring layer; Scan Health surfaces inventory gaps separately. |
| `Namespace.internet_exposed` / `contains_sensitive_data` | `False` | Same reasoning. |
| `Cluster.environment` | `"dev"` (conservative — lowest weight) | A cluster whose env hasn't been classified should not be treated as prod by accident. Admin override is explicit. |
| `Finding.epss_score` / `epss_percentile` | treated as `0.0` in comparisons | Absent EPSS means "no published probability" — do not elevate or suppress. |
| `Finding.kev_listed` | `False` | Same. |
| `WorkloadSignal` absence for a given `signal_id` | treated as "not fired" | Crucial for correctness: see below. |

**The policy-not-deployed trap.** If a Kyverno policy isn't installed
in a given cluster, `WorkloadSignal` rows never appear for its
signal_id, and the formula reads "signal not fired" — the workload
**looks clean on that dimension when it may not be**. The urgency
function cannot distinguish "policy deployed + workload clean" from
"policy never ran here." This is an **operational coverage concern,
not a scoring concern** — the formula correctly reports what it
knows. It is surfaced outside the formula via:

- **Policy-coverage tracking.** The importer enumerates Kyverno
  `ClusterPolicy` / `Policy` resources installed in each cluster and
  records them per `(cluster, policy_name)`. The signal registry is
  the authoritative list of policies the system expects. Any expected
  policy missing from a cluster produces a Scan Health row: *"Cluster
  X is missing policy Y — N workloads may be uncovered."*
- **Scanner-coverage tracking.** Cluster-level `scan_enabled` flag
  auto-flips to `false` after N consecutive missed expected imports
  for any scan kind (default N=3). Staleness reap skips clusters with
  `scan_enabled=false` to prevent false-resolve on outage; Scan
  Health shows the flipped clusters prominently.

The rule: **the scoring function trusts the data it is given and
applies defaults; the coverage layer (Scan Health, policy inventory)
is what tells the operator whether to trust the scoring.** Never mix
these concerns inside `compute_priority`.

## Recomputation triggers

Any of the following must synchronously bulk-recompute
`effective_priority` for the set of findings it touches, in one
transaction per trigger event:

- **On ingest** of a finding — using current enrichment + current live
  context.
- **On enrichment refresh** (EPSS / KEV — including clearings, when a
  CVE drops out of a feed).
- **On WorkloadSignal change** — any insert, `currently_active`
  toggle, or row update. Fan-out: `Finding.objects.filter(workload=W)`.
- **On observation change** — image rolls into or out of a workload.
  Reap creates / ages the matching Finding rows directly via `last_seen`.
- **On namespace context change** — `internet_exposed` flips,
  `contains_sensitive_data` flips. Fan-out:
  `Finding.objects.filter(workload__namespace=N)`.
- **On cluster environment change** — admin flips `environment_is_manual`.
  Fan-out: `Finding.objects.filter(workload__namespace__cluster=C)`.

Each trigger calls `recompute_batch(findings_in_scope)` — one query
pass loads relations, loops calling `score(finding)` in memory, bulk
updates `effective_priority`.

## Worked examples

`fixed_version` is captured and displayed but is **not** an input to `score()` — it does not appear as a column here.

| CVE severity | EPSS% | KEV | Env | Exposed | Signals | Sensitive | Priority |
|---|---|---|---|---|---|---|---|
| _supply-chain match_ | n/a | n/a | _any_ | _any_ | _any_ | _any_ | **Immediate** (supply-chain) |
| Critical | 0.95 | no | prod | yes | — | — | **Immediate** |
| Critical | 0.4 | yes | dev | no | — | — | **Immediate** (KEV) |
| High | 0.92 | no | prod | no | `kyverno:disallow-privileged-containers` | — | **OutOfCycle** (prod + escalation) |
| Critical | 0.3 | no | prod | no | — | — | **OutOfCycle** |
| Critical | 0.3 | no | dev | no | — | yes | **OutOfCycle** (critical + sensitive-ns, any env) |
| High | 0.92 | no | dev | no | — | — | **Scheduled** (EPSS≥0.9, env-agnostic active exploit) |
| Medium | 0.4 | no | prod | no | `kyverno:disallow-host-namespaces` | — | **OutOfCycle** (medium + prod + escalation pivot path) |
| High | 0.5 | no | non-prod | yes | — | — | **Scheduled** (severity + exposed-or-escalation) |
| Medium | 0.4 | no | prod | no | — | yes | **Scheduled** (sensitive-ns) |
| Low | 0.1 | no | dev | no | — | no | **Defer** |

## Display notes

- The UI shows the band plus the reason chain that produced it
  ("Immediate: KEV + exposed + prod"). Reasons come straight from the
  `PriorityResult.reasons` tuple. Signal-based reasons include the
  registry ID so the user can click through to the underlying
  PolicyReport / AVD check.
- An active `FindingAction` overlays the displayed state (Accepted /
  FalsePositive / Acknowledged / Scheduled) but the computed band
  stays visible for audit — so a reviewer can see both "the system
  thinks this is Immediate" and "someone accepted it until 2026-06-01."

## Three remediation paths

The three paths surfaced on the Finding detail screen
(see [01-overview.md](01-overview.md) and [08-ui.md](08-ui.md)) each
affect the priority differently:

| Path | Mechanism | How priority changes |
|---|---|---|
| **Fix** | Deploy a new image without the finding. | Old image's `deployed` flips False at the next inventory reap; finding drops out of default views entirely (no recompute — it's filtered out). |
| **Remediate** | Change the workload's config so observed `WorkloadSignal` rows flip `currently_active=false`. | Signal-change recompute reruns `compute_priority`; band drops. The CVE is still there, just ranks lower. |
| **Accept** | Create a `FindingAction` row. | No change to `effective_priority`. The action's state overlays the display; the band stays computed so revocation immediately restores the true rank. |

## Cross-references

- Signal registry: [06-signals.md](06-signals.md) — authoritative list
  of signal IDs consumed here.
- Enrichment values: [05-enrichment.md](05-enrichment.md)
- How the band surfaces in the UI: [08-ui.md](08-ui.md)
