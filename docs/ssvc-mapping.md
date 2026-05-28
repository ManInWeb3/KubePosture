# Kubernetes workload vulnerability prioritization (SSVC-inspired)

How KubePosture's priority engine maps to the [Stakeholder-Specific Vulnerability Categorization (SSVC) v2.0](https://www.sei.cmu.edu/documents/606/2021_019_001_653461.pdf) framework from Carnegie Mellon SEI.

This document is for security engineers who already know SSVC and want to understand:
- Which SSVC stakeholder role KubePosture implements.
- How each KubePosture input maps to an SSVC decision point.
- What SSVC inputs are missing, approximated, or replaced — so you can read priority labels correctly and decide where to layer in your own context.

---

## 1. Quick reference

| KubePosture concept | SSVC equivalent |
|---|---|
| Stakeholder role | **Deployer** (you run the software, you don't ship the patch) |
| `Finding.effective_priority` | SSVC deployer outcome |
| `immediate` / `out_of_band` / `scheduled` / `defer` | `Immediate` / `Out-of-cycle` / `Scheduled` / `Defer` |
| `core/urgency.py: score()` | The deployer decision tree (Figure 2 of the SSVC paper) |
| `WorkloadSignal` rows | KubePosture-specific extension — *not* part of SSVC |

KubePosture targets the SSVC **deployer** tree only. Supplier and Coordinator trees are out of scope: KubePosture does not produce patches and does not coordinate disclosures.

---

## 2. SSVC deployer tree at a glance

The SSVC deployer tree uses four decision points:

1. **Exploitation** — `none` / `PoC` / `active`
2. **System Exposure** — `small` / `controlled` / `open`
3. **Utility** = `Automatable` (yes/no) × `Value Density` (diffuse/concentrated) → `laborious` / `efficient` / `super effective`
4. **Human Impact** = `Situated Safety Impact` × `Mission Impact` → `low` / `medium` / `high` / `very high`

Outcomes: **Defer**, **Scheduled**, **Out-of-cycle**, **Immediate**.

The first two factors are largely automatable from cluster state. The last two normally require human input from workload owners, compliance, and business stakeholders.

---

## 3. Decision-point mapping

### 3.1 Exploitation → KEV + EPSS

| SSVC value | KubePosture rule |
|---|---|
| `active` | `Finding.kev_listed = true` (CISA KEV catalog match) |
| `PoC` | Approximated by `Finding.epss_percentile >= 0.9` |
| `none` | Everything else |

Sources of truth:
- KEV: `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json` — fetched daily by `core/services/enrichment.py`.
- EPSS: `https://epss.cyentia.com/epss_scores-current.csv.gz` — fetched daily; `epss_percentile` cached on each `Finding`.

KubePosture rule: **KEV match short-circuits to `Immediate`** regardless of all other inputs. This is stricter than SSVC, which still considers Mission/Safety even with `active` exploitation.

A second, even-higher-precedence short-circuit applies to **supply-chain
IoC matches** (`Category.SUPPLY_CHAIN`, produced by the matcher in
`core/services/supply_chain_matcher.py` when a deployed `SbomComponent.purl`
matches a `SupplyChainIoc.purl` from the OSV.dev feed). Any match
unconditionally resolves to `Immediate` with reason `("supply-chain",)`
— see [urgency-decision-tree.md §Supply-chain short-circuit](urgency-decision-tree.md#supply-chain-short-circuit).
This is stricter than SSVC too: SSVC has no decision point for
"the artifact itself is attacker-supplied," because SSVC assumes the
vulnerability is in legitimate code. Malicious-publish events
(Shai-Hulud, `ctx`, `ua-parser-js`) sit outside SSVC's frame, so the
mapping table below doesn't capture them — they're handled by the
short-circuit before any SSVC-derived branch runs.

EPSS≥0.9 promotes the finding regardless of environment: prod findings escalate to `OutOfCycle` (`("EPSS>=0.9","prod")`), non-prod Critical/High findings escalate to `Scheduled` (`("EPSS>=0.9","dev"|"staging")`). Active in-the-wild exploitation isn't bounded by env, even though the band is softened outside prod.

**Read this priority correctly:**
- KubePosture conflates "high exploitation likelihood" (EPSS — a forecast) with SSVC's `PoC` (an *observed* artifact). A vulnerability with public PoC code on GitHub but no EPSS signal will read as `none` here.
- There is no scrape of Metasploit / ExploitDB / GitHub PoC repositories.

### 3.2 System Exposure → `publicly_exposed`

| SSVC value | KubePosture rule |
|---|---|
| `open` | `Workload.publicly_exposed = true` OR `Namespace.internet_exposed = true` |
| `controlled` | Everything else (default semantics — cluster-network-reachable, not isolated) |
| `small` | Not detected in v1; reserved for a future lane requiring deny-all NetPol + no listening port |

The False bucket is now formally `controlled` rather than collapsed `small`/`controlled`. The decision tree's non-exposed branches (`critical + prod` → OOB, `C/H + (exposed-or-escalation)` → SCHEDULED, etc.) operate as if every non-`open` workload is reachable from elsewhere on the cluster network — which it is, by default Kubernetes flat-network semantics, unless explicitly fenced with NetworkPolicy.

`publicly_exposed` is auto-derived during inventory ingest (`core/parsers/inventory.py`):
- True iff a non-internal `LoadBalancer` Service OR a non-internal `Ingress` selects the workload.
- "Non-internal" is detected via cloud annotations (`service.beta.kubernetes.io/aws-load-balancer-internal`, `networking.gke.io/load-balancer-type=Internal`, `service.beta.kubernetes.io/azure-load-balancer-internal`) and ingress class names containing `internal`/`private`. Operators can list additional class names via the `INTERNAL_INGRESS_CLASSES` env var (CSV, case-insensitive exact match — useful for IAP-style classes like `pomerium`).
- Admin override: `publicly_exposed_is_manual` (Workload) and `exposure_is_manual` (Namespace).

`Namespace.internet_exposed` is an OR-rollup over all its workloads.

**Read this priority correctly:** the following are NOT treated as exposed:
- `NodePort` services (a `kp:has-nodeport-service` signal is recorded but is not consulted by `score()`).
- Pods with `hostNetwork=true`.
- Public Kubernetes API server endpoints.
- Workloads reachable via partner VPN/VPC peering.
- Namespaces with no `NetworkPolicy` (recorded as `kp:missing-networkpolicy` signal but not consulted).

If your cluster relies on any of the above for exposure characterisation, KubePosture under-prioritises those workloads relative to SSVC.

### 3.3 Utility → not implemented

There is no `Automatable`, `Value Density`, or `Utility` field on any KubePosture model.

What this means in practice:
- A vault server holding KMS-bound secrets and a stateless echo service get the same Utility input.
- ServiceAccount RBAC scope is captured (`KSV-0051` cluster-admin bind, `KSV-0044` wildcard verb, `KSV-0041` cluster-wide secrets) but only as escalation signals — they do not raise `Value Density`.
- Workload kind (database, IdP, registry, CI controller) is not used.
- Mounted Secret count, PV size, multi-tenancy state are not used.

**Read this priority correctly:** treat KubePosture priorities as Utility-blind. A genuine "super effective" target (high Value Density + Automatable) will not surface differently from a low-value target on the same vulnerability unless other axes happen to fire.

### 3.4 Human Impact → environment + sensitivity flag

KubePosture splits the SSVC Human Impact axis into two coarse boolean-ish inputs:

**Mission Impact proxy: `Cluster.environment`**
- Values: `prod` / `staging` / `dev`.
- Auto-detected from a regex on the cluster name (e.g. `prod`, `production`, `stag`, `staging`, `dev`, `test`, `qa`, `sandbox`).
- Cluster names that match no pattern default to **`dev`** — a silent demotion.
- Admin override: `environment_is_manual = true`.

This is a **3-bucket flat proxy** for SSVC's 4-level Mission Impact (`None/Degraded/Crippled` → `MEF Failure` → `Mission Failure`). MEF (Mission Essential Function) classification is not represented.

**Situated Safety Impact proxy: `Namespace.contains_sensitive_data`**
- Single boolean.
- Set by namespace label/annotation `posture.io/contains-sensitive-data=true`, or admin toggle.
- Admin override: `sensitive_is_manual = true`.

This is a **single boolean** for SSVC's 5-level Safety Impact (`None / Minor / Major / Hazardous / Catastrophic`) and four harm types (Physical / Environmental / Financial / Psychological).

**Read this priority correctly:**
- A namespace handling PHI in a regulated production cluster, and a namespace running internal log dashboards in the same cluster, both inherit the same `environment=prod`. The `contains_sensitive_data` flag is the only differentiator and only if someone set the label.
- The SSVC combined `Human Impact` matrix (Table 12 of the paper) is replaced by a flat sequence of `if`-branches that do not produce the same outcome distribution.
- Critical findings in a sensitive-data namespace now route to `OutOfCycle` regardless of environment (reason `("critical","sensitive-ns")`), not just SCHEDULED. The sensitivity flag therefore meaningfully promotes Critical, where previously it only affected High/Medium. A Critical CVE in a `posture.io/contains-sensitive-data=true` dev namespace is treated more aggressively than a Critical CVE in a non-sensitive dev namespace.

---

## 4. KubePosture-specific factors (no SSVC counterpart)

These inputs influence priority in KubePosture but are not part of SSVC:

### 4.1 Co-resident escalation signals (`WorkloadSignal`)

If the same workload that hosts the vulnerability also has *active* configuration weaknesses, KubePosture bumps priority. The categories that the scorer reads:

| Category | Examples |
|---|---|
| `HOST_ESCAPE` | privileged container, hostPath mount, hostNetwork/PID/IPC |
| `RBAC_ELEVATION` | SA bound to cluster-admin, Role grants pods/exec, wildcard verb, cluster-wide secrets |
| `PRIV_ESCALATION` | `allowPrivilegeEscalation=true`, risky Linux capability added |

Sources: Kyverno PolicyReports + Trivy KSV-* checks. Signal registry in `core/signals.py`.

This is a **posture-attack-path overlay** on top of vulnerability priority. SSVC handles vulnerabilities only; if a workload is misconfigured *and* hosts a CVE, SSVC's deployer tree does not couple them. KubePosture does.

Medium-severity findings on prod workloads that carry an active escalation signal route to `OutOfCycle` (reason `("medium","prod","escalation-signal")`), aligning Medium-with-pivot-path closer to High treatment. The combination represents a real production pivot path — a Medium CVE plus a host-escape primitive on the same workload is operationally equivalent to a High CVE without the primitive.

### 4.2 `has_fix` (remediation availability) — captured but not scored

`Finding.fixed_version` is extracted from the scanner and rendered on the finding detail page as informational context ("Fixed in 1.2.3"), but it does **not** influence `effective_priority`. An earlier version of the scorer used it to deprioritise unfixable findings; that input was removed for two reasons:

1. SSVC explicitly assigns remediation availability to the *supplier* tree, not the deployer tree. KubePosture targets the deployer tree, so consuming `has_fix` here was a cross-tree leak.
2. KubePosture is built for image-based, GitOps-managed clusters where the unit of change is the image, not the package. When the image is rebuilt, every package upgrades together — so whether one specific CVE has a published fix is rarely the gating signal for a deployer's reaction. The field is also unevenly populated by scanners across non-OS package ecosystems, which made it a noisy input.

### 4.3 Cluster-scoped cap

Findings with `workload IS NULL` (e.g. a ClusterRole RBAC issue) are capped at `out_of_band` — never `immediate` — because there is no workload context to reason about. This is a KubePosture-specific safety rail.

---

## 5. Stakeholder inputs and how they enter the system

SSVC assumes inputs from multiple human stakeholders. KubePosture exposes these as overrideable fields:

| SSVC stakeholder role | What they should provide | KubePosture surface |
|---|---|---|
| Threat-intel feed | Exploitation evidence | Automatic (KEV + EPSS daily refresh) |
| Cluster operator / Platform SRE | Exposure, environment | Automatic (inventory parser) + admin overrides for `publicly_exposed`, `environment` |
| Workload owner | Mission essentiality, Value Density | **No native field** — the only proxy is the namespace `contains_sensitive_data` flag, which is set by the cluster operator, not the workload owner |
| Product / Business owner | Service tier | **Not represented** |
| Compliance / Legal / DPO | Regulated data classification | The single `contains_sensitive_data` boolean. No PHI/PCI/GDPR distinction |
| CISO / Security leadership | Risk appetite (per-branch labels) | **Not configurable** — outcome labels are hard-coded in `score()` |

Practical consequence: KubePosture's priority is calibrated by Platform/SRE inputs and external threat intel. Workload owners and compliance signal must be encoded ahead of time as namespace labels (`posture.io/contains-sensitive-data`) — there is no per-workload criticality or per-workload owner attestation channel.

---

## 6. Reading a KubePosture priority — what's behind it

Each `Finding.effective_priority` is computed by `core/urgency.py: score()` and stamped on the row. The function returns a `PriorityResult` whose `reasons` tuple lists the branches that fired. You can read the rationale in three ways:

1. **API**: `GET /api/v1/findings/<id>` returns `effective_priority` plus, in v0.3.x, the reason tuple in the serializer.
2. **UI**: the workload detail page surfaces the reasons.
3. **DB**: `core_finding.effective_priority` column.

Reason tuples to expect:
- `("supply-chain",)` → supply-chain IoC match (OSV malicious-publish feed), short-circuited to `immediate`. Outside SSVC's frame; see §3.1.
- `("KEV",)` → KEV match, short-circuited to `immediate`.
- `("severity","EPSS>=0.9","exposed","prod")` → top-of-tree branch.
- `("critical","exposed","prod")`, `("high","exposed","prod")` → severity-driven prod branches.
- `("critical","sensitive-ns")` → Critical CVE in a sensitive-data namespace; `OutOfCycle` regardless of env.
- `("severity","prod","escalation-signal")` → the escalation-overlay branch (Critical/High in prod).
- `("EPSS>=0.9","prod")` → high-EPSS finding in prod; `OutOfCycle`.
- `("EPSS>=0.9","dev")` / `("EPSS>=0.9","staging")` → high-EPSS Critical/High finding outside prod; `Scheduled`.
- `("severity","sensitive-ns")` → sensitive-namespace bump for medium/high.
- `("severity","exposed-or-escalation")` → non-prod high/critical with exposure or escalation.
- `("medium","prod","escalation-signal")` → Medium prod finding with active escalation signal; `OutOfCycle` (was Scheduled before the SSVC tightening).
- `("default",)` → bottom of tree (Defer).

---

## 7. Limitations to keep in mind when consuming priorities

1. **Severity is the primary discriminator.** SSVC explicitly removes technical severity from the deployer tree. KubePosture re-introduces it (CRITICAL/HIGH gates most prod branches). Vulnerabilities with low CVSS but high exploit utility may under-prioritise.
2. **Exposure is detected as 2-state (`open` vs `controlled`).** The False bucket is treated as `controlled` (cluster-network-reachable), not isolated. The `small` band — workloads provably isolated by deny-all NetPol with no listening port — is not detected; treat all non-`open` workloads as `controlled`.
3. **Utility is absent.** Concentrated targets (databases, IdPs, secrets stores) are not surfaced unless they happen to also be exposed and host a CRITICAL.
4. **Mission/Safety is two booleans-and-an-enum, not a 4-level matrix.** Combined Human Impact (paper Table 12) is not implemented.
5. **EPSS substitutes for Exploitation PoC.** A predictive percentile is treated as if it were observed exploit code.
6. **Cluster-name regex sets environment.** Misnamed clusters silently default to `dev`. Always set `Cluster.environment_is_manual` for production clusters whose name doesn't match the regex.
7. **Risk appetite is not tunable.** Outcome labels are hard-coded; teams that need different defer/scheduled/immediate cutoffs must edit `core/urgency.py`.
8. **No workload-owner channel.** Workload criticality is encoded only at the namespace level via one label.

---

## 8. Coverage matrix

| SSVC deployer factor | KubePosture coverage | Where it lives in code |
|---|---|---|
| Exploitation (3-state) | Partial (KEV + EPSS≥0.9 proxies) | `Finding.kev_listed`, `Finding.epss_percentile` |
| System Exposure (3-state) | Partial (2-state: `open` / `controlled`; `small` not detected) | `Workload.publicly_exposed`, `Namespace.internet_exposed` |
| Utility / Automatable | Not implemented | — |
| Utility / Value Density | Not implemented | — |
| Mission Impact (4-level) | Proxied (3-bucket env) | `Cluster.environment` |
| Situated Safety Impact (5-level × 4 harm types) | Proxied (1 boolean) | `Namespace.contains_sensitive_data` |
| Combined Human Impact matrix | Not implemented | — |
| Risk-appetite tuning | Not configurable | hard-coded labels in `core/urgency.py` |
| Workload-owner attestation | Not implemented | — |
| Remediation availability (extra) | Not used in scoring (informational only) | `Finding.fixed_version` rendered on the finding detail page |
| Co-resident misconfig posture (extra) | Present | `WorkloadSignal` + `core/signals.py` |
| Cluster-scoped finding cap (extra) | Present | `core/urgency.py` workload-null branch |

---

## 9. Conformance to SSVC

**Short answer: SSVC-*inspired*, not SSVC-*conformant*.** KubePosture honors the philosophy but deviates from the specification in concrete ways.

### 9.1 What conforms (the philosophy)

- Qualitative decision tree, not a numeric score. `core/urgency.py: score()` is a tree of `if`-branches, not arithmetic on CVSS.
- Deployer-role focus. Outcomes are the SSVC deployer set (`immediate / out_of_band / scheduled / defer`) with deployer-style semantics.
- Per-deployment context, not per-CVE. Each `Finding` is per-`(workload, image)`; the same CVE in two clusters gets two priorities.
- Qualitative inputs, qualitative outputs.
- Auto-resolve and reopen lifecycle. SSVC says remediated environments must be continually monitored for vulnerabilities reintroduced by rollbacks — the import-mark reaper does this.

### 9.2 What does not conform (the specification)

The SSVC paper allows customizing *which* decision points and outcome labels you use (§Tree Construction, page 36), but explicitly says decision points, their definitions, and the decision values should not be customized. KubePosture crosses that line in several places.

#### 1. Severity is the primary discriminator — SSVC explicitly removes it from the deployer tree
SSVC paper, page 4: *"Severity should only be a part of vulnerability response prioritization."* The deployer tree (Figure 2) has no severity node — it uses Exploitation × Exposure × Utility × Human Impact. KubePosture gates most branches on `severity in (CRITICAL, HIGH)` *first* ([core/urgency.py:100-176](core/urgency.py#L100-L176)). This is the same CVSS-driven mindset SSVC was designed to replace.

#### 2. Two SSVC decision points are missing entirely
- **Utility (Automatable × Value Density):** no field, no logic, no proxy. The SSVC paper makes Utility one of four required deployer inputs.
- **Combined Human Impact matrix (Table 12):** replaced by ad-hoc `if`-branches over `environment` and `contains_sensitive_data`.

#### 3. Two decision points are collapsed below SSVC's required resolution
- **Exploitation:** SSVC defines 3 states (`none/PoC/active`); KubePosture has effectively 2 (`KEV` and `EPSS≥0.9`). PoC observation (Metasploit / ExploitDB / GitHub PoC) is not collected.
- **System Exposure:** SSVC defines 3 states (`small/controlled/open`); KubePosture detects 2 of 3 (`open` is the True bucket; `controlled` is the documented default for non-`open` workloads, applied throughout the decision tree). `small` — workloads provably isolated — is not detected.

#### 4. Non-SSVC inputs influence the outcome
- Co-resident `WorkloadSignal` posture — SSVC's deployer tree is per-vulnerability; KubePosture couples vulnerability priority with workload misconfiguration posture.
- **KEV short-circuit to `immediate`** ([urgency.py:63](core/urgency.py#L63)) — SSVC keeps Mission/Safety in the path even when Exploitation is `active`. KubePosture overrides this.

#### 5. EPSS is treated as an Exploitation observation
SSVC paper, page 17: *"Predictive systems, such as EPSS, could be used to augment this decision or to notify stakeholders of likely changes."* EPSS is not Exploitation itself. KubePosture uses `epss_percentile >= 0.9` directly as a priority gate — a category error SSVC explicitly warns about.

#### 6. Risk appetite is tunable in code, not via UI — intentional
SSVC, page 36: *"a team's risk appetite is reflected directly by the priority labels for each combination of decision values."* KubePosture hard-codes the labels in `score()`.

**This is an intentional design decision.** A UI flexible enough to safely adjust a multi-branch decision tree is difficult to build well: it has to expose every branch, prevent inconsistent label assignments, and stay legible as the tree grows. The chosen alternative is to keep the tree in code at [core/urgency.py](core/urgency.py) and adjust it there. Teams that need different defer / scheduled / out-of-band / immediate cutoffs — higher vulnerability-risk aversion, lower change-risk aversion, sector-specific priorities — edit branches directly. Code-level tuning is more expressive than typical UI tuning; the cost is that the configuration surface lives with developers, not operators.

### 9.3 Verdict table

| Conformance level | KubePosture |
|---|---|
| Same outcome enum | Yes |
| Same role focus (deployer) | Yes |
| Same formalism (qualitative tree) | Yes |
| Same decision points | No — Utility missing, Human Impact replaced |
| Same decision-point definitions | No — Exploitation and Exposure collapsed |
| Same role of severity | No — re-introduced as primary axis |
| Per-team outcome-label tuning | Yes, code-level (intentional) |
| Tree-publishable in canonical SSVC CSV/JSON | No — would not validate |

### 9.4 Honest framing

KubePosture is a Kubernetes-tailored, SSVC-inspired priority engine. Calling it "SSVC" without qualification overclaims — a security engineer expecting to import a canonical SSVC tree, customise labels via the published CSV format, and reproduce the canonical deployer-tree outcomes will be surprised. "SSVC-aligned" or "uses SSVC-style outcome labels and decision-tree formalism, with Kubernetes-specific decision points" is accurate.

### 9.5 If tighter conformance becomes a goal — fixes ordered by payoff

1. **Add the `small` Exposure state.** Detect workloads that are provably isolated — deny-all NetworkPolicy covering the namespace AND no listening container port — and demote findings on them by one band. Today every non-`open` workload is treated as `controlled`; this would let truly isolated workloads (e.g. batch CronJobs with no listener behind a default-deny netpol) drop further.
2. **Add `Automatable` and `Value Density` fields.** Initial heuristics could derive from workload kind + RBAC scope + mounted-secret count.
3. **Demote severity from primary gate to tiebreaker.** Put Mission/Safety back on the active-exploit path instead of letting KEV short-circuit them.
4. **(Lower priority — see §9.2 point 6.)** If a config-level surface becomes worth the cost, the smallest viable shape is exposing per-branch outcome labels (not the tree shape) via a YAML overlay loaded at startup, so operators can shift defer↔scheduled↔out-of-band↔immediate cutoffs without editing Python.

---

## 10. Further reading

- `core/urgency.py` — the actual decision tree.
- `core/signals.py` — registry of all `WorkloadSignal` IDs and categories.
- `core/services/enrichment.py` — KEV and EPSS ingest.
- `core/parsers/inventory.py` — environment regex, exposure derivation, sensitivity-label parsing.
- SSVC v2.0 paper: https://www.sei.cmu.edu/documents/606/2021_019_001_653461.pdf
