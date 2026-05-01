# Handling Vulnerable Images

How to respond when KubePosture flags an `Immediate` or `Out-of-Cycle` finding on a container image. The correct action depends on whether **you control the source code** of the affected image.

KubePosture is an SSVC-style **deployer-tree** tool — it tells you a finding is high priority, but it doesn't decide whether you fix the source, swap the image, accept the risk, or do something else. This guide is the operator-side flow.

> **First 30–60 minutes:** if you're triaging a fresh `Immediate` / `Out-of-Cycle` finding, run [triage-high-priority-findings.md](triage-high-priority-findings.md) first — validate the finding, recheck exposure attribution, deploy short-term mitigations (NetworkPolicy, PodSecurity, WAF). Once the blast radius is contained, this doc covers the source-level remediation path.

## TL;DR

| Image type | Primary action |
|---|---|
| **Internally-developed app** (you wrote it / you own the source) | Patch the source, rebuild, redeploy. The finding auto-resolves at the next inventory cycle. |
| **Third-party app** (Pomerium, Postgres, Argo CD, Trivy itself, anything from Docker Hub / vendor registries) | Walk the deployer funnel: applicability check → exposure recheck → compensating control → hardened-base swap → time-boxed risk acceptance. You typically do NOT fork the upstream project. |

The two flows differ because for internal apps you're both the **supplier** and the **deployer** in SSVC terms; for third-party apps you're only the deployer, and the supplier side of the workflow is out of your hands.

---

## Flow 1 — Internally-developed apps

You wrote the code, you own the Dockerfile, you push the image to your registry. The fix lives in your source tree.

### 1. Identify the source of the CVE

Trivy will tell you whether the CVE is:

- **In the application code** itself — e.g. a deserialization bug in your handler. Patch the function, write a regression test.
- **In a direct dependency** (`go.mod`, `requirements.txt`, `package.json`, `Cargo.toml`, etc.) — bump to a fixed version.
- **In a transitive dependency** — use the manifest's override mechanism:
  - Go: `replace` directive in `go.mod`
  - npm: `overrides` block in `package.json`
  - pip: `constraints.txt` pinning the transitive version
  - Cargo: `[patch]` section
  Then file an issue or PR against the direct dependency to bump its own dependency.
- **In an OS package in the base image** (libssl, glibc, busybox, etc.) — bump the base image tag, or switch to a hardened base (see Flow 2 Step 4 below — the technique applies to your own Dockerfile too).

### 2. Rebuild and redeploy

The Finding is keyed on `(source, title, severity, vuln_id, namespace, resource_kind, resource_name)` and tied to a specific image digest via `WorkloadImageObservation`. New image = new digest = the old observation falls out at the next inventory reap.

The Finding doesn't disappear instantly. The reaper auto-resolves it when the old digest is no longer observed running on any workload.

### 3. Verify the fix landed

- Trigger an out-of-band import: `kubectl create job --from=cronjob/kubeposture-import-<cluster> verify-fix -n kubeposture`
- Check the workload detail page — the finding should move to `RESOLVED`.
- If it doesn't: the new image is using the same digest (cached), or the rollout didn't replace all replicas. Force a deployment restart and re-import.

### 4. Edge case — CVE in your code with no fix yet

If you've discovered a vulnerability in your own code that you don't yet have a fix for, the supplier/deployer roles re-merge: you're a deployer of an unfixable image. Walk Flow 2 below as if it were third-party — applicability check, compensating controls, time-boxed acceptance — until you ship the patch.

---

## Flow 2 — Third-party images

The 5-step deployer funnel. Walk it in order; only fall through to the next step when the previous one doesn't apply.

### Step 1 — Applicability check

The most common reason a third-party CVE doesn't actually matter: you don't use the affected feature. Check that before reaching for any other tool — applicability triage clears roughly half the IMMEDIATE-band findings on big projects (Postgres, Nginx, Pomerium, Argo CD, Trivy itself).

**KubePosture does not yet ingest VEX statements.** Applicability checks are manual: you look up the CVE in upstream sources, decide whether it applies to your config, and if not, record the finding as **False Positive** with the justification in the reason field. The band stays computed for audit; the finding moves out of default views.

#### Where to look (ordered by signal quality)

**1. The project's GitHub Security Advisories (GHSA).** The primary source for applicability conditions on most OSS projects. Each advisory typically includes affected version ranges and a `description` that names the affected feature.

```bash
# List advisories for a repo
gh api repos/<owner>/<repo>/security-advisories --paginate \
  | jq -r '.[] | "\(.ghsa_id) \(.severity) \(.cve_id // "no-CVE") - \(.summary)"'

# Get applicability detail for one advisory
gh api repos/<owner>/<repo>/security-advisories/GHSA-xxxx-yyyy-zzzz \
  | jq '{cve_id, severity, summary, description, vulnerabilities}'
```

Examples: `pomerium/pomerium`, `argoproj/argo-cd`, `postgres/postgres`, `aquasecurity/trivy`.

**2. OSV.dev — fast machine-readable aggregator.** OSV ingests GHSA + Go vuln DB + npm + PyPI advisories. Best for "is version X affected by CVE Y" questions:

```bash
# All vulns affecting the current version of an OSS project
curl -sX POST https://api.osv.dev/v1/query \
  -H 'Content-Type: application/json' \
  -d '{"package":{"name":"github.com/pomerium/pomerium","ecosystem":"Go"},"version":"0.27.0"}' \
  | jq '.vulns[] | {id, summary}'
```

Ecosystems to know: `Go`, `npm`, `PyPI`, `Maven`, `crates.io`, `Debian`, `Alpine`, `OSS-Fuzz`.

**3. Chainguard's VEX feed** — when you run a `cgr.dev/chainguard/<image>`. Chainguard publishes proper OpenVEX statements as cosign attestations:

```bash
cosign download attestation cgr.dev/chainguard/pomerium:latest \
  --predicate-type https://openvex.dev/ns/v0.2.0 \
  | jq -r '.payload | @base64d | fromjson'
```

Each statement carries `status: not_affected | affected | fixed | under_investigation` plus an OpenVEX justification. This is the only source on this list that's actually authored *as VEX*; everything else is GHSA/OSV data that needs interpretation.

**4. The CVE write-up itself** — NVD / cve.org. Often light on applicability detail but worth a read; usually cross-links back to GHSA.

#### Worked example — Pomerium

A scanner reports `CVE-2025-XXXXX` IMMEDIATE on `pomerium/pomerium:0.27.0`.

```bash
# Step a — find the GHSA for this CVE
gh api repos/pomerium/pomerium/security-advisories --paginate \
  | jq -r '.[] | select(.cve_id=="CVE-2025-XXXXX") | .ghsa_id'

# Step b — read the applicability detail
gh api repos/pomerium/pomerium/security-advisories/GHSA-xxxx-yyyy-zzzz \
  | jq -r '.description'
```

The description says the bug is in the Okta IdP backend. Your config uses `idp_provider: google`. Conclusion: `not_affected`. Record on the finding:

- **Action type:** False Positive
- **Reason:** `not_affected — vulnerable_code_not_in_execute_path. Okta IdP backend disabled (idp_provider: google in pomerium-config).`

The OpenVEX justification taxonomy is the right vocabulary to borrow, even without a real VEX field — it forces precision and translates cleanly the day this becomes a system feature:

- `component_not_present` — the vulnerable component isn't in the image at all.
- `vulnerable_code_not_present` — present but not built in.
- `vulnerable_code_not_in_execute_path` — present but never reached at runtime (most common).
- `vulnerable_code_cannot_be_controlled_by_adversary` — reachable but inputs are sanitized upstream.
- `inline_mitigations_already_exist` — a config or compensating control neutralizes the bug.

> **Future:** ingesting OpenVEX / GHSA statements automatically and short-circuiting to `Defer` is a planned feature. It is not implemented today; the Finding model has no `vex_status` field. Track applicability decisions via False Positive actions until that lands.

### Step 2 — Recheck network exposure attribution

Not every component of a third-party deployment is internet-reachable. A CVE on a non-`open` component shouldn't trigger the IMMEDIATE band — verify the per-workload exposure flag is correct.

| App | `open` workloads | `controlled` workloads |
|---|---|---|
| Pomerium | `pomerium-proxy` | `pomerium-authorize`, `pomerium-databroker` |
| Argo CD | `argocd-server` (when ingressed) | `argocd-repo-server`, `argocd-application-controller`, `argocd-redis` |
| Vault | `vault` (when ingressed) | `vault-agent-injector` |
| Most databases | none (they should not be ingressed) | `postgres`, `redis`, `clickhouse`, … |

If KubePosture is showing IMMEDIATE on a controlled-only component, the per-workload `publicly_exposed` flag may have been incorrectly rolled up from the namespace. Manual override is on the workload detail page.

### Step 3 — Compensating control

Before swapping the image, check whether you can reduce exploitability without changing the binary:

- **WAF rule** (Cloud Armor, AWS WAF, ModSecurity) blocking the attack vector.
- **NetworkPolicy** restricting which pods can reach the vulnerable component.
- **Feature flag** in the third-party app's config that disables the vulnerable component.
- **Capability drop / read-only root filesystem / non-root user** — already covered by your Pod Security Standards if you've enforced them.
- **Auth gateway** (e.g. fronting an internal admin UI with Pomerium/IAP) — shifts SSVC Exposure from `open` to `controlled`.
- **Reduced ServiceAccount scope** — limits what an attacker who exploits the CVE can do laterally.

Record the control on the Finding via a `FindingAction` of type `Acknowledged`, with the control noted in the comment. Set a follow-up to verify the control is still in place at the next quarterly review.

This is **not the same as risk acceptance** — a compensating control is a real defense-in-depth measure that materially shifts the SSVC Exposure / Utility axes. Document it as such; it's stronger than an accept.

### Step 4 — Hardened base image swap

If steps 1–3 don't apply and the CVE is in an OS package (Alpine apk, Debian apt, UBI rpm) rather than in the app's own Go/Python/JS code, the standard modern response is to swap the base image. You do NOT fork the upstream app project.

| Hardened registry | Use case |
|---|---|
| **Chainguard** (`cgr.dev/chainguard/<image>`) | First-class rebuilds on Wolfi, daily updates, most popular images covered |
| **Distroless** (`gcr.io/distroless/...`) | Strips the OS layer entirely — kills shell/coreutils CVEs by removing them. Best for compiled binaries (Go, Rust, statically-linked) |
| **Bitnami secure builds** (`docker.io/bitnami/<image>`) | Helm-friendly, common for databases and middleware |
| **Red Hat UBI minimal / micro** | Compliance-friendly, RH support contracts, FIPS-validated builds |
| **Wolfi-based OEM builds** | Same Wolfi base as Chainguard but rebuilt by you or a third party |

Process:

1. Find a hardened equivalent of your image — for Pomerium that's `cgr.dev/chainguard/pomerium`.
2. Update Helm values / Deployment manifest to point at the new registry.
3. Test in a non-prod cluster. Watch for behavioral differences (different libc, different glibc/musl boundaries, different shell-or-no-shell).
4. Roll out to prod. Old findings auto-resolve when the old digest is no longer observed.

The supplier still owns the app code; you're only swapping the OS/base layer. **Most "OS package CVE in a third-party image" findings clear with a base swap** — those are the bulk of the IMMEDIATE-band noise on patched-but-still-flagged third-party images.

### Step 5 — Time-boxed risk acceptance

If steps 1–4 don't apply (real CVE in the app's own code, no hardened build available, no compensating control possible), accept it explicitly:

- Use the Finding risk acceptance form. **Reason and expiry are required** — KubePosture enforces this in the model.
- Expiry should point at a concrete event:
  - The next upstream release date (check the project's release cadence).
  - Your next planned migration milestone.
  - A hard cap of 30 / 60 / 90 days — never indefinite.
- KubePosture surfaces accepted findings on the dashboard with the expiry visible. The computed band stays computed for audit, so revocation immediately restores the priority.

A risk acceptance without an expiry is sweeping it under the rug. The expiry is what makes it accountable. The dashboard alerts on expiring acceptances 7/14/30 days out so they don't quietly elapse.

---

## When the funnel doesn't terminate

If you reach Step 5 repeatedly for the same third-party app, that's a signal — the project is unmaintained, chronically vulnerable, or has misaligned security priorities. Decisions to consider:

- **Replace it** with a maintained alternative.
- **Buy support.** Chainguard, Bitnami, Red Hat all sell hardened-image SLAs.
- **Reduce its scope of access** — smaller ServiceAccount, fewer mounts, narrower NetworkPolicy. Limits the blast radius when (not if) the next CVE drops.
- **Move it from `open` to `controlled` exposure** — front it with an auth gateway. This converts a public-internet IMMEDIATE pipeline into an internal-cluster Out-of-Cycle pipeline and buys you weeks of soak time on every CVE.

---

## Cross-references

- [SSVC priority engine mapping](../ssvc-mapping.md) — how Findings get bucketed into the four bands.
- [Urgency decision tree](../urgency-decision-tree.md) — the `score()` function spec, decision branches, recompute triggers.
- [CLAUDE.md](../../CLAUDE.md) — repo conventions, scanner stack, model overview.
- SSVC v2.0 paper: https://www.sei.cmu.edu/documents/606/2021_019_001_653461.pdf
