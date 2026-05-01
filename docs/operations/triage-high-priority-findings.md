# Triaging High-Priority Findings

A runbook for what to do when a finding lands in **Immediate** or **Out-of-Cycle**. The goal of the first 30–60 minutes is to **validate** the finding and **reduce the blast radius** with short-term mitigations — *before* you start the multi-day image-remediation path. Once the workload is contained, follow [handling-vulnerable-images.md](handling-vulnerable-images.md) for the source-level fix.

## When to use this doc

- A new finding shows up in `Immediate` or `Out-of-Cycle` band.
- You were paged for security on-call.
- You're sweeping the dashboard for stale high-priority findings.

If the finding is in `Scheduled` or `Defer`, this doc is overkill — those go straight to the image-remediation flow at the next sprint cadence.

---

## Step 1 — Read the reason tuple

Open the finding detail page. The `PriorityResult.reasons` tuple is the fastest way to know **which condition is firing** and therefore **which lever drops the band**. KubePosture surfaces this on the page; the source of truth is [`core/urgency.py`](../../core/urgency.py).

| Reason tuple | Levers that drop the band |
|---|---|
| `("KEV",)` | None via context — KEV short-circuits to Immediate. Only applicability (False Positive) or source-fix removes it. |
| `("severity","EPSS>=0.9","exposed","prod")` | Removing exposure → drops one band. Source fix → resolves. |
| `("critical","exposed","prod")` | Removing exposure → drops to Out-of-Cycle. |
| `("severity","prod","escalation-signal")` | Removing the WorkloadSignal (drop caps, drop hostPath, etc.) drops the band. |
| `("EPSS>=0.9","prod")` | EPSS data refresh, source fix, or env reclassification. |
| `("critical","sensitive-ns")` | Source fix only — the sensitivity flag is sticky by design. |
| `("medium","prod","escalation-signal")` | Drop the escalation signal → moves to Defer. |

Knowing which condition fires tells you whether to pull on the **applicability** lever (Step 4), the **exposure** lever (Step 3), the **escalation-signal** lever (Step 5 — PodSecurity), or jump straight to the source fix.

---

## Step 2 — Validate the finding is real

Three quick checks before doing anything operational:

### Is the workload still deployed?

```bash
kubectl get -n <ns> <kind>/<name>
```

If the workload doesn't exist, the inventory reaper will resolve the finding on the next cycle. No action needed — just wait or trigger a manual import.

### Is the underlying data fresh?

EPSS and KEV refresh daily. If the import has been failing or the cluster's `last_seen_at` is stale, EPSS-driven branches may reflect old reality.

```bash
# Force-refresh EPSS / KEV in the central web pod
kubectl exec -n kubeposture deploy/kubeposture-web -- python manage.py enrich_fetch
```

### Is the CVE disputed?

A small fraction of CVEs are filed against generic functionality and disputed by upstream. Check NVD for the `DISPUTED` tag, or the GitHub Security Advisory for `withdrawn: true`.

```bash
gh api repos/<owner>/<repo>/security-advisories \
  | jq '.[] | select(.cve_id=="CVE-2025-XXXXX") | {ghsa_id, withdrawn_at, summary}'
```

If disputed/withdrawn → record as False Positive with the upstream withdrawal as justification. Done.

---

## Step 3 — Validate exposure attribution

The `Immediate` band requires `is_exposed=True` for most reason tuples. The auto-detector is conservative but not perfect — exposure is the most common misclassification.

### Inspect what's actually exposing the workload

```bash
# All Services that select this workload
kubectl get svc -n <ns> -l <selector-key>=<selector-value> -o wide

# All Ingresses pointing at any of the above Services
kubectl get ingress -n <ns> -o yaml | yq '.items[] | select(.spec.rules[].http.paths[].backend.service.name == "<svc-name>")'
```

### Walk through the SSVC exposure check

| Detected as | Real classification | What to do |
|---|---|---|
| External LoadBalancer with public IP, no auth | `open` ✓ | Correctly flagged — proceed to mitigation. |
| Ingress fronted by Pomerium / OAuth2 Proxy / IAP / Cloudflare Access | `controlled` (auth-gated, not internet-open) | The Pomerium-aware detector may not have run yet. Manual override on the workload detail page: `publicly_exposed_is_manual=True, publicly_exposed=False`. Band drops automatically. |
| NodePort on a hardened cluster (firewall blocks node-port range from internet) | `controlled` | Manual override as above. Document the firewall stance in the action reason. |
| `hostNetwork=true` Pod | `controlled` (host firewall applies, but pivot risk is real) | Don't downgrade — the host-network signal already promotes via escalation. |
| Internal LoadBalancer (cloud annotation) | `controlled` | Detector should already classify as not-exposed. If it's flagged True, file a bug. |

### Re-score after override

KubePosture re-runs `score()` automatically on a workload's `publicly_exposed` flip via `recompute_batch`. The finding's band drops within a few seconds of the override.

---

## Step 4 — Applicability check (manual VEX)

KubePosture does not ingest VEX feeds today — applicability is a manual lookup. Full recipes (GHSA / OSV.dev / Chainguard) are in [handling-vulnerable-images.md § Step 1](handling-vulnerable-images.md#step-1--applicability-check).

Short version:

```bash
# 1. Find the GHSA describing applicability
gh api repos/<vendor>/<project>/security-advisories \
  | jq -r '.[] | select(.cve_id=="CVE-XXXX-YYYYY") | .ghsa_id'

# 2. Read the description for affected feature
gh api repos/<vendor>/<project>/security-advisories/GHSA-xxxx-yyyy-zzzz \
  | jq -r '.description'

# 3. Check your config for that feature
```

If the feature isn't enabled in your deployment → record on the finding as **False Positive** with the OpenVEX justification:

- `vulnerable_code_not_in_execute_path` — most common: feature disabled.
- `component_not_present` — the affected library isn't in your image.
- `inline_mitigations_already_exist` — a config option neutralizes the bug.

If applicable: continue.

---

## Step 5 — Deploy short-term mitigations

The fix in upstream + your image rebuild + rollout is typically days. Mitigations land in minutes and shrink the blast radius while the fix is in flight.

Pick the controls that target the actual reason tuple:

### NetworkPolicy — restrict lateral movement

The default Kubernetes network is flat. RCE on workload A means an attacker can reach every other workload's ClusterIP unless NetPol fences them.

**Default-deny ingress for the namespace** (start here if no NetPol exists):

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-ingress
  namespace: <ns>
spec:
  podSelector: {}
  policyTypes:
    - Ingress
```

**Tighten the affected workload specifically** — allow only known callers:

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-frontend-to-vulnerable
  namespace: <ns>
spec:
  podSelector:
    matchLabels:
      app: <vulnerable-workload>
  policyTypes: ["Ingress"]
  ingress:
    - from:
        - podSelector:
            matchLabels:
              app: <known-caller>
      ports:
        - protocol: TCP
          port: 8080
```

**Egress restriction** — if the CVE allows data exfiltration or C2 callback, deny egress to anything but known endpoints:

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: deny-egress-by-default
  namespace: <ns>
spec:
  podSelector:
    matchLabels:
      app: <vulnerable-workload>
  policyTypes: ["Egress"]
  egress:
    - to:
        - namespaceSelector:
            matchLabels:
              kubernetes.io/metadata.name: kube-system
      ports:
        - protocol: UDP
          port: 53
    - to:
        - podSelector:
            matchLabels:
              app: <known-downstream>
```

After applying, the `kp:missing-networkpolicy` signal should drop off the workload in KubePosture (within one inventory cycle).

### PodSecurity — drop privileges

For findings whose reason tuple includes `escalation-signal`, the fastest band drop is removing the escalation. Tighten the pod spec:

```yaml
spec:
  template:
    spec:
      automountServiceAccountToken: false   # if SA isn't used
      containers:
        - name: app
          securityContext:
            runAsNonRoot: true
            runAsUser: 1000
            readOnlyRootFilesystem: true
            allowPrivilegeEscalation: false
            capabilities:
              drop: ["ALL"]
            seccompProfile:
              type: RuntimeDefault
```

Verify after rollout: the workload's signals panel should no longer list `kyverno:disallow-privilege-escalation`, `kyverno:disallow-privileged-containers`, or `kyverno:require-run-as-nonroot`. The reason tuple will lose `escalation-signal` and the band drops one tier.

### WAF / Cloud Armor / ModSecurity rule

If the workload sits behind a cloud LB with WAF or an Ingress controller that supports ModSecurity:

- Push a temporary rule blocking the attack vector (path, method, payload signature). Most CVE write-ups include a payload PoC — convert it to a deny rule.
- Make the rule **time-bounded** (matched to the source-fix ETA) so it's not a permanent technical-debt sink.
- Set log-level high so you see attempted exploitation.
- Note the rule ID on the FindingAction reason.

### App-level feature toggle

Many third-party apps have config flags to disable the affected feature. The vendor's GHSA description usually names the feature. Examples:

- **Pomerium:** `idp_provider`, `routes` allowlist, signing key rotation.
- **Argo CD:** `application.namespaces` scope reduction, dex IdP swap.
- **Trivy:** disable specific scanners (`--scanners vuln,secret` etc.).
- **Postgres:** disable extensions you don't use, restrict roles.

Roll the change, verify behavior, document on FindingAction.

### Reduce ServiceAccount scope

If the CVE could be chained with the workload's RBAC, trim the SA. Today's RBAC is often broader than the workload actually needs — RCE on a wide SA = cluster takeover.

```bash
# What can this SA do today?
kubectl auth can-i --list --as=system:serviceaccount:<ns>:<sa>

# Inspect bindings
kubectl get rolebindings,clusterrolebindings -A \
  -o jsonpath='{range .items[?(@.subjects[*].name=="<sa>")]}{.metadata.namespace}{" "}{.metadata.name}{"\n"}{end}'
```

Drop bindings the workload doesn't use. If you can demote a `cluster-admin` binding to a scoped Role, do it now — this single change can change the SSVC Utility class for the workload from `super effective` to `efficient`.

---

## Step 6 — Plan the source-level fix

Now that the blast radius is contained, decide on the long-term path. See [handling-vulnerable-images.md](handling-vulnerable-images.md):

- **Internally-developed app** → patch source, rebuild, redeploy. ETA hours-to-days.
- **Third-party image** → walk the funnel: hardened-base swap (Chainguard / Distroless) is usually the answer for OS-package CVEs; time-boxed acceptance with expiry for unfixable upstream bugs. ETA hours-to-weeks.

Record the planned remediation date on the FindingAction so the dashboard surfaces it.

---

## Step 7 — Track to closure

- A finding auto-resolves when:
  - The image is no longer observed (new digest deployed) → reaped on next inventory cycle.
  - The underlying WorkloadSignal flips off (e.g. you applied PodSecurity).
  - The exposure flag flips False (e.g. you toggled the manual override).
  - A FindingAction (Accepted / FalsePositive) overlays it (band stays computed for audit; the finding moves out of default views).

- If a finding stays `Immediate` for **>7 days without any FindingAction overlay**, the dashboard surfaces it as a process failure — escalate.

- Re-validate FindingActions quarterly. An "Acknowledged with WAF rule in place" action only holds while the WAF rule is still deployed.

---

## Cross-references

- [Handling Vulnerable Images](handling-vulnerable-images.md) — the source-level remediation funnel (applicability check, exposure recheck, compensating control, hardened base swap, time-boxed acceptance).
- [SSVC Mapping](../ssvc-mapping.md) — how Findings map to SSVC v2.0 decision points and which conformance gaps exist.
- [Urgency Decision Tree](../urgency-decision-tree.md) — full reason-tuple inventory, per-branch logic, recompute trigger map.
