# KubePosture Documentation

## Architecture

- [Urgency Decision Tree](urgency-decision-tree.md) — the `score()` function spec: priority bands, decision branches, recompute triggers, default-handling rules, and the editable scoring contract.
- [SSVC Mapping](ssvc-mapping.md) — KubePosture's mapping to SSVC v2.0: which decision points are implemented, which are approximated, where the tool deviates from the spec, and how to read priority labels correctly.

## Operations

- [Triaging High-Priority Findings](operations/triage-high-priority-findings.md) — first 30–60 minute runbook when an `Immediate` / `Out-of-Cycle` finding lands. Validate the finding is real, recheck exposure attribution, run the manual applicability check, and deploy short-term mitigations (NetworkPolicy, PodSecurity tightening, WAF rule, ServiceAccount scope reduction) to shrink blast radius before the source fix lands.
- [Handling Vulnerable Images](operations/handling-vulnerable-images.md) — image-level remediation playbook, split between **internally-developed apps** (patch source, redeploy) and **third-party images** (the 5-step deployer funnel: applicability check → exposure recheck → compensating control → hardened-base swap → time-boxed risk acceptance). Includes `gh` / OSV / cosign commands for looking up applicability against GHSA, OSV.dev, and Chainguard VEX feeds.

## Related (at repo root)

- [CLAUDE.md](../CLAUDE.md) — repo conventions, scanner stack, data model overview, design rules.
- [README.md](../README.md) — project overview.
