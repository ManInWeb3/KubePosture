# KubePosture Documentation

## Architecture

- [Urgency Decision Tree](urgency-decision-tree.md) — the `score()` function spec: priority bands, decision branches, recompute triggers, default-handling rules, and the editable scoring contract.
- [SSVC Mapping](ssvc-mapping.md) — KubePosture's mapping to SSVC v2.0: which decision points are implemented, which are approximated, where the tool deviates from the spec, and how to read priority labels correctly.

## Operations

- [Handling Vulnerable Images](operations/handling-vulnerable-images.md) — playbook for responding to `Immediate` / `Out-of-Cycle` findings, split between **internally-developed apps** (patch source, redeploy) and **third-party images** (the 5-step deployer funnel: VEX → exposure recheck → compensating control → hardened-base swap → time-boxed risk acceptance).

## Related (at repo root)

- [CLAUDE.md](../CLAUDE.md) — repo conventions, scanner stack, data model overview, design rules.
- [README.md](../README.md) — project overview.
