# OSV vulnerability lane

Trivy stays the primary scanner. The OSV lane evaluates the SBOMs we
already store against the OSV.dev advisory data and fills the gaps:
images whose Trivy `VulnerabilityReport` is missing or failed, and new
advisories published between Trivy rescans. It never duplicates a Trivy
finding.

## Measured against Trivy

Offline match of the anonymised real captures (`fixtures/real`,
2026-10-14) vs their Trivy reports, same images, advisories published
on/before the capture, aliases collapsed
(`tests/realdata/test_osv_parity.py`, pinned in
`fixtures/osv/realdata/parity.json`):

| capture | found by both | OSV only | Trivy only |
|---|---|---|---|
| cluster-a (27 images) | 1,711 | 54 | 0 |
| cluster-b (19 images) | 2,082 | 63 | 0 |

OSV adds ≈3 % on images Trivy did scan (mostly very recent Go
advisories) and misses nothing Trivy finds on language packages. In
cluster-a's capture 629 `SbomReport`s existed against 177
`VulnerabilityReport`s — those images had no CVEs at all before this lane.

## Data flow

```
OSV bulk zip (per ecosystem, hourly, conditional GET)
   ├─ MAL-* / malicious → SupplyChainIoc            (docs/supply-chain.md)
   └─ everything else   → OsvAdvisory + OsvAffected  (skip if `modified` unchanged)
SbomComponent ──(purl_type, name)──► OsvAffected ──► core.osv_ranges.evaluate(version)
   └─► Finding(source=osv, category=vulnerability) per deployed workload,
       unless a Trivy finding exists for (workload, image, pkg, version, any alias)
```

The matcher runs per image at SBOM ingest (`core.services.ingest`) —
so `last_seen` follows the inventory cycle exactly like Trivy findings —
and fleet-wide at the end of `enrich_fetch --source osv`
(`enrichment.refresh_osv`). Findings age out the normal way once nothing
bumps `last_seen` past the cluster's next complete inventory.

## Version evaluation (`core/osv_ranges.py`)

- `versions[]` exact match first. OSV enumerates it for ECOSYSTEM-ranged
  ecosystems (PyPI, Maven, RubyGems); it is **empty for npm, Go and
  crates.io**, which only have SEMVER ranges.
- SEMVER ranges are a *set* of `[introduced, fixed)` /
  `[introduced, last_affected]` intervals — a version is affected if it
  falls in any (Go stdlib advisories routinely carry 2–3). Ordering is
  python-semver: Go pseudo-versions are prereleases of their base
  version, `+incompatible` is build metadata, a leading `v` is dropped.
- ECOSYSTEM ranges without `versions[]` are reported `unsupported`, not
  guessed (≈1.7k Maven blocks).
- Names are compared in OSV's convention: Maven `group:artifact`, PyPI
  PEP 503, **Go lower-cased** (Trivy writes `github.com/datadog/…` in the
  purl, OSV keeps `DataDog`). Trivy's `%2B` in Go purls is decoded by
  `core.purl.normalize_purl`.

`univers` was evaluated and rejected: its range membership is wrong for
`>=0 | <0.0.0-<pseudo-version>` (flags `golang.org/x/net v0.52.0`).
The api.osv.dev batch endpoint would send every private package name to
Google; the bulk zips keep the inventory local.

## Finding shape

`vuln_id` = the CVE alias when there is one (EPSS / KEV join and Trivy
naming line up), else the OSV id. `pkg_name` / `installed_version` as
the SBOM component, `fixed_version` from the matching interval,
severity from GHSA's `database_specific.severity` (Go vulndb / RustSec
entries carry none → `unknown`), CVSS vector kept, no CVSS score.
`details`: `osv_ids`, `aliases`, `references`, `primary_link`
(osv.dev). Priority: the normal tree, no short-circuit.

## Operations

- Cron: the `enrichOsvSupplyChain` job (key kept) now runs
  `enrich_fetch --source osv`. First run upserts every advisory of the
  deployed ecosystems (npm ≈ 230k); later runs touch only changed ones.
- `match_osv [--image sha256:…]` re-runs the matcher.
- Metrics: `kubeposture_osv_advisories_total{ecosystem,withdrawn}`,
  `kubeposture_sbom_components_total{ecosystem}`.
- Withdrawn advisories keep their row with `withdrawn_at`; the matcher
  skips them and their findings age out.
- Tests: `core/tests/test_osv_ranges.py` (evaluator traps),
  `core/tests/test_osv_vuln_lane.py` (loader + matcher on real
  advisories under `fixtures/osv/advisories`), realdata parity above.
  `OSV_PARITY_WRITE=1` re-pins after a deliberate change.
