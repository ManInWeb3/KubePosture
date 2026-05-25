# Supply-Chain IoC Detection

How KubePosture detects deployed packages flagged as malicious by
upstream feeds (Aikido Intel + OSV.dev), and what guarantees the
matcher and short-circuit priority rule provide.

This document covers design and data flow. For the operational runbook
(commands, cadence, env vars) see the
[README "Supply-chain detection" section](../README.md#supply-chain-detection-aikido--osv).

---

## 1. Why this lane exists

Vulnerability scanners (Trivy) report CVEs against *legitimate*
package releases. A malicious publish (maintainer takeover, attacker
upload to a typosquatted name, intentionally backdoored release) is
categorically different:

- there is no benign middle ground — the published artifact contains
  attacker code on first `import`,
- CVSS and EPSS are typically absent because the disclosure is the
  finding,
- the "fix" is to uninstall, not patch.

KubePosture treats these as a distinct lane (`Source.SUPPLY_CHAIN_IOC`,
`Category.SUPPLY_CHAIN`) that bypasses the normal scoring tree and
short-circuits to `PriorityBand.IMMEDIATE`. Rationale and what it
deliberately ignores are documented at
[urgency-decision-tree.md § Supply-chain short-circuit](urgency-decision-tree.md#supply-chain-short-circuit).

---

## 2. Data flow

```
                                    feed fetchers
   ┌──────────────────┐         ┌────────────────────┐
   │  Aikido Intel    │ HTTP    │ fetch_aikido_iocs  │ ────┐
   │  intel.aikido.dev│────────►│   (cond. GET)      │     │
   └──────────────────┘         └────────────────────┘     │
                                                           │  upsert
   ┌──────────────────┐         ┌────────────────────┐     ▼
   │  OSV.dev bulk    │ HTTP    │ fetch_osv_supply_  │   ┌──────────────────┐
   │  per-ecosystem   │────────►│   chain (cond. GET)│──►│ SupplyChainIoc   │
   └──────────────────┘         └────────────────────┘   │  (purl, feed,    │
                                            │            │   advisory_id…) │
                                            │            └────────┬────────┘
                                            │                     │
                                            │                     │
                Trivy SbomReport CRD        │  touched_purls      │
                       │                    ▼                     │
                       ▼          ┌─────────────────────┐         │
                ┌──────────────┐  │ match_iocs_to_      │◄────────┘
                │ SbomComponent│─►│   components()      │
                │ (image, purl)│  └──────────┬──────────┘
                └──────────────┘             │
                                             │  upsert_findings()
                                             ▼
                                  ┌──────────────────────┐
                                  │ Finding              │
                                  │  source=supply_chain │
                                  │  effective_priority= │
                                  │  IMMEDIATE           │
                                  └──────────────────────┘
```

Three tables anchor the lane:

| Table | Owner | Identity | Lifetime |
|---|---|---|---|
| `SbomComponent` | Trivy SbomReport ingest | `(image, purl)` unique | Pruned with image — `prune_stale_sbom_components` deletes rows whose image has no `WorkloadImageObservation.currently_deployed=True` AND `Image.last_seen_at` is older than the cutoff (default 90 days). |
| `SupplyChainIoc` | feed fetchers | `(feed_source, advisory_id, purl)` unique | Append-only; no per-row TTL. Feed re-fetch updates severity/title/url/summary in place. |
| `FeedFetchState` | feed fetchers | `state_key` (`"aikido"`, `"osv:<ecosystem>"`) | One row per upstream URL — stores ETag + Last-Modified so conditional GET can short-circuit unchanged feeds. |

`Finding` rows for matches use the standard dedup hash machinery
(see [core/services/dedup.py:23-55](../core/services/dedup.py#L23-L55))
keyed on the workload-scoped tuple — so the same `(workload, advisory,
purl)` does not duplicate across runs.

---

## 3. Feeds

Both fetchers live in [core/services/enrichment.py](../core/services/enrichment.py)
and follow the universal **zero-input no-op rule**: an empty / unreadable
response leaves existing rows intact instead of clearing them.

### Aikido Intel

- **URL.** `AIKIDO_INTEL_URL` env var. **Default is empty** — the old
  free feed at `intel.aikido.dev/api/?format=json` was retired in
  favour of an OAuth-gated endpoint at
  `app.aikido.dev/api/public/v1/research/malware/packages` (Bearer
  token, paginated 10–20/page). KubePosture does not ship credentials
  for the new endpoint, so the Aikido lane is **opt-in**: set
  `AIKIDO_INTEL_URL` to a mirror / proxy / internal endpoint you can
  read. With an empty URL the fetcher logs `aikido.skip reason=no_url`
  and returns 0 — the cron is a no-op rather than a 404 loop.
- **Format.** The fetcher accepts a top-level JSON list OR a wrapper
  object with `entries` / `data` / `malware` (see
  [`fetch_aikido_iocs`](../core/services/enrichment.py#L521)). Each
  entry should carry `purl` (preferred) or
  `package` + `version` + `ecosystem` (reconstructed). Fields read:
  `id` / `advisory_id` / `aikido_id`, `severity`, `description`,
  `url`, `date`.
- **Cadence.** ~every 15 min when configured.
- **Conditional GET.** Yes — `If-None-Match` / `If-Modified-Since`
  from `FeedFetchState[aikido]`.

> **Note.** Aikido coverage is therefore not part of the default OSS
> stack. OSV.dev (next section) is the canonical public feed and
> works without any configuration. Operators on Aikido's paid tier
> can wire their own endpoint; orgs running multiple feeds may layer
> a private aggregator behind `AIKIDO_INTEL_URL`.

### OSV.dev supply-chain

- **URL pattern.** `https://osv-vulnerabilities.storage.googleapis.com/{ecosystem}/all.zip`.
- **Ecosystems fetched.** Only those present in
  `SbomComponent.ecosystem` (distinct). The mapping from purl ecosystem
  to OSV bulk-zip path lives in
  [`PURL_TO_OSV`](../core/services/enrichment.py#L48-L59). Adding a new
  ecosystem requires one line there + (optionally) a normalisation
  hint in `core/purl.py`.
- **Filter.** Only entries with `MAL-*` advisory IDs OR
  `database_specific.malicious=true` — vulnerability CVEs come from
  Trivy / EPSS / KEV in a separate path.
- **Cadence.** ~hourly. Conditional GET keeps off-cycle ticks cheap.

Both fetchers invoke the matcher inline once they finish upserting,
passing the set of purls they touched via `touched_purls=` — so a
typical fetch only joins the matcher against the few purls that
actually changed, not the whole IoC table.

### State persistence: FeedFetchState

Conditional GET works because each fetch persists the response's
`ETag` and `Last-Modified` headers, plus `last_success_at`, into
`FeedFetchState` keyed by `state_key`. A 304 response keeps the
existing rows; a 2xx replaces ETag/Last-Modified and proceeds to
parse. The state row itself is the canonical "did this feed succeed
recently?" sensor for ops.

---

## 4. Matcher

[`core.services.supply_chain_matcher.match_iocs_to_components`](../core/services/supply_chain_matcher.py)
performs the join `SupplyChainIoc × SbomComponent × WorkloadImageObservation(currently_deployed=True)`.

The matcher is intentionally:

- **Pure-ORM, no SQL.** Three sequential queries: load IoCs grouped
  by purl, load SbomComponents matching those purls, load deployed
  observations per image.
- **Workload-fanned.** A bad purl present in one image deployed to N
  workloads produces N findings (one per workload). Sidecar pattern
  (one workload, two images, both with the same bad purl) likewise
  produces two findings (different `image_id`).
- **Multi-feed-aware.** Aikido and OSV reporting the same compromise
  produces *two* findings with distinct `advisory_id`s — by design,
  so the operator sees both pieces of evidence.
- **Re-runnable.** Repeated matches are deduplicated by `compute_hash`
  → no growth on no-op re-runs. Severity / title / URL / summary
  updates propagate into the existing finding's `details` JSONB on
  the next run.

### Output

Each match produces a `Finding` dict that goes through the standard
`core.services.dedup.upsert_findings` path:

```
source              = Source.SUPPLY_CHAIN_IOC   # = "supply_chain_ioc"
category            = Category.SUPPLY_CHAIN     # = "supply_chain"
vuln_id             = ioc.advisory_id           # GHSA-xxxx, MAL-xxxx, AIKIDO-xxxx
pkg_name            = sbom_component.name
installed_version   = sbom_component.version
severity            = ioc.severity or CRITICAL
title               = "Malicious package: {name}@{version} ({feed}:{id})"
details = {
    purl, ecosystem, feed_source, advisory_id,
    advisory_url, summary, published_at,
}
```

The `effective_priority` is set by `core.urgency.apply_score`, which
hits the `Category.SUPPLY_CHAIN` short-circuit and lands as
`PriorityBand.IMMEDIATE` regardless of severity / exposure / env /
EPSS / KEV.

### Lifecycle interactions

- **Workload undeployed.** The matcher's join requires
  `WorkloadImageObservation.currently_deployed=True`. A workload that
  scales to zero or is deleted will fail this gate on the next match;
  the existing finding row is **left in place** — the inventory reaper
  auto-resolves it on the next complete cycle, just like any other
  finding.
- **Workload re-deployed.** The next match run picks it up and either
  re-creates the finding (if previously hard-resolved) or bumps
  `last_seen` on the existing row.
- **IoC withdrawn from a feed.** Currently a no-op — `SupplyChainIoc`
  rows have no per-row TTL and are never deleted by withdrawal. The
  associated Finding becomes a permanent "this was flagged" record.

---

## 5. Browse / search surface

The `/components/` UI (`core/views_ui.py` → `components_list_view`)
exposes the SBOM inventory grouped by `purl`, with per-purl image /
workload / cluster counts. Aggregation lives in
[`core.services.components`](../core/services/components.py) — not in
queryset annotations, because per-row aggregation would be misleading
when each `SbomComponent` is `(image, purl)` and the display groups
across images.

The list view supports:

- name / version / purl search (one bar, accepts pasted purls in
  either `%40` or `@` encoding via `normalize_purl`),
- ecosystem filter dropdown (distinct values from active components),
- cluster filter (scopes both the rows and the count joins),
- `include_inactive` toggle (default off — undeployed images are
  hidden).

`POST /api/v1/sbom/search/` and `manage.py search_sbom` are wrappers
over `search_by_purls(...)`, intended for IoC-feed reconciliation
("we just learned `pkg:npm/foo@1.2.3` is malicious — who's running
it?"). Both accept exact `purls` and `purl_prefixes`.

---

## 6. purl normalisation

`SbomComponent.purl` and `SupplyChainIoc.purl` are both stored
normalised by [`core.purl.normalize_purl`](../core/purl.py):

- `%40` → `@` (some feeds URL-encode the version separator).
- Lowercased ecosystem segment.
- Other minor canonicalisations — see the module for the full list.

Migration `0006_normalize_stored_purls` retro-applies this to existing
rows so post-rollout joins line up. Always call `normalize_purl`
before comparing a user-supplied or feed-supplied purl against stored
data.

---

## 7. Smoke test

The [`seed_supply_chain_test`](../core/management/commands/seed_supply_chain_test.py)
command bootstraps a synthetic cluster + workload + image + component
+ IoC and runs the matcher inline so the full lane can be verified
without standing up real scanners. See the README for usage.

For automated coverage, see:

- [core/tests/test_services_supply_chain_matcher.py](../core/tests/test_services_supply_chain_matcher.py) — matcher unit tests.
- [core/tests/test_services_enrichment_supply_chain.py](../core/tests/test_services_enrichment_supply_chain.py) — feed fetcher tests.
- [core/tests/test_match_supply_chain_command.py](../core/tests/test_match_supply_chain_command.py) — command wrapper.
- [core/tests/test_seed_supply_chain_command.py](../core/tests/test_seed_supply_chain_command.py) — smoke-test bootstrap.
- [core/tests/test_views_ui_findings_supply_chain.py](../core/tests/test_views_ui_findings_supply_chain.py) — UI integration.
- [core/tests/test_views_ui_components_list.py](../core/tests/test_views_ui_components_list.py) — components browse.
- [core/tests/test_services_components.py](../core/tests/test_services_components.py) — components service queries.

---

## 8. Cross-references

- [urgency-decision-tree.md § Supply-chain short-circuit](urgency-decision-tree.md#supply-chain-short-circuit) — why IMMEDIATE, what it ignores.
- [pruning.md](pruning.md) — retention rules for `SbomComponent` and `SupplyChainIoc`.
- [ssvc-mapping.md](ssvc-mapping.md) — how the supply-chain lane diverges from the SSVC-derived scoring used for everything else.
- [README § Supply-chain detection](../README.md#supply-chain-detection-aikido--osv) — commands and cadence.
