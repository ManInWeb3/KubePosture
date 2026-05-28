# Supply-Chain IoC Detection

How KubePosture detects deployed packages flagged as malicious by the
OSV.dev supply-chain feed, and what guarantees the matcher and
short-circuit priority rule provide.

This document covers design and data flow. For the operational runbook
(commands, cadence, env vars) see the
[README "Supply-chain detection" section](../README.md#supply-chain-detection-osv).

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
                                    feed fetcher
   ┌──────────────────┐         ┌────────────────────┐
   │  OSV.dev bulk    │ HTTP    │ fetch_osv_supply_  │   ┌──────────────────┐
   │  per-ecosystem   │────────►│   chain (cond. GET,│──►│ SupplyChainIoc   │
   │  all.zip         │  stream │   streamed to disk)│   │  (purl, feed,    │
   └──────────────────┘  to tmp └────────────────────┘   │   advisory_id…) │
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
| `SupplyChainIoc` | feed fetcher | `(feed_source, advisory_id, purl)` unique | Append-only; no per-row TTL. Feed re-fetch updates severity/title/url/summary in place. |
| `FeedFetchState` | feed fetcher | `state_key` (`"osv:<ecosystem>"`) | One row per upstream URL — stores ETag + Last-Modified so conditional GET can short-circuit unchanged feeds. |

`Finding` rows for matches use the standard dedup hash machinery
(see [core/services/dedup.py:23-55](../core/services/dedup.py#L23-L55))
keyed on the workload-scoped tuple — so the same `(workload, advisory,
purl)` does not duplicate across runs.

---

## 3. Feeds

The fetcher lives in [core/services/enrichment.py](../core/services/enrichment.py)
and follows the universal **zero-input no-op rule**: an empty / unreadable
response leaves existing rows intact instead of clearing them.

`feed_source` is a free-text label so additional feeds can be added
later without a schema change, but OSV.dev is the only feed shipped
today — it is a public, no-auth source that works out of the box.

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
- **Memory.** Each ecosystem zip is **streamed to a temp file** by
  [`_http_download_conditional`](../core/services/enrichment.py) and
  `zipfile` decompresses one advisory at a time off disk. The payload
  is never held in RAM as one object — the npm `all.zip` is hundreds
  of MB, and an earlier `resp.read()` + `io.BytesIO` copy spiked ~2×
  that and got the cron OOMKilled. Peak memory is now flat regardless
  of zip size.
- **Cadence.** ~hourly. Conditional GET keeps off-cycle ticks cheap;
  in practice only npm re-downloads most ticks (its ETag changes
  almost hourly), the rest return 304.

The fetcher invokes the matcher inline once it finishes upserting,
passing the set of purls it touched via `touched_purls=` — so a
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
- **Multi-feed-aware.** Two feeds (or two OSV advisory IDs) reporting
  the same compromise produce *two* findings with distinct
  `advisory_id`s — by design, so the operator sees both pieces of
  evidence. (OSV is the only shipped feed today, but the join keys on
  `(feed_source, advisory_id)` so this holds if another is added.)
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
vuln_id             = ioc.advisory_id           # GHSA-xxxx, MAL-xxxx
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
- [README § Supply-chain detection](../README.md#supply-chain-detection-osv) — commands and cadence.
