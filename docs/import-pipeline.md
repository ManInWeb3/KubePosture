# Import Pipeline — design decisions

How a cluster's Trivy / Kyverno / inventory state gets from the
importer Job into the central, and **why it is built the way it is**.
The wire contract itself is in the README
([Import API contract](../README.md#import-api-contract)); this
document records the decisions behind it so they are not re-litigated
or accidentally undone. Decided October 2026 while replacing the
per-item protocol; the investigation that triggered it is in §1.

Code map:

| Concern | Where |
|---|---|
| Upload / commit / abort | [core/services/bundle_ingest.py](../core/services/bundle_ingest.py), [core/api/views_bundles.py](../core/api/views_bundles.py) |
| Reap, discard, safety net | [core/services/reaper.py](../core/services/reaper.py), [core/management/commands/reap_safety_net.py](../core/management/commands/reap_safety_net.py) |
| In-flight lock | [core/api/views.py](../core/api/views.py) (`IMPORT_LOCK_TIMEOUT`) |
| Importer | [scripts/kubeposture_importer/](../scripts/kubeposture_importer/) (`scripts/import-cluster.py` is a shim) |
| Charts | [deploy/charts/kubeposture](../deploy/charts/kubeposture), [deploy/charts/kubeposture-import](../deploy/charts/kubeposture-import) |
| Fixtures | [scripts/capture-cluster-fixture.sh](../scripts/capture-cluster-fixture.sh), [scripts/anonymize-fixture.py](../scripts/anonymize-fixture.py), `fixtures/real/<alias>/` |

---

## 1. What was wrong before

`core_ingestqueue` had grown to 14 GB. Investigation showed it was not
a leak but the design:

- every cycle re-sent every CRD as its own `POST /api/v1/ingest/`
  (~1,500 requests per cluster per cycle, SBOMs ~60 % of bytes), and
  processed payloads were retained 14 days although nothing reads
  `raw_json` after an item is `done`;
- ~70k rows were stuck forever (`claimed_at IS NULL`, pre-migration
  0008) and had to be deleted by hand;
- a truncated cycle was invisible: a failed CRD POST was only logged,
  `finish` still sent the *intended* count, and the stuck-open sweep
  **processed** partial data after an hour — which looks exactly like
  "these workloads disappeared";
- a failed inventory item blocked its whole import forever (the
  inventory gate in the claim SQL);
- a logging bug (`extra={"created": …}`) silently failed every
  VulnerabilityReport with ≥ 250 findings when DEBUG logging was on.

The queue was wiped and the database migrated to the new cluster with
`core_ingestqueue` / `core_importmark` empty
(`pg_dump --exclude-table-data`).

---

## 2. Decisions

### 2.1 One bundle per kind, one atomic commit (not per-item POSTs, not one archive)

A cycle is `POST bundles/<kind>/` once per kind (gzip NDJSON, manifest
as the first line), then one `commit/`. ~10 requests instead of
~1,500; the server verifies count + sha256 in a byte pass before
touching the database; the rows and the kind's `open` ImportMark are
inserted in one transaction.

*Why per kind rather than one archive for the whole cycle:* a kind is
the unit the reaper already works in (`(cluster, kind, import_id)`),
each bundle is small enough to verify and spool cheaply, and a single
failed kind aborts the import without re-sending the others on retry
(identical re-upload is a `200 already_uploaded` no-op).

*Why NDJSON with a manifest line, not multipart:* the importer is
stdlib-only (`urllib`); manifest-first lets the server reject a bad
upload before reading the body; no JSON parsing is needed to verify.

### 2.2 Hard cutover

`/imports/start/`, `/ingest/`, `/imports/finish/` are gone. Central and
importer charts ship in the same release; a stray old importer gets
404 and fails fast and harmlessly. No dual-protocol period because the
old protocol *is* the bug (truncated cycles processed as whole).

### 2.3 `started_at` is import-wide

The first bundle of an import fixes `started_at` for every mark of
that import. `_reap_inventory` sets
`Cluster.last_complete_inventory_at = mark.started_at`, and
`Finding.last_seen = IngestQueue.created_at`; every scan row must be
created *after* the inventory mark's `started_at` or the cycle's
findings are hidden by the default views.

### 2.4 Nothing partial is ever processed — discard, don't promote

An import that is not committed is worthless (the importer sends a
full snapshot every cycle). Two paths discard it:

- `reap_stuck_open`: marks still `open` after
  `STUCK_OPEN_TIMEOUT_SECONDS` (30 min) — the importer died before
  commit;
- `discard_import_for_failed_inventory`: the inventory payload failed
  to parse — processing the scans without it would hold them forever
  behind the inventory gate.

Discarding deletes the import's rows and moves its marks to `reaped`
with a `discard_reason` (`stuck_open` / `inventory_failed`). It never
touches `last_complete_inventory_at`, never runs the diff, never
captures a heartbeat. A discarded import is `state=reaped` +
`discard_reason`, **not a fourth state**, so every consumer of
`reaped` (in-flight lock, prune, claim SQL, test DSL) keeps working.

### 2.5 Reaps are claim-first and delete the tuple's rows

Both reaps start with the non-blocking `transition_mark_to_reaped`
claim (`FOR UPDATE SKIP LOCKED`, then the conditional UPDATE) and
return `None` if they lose it — two workers (or a worker racing the
safety net) can never both run a reap body, and the loser returns at
once instead of queueing behind the winner's transaction (which used
to park every other worker pod at 0 CPU for the length of an inventory
reap). The claim, the body and the row deletion run in one
transaction, so a failure rolls the claim back and the mark stays
`draining` for the next sweep. The priority recompute runs **after**
that transaction commits, in its own chunked commits: a pod killed
mid-recompute keeps the chunks it finished and the reap itself stays
committed; the cluster's next reap (or `recalculate_priorities`)
repairs any stale priorities.

Once the reap has recorded `failed_count` / `last_error` (newest
`error_message[:2000]`) on the ImportMark, **all** of the tuple's rows
are deleted — `done` and `failed` alike. Nothing reads `raw_json`
after `done`; the facts worth keeping live on the mark. The queue only
ever holds in-flight work, and `prune_stale_data`'s 14-day
`IngestQueue` target is a safety net for rows an errored reap left
behind.

`IMPORT_KEEP_FAILED_PAYLOADS=true` (default **off**) keeps `failed`
rows for the 14-day prune so a reproducible parse failure can be
replayed from the exact CRD. It is a debugging switch: turn it on
while investigating, off afterwards. Rejected alternative: keeping
failed payloads for 14 days by default — that is the retention that
produced the 14 GB table, for data that is needed once in a hundred
cycles.

### 2.6 Partial scan failures take the protective branch

If some non-inventory rows of a kind `failed` and the rest are `done`,
`_reap_scan` does **not** clear stale signals for that kind
(`reap.scan.partial_failure`). Project convention is to err toward
not hiding real findings: a poison item then shows as a non-zero
`failed_count` + `last_error` on every cycle's mark rather than as
silently cleared signals.

### 2.7 Volume reduction is relevance, not age

An age filter ("CRDs newer than 7 days") was rejected: `Finding.last_seen`
only advances on re-ingest and the default views require
`last_seen >= last_complete_inventory_at`, so skipping an old-but-live
report hides a live finding.

Instead the importer drops reports whose subject is not deployed
(mirroring the server's own definition, strict superset):

- image kinds (Vulnerability / Sbom / ExposedSecret) are kept iff
  `report.artifact.digest` ∈ *D* = pod `imageID` digests ∪
  digest-pinned container specs (ReplicaSet templates excluded — the
  server never reads them, and including them would resurrect
  RS-history images, which were about half of all Trivy reports);
- ConfigAudit / Kyverno PolicyReport are kept iff their subject
  resolves through `ownerReferences` to a controller present in the
  snapshot (Trivy names > 63 chars lose the `resource.name` label; the
  owner fallback covers that);
- cluster-level kinds are always kept; **pass-only Kyverno reports
  are kept** (dropping them would look like an outage to `_reap_scan`).

Enforced from day one (`relevanceFilter: true`), with
`--no-relevance-filter` / `relevanceFilter: false` as the lever if a
digest mismatch (multi-arch index vs platform manifest, mirrors) ever
shows up. The server already required digest equality, so the filter
introduces no new failure mode — it makes an existing one visible.

### 2.8 Coverage: record and alert, never abort

The importer counts expected vs matched subjects per kind
(`|D|` for image kinds, controllers for ConfigAudit / Kyverno) and
sends `coverage: {expected, matched}` in the manifest. Below
`coverage.minRatio` (0.9) the importer logs a WARNING and commit logs
`import.coverage_low` at ERROR; the import still proceeds — partial
scanner coverage is a valid snapshot, an aborted one is not. Kyverno
coverage is always informational (policies are per-namespace by
design). Statuses are `ok` / `warning` / `info` / `n/a`; there are no
per-kind ignore/check knobs (removed as dead configuration).

### 2.9 `complete_snapshot` is gone

Every committed inventory is a complete snapshot by construction (one
bundle, verified whole, committed atomically), so the per-payload
flag and `Cluster.consecutive_incomplete_inventories` were dead state
whose only effect was to make evidence of a problem disappear.
Migration 0011 drops both columns; the inventory reap always advances
the anchor and runs the deactivation sweep. Partial syncs are not a
planned feature; if they ever become one they need their own design,
not a boolean. An older importer still sending the key is accepted
and ignored.

### 2.10 Timers are ordered, and short

```
upload deadline (600 s) < importer Job deadline (900 s)
                        < central IMPORT_LOCK_TIMEOUT_SECONDS (1200 s)
                        < reaper STUCK_OPEN_TIMEOUT_SECONDS (1800 s)
```

- the upload budget leaves room for a clean `abort` before the Job is
  killed;
- the lock must outlive the Job so a slow-but-alive import is never
  raced by a second one;
- the lock must expire before the safety net discards, so an
  abandoned import stops gating new ones first.

A real cycle takes a few minutes; the previous values (1500 / 1800 /
2700 / 3600) were sized for the per-item protocol.
[tests/test_chart_invariants.py](../tests/test_chart_invariants.py)
asserts the ordering against both charts' `values.yaml`.

### 2.11 Bounded everywhere

Bundles are capped (`IMPORT_BUNDLE_MAX_COMPRESSED_BYTES` 64 MiB,
`_UNCOMPRESSED_BYTES` 128 MiB, `_ITEMS` 50k, `_LINE_BYTES` 32 MiB),
gunzipped through `zlib.decompressobj` with `max_length` (zip-bomb
safe) into a `SpooledTemporaryFile`, and inserted in batches of 100 —
server RSS per upload is a few MB regardless of bundle size. `/tmp` is
a disk-backed `emptyDir` with a `sizeLimit` in both charts (see
[operations/batch-jobs-memory.md](operations/batch-jobs-memory.md)).

### 2.12 Importer failure sequence

```
collect → index / filter / coverage → build ALL bundles to $TMP   (local failure → rc 1, nothing opened server-side)
POST bundles/inventory … bundles/<kind> … bundles/trivy.SbomReport (largest last)
   any bundle exhausts retries / 4xx / deadline → POST abort → ABORTED → rc 1
POST commit  → 200 COMMITTED → pending/clear → cleanup failed sibling Jobs → rc 0
             → 5xx retried; exhausted or 4xx → abort → rc 1
SIGTERM after the first upload → abort → rc 1
```

Count-0 bundles **are sent** for kinds whose CRD is installed but has
no objects (that is what drives the zero-input / outage rule in
`_reap_scan`); kinds whose CRD is absent are omitted.

### 2.13 Test data is real, anonymised, and verified

Synthetic fixtures missed every real-world finding (63-char Trivy
names, link-local addresses in labels, `eks.amazonaws.com` label keys,
…). Fixtures under `fixtures/real/<alias>/` are captured from real
clusters with `scripts/capture-cluster-fixture.sh` and rewritten by
`scripts/anonymize-fixture.py` (HMAC renaming with a salt that is
**never committed** — `~/.kubeposture-fixture-salt`; allowlist
rebuild; global digest re-hash so Pod `imageID` ↔ `artifact.digest` ↔
SBOM stay consistent). A fixture is only committed after `--verify`
passes: filter stats and `|D|` identical before and after, and no
original namespace / workload / host / repo string or digest leaks.
Raw captures live outside the repo and must never be added.

Suites: unit (`core/tests`, `scripts/importer_tests`), real-data
(`tests/realdata`, golden filter stats / bundle hashes), end-to-end
(`tests/integration`, real views + chaos proxy: cut request, dropped
response, 500 on a bundle, SIGTERM mid-upload, stuck-open discard).
Mutation checks confirmed the interruption tests fail when idempotency
or hash verification is removed.

---

## 3. Rollout and verification

One release carries server + importer + both charts.

1. Suspend importer CronJobs; on the central, drain and run
   `reap_safety_net`; confirm no `pending`/`processing` rows and no
   `open`/`draining` marks.
2. Upgrade the central chart (ingress `proxy-body-size` ≥ 64m).
3. Upgrade `kubeposture-import` per cluster (delete the immutable
   `-init` Job first under plain Helm); unsuspend.
4. First cycle: importer log shows `filter …`, `coverage … status=ok`,
   `COMMITTED`, rc 0. On the central:

   ```sql
   SELECT c.name, m.kind, m.state, m.observed_count, m.coverage_expected,
          m.coverage_matched, m.failed_count, m.discard_reason
     FROM core_importmark m JOIN core_cluster c ON c.id = m.cluster_id
    WHERE m.started_at > now() - interval '2 hours' ORDER BY 1, 2;   -- all reaped, no discard_reason
   SELECT status, count(*) FROM core_ingestqueue GROUP BY 1;         -- empty between cycles
   SELECT name, last_complete_inventory_at FROM core_cluster ORDER BY 1;
   ```

   A large drop in visible findings together with a low coverage ratio
   means a digest mismatch → set `relevanceFilter: false` on that
   importer (no central change) and inspect with
   `KUBEPOSTURE_LOG_LEVEL=debug`.
5. Rollback: downgrade both charts. Migrations 0010/0011 are additive
   except for the two dropped dead columns.

---

## 4. Known limits / out of scope

- `trivy.RbacAssessmentReport` is namespaced and never resolves
  server-side (`workload_not_resolved`) — pre-existing.
- Snapshot-only subject resolution is slightly stricter than the
  server's DB alias fallback (a Pod whose ReplicaSet aged out
  mid-cycle counts as `dropped_no_subject`) — low impact, visible in
  the filter stats.
- The whole bundle is inserted in one transaction: a Postgres lock /
  WAL consideration for very large clusters, not a memory one.
