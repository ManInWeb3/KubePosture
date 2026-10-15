# Batch jobs — memory, /tmp and OOM

Why the enrichment CronJobs were being OOM-killed, what was changed,
and the rules every batch job in this repo follows from now on.
Decided October 2026.

---

## 1. Where the memory actually went

Three jobs download feeds into `/tmp` and were assumed to OOM because
of the temp files. The temp files were incidental; the memory was in
Python:

| Job | Allocation | Peak |
|---|---|---|
| `enrich_fetch --source epss` | the ~330k-row feed held **five times**: gzipped `bytes` from `resp.read()`, the decompressed `str`, the same text read back from a temp file, `list(csv.reader(…))`, and finally 330k `EpssScore` model instances (~1 KB each) built *before* `bulk_create(batch_size=5000)` could help. Plus `exclude(vuln_id__in=<330k ids>)` shipped as one `NOT IN (...)`. | ~600–900 MB against a 512Mi request |
| `enrich_fetch --source osv-supply-chain` | the zip itself was already streamed to disk and read one entry at a time; the cost was the matcher's `set(SbomComponent.objects.values_list("purl").distinct())` — every distinct purl of a multi-GB table as Python strings, hourly, just to intersect with the purls the feed touched | largest single allocation of the job |
| `enrich_fetch --source kev` | small (~1.5k rows) | fine |

The bundle import path does **not** have this problem: uploads are
spooled to disk past 8 MiB and inserted 100 rows at a time.

---

## 2. Rules

### 2.1 Never hold a dataset — stream it end to end

EPSS now goes `HTTP response → gzip.GzipFile → csv.reader → chunks of
5,000 → one upsert per chunk`
([`_load_epss_rows`](../../core/services/enrichment.py)). No temp
file, no row list, no model list; peak memory is one chunk. The
`load_epss_from_file` path reads the file line by line through the
same function. KEV streams to a temp file (it is one JSON document and
must be parsed whole, but it never exists as a second `bytes` copy).
`_http_get` (whole body into `bytes`) no longer exists; `_http_open()`
yields the live response and retries only the connect phase.

A stream that dies mid-body (socket error, `IncompleteRead`, corrupt
gzip) is a failed fetch: rows that already arrived are upserted
(idempotent on `vuln_id`), but the stale-row sweep and the
Finding-cache refresh do **not** run on a partial feed — the zero-input
no-op rule still holds.

### 2.2 Keep set operations in the database

- "Rows the feed no longer lists" is `fetched_at < run_started` — the
  upsert bumps `fetched_at` on every row it touches (it is in
  `update_fields`; removing it would make the sweep delete re-listed
  rows, and the chunk test catches that). Not `NOT IN (<330k ids>)`.
- The priority recompute takes `EpssScore.objects.values("vuln_id")`
  (a subquery), not a Python list.
- The matcher intersects `touched_purls` with the SBOM table in
  chunks of 5,000 `IN (...)` lookups
  ([`_deployed_among`](../../core/services/supply_chain_matcher.py));
  a full re-scan uses `purl__in=SbomComponent.objects.values("purl")`
  (a semi-join). The result is bounded by *deployed malicious purls*,
  normally a handful.

### 2.3 Measure, don't guess

Every management command subclasses
[`KubePostureCommand`](../../core/management/base.py) and logs on
exit — return or raise:

```
INFO core.management command.finished name=enrich_fetch peak_rss_mb=41.2 elapsed_s=38.4 rc=0
```

`peak_rss_mb` is the process high-water mark (`ru_maxrss`). Memory
requests in the chart are set from these lines. An OOM-killed pod
leaves no trace of what it needed; a surviving one reports it every
run, so size with headroom first and tighten after reading a few runs.

### 2.4 Pods are honest about memory: requests == limits

Every CronJob, the worker CronJob and the shared `wait-for-db` init
container run with `requests == limits` for CPU and memory —
**Guaranteed QoS**. QoS is decided per pod, so a Burstable init
container would demote the whole job; that is why the init container
changed too. A Guaranteed pod is only killed for exceeding its *own*
limit, never evicted because a neighbour spiked.
[tests/test_chart_invariants.py](../../tests/test_chart_invariants.py)
enforces it.

Current sizes ([values.yaml](../../deploy/charts/kubeposture/values.yaml)):

| Job | Memory | Basis |
|---|---|---|
| `enrichEpss`, `enrichKev` | 512Mi | bounded by this change (one 5k chunk + Django) |
| `enrichOsvSupplyChain` | 2Gi | previous limit kept as the request; the per-advisory upsert loop is unmeasured |
| `reapSafetyNet`, `snapshotCapture`, `pruneStaleData`, `pruneSnapshots`, `recalculatePriorities` | 2Gi | previous limit kept as the request until `peak_rss_mb` lines have been read |
| `worker` | 1Gi | previous limit |

The 2Gi rows are deliberately *not* guesses downward: lower them after
a few `command.finished` lines, not before.

### 2.5 /tmp is disk, bounded, and never memory-backed

`/tmp` in every central pod (web, worker, setup Job, all CronJobs) and
in every importer pod is an `emptyDir` with a `sizeLimit`
(`tmp.sizeLimit`: 1Gi central, 256Mi importer). Disk-backed, so a
download does not count against the memory limit; bounded, so a
runaway file evicts the pod instead of filling the node. **Never**
`medium: Memory` for these — that would turn every spooled bundle and
feed back into RSS. The invariant test asserts no template uses it.

---

## 3. Diagnosing "the job OOMed"

The word covers two different kills. Check which one:

```bash
# Real memory kill — OOMKilled, exit code 137:
kubectl get pod <pod> -o jsonpath='{.status.containerStatuses[*].lastState.terminated}'

# Disk kill — the pod is Evicted with a message like
# "ephemeral local storage usage exceeds the total limit of containers":
kubectl describe pod <pod> | grep -A3 -i evicted
```

- **OOMKilled** → read the previous successful run's
  `command.finished … peak_rss_mb=` line (`kubectl logs
  job/<name>`); if the peak is near the limit, raise the value in
  `values.yaml`; if it is far below, something new is being
  materialised — look for a `list(...)`, a `set(... values_list ...)`
  or an `__in=<huge list>` in the code path.
- **Evicted (ephemeral storage)** → `tmp.sizeLimit` is too small for
  the feed, or a job leaks temp files (every download path here
  unlinks in `finally`).

---

## 4. Checklist for a new batch job

1. Subclass `KubePostureCommand` (a test fails otherwise).
2. Stream inputs; never `resp.read()` a feed, never `list()` a table.
3. Set differences / intersections go through SQL (`fetched_at`
   watermark, subquery, chunked `IN`).
4. Add the CronJob to `values.yaml` with `requests == limits`; start
   generous, tighten from `peak_rss_mb`.
5. Temp files under `/tmp` only, unlinked in `finally`.
