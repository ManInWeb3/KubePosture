# Data Retention & Pruning

Operational tables grow unbounded without intervention.
`manage.py prune_stale_data` is the daily hygiene job that keeps them
in check. This document covers what is pruned, what is intentionally
kept, and the safety rules.

For usage / flags see the command header:
[core/management/commands/prune_stale_data.py](../core/management/commands/prune_stale_data.py).
For retention logic see
[core/services/pruning.py](../core/services/pruning.py).

---

## 1. What is pruned

| Target | Predicate | Default retention | Rationale |
|---|---|---|---|
| `IngestQueue` | `status ∈ {done, failed}` AND `processed_at < cutoff` | **14 days** | Workers never re-read completed/failed items. Two weeks of audit is enough to debug an incident; older rows just bloat the table. |
| `ImportMark` | `state = reaped` AND `completed_at < cutoff` | **90 days** | REAPED marks are an audit trail of completed cycles. No operational code path reads them after reap. |
| `ScanInconsistency` | `last_observed_at < cutoff` | **30 days** | Per the model docstring: "rows older than 30 days are pruned by a maintenance job." Persistent gaps stay live because their `last_observed_at` is bumped each cycle. |
| `Finding` | `last_seen < cutoff` AND (`workload.deployed = false` OR `workload IS NULL`) | **180 days** | Hard-delete soft-resolved findings on undeployed workloads + long-stale cluster-scoped findings. Findings on deployed workloads can never age past the cutoff — every inventory cycle bumps their `last_seen`. |
| `SbomComponent` | image hasn't been observed in `cutoff` days AND no currently-deployed observation references it | **90 days** | Components on long-undeployed images. Re-ingest of an SbomReport recreates them automatically if the image comes back online. |

Each target is opt-out-able via `--skip-<target>` and has its own
`--<target>-days N` retention override.

`--dry-run` reports scanned counts without deleting. Every target's
`PruneResult` returns `(scanned, deleted)`; `deleted == 0` in dry-run.

---

## 2. What is intentionally NOT pruned

These tables are append-only by design — their growth is bounded by
either content-addressing or the data they describe, and an
inadvertent prune would create silent gaps in reconstructed history.

- **`Image`** — content-addressed by `digest`. Same image pulled into
  multiple clusters is one row. Components / observations / findings
  all FK to it; deleting an image would orphan rebuildable inventory.
  Marked as append-only in the model contract.
- **`Workload`** — historical workloads matter for trend reconstruction
  even after `deployed=False`. The inventory reaper flips `deployed`;
  pruning the row would break Snapshot back-references.
- **`WorkloadSignal`** — append-only. The reap flips
  `currently_active=False`, never deletes. Lifecycle of a finding
  depends on signal history surviving past the active phase.
- **`FindingAction`** — accept / acknowledge / false-positive / scheduled
  records are decisions; deleting them rewrites audit history.
- **`SupplyChainIoc`** — feed re-fetch updates in place; withdrawal
  from the feed is currently a no-op (no per-row TTL). Stale IoCs are
  cheap to keep and provide a historical record.
- **`Snapshot`** — pruned by a separate command,
  [`prune_snapshots`](../core/management/commands/prune_snapshots.py),
  using `SNAPSHOT_RETENTION_DAYS` (default 365). Trend charts depend
  on this retention window.
- **`EpssScore` / `KevEntry`** — replaced wholesale by the next
  enrichment refresh; no aging.

---

## 3. Safety rules

The pruning service follows three invariants:

1. **Live state is never pruned.** `IngestQueue` rows in `pending` or
   `processing`, `ImportMark` rows in `open` or `draining`, and
   findings on deployed workloads are excluded by predicate, not by
   age. An accidental clock skew that backdates `last_seen` cannot
   delete a live row because the workload-state predicate still
   protects it.
2. **No cascading delete.** Each predicate filters within one table;
   no `on_delete=CASCADE` walk runs as a side effect. This keeps the
   blast radius of a misconfigured retention to one table.
3. **Idempotent and dry-runnable.** A second `prune_stale_data` run
   after the first finds zero matching rows. `--dry-run` counts what
   would be deleted without touching the DB.

---

## 4. Cadence

Run daily. The command is fast on a healthy DB (predicates use
indexed columns; default deletes run as bulk `qs.delete()`).
Typical placement:

```
04:00 UTC  enrich_fetch --source kev
04:15 UTC  enrich_fetch --source epss
04:30 UTC  reap_safety_net
04:45 UTC  snapshot_capture
05:00 UTC  prune_stale_data
05:15 UTC  prune_snapshots
```

Snapshot operations come after pruning so the snapshot writer sees a
clean operational state. Enrichment runs first so any priority
recompute that's triggered fires before the pruner sees the
post-recompute state.

See [README § Cadence](../README.md#cadence--how-often-to-run-each-command)
for the full operational cadence table.

---

## 5. Tuning

Override per-target retention from the command line:

```bash
manage.py prune_stale_data \
    --ingest-queue-days 30 \
    --findings-days 90 \
    --skip-sbom-components
```

When deciding a value, the questions are:

- **For audit-only tables (`IngestQueue` DONE/FAILED, `ImportMark`
  REAPED).** How far back do you actually replay logs during an
  incident? In practice, never more than ~2 weeks for the queue, ~3
  months for marks.
- **For finding hard-delete.** How long do you want a resolved finding
  to remain in history before disappearing entirely? 180 days is a
  good default — anything older is overwhelmingly noise.
- **For SBOM components.** Trade-off between disk and the cost of
  re-creating a row when an undeployed image comes back online. Re-
  creation is cheap (one INSERT per (image, purl)), so the 90-day
  default is conservative.

---

## 6. Tests

- [core/tests/test_services_pruning.py](../core/tests/test_services_pruning.py)
  — one block per target covering: stale-vs-fresh boundary, active-state
  exclusion, dry-run semantics, idempotence on second run.
- [core/tests/test_prune_stale_data_command.py](../core/tests/test_prune_stale_data_command.py)
  — command wrapper: default flags, `--dry-run`, `--skip-*`, custom
  retention.
