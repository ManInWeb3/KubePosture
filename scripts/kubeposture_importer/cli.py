"""Command line + orchestration.

    python scripts/import-cluster.py <cluster> --in-cluster
    python scripts/import-cluster.py <cluster> --kubeconfig ~/.kube/config
    python scripts/import-cluster.py <cluster> --from-folder <capture>

One cycle:
  1. collect the snapshot (kube-api or folder);
  2. index it (deployed digests, workload graph), filter the scan CRDs
     for relevance, compute coverage, print one line per kind;
  3. write every bundle to $TMP — any local failure exits before a
     single byte reaches the server;
  4. upload bundles (inventory first, SbomReport last), then commit;
     any failure → abort → exit 1;
  5. print `SUMMARY {json}` for the e2e tests / log scraping.

Exit codes: 0 committed, 1 import aborted, 2 usage / configuration.
"""
from __future__ import annotations

import argparse
import json
import os
import secrets
import signal
import sys
import tempfile
import time
from pathlib import Path

from . import IMPORTER_VERSION
from .bundle import BundleMeta, BundleWriter
from .coverage import (
    ENV_CHECK_KINDS,
    ENV_IGNORE_KINDS,
    compute_coverage,
    log_lines,
    manifest_extra,
    read_kind_set,
    read_threshold,
)
from .http import HTTP_RETRY_BASE_DELAY, HTTP_TIMEOUT_DEFAULT, HttpClient
from .kinds import INVENTORY_ITEM_KINDS, INVENTORY_KIND, SCAN_KINDS
from .pending import check_pending, clear_pending
from .relevance import apply_relevance_filter
from .snapshot_index import build_index
from .sources.folder import collect_from_folder
from .trim import derive_cluster_meta, trim_manifest
from .upload import ImportInterrupted, run_upload_plan

UPLOAD_DEADLINE_DEFAULT = 1500  # < kubeposture-import activeDeadlineSeconds (1800)

_ULID_ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"


def ulid() -> str:
    """26-char Crockford-base32 ULID. Time prefix + random."""
    ts = int(time.time() * 1000)
    head_chars = []
    for _ in range(10):
        head_chars.append(_ULID_ALPHABET[ts & 0x1F])
        ts >>= 5
    head = "".join(reversed(head_chars))
    rand = "".join(_ULID_ALPHABET[secrets.randbits(5)] for _ in range(16))
    return head + rand


def _env_bool(env, name: str, default: bool) -> bool:
    raw = env.get(name)
    if raw is None or raw.strip() == "":
        return default
    return raw.strip().lower() in ("1", "true", "yes", "on")


def _env_int(env, name: str, default: int, *, warn) -> int:
    raw = env.get(name)
    if raw is None or raw.strip() == "":
        return default
    try:
        return int(raw)
    except ValueError:
        warn(f"{name}={raw!r} is not an integer; using {default}")
        return default


def _err(msg: str) -> None:
    print(msg, file=sys.stderr)


def parse_args(argv: list[str] | None = None, env=None) -> argparse.Namespace:
    env = os.environ if env is None else env
    parser = argparse.ArgumentParser(description="KubePosture importer")
    parser.add_argument("cluster_name")
    parser.add_argument("token", nargs="?", default=None,
                        help="Bearer token. Falls back to $KUBEPOSTURE_TOKEN.")
    parser.add_argument("--kubeconfig", default=None)
    parser.add_argument("--in-cluster", action="store_true",
                        help="Use in-cluster ServiceAccount config.")
    parser.add_argument("--from-folder", default=None,
                        help="Replay a captured `kubectl get -o json` dump tree.")
    parser.add_argument(
        "--on-demand-only", action="store_true",
        help=(
            "Pull-pattern trigger mode. Poll /api/v1/imports/pending/; "
            "exit fast if no admin has clicked 'Re-import' or if an "
            "import is already in flight. Otherwise run the full import "
            "and clear the pending flag. Intended for the per-minute "
            "trigger CronJob."
        ),
    )
    parser.add_argument(
        "--no-relevance-filter", action="store_true",
        help="Ship every scan CRD, even for images/workloads not currently deployed "
             "(default: filter; env KUBEPOSTURE_RELEVANCE_FILTER=false also disables).",
    )
    parser.add_argument(
        "--coverage-min-ratio", type=float, default=None,
        help="Coverage ratio below which a WARNING is printed (default 0.9; "
             "env KUBEPOSTURE_COVERAGE_MIN_RATIO). Never affects the exit code.",
    )
    parser.add_argument("--tmp-dir", default=None,
                        help="Where bundles are built (default $KUBEPOSTURE_TMP or the system temp dir).")
    parser.add_argument("--upload-deadline-seconds", type=int, default=None,
                        help=f"Wall-clock budget for uploads+commit (default {UPLOAD_DEADLINE_DEFAULT}; "
                             "env KUBEPOSTURE_UPLOAD_DEADLINE_SECONDS). Past it, abort instead of retrying.")
    parser.add_argument("--summary-json", action="store_true",
                        help="(default on) print a final `SUMMARY {json}` line.")
    args = parser.parse_args(argv)

    args.base_url = env.get("KUBEPOSTURE_URL", "http://localhost:8000")
    args.token = args.token or env.get("KUBEPOSTURE_TOKEN", "")
    args.http_timeout = _env_int(env, "KUBEPOSTURE_HTTP_TIMEOUT", HTTP_TIMEOUT_DEFAULT, warn=_err)
    try:
        args.http_retry_base_delay = float(env.get("KUBEPOSTURE_HTTP_RETRY_BASE_DELAY") or HTTP_RETRY_BASE_DELAY)
    except ValueError:
        _err("KUBEPOSTURE_HTTP_RETRY_BASE_DELAY is not a number; using the default")
        args.http_retry_base_delay = HTTP_RETRY_BASE_DELAY
    args.relevance_filter = (not args.no_relevance_filter) and _env_bool(env, "KUBEPOSTURE_RELEVANCE_FILTER", True)
    args.coverage_threshold = (
        args.coverage_min_ratio if args.coverage_min_ratio is not None else read_threshold(env, warn=_err)
    )
    args.coverage_ignore_kinds = read_kind_set(env, ENV_IGNORE_KINDS)
    args.coverage_check_kinds = read_kind_set(env, ENV_CHECK_KINDS)
    args.tmp_dir = Path(args.tmp_dir or env.get("KUBEPOSTURE_TMP") or tempfile.gettempdir())
    args.upload_deadline = (
        args.upload_deadline_seconds if args.upload_deadline_seconds is not None
        else _env_int(env, "KUBEPOSTURE_UPLOAD_DEADLINE_SECONDS", UPLOAD_DEADLINE_DEFAULT, warn=_err)
    )
    args.log_level = (env.get("KUBEPOSTURE_LOG_LEVEL") or "info").lower()
    args.cleanup_failed_jobs = _env_bool(env, "KUBEPOSTURE_CLEANUP_FAILED_JOBS", False)
    args.k8s_namespace = env.get("KUBEPOSTURE_NAMESPACE", "")
    args.cronjob_name = env.get("KUBEPOSTURE_CRONJOB_NAME", "")
    return args


# ── one cycle ──────────────────────────────────────────────────────


def build_bundles(
    *,
    cluster: str,
    import_id: str,
    by_kind: dict,
    tmp_dir: Path,
    relevance_filter: bool,
    coverage_threshold: float,
    coverage_ignore_kinds: frozenset[str] = frozenset(),
    coverage_check_kinds: frozenset[str] = frozenset(),
    debug: bool = False,
    out=print,
    err=_err,
) -> tuple[list[BundleMeta], dict]:
    """Index → filter → coverage → bundle files. Returns the bundles in
    upload order and the per-kind summary."""
    cluster_meta = derive_cluster_meta(cluster, by_kind)
    idx = build_index(by_kind)

    # Only kinds whose CRD is present (absent CRDs are not part of the import).
    scan_items = {env_kind: list(by_kind[crd_kind]) for crd_kind, env_kind in SCAN_KINDS if crd_kind in by_kind}
    filtered, stats = apply_relevance_filter(scan_items, idx, enabled=relevance_filter)

    summary: dict = {"kinds": {}}
    coverage = {}
    for kind in filtered:
        cov = compute_coverage(
            kind, stats[kind], idx, threshold=coverage_threshold,
            ignore_kinds=coverage_ignore_kinds, check_kinds=coverage_check_kinds,
        )
        coverage[kind] = cov
        for level, line in log_lines(stats[kind], cov):
            (out if level == "INFO" else err)(line if level == "INFO" else f"{level} {line}")
        if debug and stats[kind].unmatched_digests:
            err(f"filter.unmatched kind={kind} digests={','.join(sorted(stats[kind].unmatched_digests))}")
        summary["kinds"][kind] = {
            **stats[kind].as_dict(),
            "expected": cov.expected, "matched": cov.matched,
            "ratio": None if cov.ratio is None else round(cov.ratio, 4), "status": cov.status,
        }
    if debug:
        for digest, sources in sorted(idx.digest_sources.items()):
            err(f"deployed_digest {digest} sources={';'.join(sources)}")
    summary["deployed_digests"] = len(idx.deployed_digests)
    summary["controllers"] = len(idx.controllers)

    bundles: list[BundleMeta] = []
    try:
        inventory_items = (
            trim_manifest(it) for k in sorted(INVENTORY_ITEM_KINDS) for it in (by_kind.get(k) or [])
        )
        with BundleWriter(cluster=cluster, import_id=import_id, kind=INVENTORY_KIND,
                          tmp_dir=tmp_dir, complete_snapshot=True) as w:
            w.write_inventory_envelope(cluster_meta, inventory_items)
            bundles.append(w.finish(extra=manifest_extra(None, relevance_filter=relevance_filter)))
        for kind, items in filtered.items():
            with BundleWriter(cluster=cluster, import_id=import_id, kind=kind, tmp_dir=tmp_dir) as w:
                for item in items:
                    w.write_item(item)
                bundles.append(w.finish(
                    coverage=coverage[kind].manifest_coverage(),
                    extra=manifest_extra(stats[kind], relevance_filter=relevance_filter),
                ))
            summary["kinds"][kind]["count"] = len(items)
    except BaseException:
        for meta in bundles:
            meta.unlink()
        raise
    summary["kinds"][INVENTORY_KIND] = {"count": 1}
    summary["bundle_bytes"] = sum(b.compressed_bytes for b in bundles)
    summary["uncompressed_bytes"] = sum(b.uncompressed_bytes for b in bundles)
    return bundles, summary


def run_cycle(*, args: argparse.Namespace, by_kind: dict, out=print, err=_err) -> tuple[int, dict]:
    import_id = ulid()
    out(f"\n== import_id={import_id} ==")
    started = time.monotonic()
    summary: dict = {"import_id": import_id, "cluster": args.cluster_name,
                     "importer_version": IMPORTER_VERSION, "relevance_filter": args.relevance_filter}
    try:
        bundles, built = build_bundles(
            cluster=args.cluster_name, import_id=import_id, by_kind=by_kind, tmp_dir=args.tmp_dir,
            relevance_filter=args.relevance_filter, coverage_threshold=args.coverage_threshold,
            coverage_ignore_kinds=args.coverage_ignore_kinds, coverage_check_kinds=args.coverage_check_kinds,
            debug=args.log_level == "debug", out=out, err=err,
        )
    except ImportInterrupted:
        err("  SIGTERM received while building bundles; nothing was sent")
        summary.update({"rc": 1, "aborted": True, "stage": "build"})
        return 1, summary
    summary.update(built)

    client = HttpClient(
        args.base_url, args.token, timeout=args.http_timeout,
        base_delay=args.http_retry_base_delay, deadline_at=started + args.upload_deadline,
    )
    try:
        rc = run_upload_plan(
            client, import_id=import_id, cluster=args.cluster_name, bundles=bundles,
            importer={"version": IMPORTER_VERSION, "relevance_filter": args.relevance_filter},
            out=out, err=err,
        )
    finally:
        for meta in bundles:
            meta.unlink()
    summary.update({"rc": rc, "aborted": rc != 0, "elapsed_seconds": round(time.monotonic() - started, 2)})
    return rc, summary


def _install_sigterm_handler() -> None:
    def _handler(signum, frame):
        raise ImportInterrupted()
    try:
        signal.signal(signal.SIGTERM, _handler)
    except (ValueError, OSError):  # not in the main thread
        pass


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    if not args.token:
        _err("error: token required (positional arg or $KUBEPOSTURE_TOKEN)")
        return 2
    _install_sigterm_handler()

    client = HttpClient(args.base_url, args.token, timeout=args.http_timeout)
    requested_at: str | None = None
    if args.on_demand_only:
        info = check_pending(client, cluster=args.cluster_name)
        if info is None:
            return 1
        if not info.get("pending"):
            print(f"on-demand: no pending request for {args.cluster_name}, exiting")
            return 0
        if info.get("in_flight"):
            print(f"on-demand: pending request for {args.cluster_name} but import is already in flight, exiting")
            return 0
        requested_at = info.get("requested_at")
        print(f"on-demand: pending request for {args.cluster_name} (requested_at={requested_at}), running full import")

    client_module = None
    if args.from_folder:
        root = Path(args.from_folder).resolve()
        if not root.is_dir():
            _err(f"error: --from-folder path is not a directory: {root}")
            return 2
        print(f"Reading captured cluster from {root}")
        by_kind = collect_from_folder(root)
    else:
        from .sources.kube import collect_from_kube_api, load_kube_config
        print("Loading kube-api config...")
        try:
            client_module = load_kube_config(args.kubeconfig, args.in_cluster)
        except Exception as e:
            _err(f"error: failed to load kube config: {e}")
            return 2
        print("Listing from kube-api...")
        by_kind = collect_from_kube_api(client_module)

    rc, summary = run_cycle(args=args, by_kind=by_kind)
    print("SUMMARY " + json.dumps(summary, sort_keys=True))

    # Only clear the pending flag on successful import. A newer click
    # mid-import is preserved server-side via the conditional clear.
    if args.on_demand_only and rc == 0 and requested_at:
        clear_pending(client, cluster=args.cluster_name, satisfied_at=requested_at)

    if rc == 0 and client_module is not None and args.cleanup_failed_jobs:
        from .sources.kube import cleanup_failed_sibling_jobs
        if args.k8s_namespace and args.cronjob_name:
            cleanup_failed_sibling_jobs(client_module, namespace=args.k8s_namespace, cronjob_name=args.cronjob_name)
        else:
            _err("  cleanup: KUBEPOSTURE_NAMESPACE/KUBEPOSTURE_CRONJOB_NAME not set, skipping")

    return rc
