"""Pytest scenario runner — cycle-aware, evaluates `after_import` markers.

Files under `Architecture/mock_tests/<scenario>/imports/` follow the
NN_<kind>.json convention. `001-099` is cycle 1, `101-199` is cycle 2,
`201-299` is cycle 3, etc. Each cycle ends with `NN7_finish.yaml` (or
similar finish file) that flips the cycle's marks to draining; the
runner drains the queue at that boundary.

Some scenarios mix in non-ingest events: `NN0_enrichment_kev.json`
(file-driven enrichment), `NN1_advance_clock.yaml` (no-op stub).

The assertions.yaml may carry an `after_import: <NN>` key on each
assertion. The runner evaluates assertions whose `after_import`
falls in the current cycle's range AFTER the cycle drains.

YAML quirk: scenario `assertions.yaml` files use `kind:` for both the
assertion type AND a nested K8s kind value. The custom loader renames
the second occurrence so the evaluator can read both unambiguously.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

import pytest
import yaml


# ── Custom YAML loader (handles duplicate `kind:` keys) ─────────

class _DupKindLoader(yaml.SafeLoader):
    pass


def _construct_mapping(loader: yaml.Loader, node: yaml.MappingNode):
    out: dict = {}
    saw_kind = False
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=False)
        value = loader.construct_object(value_node, deep=True)
        if key == "kind":
            if not saw_kind:
                out["kind"] = value
                saw_kind = True
            else:
                first = out.get("kind")
                if first in ("workload_exists", "workload_count"):
                    out["workload_kind"] = value
                elif first in ("import_mark", "import_mark_count"):
                    out["mark_kind"] = value
                else:
                    out["kind_value"] = value
        else:
            out[key] = value
    return out


_DupKindLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _construct_mapping
)


REPO_ROOT = Path(__file__).resolve().parents[2]
SCENARIO_ROOT = REPO_ROOT / "Architecture" / "mock_tests"


def _scenario_dirs() -> list[Path]:
    return sorted(p for p in SCENARIO_ROOT.iterdir()
                  if p.is_dir() and (p / "assertions.yaml").is_file())


def _load_yaml(path: Path) -> dict:
    return yaml.load(path.read_text(), Loader=_DupKindLoader)


def _load_yaml_plain(path: Path) -> dict:
    return yaml.safe_load(path.read_text())


_FILENAME_RE = re.compile(r"^(\d+)_")


def _file_nn(p: Path) -> int | None:
    m = _FILENAME_RE.match(p.name)
    return int(m.group(1)) if m else None


def _cycle_for_nn(nn: int) -> int:
    return (nn // 100) + 1


def _split_into_cycles(imports_dir: Path) -> list[tuple[int, list[Path]]]:
    """Return [(cycle_index, [files in lex order])]."""
    files = sorted(p for p in imports_dir.iterdir() if p.is_file())
    by_cycle: dict[int, list[Path]] = {}
    for p in files:
        nn = _file_nn(p)
        if nn is None:
            continue
        by_cycle.setdefault(_cycle_for_nn(nn), []).append(p)
    return sorted(by_cycle.items())


def _scenario_cluster(scenario_dir: Path) -> str:
    for p in (scenario_dir / "imports").iterdir():
        if "finish" in p.name.lower() and p.suffix.lower() in (".yaml", ".yml"):
            doc = _load_yaml_plain(p)
            if isinstance(doc, dict) and (c := doc.get("cluster")):
                return c
    return "prod-payments-1"


# ── Single-cycle harness call ────────────────────────────────────

def _post_cycle(client, scenario_dir: Path, cluster: str, files: list[Path]) -> dict:
    """Run one cycle's worth of fixture files end-to-end via the
    test harness's load_scenario endpoint, by writing them into a
    temporary subdirectory the harness can scoop up.

    Easier path: shape an inline `payloads`/`finishes` body and POST
    that. We do NOT need to write a temp dir.
    """
    payloads: list[dict] = []
    finishes: list[dict] = []
    starts_kinds: set[str] = set()
    enrichment_calls: list[dict] = []
    import_id = ""

    # Pass 0: scan finish files first to learn the cycle's import_id.
    for p in files:
        if "finish" in p.name.lower():
            doc = _load_yaml_plain(p)
            iid = doc.get("import_id")
            if iid:
                import_id = iid
                break

    for p in files:
        name_lower = p.name.lower()

        if "finish" in name_lower:
            doc = _load_yaml_plain(p)
            iid = doc.get("import_id") or import_id
            for f in doc.get("finishes") or []:
                finishes.append({
                    "kind": f["kind"],
                    "observed_count": int(f.get("observed_count") or 0),
                    "import_id": iid,
                })
                starts_kinds.add(f["kind"])
            if not import_id and iid:
                import_id = iid
            continue

        if "enrichment" in name_lower:
            # Two acceptable shapes:
            #  a) Wrapper: {"source": "kev|epss", "path": "..."}
            #  b) Direct KEV/EPSS dump (e.g. CISA JSON). Filename
            #     hints at the source: `..._kev.json`, `..._epss.csv`.
            if p.suffix.lower() == ".json":
                doc = json.loads(p.read_text())
            else:
                doc = _load_yaml_plain(p)
            if isinstance(doc, dict) and "source" in doc and "path" in doc:
                enrichment_calls.append(doc)
            else:
                src = "kev" if "kev" in name_lower else (
                    "epss" if "epss" in name_lower else None
                )
                if src:
                    enrichment_calls.append({
                        "source": src,
                        "path": str(p.resolve()),
                    })
            continue

        if "advance_clock" in name_lower or "clock" in name_lower:
            doc = _load_yaml_plain(p) if p.suffix.lower() in (".yaml", ".yml") else json.loads(p.read_text())
            seconds = doc.get("seconds") if isinstance(doc, dict) else None
            if seconds is not None:
                enrichment_calls.append({
                    "_post_only": "/api/v1/testing/advance_clock/",
                    "_body": {"seconds": int(seconds)},
                })
            for step in (doc.get("then_run") or []):
                ep = step.get("endpoint") or ""
                if "/run_snapshot/" in ep:
                    enrichment_calls.append({"_post_only": "/api/v1/testing/run_snapshot/"})
            continue

        if p.suffix.lower() != ".json":
            continue

        doc = json.loads(p.read_text())

        if isinstance(doc, dict) and "cluster_meta" in doc and "items" in doc:
            payloads.append({
                "kind": "inventory",
                "import_id": import_id or "",
                "payload": doc,
                "complete_snapshot": bool(doc.get("complete_snapshot")),
            })
            starts_kinds.add("inventory")
            continue

        if isinstance(doc, dict) and str(doc.get("kind", "")).endswith("List"):
            for item in doc.get("items") or []:
                ikind = _envelope_kind(item.get("kind"))
                if not ikind:
                    continue
                payloads.append({
                    "kind": ikind,
                    "import_id": import_id or "",
                    "payload": item,
                    "complete_snapshot": False,
                })
                starts_kinds.add(ikind)
            continue

        # Single-item file
        ikind = _envelope_kind(doc.get("kind") if isinstance(doc, dict) else None)
        if ikind:
            payloads.append({
                "kind": ikind,
                "import_id": import_id or "",
                "payload": doc,
                "complete_snapshot": False,
            })
            starts_kinds.add(ikind)

    body = {
        "cluster": cluster,
        "import_id": import_id or "default",
        "starts": [{"kind": k} for k in sorted(starts_kinds)],
        "payloads": payloads,
        "finishes": finishes,
    }
    resp = client.post(
        "/api/v1/testing/load_scenario/",
        content_type="application/json",
        data=json.dumps(body),
    )
    assert resp.status_code == 200, resp.content

    # Apply enrichment / snapshot calls after the ingest cycle.
    for call in enrichment_calls:
        if (post_only := call.get("_post_only")):
            body = call.get("_body") or {}
            resp = client.post(
                post_only,
                content_type="application/json",
                data=json.dumps(body),
            )
            assert resp.status_code == 200, resp.content
            continue
        path = call.get("path") or ""
        if path and not Path(path).is_absolute():
            path = str((scenario_dir / "imports" / path).resolve())
        resp = client.post(
            "/api/v1/testing/run_enrichment/",
            content_type="application/json",
            data=json.dumps({"source": call["source"], "path": path}),
        )
        assert resp.status_code == 200, resp.content

    return resp.json() if resp.status_code == 200 else {}


_ITEM_KIND = {
    "VulnerabilityReport": "trivy.VulnerabilityReport",
    "ConfigAuditReport": "trivy.ConfigAuditReport",
    "ExposedSecretReport": "trivy.ExposedSecretReport",
    "RbacAssessmentReport": "trivy.RbacAssessmentReport",
    "ClusterRbacAssessmentReport": "trivy.ClusterRbacAssessmentReport",
    "InfraAssessmentReport": "trivy.InfraAssessmentReport",
    "ClusterComplianceReport": "trivy.ClusterComplianceReport",
    "PolicyReport": "kyverno.PolicyReport",
    "ClusterPolicyReport": "kyverno.ClusterPolicyReport",
}


def _envelope_kind(item_kind: str | None) -> str | None:
    if not item_kind:
        return None
    return _ITEM_KIND.get(item_kind)


# ── Pytest entry ──────────────────────────────────────────────────

def _is_finish_file(p: Path) -> bool:
    return "finish" in p.name.lower()


def _is_side_event_file(p: Path) -> bool:
    n = p.name.lower()
    return "enrichment" in n or "advance_clock" in n


def _partition_into_units(files: list[Path]) -> list[tuple[str, int, list[Path]]]:
    """Group files into runnable units.

    Returns a list of (unit_kind, marker_nn, files) tuples, where
    `unit_kind` is "cycle" or "side". Cycles are contiguous file
    ranges that end with a finish file; side events are single
    enrichment/advance_clock files. Unmarked / unfinished trailing
    files (if any) form a final cycle.

    The `marker_nn` is what an assertion's `after_import` should
    match against:
      - For a cycle: the cycle's first file NN (1, 101, 201, ...).
      - For a side event: the file's own NN.
    """
    units: list[tuple[str, int, list[Path]]] = []
    pending: list[Path] = []
    pending_first_nn: int | None = None

    for p in files:
        nn = _file_nn(p)
        if nn is None:
            continue

        if _is_side_event_file(p):
            # Flush whatever is pending as a cycle (if any).
            if pending:
                units.append(("cycle", pending_first_nn, pending))
                pending = []
                pending_first_nn = None
            units.append(("side", nn, [p]))
            continue

        if pending_first_nn is None:
            pending_first_nn = nn
        pending.append(p)

        if _is_finish_file(p):
            units.append(("cycle", pending_first_nn, pending))
            pending = []
            pending_first_nn = None

    if pending:
        units.append(("cycle", pending_first_nn, pending))

    # Normalise cycle marker to the cycle's "start NN" — first file's
    # NN inside the cycle, but rounded down to the cycle base (1, 101,
    # 201, ...). The fixture convention treats `after_import: 1` and
    # `after_import: 101` as cycle-end markers.
    out: list[tuple[str, int, list[Path]]] = []
    for kind, marker, fs in units:
        if kind == "cycle" and marker is not None:
            cycle_idx = _cycle_for_nn(marker)
            base = (cycle_idx - 1) * 100 + 1 if cycle_idx > 1 else 1
            marker = base
        out.append((kind, marker, fs))
    return out


def _run_unit(client, scenario_dir: Path, cluster: str, unit: tuple[str, int, list[Path]]) -> None:
    kind, _, files = unit
    if kind == "cycle":
        _post_cycle(client, scenario_dir, cluster, files)
        return

    # Side event — process each file (only one in v1).
    for p in files:
        name_lower = p.name.lower()
        if "enrichment" in name_lower:
            doc = json.loads(p.read_text()) if p.suffix.lower() == ".json" else _load_yaml_plain(p)
            if isinstance(doc, dict) and "source" in doc and "path" in doc:
                src = doc["source"]
                path = doc["path"]
                if path and not Path(path).is_absolute():
                    path = str((scenario_dir / "imports" / path).resolve())
            else:
                src = (
                    "kev" if "kev" in name_lower else
                    "epss" if "epss" in name_lower else None
                )
                path = str(p.resolve())
            if src:
                client.post(
                    "/api/v1/testing/run_enrichment/",
                    content_type="application/json",
                    data=json.dumps({"source": src, "path": path}),
                )
            continue
        if "advance_clock" in name_lower:
            doc = _load_yaml_plain(p) if p.suffix.lower() in (".yaml", ".yml") else json.loads(p.read_text())
            seconds = doc.get("seconds") if isinstance(doc, dict) else None
            if seconds is not None:
                client.post(
                    "/api/v1/testing/advance_clock/",
                    content_type="application/json",
                    data=json.dumps({"seconds": int(seconds)}),
                )
            for step in (doc.get("then_run") or []):
                ep = step.get("endpoint") or ""
                if "/run_snapshot/" in ep:
                    client.post(
                        "/api/v1/testing/run_snapshot/",
                        content_type="application/json",
                        data="{}",
                    )
            continue


@pytest.mark.django_db(transaction=True)
@pytest.mark.parametrize(
    "scenario_dir",
    _scenario_dirs(),
    ids=lambda p: p.name,
)
def test_scenario(scenario_dir: Path, client):
    # 1. Reset.
    resp = client.post("/api/v1/testing/reset/", content_type="application/json", data="{}")
    assert resp.status_code == 200, resp.content

    cluster = _scenario_cluster(scenario_dir)
    spec = _load_yaml(scenario_dir / "assertions.yaml")
    all_assertions = spec.get("assertions") or []
    files = sorted(
        (p for p in (scenario_dir / "imports").iterdir() if p.is_file() and _file_nn(p) is not None),
        key=lambda p: _file_nn(p),
    )

    units = _partition_into_units(files)
    failures: list[str] = []

    for kind, marker, unit_files in units:
        _run_unit(client, scenario_dir, cluster, (kind, marker, unit_files))

        # Evaluate assertions whose after_import == this unit's marker.
        cp_assertions = [a for a in all_assertions if _assertion_nn(a) == marker]
        if cp_assertions:
            body = json.dumps({"assertions": cp_assertions})
            resp = client.post(
                "/api/v1/testing/assert_batch/",
                content_type="application/json",
                data=body,
            )
            assert resp.status_code == 200, resp.content
            payload = resp.json()
            for r in payload["results"]:
                if r["pass"]:
                    continue
                failures.append(
                    f"  marker={marker} [{r['index']}] {r['kind']} → "
                    f"{r['details']}; spec={r['spec']}"
                )

    # Final-pass assertions (no after_import).
    final = [a for a in all_assertions if "after_import" not in a]
    if final:
        body = json.dumps({"assertions": final})
        resp = client.post(
            "/api/v1/testing/assert_batch/",
            content_type="application/json",
            data=body,
        )
        assert resp.status_code == 200, resp.content
        payload = resp.json()
        for r in payload["results"]:
            if r["pass"]:
                continue
            failures.append(
                f"  final [{r['index']}] {r['kind']} → "
                f"{r['details']}; spec={r['spec']}"
            )

    if failures:
        pytest.fail(
            f"{len(failures)} assertion(s) failed:\n"
            + "\n".join(failures)
        )


def _assertion_nn(a: dict) -> int:
    raw = a.get("after_import")
    if raw is None:
        return -1
    try:
        return int(str(raw).lstrip("0") or "0")
    except ValueError:
        return -1


def _assertion_cycle(a: dict) -> int | None:
    """Map an `after_import` marker to a cycle index.

    Accepts integer NN values (1, 101, 201) or quoted strings ("001",
    "101"). Missing marker → assertion is final (evaluated after the
    last cycle). For convenience, `after_import: 1` is treated the
    same as `after_import: 001` — both → cycle 1.
    """
    raw = a.get("after_import")
    if raw is None:
        return None
    try:
        nn = int(str(raw).lstrip("0") or "0")
    except ValueError:
        return None
    if nn == 0:
        return 1
    return _cycle_for_nn(nn) if nn >= 100 else 1
