"""Captured-folder source: `kubectl get <kind> -A -o json` per file, plain
or gzip-compressed (`*.json.gz`, how fixtures/real/ is stored)."""
from __future__ import annotations

import gzip
import json
from pathlib import Path

from ..kinds import FROM_FOLDER_KUBEAPI, FROM_FOLDER_KYVERNO, FROM_FOLDER_TRIVY


def _read_json(path: Path):
    if path.suffix == ".gz":
        with gzip.open(path, "rt", encoding="utf-8") as fh:
            return json.load(fh)
    return json.loads(path.read_text())


def _find(directory: Path, fname: str) -> Path | None:
    for candidate in (directory / fname, directory / (fname + ".gz")):
        if candidate.is_file():
            return candidate
    return None


def collect_from_folder(root: Path) -> dict:
    """Read a captured kubectl-dump tree. A file may be a `*List`
    wrapper, a bare list, or a single object. A missing file leaves its
    kind ABSENT (CRD not captured); an empty `items` yields `[]`."""
    out: dict[str, list[dict]] = {}

    def _read(rel_dir: str, mapping: dict[str, str]):
        d = root / rel_dir
        if not d.is_dir():
            return
        for fname, kind in mapping.items():
            p = _find(d, fname)
            if p is None:
                continue
            doc = _read_json(p)
            items = doc.get("items") if isinstance(doc, dict) else None
            if items is None and isinstance(doc, list):
                items = doc
            elif items is None:
                items = [doc]
            for it in items:
                if isinstance(it, dict):
                    it.setdefault("kind", kind)
            out.setdefault(kind, []).extend(items or [])

    _read("kubeapi", FROM_FOLDER_KUBEAPI)
    _read("trivy", FROM_FOLDER_TRIVY)
    _read("kyverno", FROM_FOLDER_KYVERNO)

    ver_path = _find(root / "kubeapi", "version.json")
    if ver_path is not None:
        ver_doc = _read_json(ver_path)
        git_version = ""
        if isinstance(ver_doc, dict):
            git_version = ver_doc.get("gitVersion") or (ver_doc.get("serverVersion") or {}).get("gitVersion") or ""
        out["__version__"] = {"git_version": git_version}
    return out
