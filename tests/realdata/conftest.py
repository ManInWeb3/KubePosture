"""Discovery of anonymised real-cluster captures under fixtures/real/.
Every module here is `realdata`-marked and skips when none exist."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
REAL = REPO / "fixtures" / "real"


def real_fixture_dirs() -> list[Path]:
    if not REAL.is_dir():
        return []
    return sorted(p for p in REAL.iterdir() if p.is_dir() and (p / "kubeapi").is_dir())


@pytest.fixture(params=real_fixture_dirs() or [None], ids=lambda p: p.name if p else "no-fixtures")
def fixture_dir(request) -> Path:
    if request.param is None:
        pytest.skip("no anonymised captures under fixtures/real/ (see fixtures/real/README.md)")
    return request.param


@pytest.fixture
def by_kind(fixture_dir):
    from kubeposture_importer.sources.folder import collect_from_folder
    return collect_from_folder(fixture_dir)


@pytest.fixture
def golden(fixture_dir):
    def _load(name: str):
        path = fixture_dir / "golden" / name
        if not path.is_file():
            pytest.skip(f"{path.relative_to(REPO)} missing — run anonymize-fixture.py --write-golden")
        return json.loads(path.read_text())
    return _load
