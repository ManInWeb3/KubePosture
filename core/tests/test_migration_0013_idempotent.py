"""Migration 0013 builds `sbomcomp_name_purl` CONCURRENTLY and is therefore
non-atomic: the index build commits independently of the migration
record. A migrate pod killed in between leaves the index behind (valid,
or INVALID when the build itself was interrupted) and the migration must
still apply on the next attempt instead of failing on "already exists"."""
from __future__ import annotations

import pytest
from django.db import connection
from django.db.migrations.executor import MigrationExecutor

BEFORE = ("core", "0012_ingestqueue_claimed_at_help_text")
TARGET = ("core", "0013_sbomcomponent_name_purl_index")
INDEX = "sbomcomp_name_purl"
CREATE = (
    f'CREATE INDEX "{INDEX}" ON "core_sbomcomponent" '
    "((regexp_replace(\"purl\", '@[^@/]*$', '')))"
)


def _index_state():
    with connection.cursor() as cur:
        cur.execute(
            "SELECT i.indisvalid FROM pg_index i JOIN pg_class c ON c.oid = i.indexrelid WHERE c.relname = %s",
            [INDEX],
        )
        row = cur.fetchone()
    return None if row is None else row[0]


@pytest.fixture
def at_0012():
    """Schema at 0012 (index absent, migration unrecorded); restores the
    full schema afterwards so the rest of the suite is unaffected."""
    executor = MigrationExecutor(connection)
    executor.migrate([BEFORE])
    assert _index_state() is None
    try:
        yield
    finally:
        with connection.cursor() as cur:
            cur.execute(f'DROP INDEX IF EXISTS "{INDEX}"')
        executor = MigrationExecutor(connection)
        executor.migrate(executor.loader.graph.leaf_nodes())


def _apply_0013():
    executor = MigrationExecutor(connection)
    executor.loader.build_graph()
    executor.migrate([TARGET])
    assert TARGET in MigrationExecutor(connection).loader.applied_migrations


@pytest.mark.django_db(transaction=True)
def test_applies_when_a_previous_run_left_a_valid_index_behind(at_0012):
    with connection.cursor() as cur:
        cur.execute(CREATE)
    assert _index_state() is True

    _apply_0013()

    assert _index_state() is True


@pytest.mark.django_db(transaction=True)
def test_rebuilds_an_invalid_leftover_from_an_interrupted_build(at_0012):
    with connection.cursor() as cur:
        cur.execute("SELECT rolsuper FROM pg_roles WHERE rolname = current_user")
        if not cur.fetchone()[0]:
            pytest.skip("marking an index INVALID needs a superuser test role")
        cur.execute(CREATE)
        cur.execute(f"UPDATE pg_index SET indisvalid = false WHERE indexrelid = '\"{INDEX}\"'::regclass")
    assert _index_state() is False

    _apply_0013()

    assert _index_state() is True


@pytest.mark.django_db(transaction=True)
def test_fresh_apply_and_reverse(at_0012):
    _apply_0013()
    assert _index_state() is True

    executor = MigrationExecutor(connection)
    executor.migrate([BEFORE])
    assert _index_state() is None
