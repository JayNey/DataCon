"""TC-11/T10: the real v2 ``submit`` path creates one family job."""

from __future__ import annotations

import json
import threading
import time

import psycopg
import pytest

from datacon import contracts, state, store

pytestmark = pytest.mark.postgres

REQUEST_V2 = {
    "schema_version": 2,
    "cve_id": "CVE-2099-0001",
    "target": {
        "kind": "source",
        "case_id": "fixture-c-parser",
        "goal": "验证固定输入在缺陷版触发预期 ASan 异常",
    },
}


def _submit(database, request):
    parsed = contracts.parse_request(json.dumps(request))
    return store.submit(database.dsn, parsed)


def test_submit_v2_returns_family_job(isolated_database):
    result = _submit(isolated_database, REQUEST_V2)
    family_id = result["job_id"]
    assert result["state"] == "AGGREGATING"

    row = isolated_database.connection.execute(
        "SELECT job_kind, family_id, parent_job_id, round_no, "
        "job_contract_version, state FROM jobs WHERE job_id = %s",
        (family_id,),
    ).fetchone()
    assert row[0] == "family"
    assert str(row[1]) == family_id
    assert row[2:4] == (None, None)
    assert row[4:6] == (2, "AGGREGATING"), (
        "v2 submit did not create a family identity row"
    )

    review = isolated_database.connection.execute(
        "SELECT count(*) FROM reviews WHERE job_id = %s", (family_id,)
    ).fetchone()[0]
    assert review == 0


def test_submit_v2_binary_family_is_archived_blocked(isolated_database, tmp_path, monkeypatch):
    monkeypatch.setenv("DATACON_EVIDENCE_ROOT", str(tmp_path / "evidence"))
    request = dict(REQUEST_V2)
    request["target"] = dict(REQUEST_V2["target"], kind="binary")

    result = _submit(isolated_database, request)
    family_id = result["job_id"]
    assert result["state"] == "BLOCKED"

    row = isolated_database.connection.execute(
        "SELECT job_kind, job_contract_version, state, reason_code, "
        "evidence_status, evidence_path, evidence_digest "
        "FROM jobs WHERE job_id = %s",
        (family_id,),
    ).fetchone()
    assert row[0:2] == ("family", 2)
    assert row[2:4] == ("BLOCKED", "UNSUPPORTED_TARGET")
    assert row[4] == "archived", "binary v2 family was left without evidence"
    assert row[5] and row[6]


def _wait_for_a_shared_release_lock_wait(database, timeout=10.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        with psycopg.connect(
            database.dsn, autocommit=True, connect_timeout=5
        ) as probe:
            waiting = probe.execute(
                "SELECT count(*) FROM pg_locks AS locks "
                "JOIN pg_stat_activity AS activity USING (pid) "
                "WHERE locks.locktype = 'advisory' AND NOT locks.granted "
                "AND activity.datname = current_database() "
                "AND activity.query LIKE '%pg_advisory_xact_lock_shared%'"
            ).fetchone()[0]
        if waiting:
            return True
        time.sleep(0.02)
    return False


def test_submit_waits_for_the_release_promotion_lock(isolated_database):
    key = state.RELEASE_LOCK_PREFIX + state.RELEASE_ENVIRONMENT
    holder = psycopg.connect(isolated_database.dsn, connect_timeout=5)
    result = {}
    errors = []

    def runner():
        try:
            result["value"] = _submit(isolated_database, REQUEST_V2)
        except BaseException as error:  # noqa: BLE001 - re-raised by the caller
            errors.append(error)

    thread = None
    try:
        holder.execute(
            "SELECT pg_advisory_xact_lock(hashtext(%s))", (key,)
        )
        thread = threading.Thread(target=runner, daemon=True)
        thread.start()
        waited = _wait_for_a_shared_release_lock_wait(isolated_database)
    finally:
        holder.commit()
        holder.close()

    assert thread is not None
    thread.join(timeout=30)
    assert not thread.is_alive(), "submit did not finish after the lock release"
    if errors:
        raise errors[0]
    assert waited, "submit never queued on the shared release lock"

    submitted = result["value"]
    assert submitted["state"] == "AGGREGATING"
    row = isolated_database.connection.execute(
        "SELECT job_kind, job_contract_version, state FROM jobs WHERE job_id = %s",
        (submitted["job_id"],),
    ).fetchone()
    assert row == ("family", 2, "AGGREGATING")
