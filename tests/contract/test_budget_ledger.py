"""TC-12/T12 step 2: family budget ledger and idempotent charge protocol.

The first six coordinates are pure: a ledger dict and a charge list stand in for
``budget_ledger`` / ``budget_charges``, and a fake clock supplies elapsed time.
The final coordinate opens two PostgreSQL connections and only proves that the
conditional ``UPDATE ... WHERE remaining >= charged`` cannot overdraw the family
ledger; it does not claim to model production multi-worker scheduling.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import os
from pathlib import Path
import threading
import uuid

import psycopg
from psycopg import sql
from psycopg.conninfo import conninfo_to_dict, make_conninfo
from psycopg.types.json import Jsonb
import pytest

from datacon import state

ROOT = Path(__file__).resolve().parents[2]
MIGRATIONS = sorted((ROOT / "migrations").glob("*.sql"))


class BudgetDatabase:
    def __init__(self, dsn, connection) -> None:
        self.dsn = dsn
        self.connection = connection


@pytest.fixture
def budget_database():
    """A migrated private schema for the two-connection charge race.

    Contract tests normally stay offline; this fixture exists only for the
    single ``postgres`` coordinate and mirrors the integration skip/fail rule.
    """
    dsn = os.getenv("DATACON_TEST_DATABASE_URL")
    if not dsn:
        if os.getenv("CI", "").strip().lower() not in ("", "0", "false", "no"):
            pytest.fail(
                "CI requires DATACON_TEST_DATABASE_URL; PostgreSQL tests "
                "must not be skipped"
            )
        pytest.skip(
            "set DATACON_TEST_DATABASE_URL to run PostgreSQL integration tests"
        )
    schema_name = f"datacon_budget_{uuid.uuid4().hex}"
    with psycopg.connect(
        dsn, autocommit=True, connect_timeout=5
    ) as admin:
        admin.execute(
            sql.SQL("CREATE SCHEMA {}").format(sql.Identifier(schema_name))
        )
    parameters = conninfo_to_dict(dsn)
    parameters["options"] = f"-csearch_path={schema_name}"
    schema_dsn = make_conninfo(**parameters)
    connection = psycopg.connect(
        schema_dsn, autocommit=True, connect_timeout=5
    )
    try:
        for migration in MIGRATIONS:
            connection.execute(migration.read_text(encoding="utf-8"))
        yield BudgetDatabase(schema_dsn, connection)
    finally:
        connection.close()
        with psycopg.connect(
            dsn, autocommit=True, connect_timeout=5
        ) as admin:
            admin.execute(
                sql.SQL("DROP SCHEMA IF EXISTS {} CASCADE").format(
                    sql.Identifier(schema_name)
                )
            )

FAMILY_ID = "2f1c0f5e-3d7a-4b6c-9f10-2a4b6c8d0e11"
JOB_ID = "0f8fad5b-d9cb-469f-a165-70867728950e"


class FakeClock:
    def __init__(self) -> None:
        self.now = datetime(2099, 1, 1, tzinfo=timezone.utc)

    def advance(self, seconds: float) -> None:
        self.now += timedelta(seconds=seconds)


def _ledger(**overrides) -> dict:
    ledger = {
        "family_id": FAMILY_ID,
        "max_total_seconds": 100,
        "max_fuzz_seconds": 60,
        "remaining_total_seconds": 100,
        "remaining_fuzz_seconds": 60,
    }
    ledger.update(overrides)
    return ledger


def _charge(
    ledger,
    charges,
    *,
    job_id=JOB_ID,
    step_key="build",
    attempt_no=1,
    charge_kind="general",
    elapsed_seconds=0,
    elapsed_fuzz_seconds=0,
):
    return state.charge_budget_local(
        ledger,
        charges,
        family_id=FAMILY_ID,
        job_id=job_id,
        step_key=step_key,
        attempt_no=attempt_no,
        charge_kind=charge_kind,
        elapsed_seconds=elapsed_seconds,
        elapsed_fuzz_seconds=elapsed_fuzz_seconds,
    )


def test_recovery_does_not_charge_twice():
    ledger = _ledger()
    charges: list[dict] = []
    clock = FakeClock()
    clock.advance(12)
    elapsed = (clock.now - datetime(2099, 1, 1, tzinfo=timezone.utc)).total_seconds()

    first = _charge(ledger, charges, elapsed_seconds=elapsed)
    second = _charge(ledger, charges, elapsed_seconds=elapsed)

    assert first.status == "charged", first.status
    assert second.status == "recovered", second.status
    assert len(charges) == 1, "budget charged twice after recovery"
    assert ledger["remaining_total_seconds"] == 88
    assert second.charge["charge_id"] == first.charge["charge_id"]


def test_retry_with_new_attempt_charges_again():
    ledger = _ledger()
    charges: list[dict] = []

    first = _charge(ledger, charges, attempt_no=1, elapsed_seconds=10)
    retry = _charge(ledger, charges, attempt_no=2, elapsed_seconds=10)

    assert first.status == "charged", first.status
    assert retry.status == "charged", "retry was free"
    assert len(charges) == 2
    assert ledger["remaining_total_seconds"] == 80


def test_fuzz_charge_decrements_both_budgets():
    ledger = _ledger()
    charges: list[dict] = []

    outcome = _charge(
        ledger,
        charges,
        step_key="fuzz",
        charge_kind="fuzz",
        elapsed_seconds=10,
        elapsed_fuzz_seconds=4.2,
    )

    assert outcome.status == "charged", outcome.status
    charge = outcome.charge
    assert charge["charge_kind"] == "fuzz"
    assert charge["fuzz_seconds"] == 5
    assert charge["seconds"] == 10
    assert 0 < charge["fuzz_seconds"] <= charge["seconds"]
    assert ledger["remaining_total_seconds"] == 90, (
        "fuzz charge only decremented one budget"
    )
    assert ledger["remaining_fuzz_seconds"] == 55, (
        "fuzz charge only decremented one budget"
    )


def test_exhaustion_returns_budget_exhausted_terminal():
    ledger = _ledger(remaining_total_seconds=5, remaining_fuzz_seconds=5)
    charges: list[dict] = []

    outcome = _charge(ledger, charges, elapsed_seconds=9)

    assert outcome.status == "budget_exhausted", outcome.status
    assert outcome.reason_code == "BUDGET_EXHAUSTED"
    assert ledger["remaining_total_seconds"] == 0
    assert len(charges) == 1

    decision = state.decide_next_round(ledger, round_no=1, max_rounds=8)

    assert not decision.allowed
    assert decision.reason_code == "BUDGET_EXHAUSTED"
    assert decision.next_round_no is None, "exhausted family created another round"


def test_report_budget_includes_fuzz_sub_budget():
    ledger = _ledger(remaining_total_seconds=80, remaining_fuzz_seconds=55)
    charges = [
        {
            "charge_id": str(uuid.uuid4()),
            "family_id": FAMILY_ID,
            "job_id": JOB_ID,
            "step_key": "build",
            "attempt_no": 1,
            "charge_kind": "general",
            "seconds": 10,
            "fuzz_seconds": 0,
        },
        {
            "charge_id": str(uuid.uuid4()),
            "family_id": FAMILY_ID,
            "job_id": JOB_ID,
            "step_key": "fuzz",
            "attempt_no": 1,
            "charge_kind": "fuzz",
            "seconds": 10,
            "fuzz_seconds": 5,
        },
    ]

    summary = state.budget_summary(ledger, charges)

    assert summary["remaining_fuzz_seconds"] == 55
    assert summary["remaining_seconds"] == 80
    assert set(summary) == {
        "max_total_seconds",
        "max_fuzz_seconds",
        "spent_seconds",
        "spent_fuzz_seconds",
        "remaining_seconds",
        "remaining_fuzz_seconds",
    }
    assert summary["spent_seconds"] == 20
    assert summary["spent_fuzz_seconds"] == 5
    assert summary["max_total_seconds"] == 100
    assert summary["max_fuzz_seconds"] == 60


def test_fuzz_cap_uses_min_of_both_budgets():
    # A general build charge drains only the total budget, so the fuzz
    # sub-budget can legitimately exceed the total. The fuzz gate must use the
    # smaller of the two, not either one alone.
    ledger = _ledger(remaining_total_seconds=20, remaining_fuzz_seconds=50)

    gate = state.budget_gate(ledger, fuzz=True)

    assert gate.allowed, "fuzz started with only one budget available"
    assert gate.hard_timeout_seconds == 20

    outcome = _charge(ledger, [], elapsed_seconds=5)
    assert outcome.status == "charged"
    assert ledger["remaining_fuzz_seconds"] > ledger["remaining_total_seconds"]

    empty = _ledger(remaining_total_seconds=0, remaining_fuzz_seconds=50)
    denied = state.budget_gate(empty, fuzz=True)
    assert not denied.allowed
    assert denied.reason_code == "BUDGET_EXHAUSTED"
    assert denied.hard_timeout_seconds == 0


@pytest.mark.postgres
def test_concurrent_charge_cannot_overdraw_family_budget(budget_database):
    family_id = uuid.uuid4()
    child_id = uuid.uuid4()
    budget_database.connection.execute(
        "INSERT INTO jobs (job_id, request, state, stage, submitted_at, "
        "job_contract_version, family_id, job_kind, parent_job_id, round_no, "
        "generation, workflow_synced) "
        "VALUES (%s, %s, 'AGGREGATING', 'family', clock_timestamp(), 2, %s, "
        "'family', NULL, NULL, 1, true)",
        (family_id, Jsonb({"schema_version": 2}), family_id),
    )
    budget_database.connection.execute(
        "INSERT INTO jobs (job_id, request, state, stage, submitted_at, "
        "job_contract_version, family_id, job_kind, parent_job_id, round_no, "
        "generation) "
        "VALUES (%s, %s, 'QUEUED', 'admission', clock_timestamp(), 2, %s, "
        "'round', %s, 2, 1)",
        (child_id, Jsonb({"schema_version": 2}), family_id, family_id),
    )
    state.initialize_budget_ledger(
        budget_database.dsn,
        family_id,
        max_total_seconds=100,
        max_fuzz_seconds=60,
    )

    barrier = threading.Barrier(2)
    outcomes: list = []
    errors: list[BaseException] = []

    def charge(step_key: str) -> None:
        try:
            barrier.wait(timeout=10)
            outcomes.append(
                state.charge_step_budget(
                    budget_database.dsn,
                    family_id=family_id,
                    job_id=child_id,
                    step_key=step_key,
                    attempt_no=1,
                    charge_kind="general",
                    elapsed_seconds=80,
                )
            )
        except BaseException as error:  # pragma: no cover - surfaced below
            errors.append(error)

    threads = [
        threading.Thread(target=charge, args=("build-alpha",)),
        threading.Thread(target=charge, args=("build-beta",)),
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=30)

    assert not errors, errors
    assert len(outcomes) == 2
    summary = state.family_budget_summary(budget_database.dsn, family_id)
    assert summary["remaining_seconds"] >= 0, (
        "remaining_total_seconds is negative"
    )
    assert summary["spent_seconds"] <= 100
    assert sum(1 for outcome in outcomes if outcome.status == "charged") <= 1
