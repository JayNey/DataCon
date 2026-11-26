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

from datacon import jsonutil, state

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
        "VALUES (%s, %s, 'RUNNING', 'build', clock_timestamp(), 2, %s, "
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


def test_budget_numeric_validation_and_zero_elapsed_fuzz_and_round_reason_code():
    ledger = _ledger()
    for bad in (float("nan"), float("inf"), float("-inf"), True, -1):
        with pytest.raises(state.StateError):
            _charge(ledger, [], elapsed_seconds=bad)
        with pytest.raises(state.StateError):
            state.compute_budget_charge(
                ledger, charge_kind="general", elapsed_seconds=bad
            )
        with pytest.raises(state.StateError):
            state.compute_budget_charge(
                ledger,
                charge_kind="fuzz",
                elapsed_seconds=1,
                elapsed_fuzz_seconds=bad,
            )

    assert state.compute_budget_charge(
        ledger, charge_kind="fuzz", elapsed_seconds=1.2, elapsed_fuzz_seconds=0.2
    ) == (2, 1)
    assert state.compute_budget_charge(
        ledger, charge_kind="fuzz", elapsed_seconds=0, elapsed_fuzz_seconds=0
    ) == (1, 1)

    charges: list[dict] = []
    zero_fuzz = _charge(
        ledger,
        charges,
        step_key="fuzz-zero",
        charge_kind="fuzz",
        elapsed_seconds=0,
        elapsed_fuzz_seconds=0,
    )
    assert zero_fuzz.status == "charged", zero_fuzz.status
    assert zero_fuzz.charge is not None
    assert zero_fuzz.charge["seconds"] == 1
    assert zero_fuzz.charge["fuzz_seconds"] == 1
    assert ledger["remaining_total_seconds"] == 99
    assert ledger["remaining_fuzz_seconds"] == 59

    round_limit = state.decide_next_round(ledger, round_no=8, max_rounds=8)
    assert not round_limit.allowed
    assert round_limit.reason_code == "BUDGET_EXHAUSTED"
    assert round_limit.sub_reason == "ROUND_BEYOND_MAX_ROUNDS"
    assert round_limit.next_round_no is None


def test_budget_summary_rejects_unreconciled_ledger():
    with pytest.raises(state.StateError, match="reconcile"):
        state.budget_summary(_ledger(remaining_total_seconds=50), [])
    with pytest.raises(state.StateError, match="reconcile"):
        state.budget_summary(_ledger(remaining_fuzz_seconds=50), [])


@pytest.mark.postgres
def test_postgres_charge_step_budget_recovery_retry_fuzz_exhaustion_and_reconciliation(
    budget_database,
):
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
        "VALUES (%s, %s, 'RUNNING', 'build', clock_timestamp(), 2, %s, "
        "'round', %s, 2, 1)",
        (child_id, Jsonb({"schema_version": 2}), family_id, family_id),
    )
    state.initialize_budget_ledger(
        budget_database.dsn,
        family_id,
        max_total_seconds=100,
        max_fuzz_seconds=60,
    )

    first = state.charge_step_budget(
        budget_database.dsn,
        family_id=family_id,
        job_id=child_id,
        step_key="build",
        attempt_no=1,
        charge_kind="general",
        elapsed_seconds=10,
    )
    assert first.status == "charged"
    assert first.charge is not None
    assert jsonutil.canonical_bytes(first.charge)

    recovered = state.charge_step_budget(
        budget_database.dsn,
        family_id=family_id,
        job_id=child_id,
        step_key="build",
        attempt_no=1,
        charge_kind="general",
        elapsed_seconds=10,
    )
    assert recovered.status == "recovered"
    assert recovered.charge == first.charge
    assert jsonutil.canonical_bytes(recovered.charge) == jsonutil.canonical_bytes(
        first.charge
    )

    retry = state.charge_step_budget(
        budget_database.dsn,
        family_id=family_id,
        job_id=child_id,
        step_key="build",
        attempt_no=2,
        charge_kind="general",
        elapsed_seconds=5,
    )
    assert retry.status == "charged"

    fuzz_frac = state.charge_step_budget(
        budget_database.dsn,
        family_id=family_id,
        job_id=child_id,
        step_key="fuzz-frac",
        attempt_no=1,
        charge_kind="fuzz",
        elapsed_seconds=0.2,
        elapsed_fuzz_seconds=0.2,
    )
    assert fuzz_frac.status == "charged"
    assert fuzz_frac.charge is not None
    assert fuzz_frac.charge["seconds"] == 1
    assert fuzz_frac.charge["fuzz_seconds"] == 1

    fuzz_zero = state.charge_step_budget(
        budget_database.dsn,
        family_id=family_id,
        job_id=child_id,
        step_key="fuzz-zero",
        attempt_no=1,
        charge_kind="fuzz",
        elapsed_seconds=0,
        elapsed_fuzz_seconds=0,
    )
    assert fuzz_zero.status == "charged"
    assert fuzz_zero.charge is not None
    assert fuzz_zero.charge["seconds"] == 1
    assert fuzz_zero.charge["fuzz_seconds"] == 1

    exhausted = state.charge_step_budget(
        budget_database.dsn,
        family_id=family_id,
        job_id=child_id,
        step_key="replay",
        attempt_no=1,
        charge_kind="general",
        elapsed_seconds=100,
    )
    assert exhausted.status == "budget_exhausted"
    assert exhausted.reason_code == "BUDGET_EXHAUSTED"

    summary = state.family_budget_summary(budget_database.dsn, family_id)
    assert summary == {
        "max_total_seconds": 100,
        "max_fuzz_seconds": 60,
        "spent_seconds": 100,
        "spent_fuzz_seconds": 2,
        "remaining_seconds": 0,
        "remaining_fuzz_seconds": 58,
    }

    budget_database.connection.execute(
        "UPDATE budget_ledger SET remaining_total_seconds = 1 WHERE family_id = %s",
        (family_id,),
    )
    with pytest.raises(state.StateError, match="reconcile"):
        state.family_budget_summary(budget_database.dsn, family_id)


@pytest.mark.postgres
def test_postgres_charge_step_budget_rejects_wrong_family_and_family_self_job(
    budget_database,
):
    family_a = uuid.uuid4()
    family_b = uuid.uuid4()
    child_b = uuid.uuid4()
    for fid in (family_a, family_b):
        budget_database.connection.execute(
            "INSERT INTO jobs (job_id, request, state, stage, submitted_at, "
            "job_contract_version, family_id, job_kind, parent_job_id, round_no, "
            "generation, workflow_synced) "
            "VALUES (%s, %s, 'AGGREGATING', 'family', clock_timestamp(), 2, %s, "
            "'family', NULL, NULL, 1, true)",
            (fid, Jsonb({"schema_version": 2}), fid),
        )
        state.initialize_budget_ledger(
            budget_database.dsn,
            fid,
            max_total_seconds=100,
            max_fuzz_seconds=60,
        )
    budget_database.connection.execute(
        "INSERT INTO jobs (job_id, request, state, stage, submitted_at, "
        "job_contract_version, family_id, job_kind, parent_job_id, round_no, "
        "generation) "
        "VALUES (%s, %s, 'RUNNING', 'build', clock_timestamp(), 2, %s, "
        "'round', %s, 1, 1)",
        (child_b, Jsonb({"schema_version": 2}), family_b, family_b),
    )

    with pytest.raises(state.StateError):
        state.charge_step_budget(
            budget_database.dsn,
            family_id=family_a,
            job_id=family_a,
            step_key="build",
            attempt_no=1,
            charge_kind="general",
            elapsed_seconds=5,
        )

    with pytest.raises(state.StateError):
        state.charge_step_budget(
            budget_database.dsn,
            family_id=family_a,
            job_id=child_b,
            step_key="build",
            attempt_no=1,
            charge_kind="general",
            elapsed_seconds=5,
        )


def test_charge_budget_local_rejects_cross_family_recovery():
    ledger = _ledger()
    charges: list[dict] = []
    first = _charge(ledger, charges, elapsed_seconds=10)
    assert first.status == "charged"

    other_family = str(uuid.uuid4())
    with pytest.raises(state.StateError, match="different family"):
        state.charge_budget_local(
            ledger,
            charges,
            family_id=other_family,
            job_id=JOB_ID,
            step_key="build",
            attempt_no=1,
            charge_kind="general",
            elapsed_seconds=10,
        )


def test_budget_summary_rejects_invalid_ranges_and_booleans():
    # Negative charge cancelling out a positive charge so spent+remaining==max
    with pytest.raises(state.StateError):
        state.budget_summary(
            _ledger(remaining_total_seconds=100, remaining_fuzz_seconds=60),
            [
                {"seconds": -10, "fuzz_seconds": 0},
                {"seconds": 10, "fuzz_seconds": 0},
            ],
        )
    # Negative charge pushing remaining_total_seconds above max_total_seconds
    with pytest.raises(state.StateError):
        state.budget_summary(
            _ledger(remaining_total_seconds=110, remaining_fuzz_seconds=60),
            [{"seconds": -10, "fuzz_seconds": 0}],
        )
    # Negative fuzz charge cancelling out a positive fuzz charge
    with pytest.raises(state.StateError):
        state.budget_summary(
            _ledger(remaining_total_seconds=90, remaining_fuzz_seconds=60),
            [
                {"seconds": 5, "fuzz_seconds": -5},
                {"seconds": 5, "fuzz_seconds": 5},
            ],
        )
    # fuzz_seconds > seconds
    with pytest.raises(state.StateError):
        state.budget_summary(
            _ledger(remaining_total_seconds=95, remaining_fuzz_seconds=50),
            [{"seconds": 5, "fuzz_seconds": 10}],
        )
    # remaining_fuzz_seconds > max_fuzz_seconds
    with pytest.raises(state.StateError):
        state.budget_summary(
            _ledger(remaining_total_seconds=100, remaining_fuzz_seconds=70),
            [{"seconds": 0, "fuzz_seconds": -10}],
        )
    # Invalid caps
    with pytest.raises(state.StateError):
        state.budget_summary(
            _ledger(
                max_total_seconds=0,
                max_fuzz_seconds=0,
                remaining_total_seconds=0,
                remaining_fuzz_seconds=0,
            ),
            [],
        )
    with pytest.raises(state.StateError):
        state.budget_summary(
            _ledger(
                max_total_seconds=50,
                max_fuzz_seconds=60,
                remaining_total_seconds=50,
                remaining_fuzz_seconds=60,
            ),
            [],
        )
    # Boolean values in ledger or charges
    with pytest.raises(state.StateError):
        state.budget_summary(
            _ledger(
                max_total_seconds=True,
                max_fuzz_seconds=0,
                remaining_total_seconds=1,
                remaining_fuzz_seconds=0,
            ),
            [],
        )
    with pytest.raises(state.StateError):
        state.budget_summary(
            _ledger(remaining_total_seconds=99, remaining_fuzz_seconds=60),
            [{"seconds": True, "fuzz_seconds": False}],
        )


@pytest.mark.postgres
def test_postgres_charge_step_budget_ledger_is_canonical_json(budget_database):
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
        "VALUES (%s, %s, 'RUNNING', 'build', clock_timestamp(), 2, %s, "
        "'round', %s, 2, 1)",
        (child_id, Jsonb({"schema_version": 2}), family_id, family_id),
    )
    state.initialize_budget_ledger(
        budget_database.dsn,
        family_id,
        max_total_seconds=20,
        max_fuzz_seconds=10,
    )

    charged = state.charge_step_budget(
        budget_database.dsn,
        family_id=family_id,
        job_id=child_id,
        step_key="build",
        attempt_no=1,
        charge_kind="general",
        elapsed_seconds=5,
    )
    assert charged.status == "charged"
    assert charged.ledger["family_id"] == str(family_id)
    assert jsonutil.canonical_bytes(charged.ledger)

    recovered = state.charge_step_budget(
        budget_database.dsn,
        family_id=family_id,
        job_id=child_id,
        step_key="build",
        attempt_no=1,
        charge_kind="general",
        elapsed_seconds=5,
    )
    assert recovered.status == "recovered"
    assert recovered.ledger["family_id"] == str(family_id)
    assert jsonutil.canonical_bytes(recovered.ledger)

    exhausted_on_charge = state.charge_step_budget(
        budget_database.dsn,
        family_id=family_id,
        job_id=child_id,
        step_key="replay",
        attempt_no=1,
        charge_kind="general",
        elapsed_seconds=50,
    )
    assert exhausted_on_charge.status == "budget_exhausted"
    assert exhausted_on_charge.ledger["family_id"] == str(family_id)
    assert jsonutil.canonical_bytes(exhausted_on_charge.ledger)

    exhausted_at_gate = state.charge_step_budget(
        budget_database.dsn,
        family_id=family_id,
        job_id=child_id,
        step_key="replay-2",
        attempt_no=1,
        charge_kind="general",
        elapsed_seconds=1,
    )
    assert exhausted_at_gate.status == "budget_exhausted"
    assert exhausted_at_gate.ledger["family_id"] == str(family_id)
    assert jsonutil.canonical_bytes(exhausted_at_gate.ledger)


@pytest.mark.postgres
def test_postgres_budget_ledger_apis_return_consistent_json_safe_records(
    budget_database,
):
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
        "VALUES (%s, %s, 'RUNNING', 'build', clock_timestamp(), 2, %s, "
        "'round', %s, 1, 1)",
        (child_id, Jsonb({"schema_version": 2}), family_id, family_id),
    )

    assert state.load_budget_ledger(budget_database.dsn, uuid.uuid4()) is None

    initialized = state.initialize_budget_ledger(
        budget_database.dsn,
        family_id,
        max_total_seconds=100,
        max_fuzz_seconds=60,
    )
    loaded = state.load_budget_ledger(budget_database.dsn, family_id)
    assert loaded is not None
    charged = state.charge_step_budget(
        budget_database.dsn,
        family_id=family_id,
        job_id=child_id,
        step_key="build",
        attempt_no=1,
        charge_kind="general",
        elapsed_seconds=5,
    )

    for record in (initialized, loaded, charged.ledger):
        assert type(record["family_id"]) is str
        assert record["family_id"] == str(family_id)
        assert type(record["updated_at"]) is str
        assert jsonutil.canonical_bytes(record)
    assert initialized["family_id"] == loaded["family_id"] == charged.ledger["family_id"]


def test_budget_helpers_reject_non_mapping_bool_negative_and_cross_family_ledger():
    for bad_ledger in (None, [("remaining_total_seconds", 10)], "bad"):
        with pytest.raises(state.StateError):
            state.budget_gate(bad_ledger)  # type: ignore[arg-type]
        with pytest.raises(state.StateError):
            state.compute_budget_charge(
                bad_ledger,  # type: ignore[arg-type]
                charge_kind="general",
                elapsed_seconds=1,
            )
        with pytest.raises(state.StateError):
            state.charge_budget_local(
                bad_ledger,  # type: ignore[arg-type]
                [],
                family_id=FAMILY_ID,
                job_id=JOB_ID,
                step_key="build",
                attempt_no=1,
                charge_kind="general",
                elapsed_seconds=1,
            )

    for bad_value in (True, False, -1):
        with pytest.raises(state.StateError):
            state.budget_gate(_ledger(remaining_total_seconds=bad_value))
        with pytest.raises(state.StateError):
            state.budget_gate(
                _ledger(remaining_fuzz_seconds=bad_value), fuzz=True
            )
        with pytest.raises(state.StateError):
            state.compute_budget_charge(
                _ledger(remaining_total_seconds=bad_value),
                charge_kind="general",
                elapsed_seconds=1,
            )
        with pytest.raises(state.StateError):
            state.compute_budget_charge(
                _ledger(remaining_fuzz_seconds=bad_value),
                charge_kind="fuzz",
                elapsed_seconds=1,
                elapsed_fuzz_seconds=1,
            )

    ledger = _ledger()
    charges: list[dict] = []
    other_family = str(uuid.uuid4())
    with pytest.raises(state.StateError, match="different family"):
        state.charge_budget_local(
            ledger,
            charges,
            family_id=other_family,
            job_id=JOB_ID,
            step_key="build",
            attempt_no=1,
            charge_kind="general",
            elapsed_seconds=5,
        )
    assert charges == []
    assert ledger["remaining_total_seconds"] == 100


@pytest.mark.postgres
def test_postgres_charge_step_budget_rejects_awaiting_review_and_terminal_new_charges_but_recovers(
    budget_database,
):
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
        "VALUES (%s, %s, 'RUNNING', 'build', clock_timestamp(), 2, %s, "
        "'round', %s, 1, 1)",
        (child_id, Jsonb({"schema_version": 2}), family_id, family_id),
    )
    state.initialize_budget_ledger(
        budget_database.dsn,
        family_id,
        max_total_seconds=100,
        max_fuzz_seconds=60,
    )

    first = state.charge_step_budget(
        budget_database.dsn,
        family_id=family_id,
        job_id=child_id,
        step_key="build",
        attempt_no=1,
        charge_kind="general",
        elapsed_seconds=10,
    )
    assert first.status == "charged"

    budget_database.connection.execute(
        "UPDATE jobs SET state = 'AWAITING_REVIEW' WHERE job_id = %s",
        (child_id,),
    )
    with pytest.raises(state.StateError, match="AWAITING_REVIEW"):
        state.charge_step_budget(
            budget_database.dsn,
            family_id=family_id,
            job_id=child_id,
            step_key="new-while-awaiting",
            attempt_no=1,
            charge_kind="general",
            elapsed_seconds=5,
        )

    budget_database.connection.execute(
        "UPDATE jobs SET state = 'BLOCKED' WHERE job_id = %s",
        (child_id,),
    )
    with pytest.raises(state.StateError, match="BLOCKED"):
        state.charge_step_budget(
            budget_database.dsn,
            family_id=family_id,
            job_id=child_id,
            step_key="new-while-blocked",
            attempt_no=1,
            charge_kind="general",
            elapsed_seconds=5,
        )
    recovered_blocked = state.charge_step_budget(
        budget_database.dsn,
        family_id=family_id,
        job_id=child_id,
        step_key="build",
        attempt_no=1,
        charge_kind="general",
        elapsed_seconds=10,
    )
    assert recovered_blocked.status == "recovered"
    assert recovered_blocked.charge == first.charge

    budget_database.connection.execute(
        "UPDATE jobs SET state = 'COMPLETED', evidence_status = 'archived', "
        "evidence_path = '/tmp/round.json', evidence_digest = %s "
        "WHERE job_id = %s",
        ("sha256:" + "a" * 64, child_id),
    )
    with pytest.raises(state.StateError, match="COMPLETED"):
        state.charge_step_budget(
            budget_database.dsn,
            family_id=family_id,
            job_id=child_id,
            step_key="new-while-completed",
            attempt_no=1,
            charge_kind="general",
            elapsed_seconds=5,
        )
    recovered_completed = state.charge_step_budget(
        budget_database.dsn,
        family_id=family_id,
        job_id=child_id,
        step_key="build",
        attempt_no=1,
        charge_kind="general",
        elapsed_seconds=10,
    )
    assert recovered_completed.status == "recovered"
    assert recovered_completed.charge == first.charge


@pytest.mark.postgres
def test_postgres_charge_step_budget_whitelist_allows_running_archiving_and_rejects_non_active_states(
    budget_database,
):
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
        "'round', %s, 1, 1)",
        (child_id, Jsonb({"schema_version": 2}), family_id, family_id),
    )
    state.initialize_budget_ledger(
        budget_database.dsn,
        family_id,
        max_total_seconds=100,
        max_fuzz_seconds=60,
    )

    for pre_active_state in ("QUEUED", "PREPARING", "READY"):
        budget_database.connection.execute(
            "UPDATE jobs SET state = %s WHERE job_id = %s",
            (pre_active_state, child_id),
        )
        with pytest.raises(state.StateError, match=pre_active_state):
            state.charge_step_budget(
                budget_database.dsn,
                family_id=family_id,
                job_id=child_id,
                step_key=f"charge-in-{pre_active_state.lower()}",
                attempt_no=1,
                charge_kind="general",
                elapsed_seconds=5,
            )
        summary = state.family_budget_summary(budget_database.dsn, family_id)
        assert summary["spent_seconds"] == 0
        assert summary["remaining_seconds"] == 100

    # RUNNING and ARCHIVING are allowed.
    budget_database.connection.execute(
        "UPDATE jobs SET state = 'RUNNING' WHERE job_id = %s",
        (child_id,),
    )
    running_charge = state.charge_step_budget(
        budget_database.dsn,
        family_id=family_id,
        job_id=child_id,
        step_key="build",
        attempt_no=1,
        charge_kind="general",
        elapsed_seconds=10,
    )
    assert running_charge.status == "charged"

    budget_database.connection.execute(
        "UPDATE jobs SET state = 'ARCHIVING' WHERE job_id = %s",
        (child_id,),
    )
    archiving_charge = state.charge_step_budget(
        budget_database.dsn,
        family_id=family_id,
        job_id=child_id,
        step_key="archive",
        attempt_no=1,
        charge_kind="general",
        elapsed_seconds=5,
    )
    assert archiving_charge.status == "charged"

    # §9.1 / ADR-004: an already RUNNING/ARCHIVING child still settles its
    # exit charge even after the parent family becomes BLOCKED.
    budget_database.connection.execute(
        "UPDATE jobs SET state = 'BLOCKED' WHERE job_id = %s",
        (family_id,),
    )
    blocked_family_charge = state.charge_step_budget(
        budget_database.dsn,
        family_id=family_id,
        job_id=child_id,
        step_key="archive-after-family-blocked",
        attempt_no=1,
        charge_kind="general",
        elapsed_seconds=3,
    )
    assert blocked_family_charge.status == "charged"

    # Returning to READY or entering terminal states still rejects new charges
    # while allowing idempotent recovery of existing charges.
    for state_name in ("READY", "BLOCKED", "COMPLETED"):
        if state_name == "COMPLETED":
            budget_database.connection.execute(
                "UPDATE jobs SET state = 'COMPLETED', evidence_status = 'archived', "
                "evidence_path = '/tmp/round.json', evidence_digest = %s "
                "WHERE job_id = %s",
                ("sha256:" + "b" * 64, child_id),
            )
        else:
            budget_database.connection.execute(
                "UPDATE jobs SET state = %s WHERE job_id = %s",
                (state_name, child_id),
            )
        with pytest.raises(state.StateError, match=state_name):
            state.charge_step_budget(
                budget_database.dsn,
                family_id=family_id,
                job_id=child_id,
                step_key=f"new-in-{state_name.lower()}",
                attempt_no=1,
                charge_kind="general",
                elapsed_seconds=5,
            )
        recovered = state.charge_step_budget(
            budget_database.dsn,
            family_id=family_id,
            job_id=child_id,
            step_key="build",
            attempt_no=1,
            charge_kind="general",
            elapsed_seconds=10,
        )
        assert recovered.status == "recovered"
        assert recovered.charge == running_charge.charge

    final_summary = state.family_budget_summary(budget_database.dsn, family_id)
    assert final_summary["spent_seconds"] == 18
    assert final_summary["remaining_seconds"] == 82


def _seed_running_child_for_fencing(database, *, generation: int = 2):
    """Seed a RUNNING round child whose lease is currently active."""
    family_id = uuid.uuid4()
    child_id = uuid.uuid4()
    database.connection.execute(
        "INSERT INTO jobs (job_id, request, state, stage, submitted_at, "
        "job_contract_version, family_id, job_kind, parent_job_id, round_no, "
        "generation, workflow_synced) "
        "VALUES (%s, %s, 'AGGREGATING', 'family', clock_timestamp(), 2, %s, "
        "'family', NULL, NULL, 1, true)",
        (family_id, Jsonb({"schema_version": 2}), family_id),
    )
    database.connection.execute(
        "INSERT INTO jobs (job_id, request, state, stage, submitted_at, "
        "job_contract_version, family_id, job_kind, parent_job_id, round_no, "
        "generation, lease_owner, lease_expires_at) "
        "VALUES (%s, %s, 'RUNNING', 'build', clock_timestamp(), 2, %s, "
        "'round', %s, 2, %s, 'worker-a', "
        "clock_timestamp() + interval '1 hour')",
        (
            child_id,
            Jsonb({"schema_version": 2}),
            family_id,
            family_id,
            generation,
        ),
    )
    state.initialize_budget_ledger(
        database.dsn,
        family_id,
        max_total_seconds=100,
        max_fuzz_seconds=60,
    )
    return family_id, child_id


@pytest.mark.postgres
def test_postgres_charge_step_budget_rejects_invalid_generation(budget_database):
    family_id, child_id = _seed_running_child_for_fencing(budget_database)

    for index, bad_generation in enumerate((True, 0, -1, "1", 1.0)):
        with pytest.raises(state.StateError, match="generation"):
            state.charge_step_budget(
                budget_database.dsn,
                family_id=family_id,
                job_id=child_id,
                step_key=f"invalid-generation-{index}",
                attempt_no=1,
                charge_kind="general",
                elapsed_seconds=5,
                generation=bad_generation,  # type: ignore[arg-type]
            )

    summary = state.family_budget_summary(budget_database.dsn, family_id)
    assert summary["spent_seconds"] == 0
    assert summary["remaining_seconds"] == 100


@pytest.mark.postgres
def test_postgres_charge_step_budget_fences_stale_generation_and_inactive_lease(
    budget_database,
):
    family_id, child_id = _seed_running_child_for_fencing(
        budget_database, generation=2
    )

    with pytest.raises(
        state.StaleGeneration,
        match="execution generation is no longer current",
    ):
        state.charge_step_budget(
            budget_database.dsn,
            family_id=family_id,
            job_id=child_id,
            step_key="stale-generation",
            attempt_no=1,
            charge_kind="general",
            elapsed_seconds=5,
            generation=1,
        )
    summary = state.family_budget_summary(budget_database.dsn, family_id)
    assert summary["spent_seconds"] == 0
    assert summary["remaining_seconds"] == 100

    budget_database.connection.execute(
        "UPDATE jobs SET lease_expires_at = clock_timestamp() "
        "- interval '1 second' WHERE job_id = %s",
        (child_id,),
    )
    with pytest.raises(
        state.StaleGeneration, match="the worker lease is no longer active"
    ):
        state.charge_step_budget(
            budget_database.dsn,
            family_id=family_id,
            job_id=child_id,
            step_key="expired-lease",
            attempt_no=1,
            charge_kind="general",
            elapsed_seconds=5,
            generation=2,
        )
    summary = state.family_budget_summary(budget_database.dsn, family_id)
    assert summary["spent_seconds"] == 0
    assert summary["remaining_seconds"] == 100

    budget_database.connection.execute(
        "UPDATE jobs SET lease_expires_at = NULL WHERE job_id = %s",
        (child_id,),
    )
    with pytest.raises(
        state.StaleGeneration, match="the worker lease is no longer active"
    ):
        state.charge_step_budget(
            budget_database.dsn,
            family_id=family_id,
            job_id=child_id,
            step_key="missing-lease",
            attempt_no=1,
            charge_kind="general",
            elapsed_seconds=5,
            generation=2,
        )
    summary = state.family_budget_summary(budget_database.dsn, family_id)
    assert summary["spent_seconds"] == 0
    assert summary["remaining_seconds"] == 100
    assert (
        budget_database.connection.execute(
            "SELECT count(*) FROM budget_charges WHERE family_id = %s",
            (family_id,),
        ).fetchone()[0]
        == 0
    )

    budget_database.connection.execute(
        "UPDATE jobs SET lease_expires_at = clock_timestamp() "
        "+ interval '1 hour' WHERE job_id = %s",
        (child_id,),
    )
    charged = state.charge_step_budget(
        budget_database.dsn,
        family_id=family_id,
        job_id=child_id,
        step_key="active-generation",
        attempt_no=1,
        charge_kind="general",
        elapsed_seconds=5,
        generation=2,
    )
    assert charged.status == "charged"
    summary = state.family_budget_summary(budget_database.dsn, family_id)
    assert summary["spent_seconds"] == 5
    assert summary["remaining_seconds"] == 95


@pytest.mark.postgres
def test_postgres_charge_step_budget_recovers_after_generation_and_lease_change(
    budget_database,
):
    family_id, child_id = _seed_running_child_for_fencing(
        budget_database, generation=2
    )

    first = state.charge_step_budget(
        budget_database.dsn,
        family_id=family_id,
        job_id=child_id,
        step_key="build",
        attempt_no=1,
        charge_kind="general",
        elapsed_seconds=10,
        generation=2,
    )
    assert first.status == "charged"

    # The worker lost its lease and another worker took over the child. The
    # already-recorded charge must still be recoverable by its idempotency key.
    budget_database.connection.execute(
        "UPDATE jobs SET generation = 3, lease_expires_at = NULL "
        "WHERE job_id = %s",
        (child_id,),
    )
    recovered = state.charge_step_budget(
        budget_database.dsn,
        family_id=family_id,
        job_id=child_id,
        step_key="build",
        attempt_no=1,
        charge_kind="general",
        elapsed_seconds=10,
        generation=1,
    )
    assert recovered.status == "recovered"
    assert recovered.charge == first.charge

    summary = state.family_budget_summary(budget_database.dsn, family_id)
    assert summary["spent_seconds"] == 10
    assert summary["remaining_seconds"] == 90
    assert (
        budget_database.connection.execute(
            "SELECT count(*) FROM budget_charges WHERE family_id = %s",
            (family_id,),
        ).fetchone()[0]
        == 1
    )


def test_charge_budget_local_guards_charge_kind_recovery_and_input_validation():
    ledger = _ledger()
    charges: list[dict] = []

    # 1. general -> fuzz re-entry on same (job_id, step_key, attempt_no) raises StateError
    first_general = _charge(
        ledger,
        charges,
        step_key="shared-step",
        attempt_no=1,
        charge_kind="general",
        elapsed_seconds=10,
    )
    assert first_general.status == "charged"
    with pytest.raises(state.StateError, match="charge_kind"):
        _charge(
            ledger,
            charges,
            step_key="shared-step",
            attempt_no=1,
            charge_kind="fuzz",
            elapsed_seconds=10,
            elapsed_fuzz_seconds=5,
        )
    assert ledger["remaining_total_seconds"] == 90
    assert ledger["remaining_fuzz_seconds"] == 60
    assert len(charges) == 1

    # 2. fuzz -> general re-entry on same (job_id, step_key, attempt_no) raises StateError
    first_fuzz = _charge(
        ledger,
        charges,
        step_key="fuzz-step",
        attempt_no=1,
        charge_kind="fuzz",
        elapsed_seconds=10,
        elapsed_fuzz_seconds=4,
    )
    assert first_fuzz.status == "charged"
    with pytest.raises(state.StateError, match="charge_kind"):
        _charge(
            ledger,
            charges,
            step_key="fuzz-step",
            attempt_no=1,
            charge_kind="general",
            elapsed_seconds=10,
        )
    assert ledger["remaining_total_seconds"] == 80
    assert ledger["remaining_fuzz_seconds"] == 56
    assert len(charges) == 2

    # 3. general charge with positive elapsed_fuzz_seconds raises StateError
    for positive_fuzz in (1, 0.1, 1e-6):
        with pytest.raises(state.StateError, match="elapsed_fuzz_seconds"):
            _charge(
                ledger,
                charges,
                step_key="bad-general",
                attempt_no=1,
                charge_kind="general",
                elapsed_seconds=5,
                elapsed_fuzz_seconds=positive_fuzz,
            )
        with pytest.raises(state.StateError, match="elapsed_fuzz_seconds"):
            state.compute_budget_charge(
                ledger,
                charge_kind="general",
                elapsed_seconds=5,
                elapsed_fuzz_seconds=positive_fuzz,
            )
    assert state.compute_budget_charge(
        ledger, charge_kind="general", elapsed_seconds=5, elapsed_fuzz_seconds=0
    ) == (5, 0)
    assert ledger["remaining_total_seconds"] == 80
    assert ledger["remaining_fuzz_seconds"] == 56

    # 4. step_key containing NUL or control characters raises StateError
    for bad_step_key in ("build\x00x", "build\x01", "build\x1f", "build\x7f"):
        with pytest.raises(state.StateError, match="step_key"):
            _charge(
                ledger,
                charges,
                step_key=bad_step_key,
                attempt_no=1,
                charge_kind="general",
                elapsed_seconds=5,
            )
    assert len(charges) == 2


@pytest.mark.postgres
def test_postgres_charge_step_budget_guards_charge_kind_recovery_and_input_validation(
    budget_database,
):
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
        "VALUES (%s, %s, 'RUNNING', 'build', clock_timestamp(), 2, %s, "
        "'round', %s, 1, 1)",
        (child_id, Jsonb({"schema_version": 2}), family_id, family_id),
    )
    state.initialize_budget_ledger(
        budget_database.dsn,
        family_id,
        max_total_seconds=100,
        max_fuzz_seconds=60,
    )

    # 1. general -> fuzz mismatch on same idempotency key raises StateError
    first_general = state.charge_step_budget(
        budget_database.dsn,
        family_id=family_id,
        job_id=child_id,
        step_key="shared-step",
        attempt_no=1,
        charge_kind="general",
        elapsed_seconds=10,
    )
    assert first_general.status == "charged"
    with pytest.raises(state.StateError, match="charge_kind"):
        state.charge_step_budget(
            budget_database.dsn,
            family_id=family_id,
            job_id=child_id,
            step_key="shared-step",
            attempt_no=1,
            charge_kind="fuzz",
            elapsed_seconds=10,
            elapsed_fuzz_seconds=5,
        )

    # 2. fuzz -> general mismatch on same idempotency key raises StateError
    first_fuzz = state.charge_step_budget(
        budget_database.dsn,
        family_id=family_id,
        job_id=child_id,
        step_key="fuzz-step",
        attempt_no=1,
        charge_kind="fuzz",
        elapsed_seconds=10,
        elapsed_fuzz_seconds=4,
    )
    assert first_fuzz.status == "charged"
    with pytest.raises(state.StateError, match="charge_kind"):
        state.charge_step_budget(
            budget_database.dsn,
            family_id=family_id,
            job_id=child_id,
            step_key="fuzz-step",
            attempt_no=1,
            charge_kind="general",
            elapsed_seconds=10,
        )

    # 3. general with positive elapsed_fuzz_seconds raises StateError
    with pytest.raises(state.StateError, match="elapsed_fuzz_seconds"):
        state.charge_step_budget(
            budget_database.dsn,
            family_id=family_id,
            job_id=child_id,
            step_key="general-with-fuzz",
            attempt_no=1,
            charge_kind="general",
            elapsed_seconds=5,
            elapsed_fuzz_seconds=1,
        )

    # 4. step_key with NUL or control chars raises StateError (not psycopg.DataError)
    for bad_step_key in ("build\x00x", "build\x01", "build\x1f", "build\x7f"):
        with pytest.raises(state.StateError, match="step_key"):
            state.charge_step_budget(
                budget_database.dsn,
                family_id=family_id,
                job_id=child_id,
                step_key=bad_step_key,
                attempt_no=1,
                charge_kind="general",
                elapsed_seconds=5,
            )

    summary = state.family_budget_summary(budget_database.dsn, family_id)
    assert summary == {
        "max_total_seconds": 100,
        "max_fuzz_seconds": 60,
        "spent_seconds": 20,
        "spent_fuzz_seconds": 4,
        "remaining_seconds": 80,
        "remaining_fuzz_seconds": 56,
    }


def test_fuzz_charge_rejects_fuzz_elapsed_exceeding_elapsed():
    # S-4: a fuzz sub-span longer than its step must fail closed instead of
    # silently inflating the total charge to the fuzz elapsed time.
    ledger = _ledger()
    charges: list[dict] = []
    for elapsed, fuzz_elapsed in ((5, 20), (1.0, 1.1), (0, 0.5)):
        with pytest.raises(
            state.StateError, match="must not exceed elapsed_seconds"
        ):
            state.compute_budget_charge(
                ledger,
                charge_kind="fuzz",
                elapsed_seconds=elapsed,
                elapsed_fuzz_seconds=fuzz_elapsed,
            )
        with pytest.raises(
            state.StateError, match="must not exceed elapsed_seconds"
        ):
            _charge(
                ledger,
                charges,
                step_key="fuzz-overlong",
                charge_kind="fuzz",
                elapsed_seconds=elapsed,
                elapsed_fuzz_seconds=fuzz_elapsed,
            )
    assert ledger["remaining_total_seconds"] == 100
    assert ledger["remaining_fuzz_seconds"] == 60
    assert charges == []

    # Boundary cases keep the normative formula.
    assert state.compute_budget_charge(
        ledger, charge_kind="fuzz", elapsed_seconds=5, elapsed_fuzz_seconds=5
    ) == (5, 5)
    assert state.compute_budget_charge(
        ledger, charge_kind="fuzz", elapsed_seconds=0, elapsed_fuzz_seconds=0
    ) == (1, 1)
    assert state.compute_budget_charge(
        ledger, charge_kind="fuzz", elapsed_seconds=1.1, elapsed_fuzz_seconds=1.0
    ) == (2, 1)
    assert state.compute_budget_charge(
        _ledger(remaining_total_seconds=3, remaining_fuzz_seconds=60),
        charge_kind="fuzz",
        elapsed_seconds=10,
        elapsed_fuzz_seconds=8,
    ) == (3, 3)


def _insert_family_and_children(connection):
    family_id = uuid.uuid4()
    campaign_id = uuid.uuid4()
    round_id = uuid.uuid4()
    v1_id = uuid.uuid4()
    connection.execute(
        "INSERT INTO jobs (job_id, request, state, stage, submitted_at, "
        "job_contract_version, family_id, job_kind, parent_job_id, round_no, "
        "generation, workflow_synced) "
        "VALUES (%s, %s, 'AGGREGATING', 'family', clock_timestamp(), 2, %s, "
        "'family', NULL, NULL, 1, true)",
        (family_id, Jsonb({"schema_version": 2}), family_id),
    )
    connection.execute(
        "INSERT INTO jobs (job_id, request, state, stage, submitted_at, "
        "job_contract_version, family_id, job_kind, parent_job_id, round_no, "
        "generation) "
        "VALUES (%s, %s, 'RUNNING', 'build', clock_timestamp(), 2, %s, "
        "'campaign', %s, NULL, 1)",
        (campaign_id, Jsonb({"schema_version": 2}), family_id, family_id),
    )
    connection.execute(
        "INSERT INTO jobs (job_id, request, state, stage, submitted_at, "
        "job_contract_version, family_id, job_kind, parent_job_id, round_no, "
        "generation) "
        "VALUES (%s, %s, 'RUNNING', 'build', clock_timestamp(), 2, %s, "
        "'round', %s, 2, 1)",
        (round_id, Jsonb({"schema_version": 2}), family_id, family_id),
    )
    connection.execute(
        "INSERT INTO jobs (job_id, request, state, stage, submitted_at) "
        "VALUES (%s, %s, 'QUEUED', 'prepare', clock_timestamp())",
        (v1_id, Jsonb({"schema_version": 1})),
    )
    return family_id, campaign_id, round_id, v1_id


@pytest.mark.postgres
def test_postgres_charge_step_budget_rejects_fuzz_elapsed_exceeding_elapsed(
    budget_database,
):
    family_id, _campaign_id, round_id, _v1_id = _insert_family_and_children(
        budget_database.connection
    )
    state.initialize_budget_ledger(
        budget_database.dsn,
        family_id,
        max_total_seconds=100,
        max_fuzz_seconds=60,
    )
    for attempt_no, (elapsed, fuzz_elapsed) in enumerate(
        ((5, 20), (1.0, 1.1)), start=1
    ):
        with pytest.raises(
            state.StateError, match="must not exceed elapsed_seconds"
        ):
            state.charge_step_budget(
                budget_database.dsn,
                family_id=family_id,
                job_id=round_id,
                step_key="fuzz-overlong",
                attempt_no=attempt_no,
                charge_kind="fuzz",
                elapsed_seconds=elapsed,
                elapsed_fuzz_seconds=fuzz_elapsed,
            )
    assert budget_database.connection.execute(
        "SELECT count(*) FROM budget_charges WHERE family_id = %s",
        (family_id,),
    ).fetchone()[0] == 0
    assert state.family_budget_summary(budget_database.dsn, family_id) == {
        "max_total_seconds": 100,
        "max_fuzz_seconds": 60,
        "spent_seconds": 0,
        "spent_fuzz_seconds": 0,
        "remaining_seconds": 100,
        "remaining_fuzz_seconds": 60,
    }


@pytest.mark.postgres
def test_postgres_initialize_budget_ledger_requires_a_v2_family(
    budget_database,
):
    # S-5: only a v2 family job may own a budget ledger.
    family_id, campaign_id, round_id, v1_id = _insert_family_and_children(
        budget_database.connection
    )
    with pytest.raises(state.StateError, match="does not exist"):
        state.initialize_budget_ledger(
            budget_database.dsn,
            uuid.uuid4(),
            max_total_seconds=100,
            max_fuzz_seconds=60,
        )
    for target in (v1_id, campaign_id, round_id):
        with pytest.raises(state.StateError, match="v2 family job"):
            state.initialize_budget_ledger(
                budget_database.dsn,
                target,
                max_total_seconds=100,
                max_fuzz_seconds=60,
            )
    assert budget_database.connection.execute(
        "SELECT count(*) FROM budget_ledger"
    ).fetchone()[0] == 0

    ledger = state.initialize_budget_ledger(
        budget_database.dsn,
        family_id,
        max_total_seconds=100,
        max_fuzz_seconds=60,
    )
    assert ledger["family_id"] == str(family_id)
    assert budget_database.connection.execute(
        "SELECT count(*) FROM budget_ledger"
    ).fetchone()[0] == 1


def test_budget_summary_validates_charge_family_id_and_charge_kind():
    # N-1: cross-family charges and inconsistent charge_kind/fuzz_seconds fail closed.
    ledger = _ledger(remaining_total_seconds=90, remaining_fuzz_seconds=55)
    other_family = str(uuid.uuid4())
    with pytest.raises(state.StateError, match="family_id"):
        state.budget_summary(
            ledger,
            [
                {
                    "family_id": other_family,
                    "charge_kind": "fuzz",
                    "seconds": 10,
                    "fuzz_seconds": 5,
                }
            ],
        )
    with pytest.raises(state.StateError, match="general charge"):
        state.budget_summary(
            ledger,
            [
                {
                    "family_id": FAMILY_ID,
                    "charge_kind": "general",
                    "seconds": 10,
                    "fuzz_seconds": 5,
                }
            ],
        )
    with pytest.raises(state.StateError, match="fuzz charge"):
        state.budget_summary(
            _ledger(remaining_total_seconds=90, remaining_fuzz_seconds=60),
            [
                {
                    "family_id": FAMILY_ID,
                    "charge_kind": "fuzz",
                    "seconds": 10,
                    "fuzz_seconds": 0,
                }
            ],
        )
    with pytest.raises(state.StateError, match="charge_kind"):
        state.budget_summary(
            ledger,
            [
                {
                    "family_id": FAMILY_ID,
                    "charge_kind": "unknown",
                    "seconds": 10,
                    "fuzz_seconds": 5,
                }
            ],
        )
    assert state.budget_summary(
        ledger,
        [
            {
                "family_id": FAMILY_ID,
                "charge_kind": "fuzz",
                "seconds": 10,
                "fuzz_seconds": 5,
            }
        ],
    ) == {
        "max_total_seconds": 100,
        "max_fuzz_seconds": 60,
        "spent_seconds": 10,
        "spent_fuzz_seconds": 5,
        "remaining_seconds": 90,
        "remaining_fuzz_seconds": 55,
    }
