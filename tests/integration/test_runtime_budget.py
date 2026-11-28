"""T12 runtime foundation (A2): budget gate, step charges and round admission.

Coordinates are registered in docs/spec/v0.2/test-plan-delta.md (T12, 改9).
Every test here is marker group ``postgres`` (D37): real PostgreSQL, no
Docker, no ASan. Containers are recording stand-ins and time is a fake clock;
nothing sleeps.
"""

from __future__ import annotations

from copy import deepcopy
from types import SimpleNamespace
from uuid import UUID, uuid4

from psycopg.types.json import Jsonb
import pytest

from datacon import contracts
from datacon import execution
from datacon import jsonutil
from datacon import state
from datacon import workflow
from datacon.tools.sandbox import SandboxError

from test_review_locks import BUILD_SPEC, PLAN_BASE, PLAN_BUILD_RECIPE_DIGEST


def _digest(token: str) -> str:
    return "sha256:" + token * 64


# Same fixture values as tests/integration/test_admission.py (not imported:
# that module name collides with tests/contract/test_admission.py when the
# whole suite is collected).
TOOLCHAIN_IMAGE_DIGEST = _digest("a")
SEED_CORPUS_DIGEST = _digest("c")
HARNESS_DIGEST = _digest("d")
# family_approvals.approval_digest is globally unique: one digest per family.
FAMILY_APPROVALS: dict = {}
FIRST_PLAN_DIGEST = _digest("f")
REVIEWER_ID = "reviewer-t12"
SIGNATURE = {
    "error": "heap-buffer-overflow",
    "function": "parse_token",
    "source": "parser.c",
    "operation": "WRITE",
    "access_size": 1,
}
DEFAULT_EXPERIMENT = {
    "input_family": "length_boundary",
    "mutation_constraints": {
        "allowed_ops": ["append", "truncate"],
        "max_input_bytes": 2048,
    },
    "expected_signature": dict(SIGNATURE),
}
DEFAULT_EXPERIMENT_DIGEST = jsonutil.digest_json(DEFAULT_EXPERIMENT)


def _envelope(*, max_rounds: int = 8) -> dict:
    return contracts.guided_envelope(
        allowed_mutation_families=["byte_flip", "length_boundary"],
        mutation_limits={
            "allowed_ops": ["append", "truncate", "byte_flip"],
            "max_input_bytes": 4096,
        },
        seed_corpus_digest=SEED_CORPUS_DIGEST,
        toolchain_image_digest=TOOLCHAIN_IMAGE_DIGEST,
        harness_digest=HARNESS_DIGEST,
        max_rounds=max_rounds,
        max_total_seconds=900,
        max_fuzz_seconds=300,
        accepted_signature_set=[dict(SIGNATURE)],
        admission_predicate_version="admission-v1",
    )


def _plan_body(
    *,
    family_id,
    round_no,
    envelope_digest,
    parent_approval_digest,
    harness_digest,
    seed_digest,
    experiment_digest,
) -> dict:
    plan = deepcopy(PLAN_BASE)
    plan.update(
        {
            "schema_version": 2,
            "family_id": str(family_id),
            "parent_job_id": str(family_id),
            "round_no": round_no,
            "envelope_digest": envelope_digest,
            "parent_approval_digest": parent_approval_digest,
            "harness_digest": harness_digest,
            "build_ref": None,
            "build_spec": deepcopy(BUILD_SPEC),
            "compile_flags": ["-g"],
            "experiment_digest": experiment_digest,
            "build_provenance_rules_version": "build-provenance-v1",
            "build_recipe_digest": PLAN_BUILD_RECIPE_DIGEST,
            "inputs": {"normal": _digest("1"), "candidate": seed_digest},
            "asan_signature": dict(SIGNATURE),
        }
    )
    return plan


pytestmark = pytest.mark.postgres

FAMILY_REQUEST = {
    "schema_version": 2,
    "exploration": {"mode": "guided"},
    "limits": {"execute_seconds": 900, "prepare_seconds": 900},
}


class FakeStepClock:
    """Monotonic stand-in that only moves when a step says so."""

    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


@pytest.fixture
def step_clock(monkeypatch):
    clock = FakeStepClock()
    monkeypatch.setattr(execution, "STEP_CLOCK", clock)
    return clock


def _seed_family(
    database,
    *,
    max_rounds: int = 8,
    ledger_total: int | None = None,
    ledger_fuzz: int | None = None,
):
    """A guided AGGREGATING family with an approved envelope and a ledger."""
    family_id = uuid4()
    approval_digest = jsonutil.digest_json({"approval": str(family_id)})
    FAMILY_APPROVALS[family_id] = approval_digest
    envelope = _envelope(max_rounds=max_rounds)
    envelope_digest = contracts.envelope_digest(envelope)
    database.connection.execute(
        "INSERT INTO jobs (job_id, request, state, stage, submitted_at, "
        "job_contract_version, family_id, job_kind, parent_job_id, round_no, "
        "generation, workflow_synced) "
        "VALUES (%s, %s, 'AGGREGATING', 'family', clock_timestamp(), 2, %s, "
        "'family', NULL, NULL, 1, true)",
        (family_id, Jsonb(FAMILY_REQUEST), family_id),
    )
    database.connection.execute(
        "INSERT INTO family_envelopes (envelope_id, family_id, envelope_digest, "
        "envelope_json, status, review_deadline_at) "
        "VALUES (%s, %s, %s, %s, 'approved', clock_timestamp())",
        (uuid4(), family_id, envelope_digest, Jsonb(envelope)),
    )
    database.connection.execute(
        "INSERT INTO family_approvals (approval_id, family_id, approval_digest, "
        "envelope_digest, first_plan_digest, reviewer_id, decided_at, supersedes) "
        "VALUES (%s, %s, %s, %s, %s, %s, clock_timestamp(), NULL)",
        (
            uuid4(),
            family_id,
            approval_digest,
            envelope_digest,
            FIRST_PLAN_DIGEST,
            REVIEWER_ID,
        ),
    )
    state.initialize_budget_ledger(
        database.dsn,
        family_id,
        max_total_seconds=(
            envelope["max_total_seconds"] if ledger_total is None else ledger_total
        ),
        max_fuzz_seconds=(
            envelope["max_fuzz_seconds"] if ledger_fuzz is None else ledger_fuzz
        ),
    )
    return family_id, envelope


def _round_plan(family_id, envelope, *, round_no: int, experiment_digest=None):
    return _plan_body(
        family_id=family_id,
        round_no=round_no,
        envelope_digest=contracts.envelope_digest(envelope),
        parent_approval_digest=FAMILY_APPROVALS[family_id],
        harness_digest=envelope["harness_digest"],
        seed_digest=SEED_CORPUS_DIGEST,
        experiment_digest=experiment_digest or DEFAULT_EXPERIMENT_DIGEST,
    )


def _running_round(database, family_id, envelope, *, round_no: int = 1):
    """An admitted-shape round child that a worker currently executes."""
    job_id = uuid4()
    plan = _round_plan(family_id, envelope, round_no=round_no)
    database.connection.execute(
        "INSERT INTO jobs (job_id, request, state, stage, submitted_at, "
        "job_contract_version, family_id, job_kind, parent_job_id, round_no, "
        "generation, lease_owner, lease_expires_at) "
        "VALUES (%s, %s, 'RUNNING', 'execute', clock_timestamp(), 2, %s, "
        "'round', %s, %s, 1, 'worker-t12', clock_timestamp() + interval '1 hour')",
        (job_id, Jsonb(FAMILY_REQUEST), family_id, family_id, round_no),
    )
    plan_digest = contracts.plan_digest(plan)
    database.connection.execute(
        "INSERT INTO plans (plan_id, job_id, plan_digest, plan, summary) "
        "VALUES (%s, %s, %s, %s, %s)",
        (uuid4(), job_id, plan_digest, Jsonb(plan), Jsonb({})),
    )
    job = state.load_job(database.dsn, job_id)
    return SimpleNamespace(
        job_id=job_id,
        job_id_text=str(job_id),
        generation=1,
        job=job,
        plan=plan,
        plan_digest=plan_digest,
        step_ceiling_seconds=None,
        budget_summary={},
    )


def _charges(database, job_id):
    return [
        tuple(row)
        for row in database.connection.execute(
            "SELECT step_key, attempt_no, charge_kind, seconds, fuzz_seconds "
            "FROM budget_charges WHERE job_id = %s ORDER BY step_key, attempt_no",
            (job_id,),
        ).fetchall()
    ]


def _attempt_rows(database, job_id):
    return [
        tuple(row)
        for row in database.connection.execute(
            "SELECT step_key, status FROM attempts WHERE job_id = %s "
            "ORDER BY step_key, attempt_no",
            (job_id,),
        ).fetchall()
    ]


def _count(database, query, params) -> int:
    return database.connection.execute(query, params).fetchone()[0]


def _ledger(database, family_id):
    return state.load_budget_ledger(database.dsn, family_id)


class RecordingContainer:
    """Stands in for one sandbox call: records the timeout it was granted."""

    def __init__(self, context, clock, *, runtime: float, error=None):
        self.context = context
        self.clock = clock
        self.runtime = runtime
        self.error = error
        self.calls: list[dict] = []

    def __call__(self, attempt_no: int, token: str) -> dict:
        self.calls.append(
            {
                "attempt_no": attempt_no,
                "ceiling": self.context.step_ceiling_seconds,
                "hard_timeout": execution._cap_to_step_budget(
                    self.context, 300.0
                ),
            }
        )
        self.clock.advance(self.runtime)
        if self.error is not None:
            raise self.error
        return {"status": "completed", "container_id": None}


def _step(database, context, step_key, container, *, charge_kind="general"):
    return execution._run_step(
        database.dsn,
        context,
        step_key=step_key,
        input_digest=None,
        action=container,
        charge_kind=charge_kind,
    )


def test_budget_gate_caps_hard_timeout_before_container_start(
    isolated_database, step_clock
):
    family_id, envelope = _seed_family(
        isolated_database, ledger_total=40, ledger_fuzz=25
    )
    context = _running_round(isolated_database, family_id, envelope)

    fuzz = RecordingContainer(context, step_clock, runtime=0.0)
    _step(isolated_database, context, "fuzz:search", fuzz, charge_kind="fuzz")
    assert fuzz.calls[0]["ceiling"] == 25.0, (
        "fuzz hard timeout did not use min(remaining_total, remaining_fuzz)"
    )
    assert fuzz.calls[0]["hard_timeout"] == 25.0
    # A zero-length fuzz step still costs one second on both budgets (§7).
    assert _ledger(isolated_database, family_id)["remaining_total_seconds"] == 39
    assert _ledger(isolated_database, family_id)["remaining_fuzz_seconds"] == 24

    general = RecordingContainer(context, step_clock, runtime=0.0)
    _step(isolated_database, context, "build:vulnerable", general)
    # A general step uses the total balance only.
    assert general.calls[0]["ceiling"] == 39.0
    assert general.calls[0]["hard_timeout"] == 39.0
    assert context.step_ceiling_seconds is None

    # Drain the fuzz sub-budget: the next fuzz step is refused before any
    # container or attempt row exists, even with total budget left.
    drain = RecordingContainer(context, step_clock, runtime=24.0)
    _step(isolated_database, context, "fuzz:drain", drain, charge_kind="fuzz")
    ledger = _ledger(isolated_database, family_id)
    assert (ledger["remaining_total_seconds"], ledger["remaining_fuzz_seconds"]) == (15, 0)
    refused = RecordingContainer(context, step_clock, runtime=0.0)
    with pytest.raises(execution.ExecutionFailed) as excinfo:
        _step(isolated_database, context, "fuzz:again", refused, charge_kind="fuzz")
    assert excinfo.value.reason_code == "BUDGET_EXHAUSTED"
    assert refused.calls == [], "fuzz started with only one budget available"
    assert not any(
        step == "fuzz:again" for step, _status in _attempt_rows(
            isolated_database, context.job_id
        )
    )

    # General steps still run on the remaining total, then the total gates
    # every step.
    last = RecordingContainer(context, step_clock, runtime=15.0)
    _step(isolated_database, context, "build:fixed", last)
    assert last.calls[0]["ceiling"] == 15.0
    assert _ledger(isolated_database, family_id)["remaining_total_seconds"] == 0
    starved = RecordingContainer(context, step_clock, runtime=0.0)
    with pytest.raises(execution.ExecutionFailed) as excinfo:
        _step(isolated_database, context, "replay:fixed:normal", starved)
    assert excinfo.value.reason_code == "BUDGET_EXHAUSTED"
    assert starved.calls == []


def test_container_exit_charges_both_budgets_once_per_attempt(
    isolated_database, step_clock
):
    family_id, envelope = _seed_family(isolated_database)
    context = _running_round(isolated_database, family_id, envelope)
    before = _ledger(isolated_database, family_id)

    fuzz = RecordingContainer(context, step_clock, runtime=7.2)
    _step(isolated_database, context, "fuzz:search", fuzz, charge_kind="fuzz")
    general = RecordingContainer(context, step_clock, runtime=3.4)
    _step(isolated_database, context, "build:vulnerable", general)

    charges = _charges(isolated_database, context.job_id)
    assert charges == [
        ("build:vulnerable", 1, "general", 4, 0),
        ("fuzz:search", 1, "fuzz", 8, 8),
    ], "fuzz charge only decremented one budget"
    after = _ledger(isolated_database, family_id)
    assert after["remaining_total_seconds"] == before["remaining_total_seconds"] - 12
    assert after["remaining_fuzz_seconds"] == before["remaining_fuzz_seconds"] - 8
    # The archived snapshot/report budget is rebuilt from the family charges.
    assert context.budget_summary["spent_seconds"] == 12
    assert context.budget_summary["spent_fuzz_seconds"] == 8

    # Recovering the same completed attempt reuses it: no container, no charge.
    again = RecordingContainer(context, step_clock, runtime=50.0)
    result, reused = _step(
        isolated_database, context, "fuzz:search", again, charge_kind="fuzz"
    )
    assert reused is True
    assert again.calls == []
    # Replaying the charge for the same (job_id, step_key, attempt_no) is
    # recovered, never a second debit.
    recovered = execution._charge_step_budget(
        isolated_database.dsn,
        context,
        step_key="fuzz:search",
        attempt_no=1,
        charge_kind="fuzz",
        elapsed_seconds=8,
    )
    assert recovered.status == "recovered"
    assert len(_charges(isolated_database, context.job_id)) == 2, (
        "budget charged twice after recovery"
    )
    assert _ledger(isolated_database, family_id) == after


@pytest.mark.parametrize(
    "error",
    [
        SandboxError("docker wait timed out", reason_code="TIMEOUT"),
        SandboxError("container was OOM killed", reason_code="RESOURCE_LIMITED"),
        RuntimeError("container runtime crashed"),
    ],
    ids=["timeout", "oom", "failure"],
)
def test_timed_out_or_failed_container_is_still_charged(
    isolated_database, step_clock, error
):
    family_id, envelope = _seed_family(isolated_database)
    context = _running_round(isolated_database, family_id, envelope)
    before = _ledger(isolated_database, family_id)

    container = RecordingContainer(context, step_clock, runtime=5.5, error=error)
    with pytest.raises(type(error)):
        _step(isolated_database, context, "replay:vulnerable:normal", container)

    assert len(container.calls) == 1
    charges = _charges(isolated_database, context.job_id)
    assert [(row[0], row[3]) for row in charges] == [
        ("replay:vulnerable:normal", 6)
    ], "a failed container step was free"
    assert (
        _ledger(isolated_database, family_id)["remaining_total_seconds"]
        == before["remaining_total_seconds"] - 6
    )


def test_round_admission_runs_before_any_container(isolated_database, tmp_path, monkeypatch):
    monkeypatch.setenv("DATACON_EVIDENCE_ROOT", str(tmp_path / "evidence"))
    family_id, envelope = _seed_family(isolated_database)

    # Denied: the experiment leaves the approved envelope. The round child is
    # derived first, then record_admission denies it; it is blocked and
    # archived without ever becoming claimable.
    outside = deepcopy(DEFAULT_EXPERIMENT)
    outside["input_family"] = "format_string"
    denied = workflow.derive_and_admit_round(
        isolated_database.dsn,
        family_id=family_id,
        round_no=1,
        plan=_round_plan(
            family_id,
            envelope,
            round_no=1,
            experiment_digest=jsonutil.digest_json(outside),
        ),
        envelope=envelope,
        seed_digest=SEED_CORPUS_DIGEST,
        experiment=outside,
    )
    denied_id = UUID(denied["job_id"])
    assert denied["admitted"] is False
    assert denied["reason_code"] == "ENVELOPE_VIOLATION"
    denied_job = state.load_job(isolated_database.dsn, denied_id)
    assert denied_job["state"] == "BLOCKED"
    assert denied_job["reason_code"] == "ENVELOPE_VIOLATION"
    assert denied_job["evidence_status"] == "archived"
    assert _count(
        isolated_database,
        "SELECT count(*) FROM admissions WHERE job_id = %s",
        (denied_id,),
    ) == 0
    events = [
        row[0]
        for row in isolated_database.connection.execute(
            "SELECT event_type FROM audit_events WHERE job_id = %s "
            "ORDER BY created_at",
            (denied_id,),
        ).fetchall()
    ]
    assert "round_admission_denied" in events
    assert "round_admitted" not in events
    # No worker can claim it and no container step was ever attempted.
    assert (
        state.claim_next(isolated_database.dsn, "worker-t12", job_contract_version=2)
        is None
    )
    assert _attempt_rows(isolated_database, denied_id) == []

    # Admitted: the next round is derived and admitted before it can run; only
    # then does the v2 claim gate hand it to a worker.
    admitted = workflow.derive_and_admit_round(
        isolated_database.dsn,
        family_id=family_id,
        round_no=2,
        plan=_round_plan(family_id, envelope, round_no=2),
        envelope=envelope,
        seed_digest=SEED_CORPUS_DIGEST,
        experiment=deepcopy(DEFAULT_EXPERIMENT),
    )
    admitted_id = UUID(admitted["job_id"])
    assert admitted["admitted"] is True
    assert _count(
        isolated_database,
        "SELECT count(*) FROM admissions WHERE job_id = %s "
        "AND approval_kind = 'policy'",
        (admitted_id,),
    ) == 1
    assert _count(
        isolated_database,
        "SELECT count(*) FROM reviews WHERE job_id IN (%s, %s)",
        (admitted_id, family_id),
    ) == 0
    claimed = state.claim_next(
        isolated_database.dsn, "worker-t12", job_contract_version=2
    )
    assert claimed is not None and claimed["job_id"] == admitted_id
    assert claimed["state"] == "RUNNING"

    # Serial children: no other round is derived while this one runs.
    busy = workflow.derive_and_admit_round(
        isolated_database.dsn,
        family_id=family_id,
        round_no=3,
        plan=_round_plan(family_id, envelope, round_no=3),
        envelope=envelope,
        seed_digest=SEED_CORPUS_DIGEST,
        experiment=deepcopy(DEFAULT_EXPERIMENT),
    )
    assert busy["derived"] is False
    assert busy["sub_reason"] == "CHILD_NOT_TERMINAL"


def _round_jobs(database, family_id):
    return [
        tuple(row)
        for row in database.connection.execute(
            "SELECT job_id, round_no, state, reason_code FROM jobs "
            "WHERE parent_job_id = %s AND job_kind = 'round' ORDER BY round_no",
            (family_id,),
        ).fetchall()
    ]


def _derive(database, family_id, envelope, *, round_no, experiment=None):
    experiment = deepcopy(DEFAULT_EXPERIMENT) if experiment is None else experiment
    return workflow.derive_and_admit_round(
        database.dsn,
        family_id=family_id,
        round_no=round_no,
        plan=_round_plan(
            family_id,
            envelope,
            round_no=round_no,
            experiment_digest=jsonutil.digest_json(experiment),
        ),
        envelope=envelope,
        seed_digest=SEED_CORPUS_DIGEST,
        experiment=experiment,
    )


def test_round_derivation_is_gated_before_creating_a_child(
    isolated_database, step_clock
):
    # Fuzz sub-budget drained by a finished step while total budget remains:
    # a validation round only runs general steps, so it MUST still derive and
    # be admitted.
    family_id, envelope = _seed_family(
        isolated_database, ledger_total=900, ledger_fuzz=300
    )
    context = _running_round(isolated_database, family_id, envelope, round_no=1)
    _step(
        isolated_database,
        context,
        "fuzz:search",
        RecordingContainer(context, step_clock, runtime=300.0),
        charge_kind="fuzz",
    )
    isolated_database.connection.execute(
        "UPDATE jobs SET state = 'INCONCLUSIVE', verdict = 'INCONCLUSIVE', "
        "reason_code = 'EVIDENCE_INCOMPLETE', lease_owner = NULL, "
        "lease_expires_at = NULL WHERE job_id = %s",
        (context.job_id,),
    )
    ledger = _ledger(isolated_database, family_id)
    assert (ledger["remaining_total_seconds"], ledger["remaining_fuzz_seconds"]) == (600, 0)
    allowed = _derive(isolated_database, family_id, envelope, round_no=2)
    assert allowed["derived"] is True and allowed["admitted"] is True, (
        "round derivation was refused although total budget remained and only "
        "the fuzz sub-budget was exhausted"
    )
    assert len(_round_jobs(isolated_database, family_id)) == 2

    # round_no beyond max_rounds: refused before any child exists.
    family_id, envelope = _seed_family(isolated_database, max_rounds=1)
    beyond = _derive(isolated_database, family_id, envelope, round_no=2)
    assert beyond["derived"] is False
    assert beyond["reason_code"] == "BUDGET_EXHAUSTED"
    assert beyond["sub_reason"] == "ROUND_BEYOND_MAX_ROUNDS"
    assert _round_jobs(isolated_database, family_id) == []

    # Total budget exhausted: refused before any child exists.
    family_id, envelope = _seed_family(
        isolated_database, ledger_total=1, ledger_fuzz=1
    )
    drain = _running_round(isolated_database, family_id, envelope, round_no=1)
    _step(
        isolated_database,
        drain,
        "build:vulnerable",
        RecordingContainer(drain, step_clock, runtime=1.0),
    )
    isolated_database.connection.execute(
        "UPDATE jobs SET state = 'INCONCLUSIVE', verdict = 'INCONCLUSIVE', "
        "reason_code = 'EVIDENCE_INCOMPLETE', lease_owner = NULL, "
        "lease_expires_at = NULL WHERE job_id = %s",
        (drain.job_id,),
    )
    starved = _derive(isolated_database, family_id, envelope, round_no=2)
    assert starved["derived"] is False
    assert starved["reason_code"] == "BUDGET_EXHAUSTED"
    assert len(_round_jobs(isolated_database, family_id)) == 1

    # A non-terminal child refuses before any child exists.
    family_id, envelope = _seed_family(isolated_database)
    _running_round(isolated_database, family_id, envelope, round_no=1)
    busy = _derive(isolated_database, family_id, envelope, round_no=2)
    assert busy["derived"] is False
    assert busy["reason_code"] is None
    assert busy["sub_reason"] == "CHILD_NOT_TERMINAL"
    assert len(_round_jobs(isolated_database, family_id)) == 1


def test_admission_failure_after_child_creation_fails_closed(
    isolated_database, tmp_path, monkeypatch
):
    monkeypatch.setenv("DATACON_EVIDENCE_ROOT", str(tmp_path / "evidence"))
    family_id, envelope = _seed_family(isolated_database)

    def broken_admission(*args, **kwargs):
        raise state.StateError("admission store unavailable")

    monkeypatch.setattr(state, "record_admission", broken_admission)
    result = _derive(isolated_database, family_id, envelope, round_no=1)

    assert result["derived"] is True
    assert result["admitted"] is False
    rounds = _round_jobs(isolated_database, family_id)
    assert len(rounds) == 1
    assert rounds[0][2:] == ("BLOCKED", "ADMISSION_DENIED"), (
        "a round whose admission raised was left READY without an admission"
    )
    job = state.load_job(isolated_database.dsn, rounds[0][0])
    assert job["evidence_status"] == "archived"
    assert state.claim_next(
        isolated_database.dsn, "worker-t12", job_contract_version=2
    ) is None


def _age_round(database, job_id, seconds: int) -> None:
    database.connection.execute(
        "UPDATE jobs SET updated_at = clock_timestamp() - make_interval(secs => %s) "
        "WHERE job_id = %s",
        (seconds, job_id),
    )


def test_unadmitted_round_after_crash_is_recovered_by_the_worker_scan(
    isolated_database, tmp_path, monkeypatch
):
    monkeypatch.setenv("DATACON_EVIDENCE_ROOT", str(tmp_path / "evidence"))
    family_id, envelope = _seed_family(isolated_database)

    def crash(*args, **kwargs):
        raise KeyboardInterrupt("process died between child and admission")

    with monkeypatch.context() as patch:
        patch.setattr(state, "record_admission", crash)
        with pytest.raises(KeyboardInterrupt):
            _derive(isolated_database, family_id, envelope, round_no=1)
    (job_id, _round_no, job_state, _reason), = _round_jobs(
        isolated_database, family_id
    )
    assert job_state == "READY"

    # Within the grace window the scan leaves an in-flight derivation alone.
    assert workflow.recover_unadmitted_rounds(isolated_database.dsn) == 0
    assert _count(
        isolated_database, "SELECT count(*) FROM admissions WHERE job_id = %s", (job_id,)
    ) == 0

    # After the grace window the scan retries the persisted admission inputs.
    _age_round(isolated_database, job_id, 3600)
    assert workflow.recover_unadmitted_rounds(isolated_database.dsn) == 1
    assert _count(
        isolated_database, "SELECT count(*) FROM admissions WHERE job_id = %s", (job_id,)
    ) == 1, "a round left READY without admission after a crash was never recovered"
    assert workflow.recover_unadmitted_rounds(isolated_database.dsn) == 0
    claimed = state.claim_next(
        isolated_database.dsn, "worker-t12", job_contract_version=2
    )
    assert claimed is not None and claimed["job_id"] == job_id

    # A retried admission that is denied fails closed: BLOCKED and archived.
    family_id, envelope = _seed_family(isolated_database)
    outside = deepcopy(DEFAULT_EXPERIMENT)
    outside["input_family"] = "format_string"
    with monkeypatch.context() as patch:
        patch.setattr(state, "record_admission", crash)
        with pytest.raises(KeyboardInterrupt):
            _derive(
                isolated_database, family_id, envelope, round_no=1,
                experiment=outside,
            )
    (job_id, _round_no, _state, _reason), = _round_jobs(
        isolated_database, family_id
    )
    _age_round(isolated_database, job_id, 3600)
    assert workflow.recover_unadmitted_rounds(isolated_database.dsn) == 1
    assert _round_jobs(isolated_database, family_id)[0][2:] == (
        "BLOCKED",
        "ENVELOPE_VIOLATION",
    )
    assert state.load_job(isolated_database.dsn, job_id)["evidence_status"] == "archived"


def test_crash_before_charge_is_recovered_by_the_worker_scan(
    isolated_database, step_clock, monkeypatch
):
    family_id, envelope = _seed_family(
        isolated_database, ledger_total=40, ledger_fuzz=25
    )
    context = _running_round(isolated_database, family_id, envelope)

    def crash(*args, **kwargs):
        raise KeyboardInterrupt("process died before the charge committed")

    with monkeypatch.context() as patch:
        patch.setattr(execution, "_charge_step_budget", crash)
        with pytest.raises(KeyboardInterrupt):
            _step(
                isolated_database,
                context,
                "fuzz:search",
                RecordingContainer(context, step_clock, runtime=3.0),
                charge_kind="fuzz",
            )
    assert _charges(isolated_database, context.job_id) == []

    # The lease is still live: a running worker owns the attempt.
    assert state.recover_uncharged_attempts(isolated_database.dsn) == 0

    # Lease expired and the attempt started long ago: the scan charges the
    # step conservatively, capped by the ceiling the gate granted (25s).
    isolated_database.connection.execute(
        "UPDATE jobs SET lease_expires_at = clock_timestamp() - interval '1 second' "
        "WHERE job_id = %s",
        (context.job_id,),
    )
    isolated_database.connection.execute(
        "UPDATE attempts SET started_at = clock_timestamp() - interval '10 hours' "
        "WHERE job_id = %s AND step_key = 'fuzz:search'",
        (context.job_id,),
    )
    assert state.recover_uncharged_attempts(isolated_database.dsn) == 1
    assert _charges(isolated_database, context.job_id) == [
        ("fuzz:search", 1, "fuzz", 25, 25)
    ], "a step that crashed before its charge was never charged"
    ledger = _ledger(isolated_database, family_id)
    assert (ledger["remaining_total_seconds"], ledger["remaining_fuzz_seconds"]) == (15, 0)
    # Idempotent: a second scan charges nothing.
    assert state.recover_uncharged_attempts(isolated_database.dsn) == 0
    assert len(_charges(isolated_database, context.job_id)) == 1
