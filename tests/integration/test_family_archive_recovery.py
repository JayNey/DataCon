"""D43 T12: family archive crash recovery converges without a lease.

The sweep runs before every claim inside ``workflow.run_worker``. A family is
eligible only when it still is ``AGGREGATING``, has children, every child is
terminal (and any BLOCKED child is workflow-synced) and no envelope is pending.
The family index is written atomically and the existing bytes always win, so a
crash between the file write and ``complete_family`` retries only the pointer
write.
"""

from __future__ import annotations

import hashlib
import json
import threading
from uuid import uuid4

import psycopg
import pytest
from psycopg.types.json import Jsonb

from datacon import evidence, state, workflow

pytestmark = pytest.mark.postgres

APPROVAL_DIGEST = "sha256:" + "52" * 32
CAMPAIGN_PLAN = "sha256:" + "2f" * 32
ROUND1_PLAN = "sha256:" + "2e" * 32
ROUND2_PLAN = "sha256:" + "0d" * 32
CAMPAIGN_DIGEST = "sha256:" + "0e" * 32
ROUND1_DIGEST = "sha256:" + "53" * 32
ROUND2_DIGEST = "sha256:" + "54" * 32

BUDGET = {
    "max_total_seconds": 900,
    "max_fuzz_seconds": 300,
    "spent_seconds": 0,
    "spent_fuzz_seconds": 0,
    "remaining_seconds": 900,
    "remaining_fuzz_seconds": 300,
}

REQUEST = {
    "schema_version": 2,
    "cve_id": "CVE-2099-0001",
    "target": {"kind": "source", "case_id": "fixture-c-parser"},
    "exploration": {
        "mode": "guided",
        "allowed_mutation_families": ["byte_flip"],
        "max_rounds": 2,
        "max_total_seconds": 900,
        "max_fuzz_seconds": 300,
    },
}


def _guided_request(max_rounds=2):
    request = json.loads(json.dumps(REQUEST))
    request["exploration"]["max_rounds"] = max_rounds
    return request


def _fixed_request():
    request = json.loads(json.dumps(REQUEST))
    request["exploration"] = {"mode": "fixed"}
    return request


def _insert_family(database, *, request=None):
    family_id = uuid4()
    database.connection.execute(
        "INSERT INTO jobs (job_id, request, state, stage, submitted_at, "
        "job_contract_version, family_id, job_kind, parent_job_id, round_no, "
        "workflow_synced) VALUES (%s, %s, 'AGGREGATING', 'family', "
        "clock_timestamp(), 2, %s, 'family', NULL, NULL, true)",
        (family_id, Jsonb(REQUEST if request is None else request), family_id),
    )
    return family_id


def _insert_child(
    database,
    family_id,
    *,
    job_kind,
    round_no,
    state_name,
    evidence_path=None,
    evidence_digest=None,
    verdict=None,
    reason_code=None,
    evidence_status="archived",
):
    job_id = uuid4()
    database.connection.execute(
        "INSERT INTO jobs (job_id, request, state, stage, submitted_at, "
        "job_contract_version, family_id, job_kind, parent_job_id, round_no, "
        "workflow_synced, verdict, reason_code, evidence_status, "
        "evidence_path, evidence_digest) VALUES (%s, %s, %s, 'execute', "
        "clock_timestamp(), 2, %s, %s, %s, %s, true, %s, %s, %s, "
        "%s, %s)",
        (
            job_id,
            Jsonb(REQUEST),
            state_name,
            family_id,
            job_kind,
            family_id,
            round_no,
            verdict,
            reason_code,
            evidence_status,
            None if evidence_path is None else str(evidence_path),
            evidence_digest,
        ),
    )
    return job_id


def _insert_plan(database, job_id, digest):
    database.connection.execute(
        "INSERT INTO plans (plan_id, job_id, plan_digest, plan, summary) "
        "VALUES (%s, %s, %s, %s, %s)",
        (uuid4(), job_id, digest, Jsonb({}), Jsonb({})),
    )


def _insert_approval(database, family_id):
    database.connection.execute(
        "INSERT INTO family_approvals (approval_id, family_id, "
        "approval_digest, envelope_digest, first_plan_digest, reviewer_id, "
        "decided_at) VALUES (%s, %s, %s, %s, %s, 'reviewer-p1', "
        "clock_timestamp())",
        (
            uuid4(),
            family_id,
            APPROVAL_DIGEST,
            "sha256:" + "b" * 64,
            CAMPAIGN_PLAN,
        ),
    )


def _insert_ledger(
    database,
    family_id,
    *,
    max_total=900,
    max_fuzz=300,
    remaining_total=900,
    remaining_fuzz=300,
):
    database.connection.execute(
        "INSERT INTO budget_ledger (family_id, max_total_seconds, "
        "max_fuzz_seconds, remaining_total_seconds, remaining_fuzz_seconds) "
        "VALUES (%s, %s, %s, %s, %s)",
        (family_id, max_total, max_fuzz, remaining_total, remaining_fuzz),
    )


def _insert_charge(database, family_id, job_id, *, step_key, kind, seconds, fuzz=0):
    database.connection.execute(
        "INSERT INTO budget_charges (charge_id, family_id, job_id, step_key, "
        "attempt_no, charge_kind, seconds, fuzz_seconds) "
        "VALUES (%s, %s, %s, %s, 1, %s, %s, %s)",
        (uuid4(), family_id, job_id, step_key, kind, seconds, fuzz),
    )


def _family_row(database, family_id):
    return database.connection.execute(
        "SELECT state, verdict, reason_code, evidence_status, evidence_path, "
        "evidence_digest FROM jobs WHERE job_id = %s",
        (family_id,),
    ).fetchone()


def _setup_family(database, tmp_path):
    family_id = _insert_family(database)
    campaign_id = _insert_child(
        database,
        family_id,
        job_kind="campaign",
        round_no=None,
        state_name="COMPLETED",
        evidence_path=tmp_path / "campaign-bundle",
        evidence_digest=CAMPAIGN_DIGEST,
    )
    round1_id = _insert_child(
        database,
        family_id,
        job_kind="round",
        round_no=1,
        state_name="INCONCLUSIVE",
        evidence_path=tmp_path / "round-1-bundle",
        evidence_digest=ROUND1_DIGEST,
        verdict="INCONCLUSIVE",
        reason_code="EVIDENCE_INCOMPLETE",
    )
    round2_id = _insert_child(
        database,
        family_id,
        job_kind="round",
        round_no=2,
        state_name="INCONCLUSIVE",
        evidence_path=tmp_path / "round-2-bundle",
        evidence_digest=ROUND2_DIGEST,
        verdict="INCONCLUSIVE",
        reason_code="EVIDENCE_INCOMPLETE",
    )
    for job_id, digest in (
        (campaign_id, CAMPAIGN_PLAN),
        (round1_id, ROUND1_PLAN),
        (round2_id, ROUND2_PLAN),
    ):
        _insert_plan(database, job_id, digest)
    _insert_approval(database, family_id)
    _insert_ledger(database, family_id)
    return family_id, campaign_id, round1_id, round2_id


def _family_index(family_id, campaign_id, round1_id, round2_id):
    return evidence.build_family_index(
        family_id=family_id,
        created_at="2099-01-01T00:00:00Z",
        family_approval_digest=APPROVAL_DIGEST,
        rounds=[
            {
                "round_no": 1,
                "job_id": str(round1_id),
                "plan_digest": ROUND1_PLAN,
                "state": "INCONCLUSIVE",
                "evidence_digest": ROUND1_DIGEST,
            },
            {
                "round_no": 2,
                "job_id": str(round2_id),
                "plan_digest": ROUND2_PLAN,
                "state": "INCONCLUSIVE",
                "evidence_digest": ROUND2_DIGEST,
            },
        ],
        campaign={"job_id": str(campaign_id), "bundle_digest": CAMPAIGN_DIGEST},
        budget=BUDGET,
    )


def _digest(path):
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def _audit_count(database, family_id, event_type):
    row = database.connection.execute(
        "SELECT count(*) FROM audit_events WHERE job_id = %s AND event_type = %s",
        (family_id, event_type),
    ).fetchone()
    return row[0]


def test_family_archive_recovery_writes_index_and_converges(
    isolated_database, tmp_path, monkeypatch
):
    evidence_root = tmp_path / "evidence"
    monkeypatch.setenv("DATACON_EVIDENCE_ROOT", str(evidence_root))
    family_id, campaign_id, round1_id, round2_id = _setup_family(
        isolated_database, tmp_path
    )

    result = workflow.run_worker(isolated_database.dsn, once=True, execute=False)

    path = evidence_root / str(family_id) / "family.json"
    assert path.is_file(), "family stayed AGGREGATING after the recovery scan"
    digest = _digest(path)
    assert _family_row(isolated_database, family_id) == (
        "COMPLETED",
        None,
        None,
        "archived",
        str(path.resolve()),
        digest,
    )
    assert result["families_converged"] == 1
    document = json.loads(path.read_bytes())
    assert document["schema_version"] == 2
    assert document["kind"] == "family_index"
    assert document["family_id"] == str(family_id)
    assert document["state"] == "COMPLETED"
    assert document["family_approval_digest"] == APPROVAL_DIGEST
    assert [entry["round_no"] for entry in document["rounds"]] == [1, 2]
    assert document["rounds"][0]["job_id"] == str(round1_id)
    assert document["rounds"][0]["evidence_digest"] == ROUND1_DIGEST
    assert document["rounds"][1]["job_id"] == str(round2_id)
    assert document["campaign"] == {
        "job_id": str(campaign_id),
        "bundle_digest": CAMPAIGN_DIGEST,
    }
    assert document["budget"] == BUDGET

    sources = state.family_export_sources(isolated_database.dsn, family_id)
    assert sources["family_path"] == str(path.resolve())
    assert sources["family_digest"] == digest
    assert sources["campaign"] == {
        "source": str(tmp_path / "campaign-bundle"),
        "digest": CAMPAIGN_DIGEST,
    }
    assert [entry["round_no"] for entry in sources["rounds"]] == [1, 2]

    before = path.read_bytes()
    workflow.run_worker(isolated_database.dsn, once=True, execute=False)
    assert path.read_bytes() == before
    assert _audit_count(isolated_database, family_id, "family_completed") == 1


def test_family_archive_recovery_reuses_existing_index_after_crash(
    isolated_database, tmp_path, monkeypatch
):
    evidence_root = tmp_path / "evidence"
    monkeypatch.setenv("DATACON_EVIDENCE_ROOT", str(evidence_root))
    family_id, campaign_id, round1_id, round2_id = _setup_family(
        isolated_database, tmp_path
    )
    path = evidence_root / str(family_id) / "family.json"
    # Crash point: the index was written before complete_family committed.
    evidence.finalize_family_index(
        path, _family_index(family_id, campaign_id, round1_id, round2_id)
    )
    written = path.read_bytes()

    workflow.run_worker(isolated_database.dsn, once=True, execute=False)

    assert path.read_bytes() == written
    digest = _digest(path)
    assert _family_row(isolated_database, family_id) == (
        "COMPLETED",
        None,
        None,
        "archived",
        str(path.resolve()),
        digest,
    )
    # The original created_at survives: the sweep must not rewrite the file.
    assert json.loads(path.read_bytes())["created_at"] == "2099-01-01T00:00:00Z"
    workflow.run_worker(isolated_database.dsn, once=True, execute=False)
    assert path.read_bytes() == written
    assert _audit_count(isolated_database, family_id, "family_completed") == 1


def test_family_archive_recovery_records_failure_and_retries(
    isolated_database, tmp_path, monkeypatch
):
    evidence_root = tmp_path / "evidence"
    monkeypatch.setenv("DATACON_EVIDENCE_ROOT", str(evidence_root))
    # The original fixture used max_rounds=2 with only round 1 INCONCLUSIVE,
    # which encoded the premature-convergence bug: a family with a remaining
    # round must keep AGGREGATING. Use a genuinely terminated family instead
    # so this coordinate still tests "failure recorded, retry converges".
    family_id = _insert_family(
        isolated_database, request=_guided_request(max_rounds=1)
    )
    campaign_id = _insert_child(
        isolated_database,
        family_id,
        job_kind="campaign",
        round_no=None,
        state_name="COMPLETED",
        evidence_path=tmp_path / "campaign-bundle",
        evidence_digest=CAMPAIGN_DIGEST,
    )
    round1_id = _insert_child(
        isolated_database,
        family_id,
        job_kind="round",
        round_no=1,
        state_name="INCONCLUSIVE",
        evidence_path=tmp_path / "round-1-bundle",
        evidence_digest=ROUND1_DIGEST,
        verdict="INCONCLUSIVE",
        reason_code="EVIDENCE_INCOMPLETE",
    )
    _insert_plan(isolated_database, campaign_id, CAMPAIGN_PLAN)
    _insert_plan(isolated_database, round1_id, ROUND1_PLAN)
    _insert_approval(isolated_database, family_id)
    # No budget ledger: archiving fails, but the failure must be recorded and
    # the family must remain retryable in AGGREGATING.

    workflow.run_worker(isolated_database.dsn, once=True, execute=False)

    assert _family_row(isolated_database, family_id) == (
        "AGGREGATING",
        None,
        None,
        None,
        None,
        None,
    )
    assert not (evidence_root / str(family_id) / "family.json").exists()
    failure = isolated_database.connection.execute(
        "SELECT detail ->> 'message' FROM audit_events "
        "WHERE job_id = %s AND event_type = 'family_archive_failed'",
        (family_id,),
    ).fetchall()
    assert len(failure) == 1
    assert "budget ledger" in failure[0][0]

    _insert_ledger(isolated_database, family_id)
    workflow.run_worker(isolated_database.dsn, once=True, execute=False)

    assert _family_row(isolated_database, family_id)[0] == "COMPLETED"
    assert (evidence_root / str(family_id) / "family.json").is_file()


# ---------------------------------------------------------------------------
# B-1: only a genuinely terminated family may converge
# ---------------------------------------------------------------------------


def _archived_family(database, tmp_path, *, max_rounds, rounds):
    """Build the common guided family rows and return their identifiers."""
    family_id = _insert_family(
        database, request=_guided_request(max_rounds=max_rounds)
    )
    campaign_id = _insert_child(
        database,
        family_id,
        job_kind="campaign",
        round_no=None,
        state_name="COMPLETED",
        evidence_path=tmp_path / "campaign-bundle",
        evidence_digest=CAMPAIGN_DIGEST,
    )
    _insert_plan(database, campaign_id, CAMPAIGN_PLAN)
    round_ids = []
    for round_no, state_name, verdict, reason_code in rounds:
        round_id = _insert_child(
            database,
            family_id,
            job_kind="round",
            round_no=round_no,
            state_name=state_name,
            evidence_path=tmp_path / f"round-{round_no}-bundle",
            evidence_digest=ROUND1_DIGEST if round_no == 1 else ROUND2_DIGEST,
            verdict=verdict,
            reason_code=reason_code,
        )
        _insert_plan(
            database,
            round_id,
            ROUND1_PLAN if round_no == 1 else ROUND2_PLAN,
        )
        round_ids.append(round_id)
    _insert_approval(database, family_id)
    _insert_ledger(database, family_id)
    return family_id, campaign_id, round_ids


def test_family_does_not_converge_before_max_rounds(
    isolated_database, tmp_path, monkeypatch
):
    evidence_root = tmp_path / "evidence"
    monkeypatch.setenv("DATACON_EVIDENCE_ROOT", str(evidence_root))
    family_id, campaign_id, round_ids = _archived_family(
        isolated_database, tmp_path,
        max_rounds=8,
        rounds=[(1, "INCONCLUSIVE", "INCONCLUSIVE", "EVIDENCE_INCOMPLETE")],
    )

    result = workflow.run_worker(
        isolated_database.dsn, once=True, execute=False
    )

    assert _family_row(isolated_database, family_id)[0] == "AGGREGATING", (
        "family converged before max_rounds was reached"
    )
    assert result["families_converged"] == 0
    assert not (evidence_root / str(family_id) / "family.json").exists()
    assert (
        _audit_count(isolated_database, family_id, "family_archive_failed") == 0
    ), "a waiting family must not be recorded as an archive failure"

    # Migration 013 must still accept the next round for this open family.
    round2_id = _insert_child(
        isolated_database,
        family_id,
        job_kind="round",
        round_no=2,
        state_name="INCONCLUSIVE",
        evidence_path=tmp_path / "round-2-bundle",
        evidence_digest=ROUND2_DIGEST,
        verdict="INCONCLUSIVE",
        reason_code="EVIDENCE_INCOMPLETE",
    )
    assert round2_id is not None


def test_campaign_only_guided_family_stays_aggregating(
    isolated_database, tmp_path, monkeypatch
):
    evidence_root = tmp_path / "evidence"
    monkeypatch.setenv("DATACON_EVIDENCE_ROOT", str(evidence_root))
    family_id, campaign_id, _ = _archived_family(
        isolated_database, tmp_path, max_rounds=8, rounds=[]
    )

    result = workflow.run_worker(
        isolated_database.dsn, once=True, execute=False
    )

    assert _family_row(isolated_database, family_id)[0] == "AGGREGATING", (
        "campaign completion alone must not converge a guided family"
    )
    assert result["families_converged"] == 0
    assert not (evidence_root / str(family_id) / "family.json").exists()


def test_family_converges_when_budget_is_exhausted(
    isolated_database, tmp_path, monkeypatch
):
    evidence_root = tmp_path / "evidence"
    monkeypatch.setenv("DATACON_EVIDENCE_ROOT", str(evidence_root))
    family_id, campaign_id, round_ids = _archived_family(
        isolated_database, tmp_path,
        max_rounds=8,
        rounds=[(1, "INCONCLUSIVE", "INCONCLUSIVE", "EVIDENCE_INCOMPLETE")],
    )
    isolated_database.connection.execute(
        "UPDATE budget_ledger SET remaining_total_seconds = 0, "
        "remaining_fuzz_seconds = 0 WHERE family_id = %s",
        (family_id,),
    )
    _insert_charge(
        isolated_database,
        family_id,
        round_ids[0],
        step_key="execute:round-1",
        kind="general",
        seconds=600,
    )
    _insert_charge(
        isolated_database,
        family_id,
        round_ids[0],
        step_key="fuzz:round-1",
        kind="fuzz",
        seconds=300,
        fuzz=300,
    )

    result = workflow.run_worker(
        isolated_database.dsn, once=True, execute=False
    )

    assert _family_row(isolated_database, family_id)[0] == "COMPLETED"
    assert result["families_converged"] == 1
    assert (evidence_root / str(family_id) / "family.json").is_file()


def test_family_converges_when_last_round_formed_a_verdict(
    isolated_database, tmp_path, monkeypatch
):
    evidence_root = tmp_path / "evidence"
    monkeypatch.setenv("DATACON_EVIDENCE_ROOT", str(evidence_root))
    family_id, campaign_id, round_ids = _archived_family(
        isolated_database, tmp_path,
        max_rounds=8,
        rounds=[(1, "REPRODUCED", "REPRODUCED", "ASAN_SIGNATURE_MATCHED")],
    )

    result = workflow.run_worker(
        isolated_database.dsn, once=True, execute=False
    )

    assert _family_row(isolated_database, family_id)[0] == "COMPLETED"
    assert result["families_converged"] == 1
    document = json.loads(
        (evidence_root / str(family_id) / "family.json").read_bytes()
    )
    assert [entry["state"] for entry in document["rounds"]] == ["REPRODUCED"]


# ---------------------------------------------------------------------------
# B-2: no orphan index, pending envelope checked before the write
# ---------------------------------------------------------------------------


def test_archive_family_rejects_pending_envelope_before_writing(
    isolated_database, tmp_path, monkeypatch
):
    evidence_root = tmp_path / "evidence"
    monkeypatch.setenv("DATACON_EVIDENCE_ROOT", str(evidence_root))
    family_id, campaign_id, round_ids = _archived_family(
        isolated_database, tmp_path,
        max_rounds=1,
        rounds=[(1, "INCONCLUSIVE", "INCONCLUSIVE", "EVIDENCE_INCOMPLETE")],
    )
    isolated_database.connection.execute(
        "INSERT INTO family_envelopes (envelope_id, family_id, envelope_digest, "
        "envelope_json, status) VALUES (%s, %s, %s, %s, 'pending')",
        (
            uuid4(),
            family_id,
            "sha256:" + "b" * 64,
            Jsonb({"max_rounds": 1}),
        ),
    )

    with pytest.raises(state.StateError):
        state.archive_family(isolated_database.dsn, family_id)

    assert not (evidence_root / str(family_id) / "family.json").exists(), (
        "archive_family wrote an index before rejecting the pending envelope"
    )


def test_archive_family_cleans_orphan_after_complete_failure(
    isolated_database, tmp_path, monkeypatch
):
    evidence_root = tmp_path / "evidence"
    monkeypatch.setenv("DATACON_EVIDENCE_ROOT", str(evidence_root))
    family_id, campaign_id, round_ids = _archived_family(
        isolated_database, tmp_path,
        max_rounds=1,
        rounds=[(1, "INCONCLUSIVE", "INCONCLUSIVE", "EVIDENCE_INCOMPLETE")],
    )
    path = evidence_root / str(family_id) / "family.json"
    real_complete = state._complete_family_in_tx

    def _boom(*args, **kwargs):
        raise state.StateError("simulated complete_family failure")

    monkeypatch.setattr(state, "_complete_family_in_tx", _boom)
    with pytest.raises(state.StateError):
        state.archive_family(isolated_database.dsn, family_id)
    assert not path.exists(), "failed convergence left an orphan family index"

    monkeypatch.setattr(state, "_complete_family_in_tx", real_complete)
    result = state.archive_family(isolated_database.dsn, family_id)
    assert result["state"] == "COMPLETED"
    assert path.is_file()
    assert _family_row(isolated_database, family_id)[5] == _digest(path)


def test_archive_family_replaces_stale_orphan_after_new_envelope(
    isolated_database, tmp_path, monkeypatch
):
    evidence_root = tmp_path / "evidence"
    monkeypatch.setenv("DATACON_EVIDENCE_ROOT", str(evidence_root))
    family_id, campaign_id, round_ids = _archived_family(
        isolated_database, tmp_path,
        max_rounds=1,
        rounds=[(1, "INCONCLUSIVE", "INCONCLUSIVE", "EVIDENCE_INCOMPLETE")],
    )
    path = evidence_root / str(family_id) / "family.json"
    path.parent.mkdir(parents=True)
    stale = evidence.build_family_index(
        family_id=family_id,
        created_at="2099-01-01T00:00:00Z",
        family_approval_digest="sha256:" + "99" * 32,
        rounds=[
            {
                "round_no": 1,
                "job_id": str(round_ids[0]),
                "plan_digest": ROUND1_PLAN,
                "state": "INCONCLUSIVE",
                "evidence_digest": ROUND1_DIGEST,
            }
        ],
        campaign={"job_id": str(campaign_id), "bundle_digest": CAMPAIGN_DIGEST},
        budget=BUDGET,
    )
    evidence.finalize_family_index(path, stale)
    assert _family_row(isolated_database, family_id)[4] is None

    result = state.archive_family(isolated_database.dsn, family_id)

    assert result["state"] == "COMPLETED"
    document = json.loads(path.read_bytes())
    assert document["family_approval_digest"] == APPROVAL_DIGEST, (
        "an unprotected orphan blocked the rebuilt family index"
    )
    assert _family_row(isolated_database, family_id)[5] == _digest(path)


# ---------------------------------------------------------------------------
# B-3: terminal-but-unindexable children converge once, never retry forever
# ---------------------------------------------------------------------------


def test_unindexable_failed_child_converges_family_once(
    isolated_database, tmp_path, monkeypatch
):
    evidence_root = tmp_path / "evidence"
    monkeypatch.setenv("DATACON_EVIDENCE_ROOT", str(evidence_root))
    family_id = _insert_family(
        isolated_database, request=_guided_request(max_rounds=8)
    )
    campaign_id = _insert_child(
        isolated_database,
        family_id,
        job_kind="campaign",
        round_no=None,
        state_name="COMPLETED",
        evidence_path=tmp_path / "campaign-bundle",
        evidence_digest=CAMPAIGN_DIGEST,
    )
    round_id = _insert_child(
        isolated_database,
        family_id,
        job_kind="round",
        round_no=1,
        state_name="FAILED",
        evidence_status="failed",
        reason_code="EVIDENCE_WRITE_FAILED",
    )
    _insert_plan(isolated_database, campaign_id, CAMPAIGN_PLAN)
    _insert_plan(isolated_database, round_id, ROUND1_PLAN)
    _insert_approval(isolated_database, family_id)
    _insert_ledger(isolated_database, family_id)

    first = state.converge_families(isolated_database.dsn)
    row = _family_row(isolated_database, family_id)
    assert row[0] == "FAILED", (
        "an unindexable FAILED child left the family retrying forever"
    )
    assert row[2] == "EVIDENCE_WRITE_FAILED"
    assert first == []
    assert (
        _audit_count(
            isolated_database, family_id, "family_terminal_without_index"
        )
        == 1
    )

    second = state.converge_families(isolated_database.dsn)
    assert second == []
    assert (
        _audit_count(
            isolated_database, family_id, "family_terminal_without_index"
        )
        == 1
    ), "the terminal family was re-scanned and audited again"
    assert state.ReleaseStore(isolated_database.dsn).active_slots() == 0


def test_unindexable_blocked_child_without_plan_converges_family_once(
    isolated_database, tmp_path, monkeypatch
):
    evidence_root = tmp_path / "evidence"
    monkeypatch.setenv("DATACON_EVIDENCE_ROOT", str(evidence_root))
    family_id = _insert_family(
        isolated_database, request=_guided_request(max_rounds=8)
    )
    campaign_id = _insert_child(
        isolated_database,
        family_id,
        job_kind="campaign",
        round_no=None,
        state_name="COMPLETED",
        evidence_path=tmp_path / "campaign-bundle",
        evidence_digest=CAMPAIGN_DIGEST,
    )
    # A pre-plan-freeze BLOCKED child: archived blocked bundle, no plan row.
    _insert_child(
        isolated_database,
        family_id,
        job_kind="round",
        round_no=1,
        state_name="BLOCKED",
        evidence_path=tmp_path / "blocked-bundle",
        evidence_digest=ROUND1_DIGEST,
        reason_code="REVIEW_REJECTED",
    )
    _insert_plan(isolated_database, campaign_id, CAMPAIGN_PLAN)
    _insert_approval(isolated_database, family_id)
    _insert_ledger(isolated_database, family_id)

    assert state.converge_families(isolated_database.dsn) == []
    row = _family_row(isolated_database, family_id)
    assert row[0] == "BLOCKED"
    assert row[2] == "REVIEW_REJECTED"
    assert (
        _audit_count(
            isolated_database, family_id, "family_terminal_without_index"
        )
        == 1
    )
    assert state.converge_families(isolated_database.dsn) == []
    assert (
        _audit_count(
            isolated_database, family_id, "family_terminal_without_index"
        )
        == 1
    )
    assert state.ReleaseStore(isolated_database.dsn).active_slots() == 0


# ---------------------------------------------------------------------------
# B-4: serialize snapshot -> write -> pointer per family
# ---------------------------------------------------------------------------


def test_archive_family_holds_family_lock_while_writing_index(
    isolated_database, tmp_path, monkeypatch
):
    evidence_root = tmp_path / "evidence"
    monkeypatch.setenv("DATACON_EVIDENCE_ROOT", str(evidence_root))
    family_id, campaign_id, round_ids = _archived_family(
        isolated_database, tmp_path,
        max_rounds=1,
        rounds=[(1, "INCONCLUSIVE", "INCONCLUSIVE", "EVIDENCE_INCOMPLETE")],
    )
    observed = {}
    real_finalize = evidence.finalize_family_index

    def _probe(path, document=None, **kwargs):
        with psycopg.connect(isolated_database.dsn) as other:
            try:
                other.execute(
                    "SELECT 1 FROM jobs WHERE job_id = %s FOR UPDATE NOWAIT",
                    (family_id,),
                )
                observed["locked"] = False
            except psycopg.errors.LockNotAvailable:
                observed["locked"] = True
        return real_finalize(path, document, **kwargs)

    monkeypatch.setattr(evidence, "finalize_family_index", _probe)
    state.archive_family(isolated_database.dsn, family_id)

    assert observed["locked"] is True, (
        "the family row was not locked across the family.json write"
    )


def test_concurrent_archive_calls_keep_disk_and_database_in_sync(
    isolated_database, tmp_path, monkeypatch
):
    evidence_root = tmp_path / "evidence"
    monkeypatch.setenv("DATACON_EVIDENCE_ROOT", str(evidence_root))
    family_id, campaign_id, round_ids = _archived_family(
        isolated_database, tmp_path,
        max_rounds=1,
        rounds=[(1, "INCONCLUSIVE", "INCONCLUSIVE", "EVIDENCE_INCOMPLETE")],
    )
    barrier = threading.Barrier(2)
    results = []
    errors = []

    def _worker():
        try:
            barrier.wait(timeout=10)
            results.append(
                state.archive_family(isolated_database.dsn, family_id)
            )
        except BaseException as error:  # noqa: BLE001 - surfaced below
            errors.append(error)

    threads = [threading.Thread(target=_worker) for _ in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=30)

    assert errors == []
    assert len(results) == 2
    path = evidence_root / str(family_id) / "family.json"
    digest = _digest(path)
    row = _family_row(isolated_database, family_id)
    assert row[0] == "COMPLETED"
    assert row[5] == digest, "the database pointer and disk bytes diverged"
    assert {entry["evidence_digest"] for entry in results} == {digest}

    again = state.archive_family(isolated_database.dsn, family_id)
    assert again["state"] == "COMPLETED"
    sources = state.family_export_sources(isolated_database.dsn, family_id)
    assert sources["family_digest"] == digest
    assert sources["campaign"]["digest"] == CAMPAIGN_DIGEST


# ---------------------------------------------------------------------------
# S-8: the archive root must not route through symlinks
# ---------------------------------------------------------------------------


def test_archive_family_rejects_symlinked_evidence_root(
    isolated_database, tmp_path, monkeypatch
):
    real_root = tmp_path / "real-evidence"
    real_root.mkdir()
    link = tmp_path / "linked-evidence"
    link.symlink_to(real_root, target_is_directory=True)
    monkeypatch.setenv("DATACON_EVIDENCE_ROOT", str(link))
    family_id, campaign_id, round_ids = _archived_family(
        isolated_database, tmp_path,
        max_rounds=1,
        rounds=[(1, "INCONCLUSIVE", "INCONCLUSIVE", "EVIDENCE_INCOMPLETE")],
    )

    with pytest.raises((state.StateError, evidence.BundleError)):
        state.archive_family(isolated_database.dsn, family_id)

    assert not (real_root / str(family_id) / "family.json").exists()


def test_archive_family_rejects_symlinked_family_directory(
    isolated_database, tmp_path, monkeypatch
):
    root = tmp_path / "evidence"
    root.mkdir()
    family_id, campaign_id, round_ids = _archived_family(
        isolated_database, tmp_path,
        max_rounds=1,
        rounds=[(1, "INCONCLUSIVE", "INCONCLUSIVE", "EVIDENCE_INCOMPLETE")],
    )
    escaped = tmp_path / "escaped"
    escaped.mkdir()
    (root / str(family_id)).symlink_to(escaped, target_is_directory=True)
    monkeypatch.setenv("DATACON_EVIDENCE_ROOT", str(root))

    with pytest.raises((state.StateError, evidence.BundleError)):
        state.archive_family(isolated_database.dsn, family_id)

    assert not (escaped / "family.json").exists()


def test_fixed_family_archives_without_campaign_and_exports_sources(
    isolated_database, tmp_path, monkeypatch
):
    evidence_root = tmp_path / "evidence"
    monkeypatch.setenv("DATACON_EVIDENCE_ROOT", str(evidence_root))
    family_id = _insert_family(
        isolated_database, request=_fixed_request()
    )
    round1_id = _insert_child(
        isolated_database,
        family_id,
        job_kind="round",
        round_no=1,
        state_name="REPRODUCED",
        evidence_path=tmp_path / "round-1-bundle",
        evidence_digest=ROUND1_DIGEST,
        verdict="REPRODUCED",
        reason_code="ASAN_SIGNATURE_MATCHED",
    )
    _insert_plan(isolated_database, round1_id, ROUND1_PLAN)
    _insert_approval(isolated_database, family_id)
    _insert_ledger(isolated_database, family_id)

    result = state.archive_family(isolated_database.dsn, family_id)

    assert result["state"] == "COMPLETED"
    path = evidence_root / str(family_id) / "family.json"
    document = json.loads(path.read_bytes())
    assert document["campaign"] is None
    assert [entry["round_no"] for entry in document["rounds"]] == [1]
    assert document["rounds"][0]["state"] == "REPRODUCED"

    sources = state.family_export_sources(isolated_database.dsn, family_id)
    assert sources["campaign"] is None
    assert [entry["round_no"] for entry in sources["rounds"]] == [1]
    assert sources["family_digest"] == result["evidence_digest"]

    family_status = state.status(isolated_database.dsn, family_id)
    assert family_status["family"]["max_rounds"] == 1
    assert family_status["campaign"] is None


def test_archive_family_retries_after_envelope_is_approved(
    isolated_database, tmp_path, monkeypatch
):
    """pending -> no file -> approved new envelope -> index uses the new tail."""
    evidence_root = tmp_path / "evidence"
    monkeypatch.setenv("DATACON_EVIDENCE_ROOT", str(evidence_root))
    family_id, campaign_id, round_ids = _archived_family(
        isolated_database, tmp_path,
        max_rounds=1,
        rounds=[(1, "INCONCLUSIVE", "INCONCLUSIVE", "EVIDENCE_INCOMPLETE")],
    )
    old_approval = isolated_database.connection.execute(
        "SELECT approval_id FROM family_approvals WHERE family_id = %s",
        (family_id,),
    ).fetchone()[0]
    new_envelope_digest = "sha256:" + "c" * 64
    new_approval_digest = "sha256:" + "77" * 32
    isolated_database.connection.execute(
        "INSERT INTO family_envelopes (envelope_id, family_id, envelope_digest, "
        "envelope_json, status) VALUES (%s, %s, %s, %s, 'pending')",
        (
            uuid4(),
            family_id,
            new_envelope_digest,
            Jsonb({"max_rounds": 1}),
        ),
    )

    with pytest.raises(state.StateError):
        state.archive_family(isolated_database.dsn, family_id)
    path = evidence_root / str(family_id) / "family.json"
    assert not path.exists(), "pending envelope produced a family index"

    # Simulate the D42 approval of the re-proposed envelope: approve the row and
    # append a new chain tail superseding the original approval.
    isolated_database.connection.execute(
        "UPDATE family_envelopes SET status = 'approved' "
        "WHERE family_id = %s AND envelope_digest = %s",
        (family_id, new_envelope_digest),
    )
    isolated_database.connection.execute(
        "INSERT INTO family_approvals (approval_id, family_id, approval_digest, "
        "envelope_digest, first_plan_digest, supersedes, reviewer_id, decided_at) "
        "VALUES (%s, %s, %s, %s, %s, %s, 'reviewer-p1', clock_timestamp())",
        (
            uuid4(),
            family_id,
            new_approval_digest,
            new_envelope_digest,
            CAMPAIGN_PLAN,
            old_approval,
        ),
    )

    result = state.archive_family(isolated_database.dsn, family_id)

    assert result["state"] == "COMPLETED"
    document = json.loads(path.read_bytes())
    assert document["family_approval_digest"] == new_approval_digest
    assert _family_row(isolated_database, family_id)[5] == _digest(path)
