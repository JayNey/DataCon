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
from pathlib import Path as _Path
import sys as _sys
import threading
from uuid import uuid4

import psycopg
import pytest
from psycopg.types.json import Jsonb

from datacon import evidence, state, workflow
from datacon import execution as _execution
from datacon import fuzz as _fuzz

_CONTRACT_DIR = str(_Path(__file__).resolve().parents[1] / "contract")
if _CONTRACT_DIR not in _sys.path:
    _sys.path.append(_CONTRACT_DIR)

from test_build_spec_execution import (  # noqa: E402
    FIXTURE_CASES as _FIXTURE_CASES,
    _configure_isolated_roots,
)
from test_fuzz import (  # noqa: E402
    _Clock,
    _FakeCampaignSandbox,
    _cmake_compile_commands_bytes,
    FACE_FLAGS,
    guided_campaign_plan,
)

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


def _insert_approval(database, family_id, approval_digest=APPROVAL_DIGEST):
    database.connection.execute(
        "INSERT INTO family_approvals (approval_id, family_id, "
        "approval_digest, envelope_digest, first_plan_digest, reviewer_id, "
        "decided_at) VALUES (%s, %s, %s, %s, %s, 'reviewer-p1', "
        "clock_timestamp())",
        (
            uuid4(),
            family_id,
            approval_digest,
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


def _archived_family(
    database, tmp_path, *, max_rounds, rounds, approval_digest=APPROVAL_DIGEST
):
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
    _insert_approval(database, family_id, approval_digest)
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
    # Without a ``family_transition_decided`` event the campaign-only family
    # must not archive: campaign completion alone is not a family conclusion.
    # The no-seed path archives only after the runtime records
    # ``no_next_round`` (see the two decision coordinates below).
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


def _decision_events(database, family_id):
    return database.connection.execute(
        "SELECT stage, reason_code, detail FROM audit_events "
        "WHERE job_id = %s AND event_type = 'family_transition_decided' "
        "ORDER BY event_id",
        (family_id,),
    ).fetchall()


def _approval_digest(tag):
    return "sha256:" + hashlib.sha256(tag.encode()).hexdigest()


NO_SEED_AT_CAMPAIGN = dict(
    after_round_no=0,
    decision="no_next_round",
    reason_code="NO_CANDIDATE_SEED",
    candidate_seed_count=0,
)
NEXT_AFTER_CAMPAIGN = dict(
    after_round_no=0,
    decision="next_round",
    candidate_seed_count=1,
    next_round_no=1,
)
NO_SEED_AFTER_ROUND1 = dict(
    after_round_no=1,
    decision="no_next_round",
    reason_code="NO_REMAINING_SEEDS",
    candidate_seed_count=0,
)


def _decide(database, family_id, campaign_id, **kwargs):
    return state.record_family_transition_decision(
        database.dsn, family_id, campaign_job_id=campaign_id, **kwargs
    )


def _assert_rejected_without_event(database, family_id, campaign_id, **kwargs):
    before = len(_decision_events(database, family_id))
    try:
        _decide(database, family_id, campaign_id, **kwargs)
    except (state.StateError, TypeError):
        pass
    else:
        pytest.fail(f"ineligible decision was accepted: {kwargs}")
    assert len(_decision_events(database, family_id)) == before, (
        f"rejected decision wrote an event: {kwargs}"
    )


# Fail-closed argument combinations at the campaign decision point (B-2).
# Each must be refused before any event is written.
_REJECTED_CAMPAIGN_POINT_CALLS = [
    dict(after_round_no=0, decision="stop", reason_code="NO_CANDIDATE_SEED",
         candidate_seed_count=0),
    dict(after_round_no=0, decision="no_next_round", candidate_seed_count=0),
    dict(after_round_no=0, decision="no_next_round",
         reason_code="NO_CANDIDATE_SEED"),
    dict(after_round_no=0, decision="no_next_round",
         reason_code="NO_CANDIDATE_SEED", candidate_seed_count=-1),
    dict(after_round_no=0, decision="no_next_round",
         reason_code="NO_CANDIDATE_SEED", candidate_seed_count=5),
    dict(after_round_no=0, decision="no_next_round",
         reason_code="NO_CANDIDATE_SEED", candidate_seed_count=False),
    dict(after_round_no=0, decision="no_next_round",
         reason_code="REPRODUCED", candidate_seed_count=0),
    dict(after_round_no=0, decision="no_next_round",
         reason_code="FOO", candidate_seed_count=0),
    # NO_REMAINING_SEEDS belongs to the round decision points only.
    dict(after_round_no=0, decision="no_next_round",
         reason_code="NO_REMAINING_SEEDS", candidate_seed_count=0),
    dict(after_round_no=0, decision="no_next_round",
         reason_code="NO_CANDIDATE_SEED", candidate_seed_count=0,
         next_round_no=1),
    dict(after_round_no=0, decision="next_round"),
    dict(after_round_no=0, decision="next_round", next_round_no=1),
    dict(after_round_no=0, decision="next_round", next_round_no=1,
         candidate_seed_count=0),
    dict(after_round_no=0, decision="next_round", next_round_no=1,
         reason_code="NO_CANDIDATE_SEED", candidate_seed_count=0),
    dict(after_round_no=0, decision="next_round", next_round_no=1,
         reason_code="NO_CANDIDATE_SEED", candidate_seed_count=1),
    dict(after_round_no=0, decision="next_round", next_round_no=0,
         candidate_seed_count=1),
    dict(after_round_no=0, decision="next_round", next_round_no=True,
         candidate_seed_count=1),
    dict(after_round_no=0, decision="next_round", next_round_no=1.0,
         candidate_seed_count=1),
    dict(after_round_no=0, decision="next_round", next_round_no=2,
         candidate_seed_count=1),
    dict(after_round_no=0, decision="next_round", next_round_no=99,
         candidate_seed_count=1),
    # A round decision point with no round child yet.
    dict(after_round_no=1, decision="no_next_round",
         reason_code="NO_REMAINING_SEEDS", candidate_seed_count=0),
    dict(after_round_no=-1, decision="no_next_round",
         reason_code="NO_CANDIDATE_SEED", candidate_seed_count=0),
    dict(after_round_no=True, decision="no_next_round",
         reason_code="NO_CANDIDATE_SEED", candidate_seed_count=0),
    # after_round_no is a required keyword (P2 must name its decision point).
    dict(decision="no_next_round", reason_code="NO_CANDIDATE_SEED",
         candidate_seed_count=0),
    # ``now`` was removed (S-3): the event time is the database clock.
    dict(NO_SEED_AT_CAMPAIGN, now="2099-01-01T00:00:00Z"),
]


def _assert_decision_rejected(isolated_database, tmp_path, family_id, campaign_id):
    """Every malformed or ineligible call is refused and writes nothing."""
    database = isolated_database
    for kwargs in _REJECTED_CAMPAIGN_POINT_CALLS:
        _assert_rejected_without_event(database, family_id, campaign_id, **kwargs)
    with pytest.raises(TypeError):
        _decide(database, family_id, campaign_id, now=None, **NO_SEED_AT_CAMPAIGN)

    # The campaign must be this family's own COMPLETED campaign child: a
    # real COMPLETED campaign of another family is refused, as is an unknown id.
    other_family, other_campaign, _ = _archived_family(
        database, tmp_path / "other", max_rounds=8, rounds=[],
        approval_digest=_approval_digest(f"other-{family_id}"),
    )
    _assert_rejected_without_event(
        database, family_id, other_campaign, **NO_SEED_AT_CAMPAIGN
    )
    _assert_rejected_without_event(
        database, family_id, uuid4(), **NO_SEED_AT_CAMPAIGN
    )
    # A non-family job or a v1 job is not a family.
    _assert_rejected_without_event(
        database, campaign_id, campaign_id, **NO_SEED_AT_CAMPAIGN
    )
    v1_job = uuid4()
    database.connection.execute(
        "INSERT INTO jobs (job_id, request, state, stage, submitted_at) "
        "VALUES (%s, %s, 'QUEUED', 'queued', clock_timestamp())",
        (v1_job, Jsonb({"cve_id": "CVE-2099-0001"})),
    )
    _assert_rejected_without_event(
        database, v1_job, campaign_id, **NO_SEED_AT_CAMPAIGN
    )
    database.connection.execute("DELETE FROM jobs WHERE job_id = %s", (v1_job,))

    database.connection.execute(
        "UPDATE jobs SET state = 'RUNNING', evidence_status = NULL, "
        "evidence_path = NULL, evidence_digest = NULL WHERE job_id = %s",
        (campaign_id,),
    )
    _assert_rejected_without_event(
        database, family_id, campaign_id, **NO_SEED_AT_CAMPAIGN
    )
    database.connection.execute(
        "UPDATE jobs SET state = 'COMPLETED', evidence_status = 'archived', "
        "evidence_path = %s, evidence_digest = %s WHERE job_id = %s",
        (str(tmp_path / "campaign-bundle"), CAMPAIGN_DIGEST, campaign_id),
    )
    database.connection.execute(
        "INSERT INTO family_envelopes (envelope_id, family_id, "
        "envelope_digest, envelope_json, status) "
        "VALUES (%s, %s, %s, %s, 'pending')",
        (uuid4(), family_id, "sha256:" + "c" * 64, Jsonb({})),
    )
    _assert_rejected_without_event(
        database, family_id, campaign_id, **NO_SEED_AT_CAMPAIGN
    )
    database.connection.execute(
        "DELETE FROM family_envelopes WHERE family_id = %s", (family_id,)
    )
    assert _decision_events(database, family_id) == []
    assert _decision_events(database, other_family) == []

    # Nothing was recorded, so neither family may archive.
    workflow.run_worker(database.dsn, once=True, execute=False)
    assert _family_row(database, family_id)[0] == "AGGREGATING"
    assert _family_row(database, other_family)[0] == "AGGREGATING"
    return other_family, other_campaign


def test_campaign_only_guided_family_archives_after_no_seed_decision(
    isolated_database, tmp_path, monkeypatch
):
    evidence_root = tmp_path / "evidence"
    monkeypatch.setenv("DATACON_EVIDENCE_ROOT", str(evidence_root))
    family_id, campaign_id, _ = _archived_family(
        isolated_database, tmp_path, max_rounds=8, rounds=[]
    )

    decision = _decide(
        isolated_database, family_id, campaign_id, **NO_SEED_AT_CAMPAIGN
    )
    assert decision["decision"] == "no_next_round"
    assert decision["after_round_no"] == 0
    assert decision["candidate_seed_count"] == 0
    assert isinstance(decision["created_at"], str)
    assert decision["created_at"].endswith("Z")

    result = workflow.run_worker(
        isolated_database.dsn, once=True, execute=False
    )

    path = evidence_root / str(family_id) / "family.json"
    row = _family_row(isolated_database, family_id)
    assert row[0] == "COMPLETED", (
        "no_next_round decision did not archive the campaign-only family"
    )
    assert result["families_converged"] == 1
    assert path.is_file()
    assert row[4] and row[5]
    assert row[4] == str(path.resolve())
    assert row[5] == _digest(path)
    assert _audit_count(isolated_database, family_id, "family_completed") == 1
    document = json.loads(path.read_bytes())
    assert document["rounds"] == []
    assert document["campaign"] == {
        "job_id": str(campaign_id),
        "bundle_digest": CAMPAIGN_DIGEST,
    }


def test_family_transition_decision_is_idempotent_and_rejects_conflict(
    isolated_database, tmp_path, monkeypatch
):
    evidence_root = tmp_path / "evidence"
    monkeypatch.setenv("DATACON_EVIDENCE_ROOT", str(evidence_root))
    family_id, campaign_id, _ = _archived_family(
        isolated_database, tmp_path, max_rounds=8, rounds=[]
    )
    other_family, other_campaign = _assert_decision_rejected(
        isolated_database, tmp_path, family_id, campaign_id
    )

    first = _decide(
        isolated_database, family_id, campaign_id,
        **dict(NEXT_AFTER_CAMPAIGN, candidate_seed_count=2),
    )
    second = _decide(
        isolated_database, family_id, campaign_id,
        **dict(NEXT_AFTER_CAMPAIGN, candidate_seed_count=2),
    )
    assert first == second
    events = _decision_events(isolated_database, family_id)
    assert len(events) == 1, "idempotent decision wrote a second event"
    stage, reason_code, detail = events[0]
    assert stage == "transition"
    assert reason_code is None
    assert detail == {
        "campaign_job_id": str(campaign_id),
        "after_round_no": 0,
        "decision": "next_round",
        "candidate_seed_count": 2,
        "next_round_no": 1,
        "reason_code": None,
    }

    # Same decision point, different decision or detail: a conflict.
    for kwargs in (
        NO_SEED_AT_CAMPAIGN,
        dict(NEXT_AFTER_CAMPAIGN, candidate_seed_count=3),
        dict(NEXT_AFTER_CAMPAIGN, candidate_seed_count=2, next_round_no=2),
        dict(NEXT_AFTER_CAMPAIGN, candidate_seed_count=2,
             reason_code="NO_CANDIDATE_SEED"),
    ):
        _assert_rejected_without_event(
            isolated_database, family_id, campaign_id, **kwargs
        )
    assert len(_decision_events(isolated_database, family_id)) == 1

    # next_round without its round child must not archive early.
    result = workflow.run_worker(
        isolated_database.dsn, once=True, execute=False
    )
    assert _family_row(isolated_database, family_id)[0] == "AGGREGATING", (
        "next_round decision archived the family before its round ran"
    )
    assert result["families_converged"] == 0
    assert not (evidence_root / str(family_id) / "family.json").exists()
    assert (
        _audit_count(isolated_database, family_id, "family_archive_failed") == 0
    )

    # A family that already COMPLETED still answers an identical retry with
    # the original record (idempotency is checked first) and refuses a
    # different one; neither writes an event.
    recorded = _decide(
        isolated_database, other_family, other_campaign, **NO_SEED_AT_CAMPAIGN
    )
    workflow.run_worker(isolated_database.dsn, once=True, execute=False)
    assert _family_row(isolated_database, other_family)[0] == "COMPLETED"
    again = _decide(
        isolated_database, other_family, other_campaign, **NO_SEED_AT_CAMPAIGN
    )
    assert again == recorded
    _assert_rejected_without_event(
        isolated_database, other_family, other_campaign, **NEXT_AFTER_CAMPAIGN
    )
    assert len(_decision_events(isolated_database, other_family)) == 1


def test_family_archives_after_seeds_exhausted_mid_family(
    isolated_database, tmp_path, monkeypatch
):
    evidence_root = tmp_path / "evidence"
    monkeypatch.setenv("DATACON_EVIDENCE_ROOT", str(evidence_root))
    family_id, campaign_id, _ = _archived_family(
        isolated_database, tmp_path, max_rounds=8, rounds=[]
    )
    _decide(isolated_database, family_id, campaign_id, **NEXT_AFTER_CAMPAIGN)

    # Round 1 still running: no decision after round 1 yet.
    round1_id = _insert_child(
        isolated_database,
        family_id,
        job_kind="round",
        round_no=1,
        state_name="RUNNING",
        evidence_status=None,
    )
    _insert_plan(isolated_database, round1_id, ROUND1_PLAN)
    _assert_rejected_without_event(
        isolated_database, family_id, campaign_id, **NO_SEED_AFTER_ROUND1
    )
    isolated_database.connection.execute(
        "UPDATE jobs SET state = 'INCONCLUSIVE', verdict = 'INCONCLUSIVE', "
        "reason_code = 'EVIDENCE_INCOMPLETE', evidence_status = 'archived', "
        "evidence_path = %s, evidence_digest = %s WHERE job_id = %s",
        (str(tmp_path / "round-1-bundle"), ROUND1_DIGEST, round1_id),
    )

    # Ineligible decision points and payloads are refused without an event.
    for kwargs in (
        dict(NO_SEED_AFTER_ROUND1, after_round_no=2),
        dict(NO_SEED_AFTER_ROUND1, reason_code="NO_CANDIDATE_SEED"),
        dict(NO_SEED_AFTER_ROUND1, candidate_seed_count=1),
        dict(after_round_no=1, decision="next_round", candidate_seed_count=1,
             next_round_no=1),
        dict(after_round_no=1, decision="next_round", candidate_seed_count=1,
             next_round_no=9),
    ):
        _assert_rejected_without_event(
            isolated_database, family_id, campaign_id, **kwargs
        )
    # The family's own round child is not its campaign.
    _assert_rejected_without_event(
        isolated_database, family_id, round1_id, **NO_SEED_AFTER_ROUND1
    )

    # Only next_round@0 exists: the family keeps waiting.
    for _ in range(2):
        result = workflow.run_worker(
            isolated_database.dsn, once=True, execute=False
        )
        assert result["families_converged"] == 0
    assert _family_row(isolated_database, family_id)[0] == "AGGREGATING"

    _decide(isolated_database, family_id, campaign_id, **NO_SEED_AFTER_ROUND1)
    assert len(_decision_events(isolated_database, family_id)) == 2

    result = workflow.run_worker(
        isolated_database.dsn, once=True, execute=False
    )
    path = evidence_root / str(family_id) / "family.json"
    row = _family_row(isolated_database, family_id)
    assert row[0] == "COMPLETED", (
        "no_next_round after round 1 did not archive the family"
    )
    assert result["families_converged"] == 1
    assert row[5] == _digest(path)
    document = json.loads(path.read_bytes())
    assert [entry["round_no"] for entry in document["rounds"]] == [1]
    assert document["rounds"][0]["job_id"] == str(round1_id)
    assert _audit_count(isolated_database, family_id, "family_completed") == 1


def test_campaign_decision_cannot_archive_a_family_with_rounds(
    isolated_database, tmp_path, monkeypatch
):
    evidence_root = tmp_path / "evidence"
    monkeypatch.setenv("DATACON_EVIDENCE_ROOT", str(evidence_root))
    family_id, campaign_id, round_ids = _archived_family(
        isolated_database, tmp_path,
        max_rounds=8,
        rounds=[(1, "INCONCLUSIVE", "INCONCLUSIVE", "EVIDENCE_INCOMPLETE")],
    )
    # Round 1 already exists, so the campaign decision point has passed.
    _assert_rejected_without_event(
        isolated_database, family_id, campaign_id, **NO_SEED_AT_CAMPAIGN
    )
    _assert_rejected_without_event(
        isolated_database, family_id, campaign_id, **NEXT_AFTER_CAMPAIGN
    )
    # next_round beyond the effective max_rounds is refused.
    capped_family, capped_campaign, _ = _archived_family(
        isolated_database, tmp_path / "capped",
        max_rounds=1,
        rounds=[(1, "INCONCLUSIVE", "INCONCLUSIVE", "EVIDENCE_INCOMPLETE")],
        approval_digest=_approval_digest(f"capped-{family_id}"),
    )
    _assert_rejected_without_event(
        isolated_database, capped_family, capped_campaign,
        after_round_no=1, decision="next_round", candidate_seed_count=1,
        next_round_no=2,
    )

    # A no_next_round event at a stale decision point must not archive: plant
    # one directly (bypassing the entry) and the gate still waits.
    isolated_database.connection.execute(
        "INSERT INTO audit_events (job_id, stage, event_type, detail) "
        "VALUES (%s, 'transition', 'family_transition_decided', %s)",
        (
            family_id,
            Jsonb({
                "campaign_job_id": str(campaign_id),
                "after_round_no": 0,
                "decision": "no_next_round",
                "candidate_seed_count": 0,
                "next_round_no": None,
                "reason_code": "NO_CANDIDATE_SEED",
            }),
        ),
    )
    # A legacy event without after_round_no is never adopted either.
    isolated_database.connection.execute(
        "INSERT INTO audit_events (job_id, stage, event_type, detail) "
        "VALUES (%s, 'transition', 'family_transition_decided', %s)",
        (
            family_id,
            Jsonb({
                "campaign_job_id": str(campaign_id),
                "decision": "no_next_round",
                "candidate_seed_count": 0,
                "next_round_no": None,
                "reason_code": "NO_CANDIDATE_SEED",
            }),
        ),
    )
    result = workflow.run_worker(
        isolated_database.dsn, once=True, execute=False
    )
    assert _family_row(isolated_database, family_id)[0] == "AGGREGATING", (
        "a campaign-point no_next_round archived a family with rounds"
    )
    assert not (evidence_root / str(family_id) / "family.json").exists()
    # The capped family archives on max_rounds, not on any decision.
    assert _family_row(isolated_database, capped_family)[0] == "COMPLETED"
    assert result["families_converged"] == 1
    assert round_ids


def test_family_transition_decision_is_serialized_under_concurrency(
    isolated_database, tmp_path
):
    family_id, campaign_id, _ = _archived_family(
        isolated_database, tmp_path, max_rounds=8, rounds=[]
    )
    workers = 4

    def race(calls):
        barrier = threading.Barrier(len(calls))
        outcomes = [None] * len(calls)

        def run(index, target_family, target_campaign, kwargs):
            barrier.wait()
            try:
                outcomes[index] = (
                    "ok",
                    state.record_family_transition_decision(
                        isolated_database.dsn,
                        target_family,
                        campaign_job_id=target_campaign,
                        **kwargs,
                    ),
                )
            except Exception as error:  # noqa: BLE001 - reported below
                outcomes[index] = ("error", f"{type(error).__name__}: {error}")

        threads = [
            threading.Thread(target=run, args=(index, *call))
            for index, call in enumerate(calls)
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=30)
        return outcomes

    same = race(
        [(family_id, campaign_id, NO_SEED_AT_CAMPAIGN)] * workers
    )
    assert [kind for kind, _ in same] == ["ok"] * workers
    records = [record for _, record in same]
    assert all(record == records[0] for record in records)
    assert len(_decision_events(isolated_database, family_id)) == 1

    other_family, other_campaign, _ = _archived_family(
        isolated_database, tmp_path / "race", max_rounds=8, rounds=[],
        approval_digest=_approval_digest(f"race-{family_id}"),
    )
    mixed = race(
        [
            (other_family, other_campaign, NO_SEED_AT_CAMPAIGN),
            (other_family, other_campaign, NEXT_AFTER_CAMPAIGN),
        ]
        * 2
    )
    winners = {
        record["decision"] for kind, record in mixed if kind == "ok"
    }
    assert len(winners) == 1, f"conflicting decisions both won: {mixed}"
    assert sum(kind == "ok" for kind, _ in mixed) == 2
    assert len(_decision_events(isolated_database, other_family)) == 1


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

    out_term = workflow.run_worker(isolated_database.dsn, once=True, execute=False)
    assert out_term["families_converged"] == 0
    assert out_term["families_terminated"] == 1
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


def test_guided_family_waits_for_validation_when_only_fuzz_budget_is_exhausted(
    isolated_database, tmp_path, monkeypatch
):
    """改9: a guided family whose fuzz sub-budget is exhausted stays AGGREGATING.

    Validation rounds only execute general steps (build/replay), so exhausting
    the fuzz sub-budget during campaign must not prematurely archive the family
    while total budget and rounds remain.
    """
    evidence_root = tmp_path / "evidence"
    monkeypatch.setenv("DATACON_EVIDENCE_ROOT", str(evidence_root))
    family_id, campaign_id, round_ids = _archived_family(
        isolated_database, tmp_path,
        max_rounds=8,
        rounds=[(1, "INCONCLUSIVE", "INCONCLUSIVE", "EVIDENCE_INCOMPLETE")],
    )
    isolated_database.connection.execute(
        "UPDATE budget_ledger SET remaining_total_seconds = 600, "
        "remaining_fuzz_seconds = 0 WHERE family_id = %s",
        (family_id,),
    )
    _insert_charge(
        isolated_database,
        family_id,
        campaign_id,
        step_key="fuzz:campaign",
        kind="fuzz",
        seconds=300,
        fuzz=300,
    )

    # A fixed family before its first round finishes is unaffected too.
    fixed_family = _insert_family(isolated_database, request=_fixed_request())
    _insert_approval(isolated_database, fixed_family, "sha256:" + "5f" * 32)
    _insert_ledger(
        isolated_database,
        fixed_family,
        max_total=900,
        max_fuzz=0,
        remaining_total=900,
        remaining_fuzz=0,
    )

    result = workflow.run_worker(isolated_database.dsn, once=True, execute=False)

    assert _family_row(isolated_database, family_id)[0] == "AGGREGATING", (
        "guided family archived before validation when only fuzz sub-budget was exhausted"
    )
    assert result["families_converged"] == 0
    assert not (evidence_root / str(family_id) / "family.json").exists()
    assert _family_row(isolated_database, fixed_family)[0] == "AGGREGATING"


def test_worker_scan_charges_before_family_is_sealed(
    isolated_database, tmp_path, monkeypatch
):
    """T12 B3: recover uncharged attempts before sealing, and never charge a sealed family."""
    evidence_root = tmp_path / "evidence"
    monkeypatch.setenv("DATACON_EVIDENCE_ROOT", str(evidence_root))
    family_id, campaign_id, round_ids = _archived_family(
        isolated_database,
        tmp_path,
        max_rounds=1,
        rounds=[(1, "INCONCLUSIVE", "INCONCLUSIVE", "EVIDENCE_INCOMPLETE")],
    )
    # Round 1 completed in generation 2; generation 1 crashed before charging.
    isolated_database.connection.execute(
        "UPDATE jobs SET generation = 2 WHERE job_id = %s",
        (round_ids[0],),
    )
    isolated_database.connection.execute(
        "INSERT INTO attempts (attempt_id, job_id, stage, step_key, attempt_no, "
        "generation, status, result, started_at) "
        "VALUES (%s, %s, 'execute', 'build:vulnerable', 1, 1, 'started', %s, "
        "clock_timestamp() - interval '1 hour')",
        (
            uuid4(),
            round_ids[0],
            Jsonb({"budget": {"charge_kind": "general", "ceiling_seconds": 120.0}}),
        ),
    )

    # Direct converge_families must wait while an uncharged attempt is pending.
    assert state.converge_families(isolated_database.dsn) == [], (
        "family was sealed while an uncharged budget attempt was still pending"
    )
    assert _family_row(isolated_database, family_id)[0] == "AGGREGATING"

    # Worker scan recovers the charge first, then seals family.json with the
    # exact post-recovery budget.
    out = workflow.run_worker(isolated_database.dsn, once=True, execute=False)
    assert out["charges_recovered"] == 1
    assert out["families_converged"] == 1
    assert out["families_terminated"] == 0
    assert _family_row(isolated_database, family_id)[0] == "COMPLETED"
    doc = json.loads((evidence_root / str(family_id) / "family.json").read_bytes())
    summary = state.family_budget_summary(isolated_database.dsn, family_id)
    assert doc["budget"] == summary, (
        f"family.json budget {doc['budget']} diverged from family_budget_summary {summary}"
    )
    assert doc["budget"]["spent_seconds"] == 120
    assert doc["budget"]["remaining_seconds"] == 780

    # A second scan changes nothing.
    again = workflow.run_worker(isolated_database.dsn, once=True, execute=False)
    assert again["charges_recovered"] == 0
    assert again["families_converged"] == 0
    assert state.family_budget_summary(isolated_database.dsn, family_id) == summary

    # Once a family is already sealed (not AGGREGATING), a late uncharged
    # attempt row must never mutate its ledger: skip, audit, and remove from
    # future candidate scans.
    late_attempt_id = uuid4()
    isolated_database.connection.execute(
        "INSERT INTO attempts (attempt_id, job_id, stage, step_key, attempt_no, "
        "generation, status, result, started_at) "
        "VALUES (%s, %s, 'execute', 'build:fixed', 2, 1, 'started', %s, "
        "clock_timestamp() - interval '1 hour')",
        (
            late_attempt_id,
            round_ids[0],
            Jsonb({"budget": {"charge_kind": "general", "ceiling_seconds": 60.0}}),
        ),
    )
    assert state.recover_uncharged_attempts(isolated_database.dsn) == 0, (
        "recover_uncharged_attempts mutated the budget of an already-sealed family"
    )
    assert state.family_budget_summary(isolated_database.dsn, family_id) == summary
    late_row = isolated_database.connection.execute(
        "SELECT status, result FROM attempts WHERE attempt_id = %s",
        (late_attempt_id,),
    ).fetchone()
    assert late_row[0] == "infra_error", (
        "skipped attempt on sealed family stayed a started candidate"
    )
    assert late_row[1]["budget_recovery"] == "unchargeable"
    skipped_events = isolated_database.connection.execute(
        "SELECT detail FROM audit_events "
        "WHERE job_id = %s AND event_type = 'budget_charge_recovery_skipped'",
        (round_ids[0],),
    ).fetchall()
    assert len(skipped_events) == 1
    assert skipped_events[0][0]["reason"] == "family_not_aggregating"
    assert state.recover_uncharged_attempts(isolated_database.dsn) == 0
    assert (
        isolated_database.connection.execute(
            "SELECT count(*) FROM audit_events "
            "WHERE job_id = %s AND event_type = 'budget_charge_recovery_skipped'",
            (round_ids[0],),
        ).fetchone()[0]
        == 1
    )


# ---------------------------------------------------------------------------
# T12 B1 (改9 增补): the worker runs a v2 campaign end to end and takes the
# family decision at the campaign point (edges #20/#23/#24).
# ---------------------------------------------------------------------------

def _seed_ready_campaign(database, *, max_fuzz_seconds=60):
    """A guided family whose human-approved campaign child is READY to claim."""
    job, plan, plan_digest, review, envelope = guided_campaign_plan(
        max_fuzz_seconds=max_fuzz_seconds
    )
    family_id = uuid4()
    campaign_id = uuid4()
    plan = json.loads(json.dumps(plan))
    plan["family_id"] = plan["parent_job_id"] = str(family_id)
    from datacon import contracts as _contracts

    plan_digest = _contracts.plan_digest(plan)
    request = json.loads(json.dumps(job["request"]))
    envelope_digest = _contracts.envelope_digest(envelope)
    connection = database.connection
    connection.execute(
        "INSERT INTO jobs (job_id, request, state, stage, submitted_at, "
        "job_contract_version, family_id, job_kind, parent_job_id, round_no, "
        "generation, workflow_synced) VALUES (%s, %s, 'AGGREGATING', 'family', "
        "clock_timestamp(), 2, %s, 'family', NULL, NULL, 1, true)",
        (family_id, Jsonb(request), family_id),
    )
    connection.execute(
        "INSERT INTO family_envelopes (envelope_id, family_id, envelope_digest, "
        "envelope_json, status, review_deadline_at) "
        "VALUES (%s, %s, %s, %s, 'approved', clock_timestamp())",
        (uuid4(), family_id, envelope_digest, Jsonb(envelope)),
    )
    approval_digest = "sha256:" + hashlib.sha256(str(family_id).encode()).hexdigest()
    connection.execute(
        "INSERT INTO family_approvals (approval_id, family_id, approval_digest, "
        "envelope_digest, first_plan_digest, reviewer_id, decided_at, supersedes) "
        "VALUES (%s, %s, %s, %s, %s, 'reviewer-01', clock_timestamp(), NULL)",
        (uuid4(), family_id, approval_digest, envelope_digest, plan_digest),
    )
    connection.execute(
        "INSERT INTO reviews (review_id, job_id, plan_digest, reviewer_id, "
        "decision, review_deadline_at, decided_at) VALUES (%s, %s, %s, "
        "'reviewer-01', 'approve', clock_timestamp(), clock_timestamp())",
        (uuid4(), family_id, plan_digest),
    )
    state.initialize_budget_ledger(
        database.dsn,
        family_id,
        max_total_seconds=envelope["max_total_seconds"],
        max_fuzz_seconds=envelope["max_fuzz_seconds"],
    )
    connection.execute(
        "INSERT INTO jobs (job_id, request, state, stage, submitted_at, "
        "job_contract_version, family_id, job_kind, parent_job_id, round_no, "
        "generation, workflow_synced) VALUES (%s, %s, 'READY', 'review', "
        "clock_timestamp(), 2, %s, 'campaign', %s, NULL, 0, true)",
        (campaign_id, Jsonb(request), family_id, family_id),
    )
    connection.execute(
        "INSERT INTO plans (plan_id, job_id, plan_digest, plan, summary) "
        "VALUES (%s, %s, %s, %s, %s)",
        (uuid4(), campaign_id, plan_digest, Jsonb(plan), Jsonb({})),
    )
    return family_id, campaign_id, plan, approval_digest, envelope


def _install_fake_campaign_sandbox(monkeypatch, plan, *, crashes):
    clock = _Clock()
    monkeypatch.setattr(_execution, "STEP_CLOCK", clock)
    created = []

    def _factory(**_kwargs):
        sandbox = _FakeCampaignSandbox(
            crashes=crashes,
            clock=clock,
            image_digest=plan["image_digest"],
            build_recipe_digest=plan["build_recipe_digest"],
            faces={
                version: _cmake_compile_commands_bytes(flags=list(FACE_FLAGS))
                for version in ("vulnerable", "fixed")
            },
            face_name="compile_commands.json",
        )
        created.append(sandbox)
        return sandbox

    monkeypatch.setattr(_execution, "DockerSandbox", _factory)
    return created


def _transition_events(database, family_id):
    return [
        row[0]
        for row in database.connection.execute(
            "SELECT detail FROM audit_events WHERE job_id = %s "
            "AND event_type = 'family_transition_decided' ORDER BY event_id",
            (family_id,),
        ).fetchall()
    ]


def test_worker_runs_v2_campaign_and_derives_admitted_round(
    isolated_database, tmp_path, monkeypatch
):
    """v2 claim → campaign → COMPLETED → next_round@0 → round 1 READY + admitted."""
    database = isolated_database
    run_root, _evidence_root = _configure_isolated_roots(tmp_path, monkeypatch)
    family_id, campaign_id, plan, approval_digest, envelope = _seed_ready_campaign(
        database
    )
    sandboxes = _install_fake_campaign_sandbox(
        monkeypatch, plan, crashes=(b"WXYZ\n", b"QRST\n")
    )

    result = workflow.run_worker(
        database.dsn, once=True, case_root=str(_FIXTURE_CASES), run_root=str(run_root)
    )

    assert result["job_id"] == str(campaign_id)
    campaign = state.load_job(database.dsn, campaign_id)
    assert campaign["state"] == "COMPLETED", campaign
    assert campaign["verdict"] is None and campaign["reason_code"] is None
    assert campaign["evidence_status"] == "archived"
    assert campaign["lease_owner"] is None and campaign["workflow_synced"] is True
    verified = evidence.verify_bundle(campaign["evidence_path"])
    assert evidence.canonical_manifest_digest(verified.manifest) == campaign["evidence_digest"]
    assert len(sandboxes) == 1 and len(sandboxes[0].fuzz_calls) == 1
    assert sandboxes[0].replay_calls == []

    # Fuzz time is charged to both budgets; general steps only to the total.
    charges = database.connection.execute(
        "SELECT charge_kind, seconds, fuzz_seconds FROM budget_charges "
        "WHERE job_id = %s ORDER BY step_key",
        (campaign_id,),
    ).fetchall()
    fuzz_rows = [row for row in charges if row[0] == "fuzz"]
    assert len(fuzz_rows) == 1 and fuzz_rows[0][1] == fuzz_rows[0][2] >= 1
    assert all(row[2] == 0 for row in charges if row[0] == "general")

    # The family decided at the campaign point and derived round 1.
    events = _transition_events(database, family_id)
    assert len(events) == 1
    assert events[0]["after_round_no"] == 0
    assert events[0]["decision"] == "next_round"
    assert events[0]["candidate_seed_count"] == 2
    assert events[0]["next_round_no"] == 1
    rounds = database.connection.execute(
        "SELECT job_id, state, round_no FROM jobs WHERE parent_job_id = %s "
        "AND job_kind = 'round'",
        (family_id,),
    ).fetchall()
    assert len(rounds) == 1 and rounds[0][1] == "READY" and rounds[0][2] == 1
    round_id = rounds[0][0]
    admission = state.get_admission(database.dsn, round_id)
    assert admission is not None and admission["approval_kind"] == "policy"
    assert admission["seed_digest"] == _fuzz.validate_crash_seed_record(
        json.loads(verified.file_data[_fuzz.FUZZ_PROVENANCE_PATH])["crash_seeds"][0]
    )["sha256"]
    round_plan = state.get_plan(database.dsn, round_id)["plan"]
    assert round_plan["parent_approval_digest"] == approval_digest
    assert round_plan["inputs"]["candidate"] == admission["seed_digest"]
    assert round_plan["build_ref"] is None  # validation reuse is stage C
    assert state.load_job(database.dsn, family_id)["state"] == "AGGREGATING"

    # Re-entry is idempotent: while round 1 is not terminal the family stands
    # at no decision point, so nothing is decided or derived again.
    assert workflow.advance_family_transition(
        database.dsn, family_id, case_root=str(_FIXTURE_CASES), run_root=str(run_root)
    ) is None
    workflow.advance_family_transitions(
        database.dsn, case_root=str(_FIXTURE_CASES), run_root=str(run_root)
    )
    assert len(_transition_events(database, family_id)) == 1
    assert database.connection.execute(
        "SELECT count(*) FROM jobs WHERE parent_job_id = %s AND job_kind = 'round'",
        (family_id,),
    ).fetchone()[0] == 1

    # Crash window: next_round recorded but the child never created. The
    # sweep re-derives exactly the same plan without a second decision.
    database.connection.execute(
        "DELETE FROM admissions WHERE job_id = %s", (round_id,)
    )
    database.connection.execute("DELETE FROM audit_events WHERE job_id = %s", (round_id,))
    database.connection.execute("DELETE FROM plans WHERE job_id = %s", (round_id,))
    database.connection.execute("DELETE FROM jobs WHERE job_id = %s", (round_id,))
    swept = workflow.advance_family_transitions(
        database.dsn, case_root=str(_FIXTURE_CASES), run_root=str(run_root)
    )
    assert swept == 1
    rederived = database.connection.execute(
        "SELECT p.plan_digest FROM jobs j JOIN plans p ON p.job_id = j.job_id "
        "WHERE j.parent_job_id = %s AND j.job_kind = 'round'",
        (family_id,),
    ).fetchall()
    from datacon import contracts as _contracts

    assert [row[0] for row in rederived] == [_contracts.plan_digest(round_plan)]
    assert len(_transition_events(database, family_id)) == 1


def test_worker_archives_family_after_zero_seed_campaign(
    isolated_database, tmp_path, monkeypatch
):
    """0 crash: no_next_round(NO_CANDIDATE_SEED)@0 then the sweep archives."""
    database = isolated_database
    run_root, _evidence_root = _configure_isolated_roots(tmp_path, monkeypatch)
    family_id, campaign_id, plan, _approval, _envelope = _seed_ready_campaign(database)
    _install_fake_campaign_sandbox(monkeypatch, plan, crashes=())

    workflow.run_worker(
        database.dsn, once=True, case_root=str(_FIXTURE_CASES), run_root=str(run_root)
    )

    assert state.load_job(database.dsn, campaign_id)["state"] == "COMPLETED"
    events = _transition_events(database, family_id)
    assert len(events) == 1
    assert events[0]["decision"] == "no_next_round"
    assert events[0]["reason_code"] == "NO_CANDIDATE_SEED"
    assert events[0]["candidate_seed_count"] == 0
    assert database.connection.execute(
        "SELECT count(*) FROM jobs WHERE parent_job_id = %s AND job_kind = 'round'",
        (family_id,),
    ).fetchone()[0] == 0

    second = workflow.run_worker(
        database.dsn, once=True, case_root=str(_FIXTURE_CASES), run_root=str(run_root)
    )

    assert second["processed"] == 0
    assert second["families_converged"] == 1
    family = state.load_job(database.dsn, family_id)
    assert family["state"] == "COMPLETED"
    assert family["evidence_status"] == "archived"
    index = json.loads(open(family["evidence_path"], "rb").read())
    assert index["campaign"]["job_id"] == str(campaign_id)
    assert index["rounds"] == []
    assert len(_transition_events(database, family_id)) == 1


def _finish_round_inconclusive(database, round_id, token):
    database.connection.execute(
        "UPDATE jobs SET state = 'INCONCLUSIVE', stage = 'done', "
        "verdict = 'INCONCLUSIVE', verdict_reason = 'INTERMITTENT', "
        "reason_code = 'INTERMITTENT', evidence_status = 'archived', "
        "evidence_path = %s, evidence_digest = %s, workflow_synced = true "
        "WHERE job_id = %s",
        (f"/tmp/round-{round_id}", "sha256:" + token * 64, round_id),
    )


def test_round_points_use_the_next_seed_then_record_no_remaining_seeds(
    isolated_database, tmp_path, monkeypatch
):
    """Edge #26: round k INCONCLUSIVE → next seed, until the seeds run out."""
    database = isolated_database
    run_root, _evidence_root = _configure_isolated_roots(tmp_path, monkeypatch)
    family_id, campaign_id, plan, _approval, _envelope = _seed_ready_campaign(database)
    _install_fake_campaign_sandbox(
        monkeypatch, plan, crashes=(b"WXYZ\n", b"QRST\n")
    )
    workflow.run_worker(
        database.dsn, once=True, case_root=str(_FIXTURE_CASES), run_root=str(run_root)
    )
    campaign = state.load_job(database.dsn, campaign_id)
    seeds = workflow.campaign_candidate_seeds(campaign)
    assert [seed["sha256"] for seed in seeds] == [
        "sha256:" + hashlib.sha256(b"WXYZ\n").hexdigest(),
        "sha256:" + hashlib.sha256(b"QRST\n").hexdigest(),
    ]

    def _round(round_no):
        row = database.connection.execute(
            "SELECT j.job_id, p.plan FROM jobs j JOIN plans p ON p.job_id = j.job_id "
            "WHERE j.parent_job_id = %s AND j.round_no = %s",
            (family_id, round_no),
        ).fetchone()
        return row[0], row[1]

    round1, plan1 = _round(1)
    assert plan1["inputs"]["candidate"] == seeds[0]["sha256"]
    _finish_round_inconclusive(database, round1, "6")
    assert workflow.advance_family_transitions(
        database.dsn, case_root=str(_FIXTURE_CASES), run_root=str(run_root)
    ) == 1
    round2, plan2 = _round(2)
    assert plan2["inputs"]["candidate"] == seeds[1]["sha256"]
    assert state.get_admission(database.dsn, round2) is not None
    _finish_round_inconclusive(database, round2, "7")

    result = workflow.run_worker(
        database.dsn, once=True, case_root=str(_FIXTURE_CASES), run_root=str(run_root)
    )

    events = _transition_events(database, family_id)
    assert [(e["after_round_no"], e["decision"]) for e in events] == [
        (0, "next_round"),
        (1, "next_round"),
        (2, "no_next_round"),
    ]
    assert events[1]["candidate_seed_count"] == 1
    assert events[2]["reason_code"] == "NO_REMAINING_SEEDS"
    assert result["family_transitions"] == 1
    # Archived in the same poll: the decision is taken before sealing.
    family = state.load_job(database.dsn, family_id)
    assert family["state"] == "COMPLETED", family
    index = json.loads(open(family["evidence_path"], "rb").read())
    assert [item["round_no"] for item in index["rounds"]] == [1, 2]
