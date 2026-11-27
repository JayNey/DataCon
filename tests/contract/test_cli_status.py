"""D33/D40/D43 T12: ``status`` family, campaign and rounds views.

The status composition is exercised against a recording connection double so
the assertions are about the payload derived from persisted rows, not about
PostgreSQL itself. The real convergence (file digest, pointer and audit) is
covered by ``tests/integration/test_family_archive_recovery.py``.
"""

from __future__ import annotations

import hashlib
from uuid import UUID

import pytest

from datacon import evidence, state

FAMILY_ID = UUID("2f1c0f5e-3d7a-4b6c-9f10-2a4b6c8d0e11")
CAMPAIGN_ID = UUID("9a1b2c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4d")
ROUND1_ID = UUID("3b7e1f2a-5c6d-4e8f-9012-3456789abcde")
ROUND2_ID = UUID("0f8fad5b-d9cb-469f-a165-70867728950e")
CAMPAIGN_PLAN = "sha256:" + "2f" * 32
ROUND1_PLAN = "sha256:" + "2e" * 32
ROUND2_PLAN = "sha256:" + "0d" * 32
APPROVAL_DIGEST = "sha256:" + "52" * 32
CAMPAIGN_DIGEST = "sha256:" + "0e" * 32
ROUND1_DIGEST = "sha256:" + "53" * 32
ROUND2_DIGEST = "sha256:" + "54" * 32

LEDGER = {
    "family_id": FAMILY_ID,
    "max_total_seconds": 900,
    "max_fuzz_seconds": 300,
    "remaining_total_seconds": 360,
    "remaining_fuzz_seconds": 120,
}
CHARGES = [
    {"seconds": 360, "fuzz_seconds": 60},
    {"seconds": 180, "fuzz_seconds": 120},
]
BUDGET = {
    "max_total_seconds": 900,
    "max_fuzz_seconds": 300,
    "spent_seconds": 540,
    "spent_fuzz_seconds": 180,
    "remaining_seconds": 360,
    "remaining_fuzz_seconds": 120,
}


class _Rows:
    def __init__(self, rows):
        self._rows = list(rows)

    def fetchone(self):
        return self._rows[0] if self._rows else None

    def fetchall(self):
        return list(self._rows)


class _StatusConnection:
    """Minimal recording double for the four status queries."""

    def __init__(
        self,
        *,
        job,
        children=(),
        review=None,
        admissions=(),
        ledger=None,
        charges=(),
    ):
        self.job = job
        self.children = list(children)
        self.review = review
        self.admissions = list(admissions)
        self.ledger = ledger
        self.charges = list(charges)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def execute(self, query, params=None):
        if "FROM budget_ledger" in query:
            return _Rows([self.ledger] if self.ledger is not None else [])
        if "FROM budget_charges" in query:
            return _Rows(self.charges)
        if "FROM reviews" in query:
            return _Rows([self.review] if self.review is not None else [])
        if "FROM admissions" in query:
            return _Rows([{"job_id": job_id} for job_id in self.admissions])
        if "parent_job_id" in query:
            return _Rows(self.children)
        if "FROM jobs j" in query:
            return _Rows([self.job] if self.job is not None else [])
        raise AssertionError(f"unexpected status query: {query}")


def _family_job(
    *,
    state_name="AGGREGATING",
    evidence_status=None,
    evidence_path=None,
    evidence_digest=None,
    max_rounds=8,
):
    return {
        "job_id": FAMILY_ID,
        "state": state_name,
        "stage": "family",
        "reason_code": None,
        "last_error": None,
        "verdict": None,
        "verdict_reason": None,
        "evidence_digest": evidence_digest,
        "evidence_path": evidence_path,
        "evidence_status": evidence_status,
        "evidence_error": None,
        "plan_digest": None,
        "summary": None,
        "plan": None,
        "plan_created_at": None,
        "decision": None,
        "reviewer_id": None,
        "review_plan_digest": None,
        "decided_at": None,
        "job_kind": "family",
        "family_id": FAMILY_ID,
        "request": {
            "schema_version": 2,
            "exploration": {"mode": "guided", "max_rounds": max_rounds},
        },
    }


def _child(
    job_id,
    *,
    job_kind,
    round_no,
    state_name,
    plan_digest,
    evidence_digest,
    verdict=None,
    reason_code=None,
    evidence_status="archived",
):
    return {
        "job_id": job_id,
        "job_kind": job_kind,
        "round_no": round_no,
        "state": state_name,
        "verdict": verdict,
        "reason_code": reason_code,
        "evidence_status": evidence_status,
        "evidence_path": f"/evidence/{job_id}",
        "evidence_digest": evidence_digest,
        "workflow_synced": True,
        "plan_digest": plan_digest,
    }


def _campaign_child(state_name="COMPLETED"):
    return _child(
        CAMPAIGN_ID,
        job_kind="campaign",
        round_no=None,
        state_name=state_name,
        plan_digest=CAMPAIGN_PLAN,
        evidence_digest=CAMPAIGN_DIGEST,
    )


def _round_children():
    return [
        _child(
            ROUND1_ID,
            job_kind="round",
            round_no=1,
            state_name="INCONCLUSIVE",
            plan_digest=ROUND1_PLAN,
            evidence_digest=ROUND1_DIGEST,
            verdict="INCONCLUSIVE",
            reason_code="EVIDENCE_INCOMPLETE",
        ),
        _child(
            ROUND2_ID,
            job_kind="round",
            round_no=2,
            state_name="INCONCLUSIVE",
            plan_digest=ROUND2_PLAN,
            evidence_digest=ROUND2_DIGEST,
            verdict="INCONCLUSIVE",
            reason_code="EVIDENCE_INCOMPLETE",
        ),
    ]


def _install(monkeypatch, connection):
    monkeypatch.setattr(state, "_connect", lambda dsn: connection)


def _family_index(campaign=True):
    rounds = (
        [1, 2]
        if campaign
        else [1]
    )
    return evidence.build_family_index(
        family_id=FAMILY_ID,
        created_at="2099-01-01T00:00:00Z",
        family_approval_digest=APPROVAL_DIGEST,
        rounds=[
            {
                "round_no": round_no,
                "job_id": str(ROUND1_ID if round_no == 1 else ROUND2_ID),
                "plan_digest": ROUND1_PLAN if round_no == 1 else ROUND2_PLAN,
                "state": "INCONCLUSIVE",
                "evidence_digest": (
                    ROUND1_DIGEST if round_no == 1 else ROUND2_DIGEST
                ),
            }
            for round_no in rounds
        ],
        campaign=(
            {"job_id": str(CAMPAIGN_ID), "bundle_digest": CAMPAIGN_DIGEST}
            if campaign
            else None
        ),
        budget=BUDGET,
    )


def test_campaign_status_lists_campaign_and_rounds(monkeypatch):
    connection = _StatusConnection(
        job=_family_job(),
        children=[_campaign_child(), *_round_children()],
        review={"plan_digest": CAMPAIGN_PLAN},
        admissions=[ROUND1_ID, ROUND2_ID],
        ledger=LEDGER,
        charges=CHARGES,
    )
    _install(monkeypatch, connection)

    payload = state.status("postgresql://unused", FAMILY_ID)

    assert payload["state"] == "AGGREGATING"
    assert payload["family"] == {
        "family_id": str(FAMILY_ID),
        "max_rounds": 8,
        "rounds_used": 2,
    }
    campaign = payload["campaign"]
    assert campaign == {
        "job_id": str(CAMPAIGN_ID),
        "round_no": None,
        "state": "COMPLETED",
        "plan_digest": CAMPAIGN_PLAN,
        "admission_kind": "human",
        "verdict": None,
        "evidence_status": "archived",
        "reason_code": None,
    }
    assert [entry["round_no"] for entry in payload["rounds"]] == [1, 2]
    assert payload["rounds"][0] == {
        "round_no": 1,
        "job_id": str(ROUND1_ID),
        "state": "INCONCLUSIVE",
        "plan_digest": ROUND1_PLAN,
        "admission_kind": "policy",
        "verdict": "INCONCLUSIVE",
        "evidence_status": "archived",
        "reason_code": "EVIDENCE_INCOMPLETE",
    }
    assert payload["budget"] == BUDGET
    assert payload["budget"]["remaining_fuzz_seconds"] == 120


def test_campaign_and_family_terminal_state_completed(monkeypatch):
    running = _StatusConnection(
        job=_family_job(state_name="AGGREGATING"),
        children=[_campaign_child("COMPLETED")],
        review={"plan_digest": CAMPAIGN_PLAN},
        ledger=LEDGER,
        charges=CHARGES,
    )
    _install(monkeypatch, running)
    payload = state.status("postgresql://unused", FAMILY_ID)
    assert payload["state"] == "AGGREGATING"
    assert payload["campaign"]["state"] == "COMPLETED"
    assert payload["campaign"]["verdict"] is None
    assert payload["campaign"]["reason_code"] is None
    assert payload["campaign"]["state"] != "INCONCLUSIVE"

    archived = _StatusConnection(
        job=_family_job(
            state_name="COMPLETED",
            evidence_status="archived",
            evidence_path=f"/evidence/{FAMILY_ID}/family.json",
            evidence_digest=APPROVAL_DIGEST,
        ),
        children=[_campaign_child("COMPLETED")],
        review={"plan_digest": CAMPAIGN_PLAN},
        ledger=LEDGER,
        charges=CHARGES,
    )
    _install(monkeypatch, archived)
    payload = state.status("postgresql://unused", FAMILY_ID)
    assert payload["state"] == "COMPLETED"
    assert payload["state"] != "INCONCLUSIVE"
    assert payload["campaign"]["state"] == "COMPLETED"


def test_family_completed_sets_evidence_path_and_digest(monkeypatch, tmp_path):
    index = _family_index()
    path = tmp_path / "evidence" / str(FAMILY_ID) / "family.json"
    completed = []

    info = evidence.finalize_family_index(
        path,
        index,
        complete=lambda evidence_path, digest: completed.append(
            (evidence_path, digest)
        ),
    )

    expected_digest = "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()
    assert completed == [(str(path), expected_digest)]
    assert info.digest == expected_digest
    assert index["state"] == "COMPLETED"
    assert index["rounds"][0]["evidence_digest"] == ROUND1_DIGEST

    _install(
        monkeypatch,
        _StatusConnection(
            job=_family_job(
                state_name="COMPLETED",
                evidence_status="archived",
                evidence_path=str(path),
                evidence_digest=expected_digest,
            ),
            children=[_campaign_child(), *_round_children()],
            review={"plan_digest": CAMPAIGN_PLAN},
            admissions=[ROUND1_ID, ROUND2_ID],
            ledger=LEDGER,
            charges=CHARGES,
        ),
    )
    payload = state.status("postgresql://unused", FAMILY_ID)
    assert payload["state"] == "COMPLETED"
    assert payload["evidence"] == {
        "available": True,
        "status": "archived",
        "digest": expected_digest,
        "path": str(path),
        "error": None,
    }


def test_family_completed_requires_family_index(tmp_path):
    index = _family_index()
    completed = []

    def _complete(evidence_path, digest):
        completed.append((evidence_path, digest))

    with pytest.raises(evidence.BundleError):
        evidence.finalize_family_index(
            tmp_path / "missing-family.json", None, complete=_complete
        )
    assert completed == [], "family COMPLETED without a family index"

    path = tmp_path / "family.json"
    evidence.finalize_family_index(path, index)
    with pytest.raises(evidence.BundleError):
        evidence.finalize_family_index(
            path,
            index,
            expected_digest="sha256:" + "0" * 64,
            complete=_complete,
        )
    assert completed == [], "family COMPLETED with a mismatched index digest"

    path.chmod(0o644)
    path.write_bytes(b'{"kind":"family_index"}\n')
    with pytest.raises(evidence.BundleError):
        evidence.finalize_family_index(path, None, complete=_complete)
    assert completed == [], "family COMPLETED with an invalid family index"


def test_round_status_uses_terminal_state_and_evidence_status(monkeypatch):
    _install(
        monkeypatch,
        _StatusConnection(
            job=_family_job(state_name="AGGREGATING"),
            children=[*_round_children()],
            review={"plan_digest": ROUND1_PLAN},
            admissions=[ROUND2_ID],
            ledger=LEDGER,
            charges=CHARGES,
        ),
    )

    payload = state.status("postgresql://unused", FAMILY_ID)

    assert [entry["state"] for entry in payload["rounds"]] == [
        "INCONCLUSIVE",
        "INCONCLUSIVE",
    ]
    assert all(
        entry["state"] != "ARCHIVED" for entry in payload["rounds"]
    ), "round state ARCHIVED is not a job state"
    assert [entry["evidence_status"] for entry in payload["rounds"]] == [
        "archived",
        "archived",
    ]
    assert payload["rounds"][0]["admission_kind"] == "human"
    assert payload["rounds"][1]["admission_kind"] == "policy"
    assert payload["rounds"][0]["plan_digest"] == ROUND1_PLAN
    assert payload["rounds"][1]["job_id"] == str(ROUND2_ID)
