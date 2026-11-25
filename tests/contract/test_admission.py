"""TC-12/T12 step 1: deterministic policy admission and its audit event.

Every test drives the pure admission predicate with an injected clock and a
recording store. The store never opens PostgreSQL, starts Docker or sleeps, and
the campaign bundle is only a digest input. Charging a budget, creating the
next round child and reuse remain out of scope for this T12 increment.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import uuid

from datacon import contracts, state


def _digest(token: str) -> str:
    return "sha256:" + token * 64


TOOLCHAIN_IMAGE_DIGEST = _digest("a")
SEED_CORPUS_DIGEST = _digest("c")
HARNESS_DIGEST = _digest("d")
APPROVAL_DIGEST = _digest("e")
CAMPAIGN_BUNDLE_DIGEST = _digest("f")
FAMILY_ID = "2f1c0f5e-3d7a-4b6c-9f10-2a4b6c8d0e11"
JOB_ID = "0f8fad5b-d9cb-469f-a165-70867728950e"
ADMISSION_ID = uuid.UUID("7c9e6679-7425-40de-944b-e07fc1f90ae7")
DECIDED_AT = datetime(2099, 1, 1, tzinfo=timezone.utc)

SIGNATURE = {
    "error": "heap-buffer-overflow",
    "function": "parse_token",
    "source": "parser.c",
    "operation": "WRITE",
    "access_size": 1,
}


class FakeClock:
    def __init__(self, now: datetime = DECIDED_AT) -> None:
        self.now = now

    def __call__(self) -> datetime:
        return self.now

    def advance(self, seconds: int) -> None:
        self.now += timedelta(seconds=seconds)


class RecordingAdmissionStore:
    def __init__(self) -> None:
        self.calls: list[str] = []
        self.admissions: list[dict] = []
        self.events: list[dict] = []
        self.reviews: list[dict] = []
        self.family_approvals: list[dict] = []
        self.rounds: list[dict] = []

    def record_admission(self, admission) -> None:
        self.calls.append("record_admission")
        self.admissions.append(dict(admission))

    def append_event(self, event) -> None:
        self.calls.append("append_event")
        self.events.append(dict(event))

    def insert_review(self, review) -> None:
        self.calls.append("insert_review")
        self.reviews.append(dict(review))

    def update_family_approval(self, approval) -> None:
        self.calls.append("update_family_approval")
        self.family_approvals.append(dict(approval))

    def create_round(self, round_record) -> None:
        self.calls.append("create_round")
        self.rounds.append(dict(round_record))


def _guided_envelope() -> dict:
    return contracts.guided_envelope(
        allowed_mutation_families=["byte_flip", "length_boundary"],
        mutation_limits={
            "allowed_ops": ["append", "truncate", "byte_flip"],
            "max_input_bytes": 4096,
        },
        seed_corpus_digest=SEED_CORPUS_DIGEST,
        toolchain_image_digest=TOOLCHAIN_IMAGE_DIGEST,
        harness_digest=HARNESS_DIGEST,
        max_rounds=8,
        max_total_seconds=900,
        max_fuzz_seconds=300,
        accepted_signature_set=[dict(SIGNATURE)],
        admission_predicate_version="admission-v1",
    )


def _budget_snapshot() -> dict:
    return {
        "remaining_total_seconds": 900,
        "remaining_fuzz_seconds": 300,
    }


def _admit(
    store: RecordingAdmissionStore | None = None,
    *,
    clock: FakeClock | None = None,
    round_no: int = 2,
    recomputable: bool = True,
    campaign_bundle_digest: str | None = None,
    existing_rounds: tuple[int, ...] = (),
    approved_envelope_digest: str | None = None,
    plan_envelope_digest: str | None = None,
):
    binding_options = {}
    if approved_envelope_digest is not None:
        binding_options["approved_envelope_digest"] = approved_envelope_digest
    if plan_envelope_digest is not None:
        binding_options["plan_envelope_digest"] = plan_envelope_digest
    return state.policy_admit_round(
        store=store,
        clock=clock or FakeClock(),
        job_id=JOB_ID,
        parent_job_id=FAMILY_ID,
        envelope=_guided_envelope(),
        parent_approval_digest=APPROVAL_DIGEST,
        approval_chain_tail_digest=APPROVAL_DIGEST,
        seed_digest=SEED_CORPUS_DIGEST,
        round_no=round_no,
        budget_snapshot=_budget_snapshot(),
        experiment=None,
        recomputable=recomputable,
        campaign_bundle_digest=campaign_bundle_digest,
        admission_id=ADMISSION_ID,
        existing_rounds=existing_rounds,
        **binding_options,
    )


def test_admission_predicate_recomputes_offline():
    store = RecordingAdmissionStore()
    recorded = _admit(store=store)

    # Offline recomputation sees only the envelope, parent approval, seed,
    # round and budget snapshot. The injected clock is the database clock the
    # recorded row was written with, so every admission field is reproducible.
    recomputed = _admit(clock=FakeClock(DECIDED_AT))

    assert recorded.admitted and recomputed.admitted
    assert recorded.admission == recomputed.admission, (
        "recomputed admission differs from recorded decision"
    )
    assert store.admissions == [recomputed.admission]
    assert recomputed.admission["predicate_version"] == "admission-v1"
    assert recomputed.admission["envelope_digest"] == contracts.envelope_digest(
        _guided_envelope()
    )


def test_non_recomputable_admission_cites_campaign_bundle():
    outcome = _admit(
        recomputable=False,
        campaign_bundle_digest=CAMPAIGN_BUNDLE_DIGEST,
    )

    assert outcome.admitted, outcome.reason_code
    assert outcome.admission["recomputable"] is False
    assert (
        outcome.admission["supporting_bundle_digest"]
        == CAMPAIGN_BUNDLE_DIGEST
    ), "non-recomputable admission did not cite the campaign bundle"
    assert (
        outcome.event_detail["supporting_bundle_digest"]
        == CAMPAIGN_BUNDLE_DIGEST
    ), "the admission audit event did not cite the campaign bundle"

    recomputable = _admit()
    assert recomputable.admission["recomputable"] is True
    assert recomputable.admission["supporting_bundle_digest"] is None


def test_policy_admission_appends_round_admitted_event():
    admitted_store = RecordingAdmissionStore()
    admitted = _admit(store=admitted_store)

    assert admitted.admitted, admitted.reason_code
    assert [event["event_type"] for event in admitted_store.events] == [
        "round_admitted"
    ], "round_admitted"
    assert admitted_store.events[0]["detail"]["round_no"] == 2
    assert admitted_store.events[0]["detail"]["approval_kind"] == "policy"
    assert not admitted_store.reviews

    denied_store = RecordingAdmissionStore()
    denied = _admit(store=denied_store, existing_rounds=(2,))

    assert not denied.admitted
    assert denied.reason_code == "ADMISSION_DENIED"
    assert not denied_store.admissions
    assert denied_store.events[-1]["event_type"] == "round_admission_denied"
    assert denied_store.events[-1]["reason_code"] == "ADMISSION_DENIED"


def test_admission_envelope_must_match_approval():
    store = RecordingAdmissionStore()
    unapproved_digest = _digest("b")

    outcome = _admit(store=store, approved_envelope_digest=unapproved_digest)

    assert not outcome.admitted
    assert outcome.reason_code == "ADMISSION_DENIED"
    assert outcome.sub_reason == "PARENT_APPROVAL_ENVELOPE_MISMATCH"
    assert not store.admissions, "unapproved envelope wrote an admissions row"
    assert [event["event_type"] for event in store.events] == [
        "round_admission_denied"
    ]
    assert store.events[0]["detail"]["sub_reason"] == (
        "PARENT_APPROVAL_ENVELOPE_MISMATCH"
    )
    assert store.events[0]["reason_code"] == "ADMISSION_DENIED"


def test_admission_plan_envelope_must_match():
    store = RecordingAdmissionStore()
    plan_digest = _digest("b")

    outcome = _admit(store=store, plan_envelope_digest=plan_digest)

    assert not outcome.admitted
    assert outcome.reason_code == "ADMISSION_DENIED"
    assert outcome.sub_reason == "PLAN_ENVELOPE_MISMATCH"
    assert not store.admissions, "plan/envelope mismatch wrote an admissions row"
    assert [event["event_type"] for event in store.events] == [
        "round_admission_denied"
    ]
    assert store.events[0]["detail"]["sub_reason"] == "PLAN_ENVELOPE_MISMATCH"


def test_round_beyond_max_rounds_is_denied():
    envelope = _guided_envelope()
    store = RecordingAdmissionStore()

    outcome = _admit(store=store, round_no=envelope["max_rounds"] + 1)

    assert not outcome.admitted and not store.admissions, (
        "round beyond max_rounds was created"
    )
    assert outcome.reason_code == "ADMISSION_DENIED"
    assert "record_admission" not in store.calls
    assert store.events[-1]["event_type"] == "round_admission_denied"

    # The bound is inclusive: the last allowed round still admits.
    last_allowed = _admit(
        store=RecordingAdmissionStore(), round_no=envelope["max_rounds"]
    )
    assert last_allowed.admitted
