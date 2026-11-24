"""D42 T10: ``propose-envelope`` request, registry and pending constraints."""

from __future__ import annotations


import pytest
from psycopg.types.json import Jsonb

from datacon import jsonutil, state

from test_review_locks import (
    ENVELOPE_2,
    _family_request,
    _row,
    _seed_family,
)

pytestmark = pytest.mark.postgres

LEGAL_SIGNATURE = {
    "error": "heap-buffer-overflow",
    "function": "parse_token",
    "source": "parser.c",
    "operation": "WRITE",
    "access_size": 1,
}


def _envelope(**overrides):
    body = {
        "mode": "guided",
        "allowed_mutation_families": ["byte_flip", "length_boundary"],
        "mutation_limits": {
            "allowed_ops": ["append", "truncate", "byte_flip"],
            "max_input_bytes": 4096,
        },
        "seed_corpus_digest": "sha256:" + "a" * 64,
        "fuzz_image_digest": "sha256:" + "b" * 64,
        "harness_digest": "sha256:" + "c" * 64,
        "max_rounds": 8,
        "max_total_seconds": 900,
        "max_fuzz_seconds": 300,
        "accepted_signature_set": [dict(LEGAL_SIGNATURE)],
        "admission_predicate_version": "admission-v1",
    }
    body.update(overrides)
    return body


def _fixed_envelope():
    return {
        "mode": "fixed",
        "allowed_mutation_families": [],
        "mutation_limits": {"allowed_ops": [], "max_input_bytes": 0},
        "seed_corpus_digest": None,
        "fuzz_image_digest": None,
        "harness_digest": "sha256:" + "c" * 64,
        "max_rounds": 1,
        "max_total_seconds": 900,
        "max_fuzz_seconds": 0,
        "accepted_signature_set": [dict(LEGAL_SIGNATURE)],
        "admission_predicate_version": "admission-v1",
    }


def _approved_family(database, *, mode="guided", pending=None):
    return _seed_family(
        database,
        mode=mode,
        first_approval=True,
        pending_envelope=pending,
    )


def test_propose_envelope_creates_one_pending_row(isolated_database):
    seed = _approved_family(isolated_database)
    body = _envelope()
    result = state.propose_envelope(
        isolated_database.dsn, seed["family_id"], body, operator_id="operator-p1"
    )
    assert result["status"] == "pending"
    assert result["envelope_digest"] == jsonutil.digest_json(body)
    digest, status, stored = _row(
        isolated_database,
        "SELECT envelope_digest, status, envelope_json FROM family_envelopes "
        "WHERE family_id = %s AND status = 'pending'",
        (seed["family_id"],),
    )
    assert digest == result["envelope_digest"]
    assert status == "pending"
    assert stored == body


def test_propose_envelope_repeated_body_is_rejected(isolated_database):
    seed = _approved_family(isolated_database)
    body = _envelope()
    state.propose_envelope(isolated_database.dsn, seed["family_id"], body)

    # Move the first row out of pending so the repeat hits the
    # (family_id, envelope_digest) uniqueness, not the one-pending index.
    isolated_database.connection.execute(
        "UPDATE family_envelopes SET status = 'approved', reviewer_id = 'r', "
        "decided_at = clock_timestamp() "
        "WHERE family_id = %s AND envelope_digest = %s",
        (seed["family_id"], jsonutil.digest_json(body)),
    )
    with pytest.raises(state.StateError, match="already proposed"):
        state.propose_envelope(isolated_database.dsn, seed["family_id"], body)


def test_propose_envelope_rejects_second_pending(isolated_database):
    seed = _approved_family(isolated_database, pending=ENVELOPE_2)
    with pytest.raises(state.StateError, match="pending"):
        state.propose_envelope(isolated_database.dsn, seed["family_id"], _envelope())


def test_fixed_family_cannot_propose_guided(isolated_database):
    seed = _approved_family(isolated_database, mode="fixed")
    with pytest.raises(state.StateError, match="fixed family"):
        state.propose_envelope(
            isolated_database.dsn, seed["family_id"], _envelope()
        )


@pytest.mark.parametrize(
    "overrides",
    [
        {"max_rounds": 9},
        {"max_total_seconds": 901},
        {"max_fuzz_seconds": 301},
        {"allowed_mutation_families": ["byte_flip", "delete"]},
    ],
)
def test_propose_envelope_rejects_request_expansion(isolated_database, overrides):
    seed = _approved_family(isolated_database)
    with pytest.raises(state.StateError):
        state.propose_envelope(
            isolated_database.dsn,
            seed["family_id"],
            _envelope(**overrides),
        )


def test_propose_envelope_rejects_non_aggregating_or_non_family(
    isolated_database,
):
    seed = _approved_family(isolated_database)
    isolated_database.connection.execute(
        "UPDATE jobs SET state = 'COMPLETED', evidence_status = 'archived', "
        "evidence_path = '/tmp/family.json', evidence_digest = %s "
        "WHERE job_id = %s",
        ("sha256:" + "f" * 64, seed["family_id"]),
    )
    with pytest.raises(state.StateError):
        state.propose_envelope(
            isolated_database.dsn, seed["family_id"], _envelope()
        )

    with pytest.raises(state.StateError, match="not a family"):
        state.propose_envelope(
            isolated_database.dsn, seed["child_id"], _envelope()
        )


def test_propose_envelope_rejects_case_registry_expansion(isolated_database):
    seed = _approved_family(isolated_database)
    relaxed = _family_request("guided")
    relaxed["exploration"]["max_rounds"] = 10
    relaxed["exploration"]["max_total_seconds"] = 1000
    relaxed["exploration"]["max_fuzz_seconds"] = 400
    relaxed["exploration"]["allowed_mutation_families"].append("delete")
    relaxed["exploration"]["mutation_limits"] = {
        "allowed_ops": ["append", "truncate", "byte_flip", "delete"]
    }
    isolated_database.connection.execute(
        "UPDATE jobs SET request = %s WHERE job_id = %s",
        (Jsonb(relaxed), seed["family_id"]),
    )

    # Every one of these stays inside the relaxed request but outside the
    # registered case ceiling.
    invalid = [
        _envelope(max_rounds=9),
        _envelope(max_total_seconds=901),
        _envelope(max_fuzz_seconds=350),
        _envelope(allowed_mutation_families=["byte_flip", "delete"]),
        _envelope(
            mutation_limits={
                "allowed_ops": ["append", "delete"],
                "max_input_bytes": 1024,
            }
        ),
        _envelope(
            mutation_limits={
                "allowed_ops": ["append"],
                "max_input_bytes": 8192,
            }
        ),
        _envelope(
            accepted_signature_set=[
                {
                    "error": "use-after-free",
                    "function": "parse_token",
                    "source": "parser.c",
                }
            ]
        ),
    ]
    for body in invalid:
        with pytest.raises(state.StateError, match="case registry"):
            state.propose_envelope(
                isolated_database.dsn, seed["family_id"], body
            )

    # The legal envelope still passes.
    result = state.propose_envelope(
        isolated_database.dsn, seed["family_id"], _envelope()
    )
    assert result["status"] == "pending"


def test_propose_envelope_requires_a_first_approval(isolated_database):
    seed = _seed_family(
        isolated_database,
        mode="guided",
        first_approval=False,
        pending_envelope=None,
    )

    with pytest.raises(state.StateError, match="no first approval"):
        state.propose_envelope(
            isolated_database.dsn, seed["family_id"], _envelope()
        )
    assert _row(
        isolated_database,
        "SELECT count(*) FROM family_envelopes WHERE family_id = %s",
        (seed["family_id"],),
    )[0] == 0
