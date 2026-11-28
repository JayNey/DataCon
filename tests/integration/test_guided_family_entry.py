"""T12 (改9 增补): a guided family runs end to end from its own submit.

``datacon submit`` of a guided v2 request creates the family and its campaign
child; the worker prepares the campaign (offline analysis → campaign plan +
envelope from the case registry → frozen, awaiting review); a human approves
the family; the worker then runs the campaign, derives and admits round 1,
replays it and archives the family. Marker group ``postgres`` (fake sandbox,
fake step clock). Registered in docs/spec/v0.2/test-plan-delta.md.
"""

from __future__ import annotations

import json
from pathlib import Path
import sys

import pytest

from datacon import contracts, evidence, execution, fuzz, state, store, workflow

_CONTRACT_DIR = str(Path(__file__).resolve().parents[1] / "contract")
if _CONTRACT_DIR not in sys.path:
    sys.path.append(_CONTRACT_DIR)

from test_build_spec_execution import (  # noqa: E402
    FIXTURE_CASES,
    _configure_isolated_roots,
)
from test_fuzz import _Clock, _FakeCampaignSandbox  # noqa: E402

pytestmark = pytest.mark.postgres

# The fixture build's reviewed shell face (both versions, normalized).
FIXTURE_SHELL_FACE = b"datacon-build-runner: warning: chmod -R u+w /work failed\n"


def _guided_request() -> dict:
    manifest = json.loads((FIXTURE_CASES / "manifest.json").read_text())
    return contracts.parse_request(
        json.dumps(
            {
                "schema_version": 2,
                "cve_id": manifest["cve_id"],
                "target": {
                    "kind": "source",
                    "case_id": "fixture-c-parser",
                    "goal": "search the parser with the fixed fuzz shim",
                },
                "limits": manifest["limits"],
                "exploration": {
                    "mode": "guided",
                    "allowed_mutation_families": ["byte_flip", "length_boundary"],
                    "max_rounds": 8,
                    "max_total_seconds": 900,
                    "max_fuzz_seconds": 60,
                },
            }
        )
    )


def _children(database, family_id):
    return {
        (row[0], row[1]): (row[2], row[3])
        for row in database.connection.execute(
            "SELECT job_kind, round_no, job_id, state FROM jobs "
            "WHERE parent_job_id = %s",
            (family_id,),
        ).fetchall()
    }


def test_guided_submit_runs_end_to_end_through_human_review(
    isolated_database, tmp_path, monkeypatch
):
    database = isolated_database
    run_root, _evidence_root = _configure_isolated_roots(tmp_path, monkeypatch)
    monkeypatch.setenv("DATACON_CASE_ROOT", str(FIXTURE_CASES))
    clock = _Clock()
    monkeypatch.setattr(execution, "STEP_CLOCK", clock)
    sandboxes: list[_FakeCampaignSandbox] = []

    def _factory(**kwargs):
        sandbox = _FakeCampaignSandbox(
            crashes=(b"ABCD\n",),
            clock=clock,
            image_digest=kwargs["image"].split("@", 1)[1],
            build_recipe_digest="sha256:" + "0" * 64,
            faces={"vulnerable": FIXTURE_SHELL_FACE, "fixed": FIXTURE_SHELL_FACE},
            face_name="shell-face.log",
        )
        sandboxes.append(sandbox)
        return sandbox

    monkeypatch.setattr(execution, "DockerSandbox", _factory)

    def _worker():
        return workflow.run_worker(
            database.dsn, once=True, case_root=str(FIXTURE_CASES), run_root=str(run_root)
        )

    submitted = store.submit(database.dsn, _guided_request())
    family_id = submitted["job_id"]
    assert submitted["state"] == "AGGREGATING"
    children = _children(database, family_id)
    assert set(children) == {("campaign", None)}, children
    campaign_id, campaign_state = children[("campaign", None)]
    assert campaign_state == "QUEUED"

    # The worker prepares the campaign: plan + envelope frozen, awaiting review.
    _worker()
    campaign = state.load_job(database.dsn, campaign_id)
    assert campaign["state"] == "AWAITING_REVIEW", campaign
    plan_row = state.get_plan(database.dsn, campaign_id)
    plan = plan_row["plan"]
    assert plan["schema_version"] == 2 and plan["round_no"] is None
    assert plan["inputs"] is None and plan["build_ref"] is None
    assert plan["parent_approval_digest"] is None
    registry = json.loads((FIXTURE_CASES / "registry.json").read_text())
    assert plan["build_spec"] == registry["cases"]["fixture-c-parser"]["build_spec"]
    envelope_row = database.connection.execute(
        "SELECT envelope_json, status FROM family_envelopes WHERE family_id = %s",
        (family_id,),
    ).fetchone()
    envelope, envelope_status = envelope_row
    assert envelope_status == "pending"
    assert contracts.envelope_digest(envelope) == plan["envelope_digest"]
    manifest = json.loads((FIXTURE_CASES / "manifest.json").read_text())
    assert envelope["harness_digest"] == fuzz.guided_harness_digest(
        manifest["materials"][manifest["harness"]], fuzz.FUZZ_SHIM_REVIEWED_DIGEST
    )
    assert envelope["max_fuzz_seconds"] == 60
    # Waiting for a human: further polls neither claim nor change it.
    _worker()
    assert state.load_job(database.dsn, campaign_id)["state"] == "AWAITING_REVIEW"

    review = state.record_review(
        database.dsn,
        family_id,
        plan_digest=plan_row["plan_digest"],
        decision="approve",
        reviewer_id="reviewer-01",
    )
    assert review.status == "applied", review

    for _ in range(8):
        _worker()
        if state.load_job(database.dsn, family_id)["state"] != "AGGREGATING":
            break

    campaign = state.load_job(database.dsn, campaign_id)
    assert campaign["state"] == "COMPLETED", (
        campaign["reason_code"],
        campaign["last_error"],
        campaign["evidence_error"],
    )
    children = _children(database, family_id)
    round_id, round_state = children[("round", 1)]
    assert round_state == "REPRODUCED", children
    family = state.load_job(database.dsn, family_id)
    assert family["state"] == "COMPLETED", family
    index = json.loads(open(family["evidence_path"], "rb").read())
    assert index["campaign"]["job_id"] == str(campaign_id)
    assert [item["round_no"] for item in index["rounds"]] == [1]
    validation = evidence.verify_bundle(state.load_job(database.dsn, round_id)["evidence_path"])
    assert validation.manifest["reuse_origin"]["source_job_id"] == str(campaign_id)
    # One sandbox per executed child; the validation round never rebuilt.
    assert len(sandboxes) == 2 and sandboxes[1].build_calls == []
