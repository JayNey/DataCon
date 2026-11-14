"""TC-04/TC-05/TC-06 execution, recovery and evidence integration tests.

The target-facing branches use a typed fake sandbox; a separate Docker-marked
test exercises the real image, isolation probe and ASan replay.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import uuid
from uuid import UUID

import pytest

from datacon import execution, state
from datacon.asan import parse_asan
from datacon.evidence import verify_bundle
from datacon.tools.sandbox import (
    BuildResult,
    ProbeReport,
    ReplayResult,
    SandboxPolicyError,
)
from support import (
    cli,
    copy_cases,
    review,
    status,
    submit,
    worker,
    write_request,
)

pytestmark = pytest.mark.postgres

ASAN_LOG = """\
==7==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x502000000014
WRITE of size 1 at 0x502000000014 thread T0
    #0 0x55555565fadf in parse_token /fixture/vulnerable/parser.c:22:17
    #1 0x55555565fc67 in main /fixture/harness.c:14:19
SUMMARY: AddressSanitizer: heap-buffer-overflow /fixture/vulnerable/parser.c:22:17 in parse_token
"""


def digest(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


class FakeSandbox:
    def __init__(self, *, case_id="fixture-c-parser", overrides=None):
        self.case_id = case_id
        self.overrides = overrides or {}
        self.probes = 0
        self.builds = 0
        self.replays = 0
        self.reclaimed = 0

    def reclaim_job(self):
        self.reclaimed += 1
        return 0

    def probe(self, *, deadline_seconds):
        self.probes += 1
        return ProbeReport(
            ok=True,
            checks={"uid": "65534", "seccomp": "2", "routes": ""},
            compiler_version="Debian clang version 19.1.7",
            image_digest="sha256:" + "a" * 64,
            raw="uid=65534\nseccomp=2\n",
            limits={},
        )

    def build(self, version, *, materials_dir, compile_args, deadline_seconds):
        self.builds += 1
        artifact = f"fake-{version}-binary".encode()
        return BuildResult(
            version=version,
            status="completed",
            exit_code=0,
            duration_seconds=0.01,
            container_id=f"fake-build-{version}",
            image_digest="sha256:" + "a" * 64,
            compile_args=tuple(compile_args),
            artifact_digest=digest(artifact),
            log=b"",
            log_truncated=False,
            artifact=artifact,
            metadata={
                "build_recipe_digest": "sha256:" + "b" * 64,
                "build_command": ["/bin/sh", "/fixture/build.sh", version],
            },
        )

    def replay(
        self,
        version,
        phase,
        *,
        artifact_path,
        input_path,
        asan_options,
        timeout_seconds,
        deadline_seconds,
    ):
        self.replays += 1
        key = f"{version}:{phase}"
        override = self.overrides.get(key)
        data = Path(input_path).read_bytes()
        stdout = b"OK\n" if phase == "normal" else b"ABC\n"
        stderr = b""
        exit_code = 0
        signature = None
        status_value = "completed"
        if override == "timeout":
            status_value = "timeout"
            exit_code = None
        elif override == "infra":
            status_value = "infra_error"
            exit_code = None
        elif self.case_id == "fixture-c-parser" and version == "vulnerable" and phase.startswith("candidate"):
            stdout = b""
            stderr = ASAN_LOG.encode()
            exit_code = 86
            signature = parse_asan(ASAN_LOG)
        elif self.case_id == "fixture-c-parser" and version == "fixed" and phase.startswith("candidate"):
            stdout = b"ABCD\n"
        return ReplayResult(
            version=version,
            phase=phase,
            status=status_value,
            exit_code=exit_code,
            duration_seconds=0.01,
            container_id=f"fake-replay-{version}-{phase}",
            input_digest=digest(data),
            stdout=stdout,
            stderr=stderr,
            signature=signature,
            timed_out=status_value == "timeout",
            quota_hit=False,
            log_truncated=False,
            metadata={
                "image_digest": "sha256:" + "a" * 64,
                "asan_options": asan_options,
                "limits_hit": [],
            },
        )


def prepare_approved_job(database, tmp_path, *, case_id="fixture-c-parser"):
    job = submit(database.dsn, write_request(tmp_path, case_id=case_id))
    worker(database.dsn)
    digest = status(database.dsn, job["job_id"])["pending_plan"]["plan_digest"]
    accepted = review(
        database.dsn,
        job["job_id"],
        digest,
        "approve",
        env_extra={"DATACON_OPERATOR_ID": "reviewer-1"},
    )
    assert accepted.returncode == 0, accepted.stderr
    worker(database.dsn)  # sync the graph and finalize READY
    claimed = state.claim_next(database.dsn, "execution-test")
    assert claimed is not None and claimed["state"] == "RUNNING"
    return job, digest, claimed["generation"]


def run_with_fake(database, job, generation, tmp_path, sandbox, monkeypatch):
    run_root = tmp_path / "runs"
    evidence_root = tmp_path / "evidence"
    monkeypatch.setenv("DATACON_RUN_ROOT", str(run_root))
    monkeypatch.setenv("DATACON_EVIDENCE_ROOT", str(evidence_root))
    monkeypatch.delenv("DATACON_FAULT_AFTER_TOOL", raising=False)
    return execution.run_execution(
        database.dsn,
        UUID(job["job_id"]),
        generation,
        run_root=run_root,
        sandbox=sandbox,
    )


def test_reproduced_execution_archives_six_replays(isolated_database, tmp_path, monkeypatch):
    job, digest, generation = prepare_approved_job(isolated_database, tmp_path)
    sandbox = FakeSandbox()

    outcome = run_with_fake(
        isolated_database, job, generation, tmp_path, sandbox, monkeypatch
    )

    assert outcome.state == "REPRODUCED"
    assert outcome.verdict == "REPRODUCED"
    assert sandbox.probes == 1
    assert sandbox.builds == 2
    assert sandbox.replays == 6

    current = status(isolated_database.dsn, job["job_id"])
    assert current["state"] == "REPRODUCED"
    assert current["verdict"] == "REPRODUCED"
    assert current["evidence"]["available"] is True
    verified = verify_bundle(current["evidence"]["path"])
    assert verified.manifest["job_id"] == job["job_id"]
    report = json.loads(verified.file_data["report.json"])
    assert report["verdict"] == "REPRODUCED"
    assert len(report["replays"]) == 6
    assert {run["phase"] for run in report["replays"]} == {
        "normal",
        "candidate_1",
        "candidate_2",
    }
    assert {run["version"] for run in report["replays"]} == {"vulnerable", "fixed"}


def test_clean_candidate_is_not_reproduced(isolated_database, tmp_path, monkeypatch):
    job, _, generation = prepare_approved_job(
        isolated_database, tmp_path, case_id="fixture-c-parser-clean"
    )
    sandbox = FakeSandbox(case_id="fixture-c-parser-clean")

    outcome = run_with_fake(
        isolated_database, job, generation, tmp_path, sandbox, monkeypatch
    )

    assert outcome.state == "NOT_REPRODUCED"
    assert outcome.verdict == "NOT_REPRODUCED"
    assert sandbox.replays == 6


def test_isolation_probe_failure_blocks_before_any_target_container(
    isolated_database, tmp_path, monkeypatch
):
    job, _, generation = prepare_approved_job(isolated_database, tmp_path)
    sandbox = FakeSandbox()

    def denied(*, deadline_seconds):
        sandbox.probes += 1
        raise SandboxPolicyError("seccomp is unavailable")

    sandbox.probe = denied
    outcome = run_with_fake(
        isolated_database, job, generation, tmp_path, sandbox, monkeypatch
    )

    assert outcome.state == "BLOCKED"
    assert outcome.reason_code == "POLICY_DENIED"
    assert sandbox.builds == 0
    assert sandbox.replays == 0
    current = status(isolated_database.dsn, job["job_id"])
    assert current["state"] == "BLOCKED"
    assert current["reason_code"] == "POLICY_DENIED"
    assert current["evidence"]["available"] is True


def test_plan_digest_drift_blocks_without_target_calls(
    isolated_database, tmp_path, monkeypatch
):
    job, digest, generation = prepare_approved_job(isolated_database, tmp_path)
    isolated_database.connection.execute(
        "UPDATE plans SET plan_digest = %s WHERE job_id = %s",
        ("sha256:" + "0" * 64, UUID(job["job_id"])),
    )
    sandbox = FakeSandbox()
    outcome = run_with_fake(
        isolated_database, job, generation, tmp_path, sandbox, monkeypatch
    )
    assert outcome.state == "BLOCKED"
    assert outcome.reason_code == "PLAN_MISMATCH"
    assert sandbox.builds == 0 and sandbox.replays == 0


def test_material_drift_blocks_without_target_calls(
    isolated_database, tmp_path, monkeypatch
):
    case_root = copy_cases(tmp_path)
    monkeypatch.setenv("DATACON_CASE_ROOT", str(case_root))
    job, _, generation = prepare_approved_job(isolated_database, tmp_path)
    candidate = case_root / "inputs" / "candidate.txt"
    candidate.write_bytes(b"ABCD\nTAMPERED\n")
    sandbox = FakeSandbox()
    outcome = run_with_fake(
        isolated_database, job, generation, tmp_path, sandbox, monkeypatch
    )
    assert outcome.state == "BLOCKED"
    assert outcome.reason_code in ("MATERIAL_MISSING", "PLAN_MISMATCH")
    assert sandbox.builds == 0 and sandbox.replays == 0


def test_replay_timeout_is_inconclusive_and_reported(
    isolated_database, tmp_path, monkeypatch
):
    job, _, generation = prepare_approved_job(isolated_database, tmp_path)
    sandbox = FakeSandbox(overrides={"vulnerable:candidate_2": "timeout"})
    outcome = run_with_fake(
        isolated_database, job, generation, tmp_path, sandbox, monkeypatch
    )
    assert outcome.state == "INCONCLUSIVE"
    assert outcome.verdict == "INCONCLUSIVE"
    assert outcome.verdict_reason == "TIMEOUT"
    current = status(isolated_database.dsn, job["job_id"])
    assert current["reason_code"] == "TIMEOUT"
    report = json.loads(
        verify_bundle(current["evidence"]["path"]).file_data["report.json"]
    )
    assert report["rule"]["reason_code"] == "TIMEOUT"


def test_missing_replay_evidence_is_inconclusive(
    isolated_database, tmp_path, monkeypatch
):
    job, _, generation = prepare_approved_job(isolated_database, tmp_path)
    sandbox = FakeSandbox(overrides={"fixed:candidate_2": "infra"})
    outcome = run_with_fake(
        isolated_database, job, generation, tmp_path, sandbox, monkeypatch
    )
    assert outcome.state == "INCONCLUSIVE"
    assert outcome.verdict == "INCONCLUSIVE"
    assert outcome.verdict_reason == "EVIDENCE_INCOMPLETE"


def test_archive_failure_is_visible_in_status(
    isolated_database, tmp_path, monkeypatch
):
    job, _, generation = prepare_approved_job(isolated_database, tmp_path)
    sandbox = FakeSandbox()
    evidence_file = tmp_path / "not-a-directory"
    evidence_file.write_text("occupied", encoding="utf-8")
    monkeypatch.setenv("DATACON_EVIDENCE_ROOT", str(evidence_file))
    outcome = execution.run_execution(
        isolated_database.dsn,
        UUID(job["job_id"]),
        generation,
        run_root=tmp_path / "runs",
        sandbox=sandbox,
    )
    assert outcome.state == "FAILED"
    assert outcome.reason_code == "EVIDENCE_WRITE_FAILED"
    current = status(isolated_database.dsn, job["job_id"])
    assert current["state"] == "FAILED"
    assert current["reason_code"] == "EVIDENCE_WRITE_FAILED"
    assert current["evidence"]["available"] is False
    assert current["evidence"]["error"]


def test_completed_journals_are_reused_after_generation_takeover(
    isolated_database, tmp_path, monkeypatch
):
    job, _, generation = prepare_approved_job(isolated_database, tmp_path)
    first = FakeSandbox()
    outcome = run_with_fake(
        isolated_database, job, generation, tmp_path, first, monkeypatch
    )
    assert outcome.state == "REPRODUCED"
    job_uuid = UUID(job["job_id"])

    # Simulate a restart that loses the terminal write: a new generation owns
    # the same plan and finds the durable tool journals.
    isolated_database.connection.execute(
        "UPDATE jobs SET state = 'RUNNING', stage = 'execute', generation = %s, "
        "lease_owner = 'recovery-worker', lease_expires_at = now() + interval '10 minutes', "
        "workflow_synced = false, verdict = NULL, verdict_reason = NULL, "
        "evidence_digest = NULL, evidence_path = NULL, evidence_status = NULL, "
        "evidence_error = NULL, reason_code = NULL WHERE job_id = %s",
        (generation + 1, job_uuid),
    )
    second = FakeSandbox()
    recovered = run_with_fake(
        isolated_database, job, generation + 1, tmp_path, second, monkeypatch
    )
    assert recovered.state == "REPRODUCED"
    assert second.probes == 1
    assert second.builds == 0
    assert second.replays == 0

    # The old generation can never write a new result back.
    assert state.record_attempt(
        isolated_database.dsn,
        job_uuid,
        stage="execute",
        step_key="build:vulnerable",
        attempt_no=99,
        generation=generation,
        input_digest=None,
        status="completed",
        result={"stale": True},
    ) is False


def test_export_and_verify_bundle_from_cli(
    isolated_database, tmp_path, monkeypatch
):
    job, _, generation = prepare_approved_job(isolated_database, tmp_path)
    run_with_fake(
        isolated_database, job, generation, tmp_path, FakeSandbox(), monkeypatch
    )
    current = status(isolated_database.dsn, job["job_id"])
    source = current["evidence"]["path"]

    verified = cli("verify-bundle", source, database_url=isolated_database.dsn)
    assert verified.returncode == 0, verified.stderr
    assert json.loads(verified.stdout)["status"] == "valid"

    destination = tmp_path / "exported"
    exported = cli(
        "export",
        job["job_id"],
        "--out",
        str(destination),
        database_url=isolated_database.dsn,
    )
    assert exported.returncode == 0, exported.stderr
    assert json.loads(exported.stdout)["manifest_digest"] == current["evidence"]["digest"]
    assert verify_bundle(destination).manifest_digest == current["evidence"]["digest"]

    (destination / "plan.json").write_text("{}", encoding="utf-8")
    tampered = cli("verify-bundle", str(destination), database_url=isolated_database.dsn)
    assert tampered.returncode == 3
    assert json.loads(tampered.stderr)["reason_code"] == "DIGEST_MISMATCH"

    extra = tmp_path / "source-extra"
    extra.mkdir()
    (extra / "manifest.json").write_text(
        (Path(source) / "manifest.json").read_text(), encoding="utf-8"
    )
    (extra / "extra.txt").write_text("extra", encoding="utf-8")
    rejected = cli("verify-bundle", str(extra), database_url=isolated_database.dsn)
    assert rejected.returncode == 3
    assert json.loads(rejected.stderr)["reason_code"] in (
        "MISSING_FILE",
        "EXTRA_FILE",
    )
