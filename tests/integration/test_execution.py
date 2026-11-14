"""TC-04/TC-05/TC-06 execution, recovery and evidence integration tests.

The target-facing branches use a typed fake sandbox; a separate Docker-marked
test exercises the real image, isolation probe and ASan replay.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shutil
import threading
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
    SandboxError,
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
    def __init__(
        self, *, case_id="fixture-c-parser", overrides=None, large_log_bytes=0
    ):
        self.case_id = case_id
        self.overrides = overrides or {}
        self.large_log_bytes = large_log_bytes
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
            stderr = ASAN_LOG.encode() + (
                b"X" * self.large_log_bytes if self.large_log_bytes else b""
            )
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


def test_archive_verifies_the_staged_bundle_before_publishing(
    isolated_database, tmp_path, monkeypatch
):
    from datacon.evidence import BundleError

    job, _, generation = prepare_approved_job(isolated_database, tmp_path)
    evidence_root = tmp_path / "evidence"

    def reject_staged_bundle(path):
        raise BundleError("INVALID_MANIFEST", "staged bundle is missing replay evidence")

    monkeypatch.setattr(execution, "verify_bundle", reject_staged_bundle)
    outcome = run_with_fake(
        isolated_database, job, generation, tmp_path, FakeSandbox(), monkeypatch
    )
    assert outcome.state == "FAILED"
    assert outcome.reason_code == "EVIDENCE_WRITE_FAILED"
    current = status(isolated_database.dsn, job["job_id"])
    assert current["state"] == "FAILED"
    assert current["evidence"]["available"] is False
    assert current["evidence"]["error"]
    assert not (evidence_root / job["job_id"]).exists()


@pytest.mark.parametrize("error_type", ["StaleGeneration", "StateError"])
def test_archive_error_path_contains_finish_execution_failures(
    isolated_database, tmp_path, monkeypatch, error_type
):
    from datacon.evidence import BundleError

    job, _, generation = prepare_approved_job(isolated_database, tmp_path)

    def reject_staged_bundle(path):
        raise BundleError("INVALID_MANIFEST", "cannot verify")

    def fail_finish(*args, **kwargs):
        raise getattr(state, error_type)("write failed")

    monkeypatch.setattr(execution, "verify_bundle", reject_staged_bundle)
    monkeypatch.setattr(execution.state, "finish_execution", fail_finish)
    outcome = run_with_fake(
        isolated_database, job, generation, tmp_path, FakeSandbox(), monkeypatch
    )
    assert outcome.state == "STALE"


def test_large_replay_logs_are_summarized_not_embedded(
    isolated_database, tmp_path, monkeypatch
):
    job, _, generation = prepare_approved_job(isolated_database, tmp_path)
    sentinel = b"LARGE-LOG-SENTINEL"
    sandbox = FakeSandbox(large_log_bytes=200_000)
    outcome = run_with_fake(
        isolated_database, job, generation, tmp_path, sandbox, monkeypatch
    )
    assert outcome.state == "REPRODUCED", outcome
    current = status(isolated_database.dsn, job["job_id"])
    verified = verify_bundle(current["evidence"]["path"])
    report_text = verified.file_data["report.json"].decode("utf-8")
    metadata_text = verified.file_data["metadata/execution.json"].decode("utf-8")
    assert "X" * 200_000 not in report_text
    assert "X" * 200_000 not in metadata_text
    assert len(report_text) < 200_000
    assert len(metadata_text) < 200_000
    report = json.loads(report_text)
    replay = next(
        item
        for item in report["replays"]
        if item["version"] == "vulnerable" and item["phase"] == "candidate_1"
    )
    assert replay["stderr_bytes"] > 200_000
    assert replay["stderr_sha256"].startswith("sha256:")
    assert "stdout_bytes" in replay
    assert "stderr" not in replay
    assert "stdout" not in replay
    # The raw log remains available as evidence.
    raw = verified.file_data["replay/vulnerable/candidate_1/stderr.log"]
    assert raw.startswith(ASAN_LOG.encode())
    assert len(raw) > 200_000
    # The DB attempt result is bounded and does not duplicate the raw log.
    row = isolated_database.connection.execute(
        "SELECT result FROM attempts WHERE job_id = %s AND stage = 'execute' "
        "AND step_key = 'replay:vulnerable:candidate_1'",
        (UUID(job["job_id"]),),
    ).fetchone()
    stored = json.dumps(row[0])
    assert len(stored) < 100_000
    assert "X" * 10_000 not in stored


def test_cli_export_rejects_a_trusted_digest_mismatch(
    isolated_database, tmp_path, monkeypatch
):
    job, _, generation = prepare_approved_job(isolated_database, tmp_path)
    run_with_fake(
        isolated_database, job, generation, tmp_path, FakeSandbox(), monkeypatch
    )
    current = status(isolated_database.dsn, job["job_id"])
    assert current["evidence"]["available"] is True
    isolated_database.connection.execute(
        "UPDATE jobs SET evidence_digest = %s WHERE job_id = %s",
        ("sha256:" + "0" * 64, UUID(job["job_id"])),
    )
    destination = tmp_path / "exported"
    exported = cli(
        "export",
        job["job_id"],
        "--out",
        str(destination),
        database_url=isolated_database.dsn,
    )
    assert exported.returncode == 3
    assert json.loads(exported.stderr)["reason_code"] in (
        "EVIDENCE_INTEGRITY_ERROR",
        "DIGEST_MISMATCH",
    )
    assert not destination.exists()


def _make_new_generation(database, job_id, generation):
    database.connection.execute(
        "UPDATE jobs SET state = 'RUNNING', stage = 'execute', generation = %s, "
        "lease_owner = 'recovery-worker', lease_expires_at = now() + interval '10 minutes', "
        "workflow_synced = false, verdict = NULL, verdict_reason = NULL, "
        "evidence_digest = NULL, evidence_path = NULL, evidence_status = NULL, "
        "reason_code = NULL WHERE job_id = %s",
        (generation + 1, UUID(job_id) if isinstance(job_id, str) else job_id),
    )


def _reused_flags(database, job_id, step_key):
    rows = database.connection.execute(
        "SELECT result FROM attempts WHERE job_id = %s AND stage = 'execute' "
        "AND step_key = %s ORDER BY generation DESC, attempt_no DESC",
        (UUID(job_id) if isinstance(job_id, str) else job_id, step_key),
    ).fetchall()
    return [
        bool(row[0].get("reused"))
        for row in rows
        if isinstance(row[0], dict)
    ]


def test_journal_without_database_provenance_is_not_adopted(
    isolated_database, tmp_path, monkeypatch
):
    job, _, generation = prepare_approved_job(isolated_database, tmp_path)
    run_with_fake(
        isolated_database, job, generation, tmp_path, FakeSandbox(), monkeypatch
    )
    job_uuid = UUID(job["job_id"])
    # An attacker with run-root write access deletes no journal but has no
    # database row to bind it to.
    isolated_database.connection.execute(
        "DELETE FROM attempts WHERE job_id = %s AND stage = 'execute' "
        "AND step_key = 'build:vulnerable'",
        (job_uuid,),
    )
    _make_new_generation(isolated_database, job_uuid, generation)
    second = FakeSandbox()
    recovered = run_with_fake(
        isolated_database, job, generation + 1, tmp_path, second, monkeypatch
    )
    assert recovered.state == "REPRODUCED", status(
        isolated_database.dsn, job["job_id"]
    )
    assert second.builds == 1, "journal without a DB attempt row must not be adopted"
    assert _reused_flags(isolated_database, job_uuid, "build:vulnerable")[0] is False


def test_journal_with_wrong_attempt_token_is_not_adopted(
    isolated_database, tmp_path, monkeypatch
):
    job, _, generation = prepare_approved_job(isolated_database, tmp_path)
    run_with_fake(
        isolated_database, job, generation, tmp_path, FakeSandbox(), monkeypatch
    )
    job_uuid = UUID(job["job_id"])
    isolated_database.connection.execute(
        "UPDATE attempts SET attempt_token = 'forged' WHERE job_id = %s "
        "AND stage = 'execute' AND step_key = 'build:vulnerable'",
        (job_uuid,),
    )
    _make_new_generation(isolated_database, job_uuid, generation)
    second = FakeSandbox()
    recovered = run_with_fake(
        isolated_database, job, generation + 1, tmp_path, second, monkeypatch
    )
    assert recovered.state == "REPRODUCED"
    assert second.builds == 1, "journal with a wrong attempt token must not be adopted"


def test_journal_with_wrong_generation_is_not_adopted(
    isolated_database, tmp_path, monkeypatch
):
    import hmac as hmac_module

    job, _, generation = prepare_approved_job(isolated_database, tmp_path)
    run_with_fake(
        isolated_database, job, generation, tmp_path, FakeSandbox(), monkeypatch
    )
    job_uuid = UUID(job["job_id"])
    journal = next(
        (tmp_path / "runs" / job["job_id"]).glob(
            "*/run/steps/build_vulnerable/generation-*/attempt-*/run.json"
        )
    )
    payload = json.loads(journal.read_text(encoding="utf-8"))
    payload["generation"] = 999
    secret = (tmp_path / ".datacon-journal-secret").read_bytes()
    body = {key: value for key, value in payload.items() if key != "hmac"}
    encoded = json.dumps(
        body, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    payload["hmac"] = hmac_module.new(secret, encoded, hashlib.sha256).hexdigest()
    journal.write_text(json.dumps(payload), encoding="utf-8")
    _make_new_generation(isolated_database, job_uuid, generation)
    second = FakeSandbox()
    recovered = run_with_fake(
        isolated_database, job, generation + 1, tmp_path, second, monkeypatch
    )
    assert recovered.state == "REPRODUCED"
    assert second.builds == 1, "journal with a wrong generation must not be adopted"


def test_completed_attempt_with_a_different_input_digest_is_not_reused(
    isolated_database, tmp_path, monkeypatch
):
    job, _, generation = prepare_approved_job(isolated_database, tmp_path)
    job_uuid = UUID(job["job_id"])
    isolated_database.connection.execute(
        "INSERT INTO attempts (attempt_id, job_id, stage, step_key, attempt_no, "
        "generation, input_digest, status, result) VALUES "
        "(%s, %s, 'execute', 'build:vulnerable', 1, %s, %s, 'completed', %s)",
        (
            uuid.uuid4(),
            job_uuid,
            generation,
            "sha256:" + "0" * 64,
            json.dumps({"status": "completed", "version": "vulnerable"}),
        ),
    )
    sandbox = FakeSandbox()
    outcome = run_with_fake(
        isolated_database, job, generation, tmp_path, sandbox, monkeypatch
    )
    # A completed row for different bytes is discarded, not adopted, and the
    # step executes once for the requested input instead.
    assert outcome.state == "REPRODUCED"
    assert sandbox.builds == 2
    rows = isolated_database.connection.execute(
        "SELECT input_digest, result FROM attempts WHERE job_id = %s "
        "AND stage = 'execute' AND step_key = 'build:vulnerable' "
        "AND generation = %s ORDER BY attempt_no",
        (job_uuid, generation),
    ).fetchall()
    assert len(rows) == 2
    assert rows[0][0] == "sha256:" + "0" * 64
    assert rows[0][1] == {"status": "completed", "version": "vulnerable"}
    assert rows[1][1].get("reused") is not True


def test_archive_crash_recovery_is_archive_only_and_keeps_the_verdict(
    isolated_database, tmp_path, monkeypatch
):
    job, _, generation = prepare_approved_job(isolated_database, tmp_path)
    job_uuid = UUID(job["job_id"])
    real_mark = state.mark_archiving
    original_archive = execution._archive

    def crash_during_archive(dsn, context, **kwargs):
        real_mark(dsn, context.job_id, generation=context.generation)
        # The execute deadline has already expired; an archive-only recovery
        # must still be able to commit the completed six-replay verdict.
        isolated_database.connection.execute(
            "UPDATE jobs SET execute_deadline_at = "
            "clock_timestamp() - interval '1 minute' WHERE job_id = %s",
            (job_uuid,),
        )
        raise SystemExit(99)

    monkeypatch.setattr(execution, "_archive", crash_during_archive)
    with pytest.raises(SystemExit):
        run_with_fake(
            isolated_database, job, generation, tmp_path, FakeSandbox(), monkeypatch
        )
    monkeypatch.setattr(execution, "_archive", original_archive)
    crashed = state.load_job(isolated_database.dsn, job_uuid)
    assert crashed["state"] == "ARCHIVING"
    lease_extended = isolated_database.connection.execute(
        "SELECT lease_expires_at > clock_timestamp() + interval '50 seconds' "
        "FROM jobs WHERE job_id = %s",
        (job_uuid,),
    ).fetchone()[0]
    assert lease_extended, "mark_archiving must reserve at least 60 seconds"
    isolated_database.connection.execute(
        "UPDATE jobs SET lease_expires_at = clock_timestamp() - interval '1 second' "
        "WHERE job_id = %s",
        (job_uuid,),
    )
    claimed = state.claim_next(isolated_database.dsn, "archive-recovery")
    assert claimed is not None
    assert claimed["state"] == "ARCHIVING"

    class ExplodingSandbox:
        def __getattr__(self, name):
            def fail(*args, **kwargs):
                raise AssertionError(f"archive recovery started a container: {name}")

            return fail

    monkeypatch.delenv("DATACON_FAULT_DURING_ARCHIVE", raising=False)
    recovered = execution.run_execution(
        isolated_database.dsn,
        job_uuid,
        claimed["generation"],
        run_root=tmp_path / "runs",
        sandbox=ExplodingSandbox(),
    )
    assert recovered.state == "REPRODUCED", recovered
    assert recovered.verdict == "REPRODUCED"
    current = status(isolated_database.dsn, job["job_id"])
    assert current["state"] == "REPRODUCED"
    assert current["verdict"] == "REPRODUCED"
    assert current["evidence"]["available"] is True
    report = json.loads(
        verify_bundle(current["evidence"]["path"]).file_data["report.json"]
    )
    assert report["verdict"] == "REPRODUCED"
    assert len(report["replays"]) == 6


def test_symlinked_evidence_destination_becomes_failed_not_running(
    isolated_database, tmp_path, monkeypatch
):
    job, _, generation = prepare_approved_job(isolated_database, tmp_path)
    evidence_root = tmp_path / "evidence"
    evidence_root.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    (evidence_root / job["job_id"]).symlink_to(outside, target_is_directory=True)
    monkeypatch.setenv("DATACON_EVIDENCE_ROOT", str(evidence_root))
    outcome = execution.run_execution(
        isolated_database.dsn,
        UUID(job["job_id"]),
        generation,
        run_root=tmp_path / "runs",
        sandbox=FakeSandbox(),
    )
    assert outcome.state == "FAILED", outcome
    assert outcome.reason_code == "EVIDENCE_WRITE_FAILED"
    current = status(isolated_database.dsn, job["job_id"])
    assert current["state"] == "FAILED"
    assert current["reason_code"] == "EVIDENCE_WRITE_FAILED"
    assert current["evidence"]["error"]
    assert current["state"] != "RUNNING"


class TimeoutSandbox(FakeSandbox):
    def replay(self, version, phase, **kwargs):
        if (version, phase) == ("vulnerable", "candidate_2"):
            self.replays += 1
            raise SandboxError("docker exec/wait timed out", reason_code="TIMEOUT")
        return super().replay(version, phase, **kwargs)


def test_sandbox_timeout_is_recorded_as_inconclusive_replay_evidence(
    isolated_database, tmp_path, monkeypatch
):
    from datacon.tools.sandbox import SandboxError

    job, _, generation = prepare_approved_job(isolated_database, tmp_path)
    sandbox = TimeoutSandbox()
    outcome = run_with_fake(
        isolated_database, job, generation, tmp_path, sandbox, monkeypatch
    )
    assert outcome.state == "INCONCLUSIVE", outcome
    assert outcome.verdict == "INCONCLUSIVE"
    assert outcome.verdict_reason == "TIMEOUT"
    current = status(isolated_database.dsn, job["job_id"])
    assert current["state"] == "INCONCLUSIVE"
    assert current["reason_code"] == "TIMEOUT"
    verified = verify_bundle(current["evidence"]["path"])
    report = json.loads(verified.file_data["report.json"])
    assert report["verdict"] == "INCONCLUSIVE"
    assert report["rule"]["reason_code"] == "TIMEOUT"
    timeout_run = next(
        run
        for run in report["replays"]
        if run["version"] == "vulnerable" and run["phase"] == "candidate_2"
    )
    assert timeout_run["status"] == "timeout"
    assert timeout_run["timed_out"] is True
    assert len(report["replays"]) == 6
    assert "replay/vulnerable/candidate_2/metadata.json" in verified.file_data


class CrashAfterBuildSandbox(FakeSandbox):
    def build(self, version, **kwargs):
        result = super().build(version, **kwargs)
        if version == "vulnerable":
            raise SystemExit(98)
        return result


def test_step_attempts_are_bounded_across_generations(
    isolated_database, tmp_path, monkeypatch
):
    job, _, generation = prepare_approved_job(isolated_database, tmp_path)
    job_uuid = UUID(job["job_id"])
    for _ in range(2):
        sandbox = CrashAfterBuildSandbox()
        with pytest.raises(SystemExit):
            run_with_fake(
                isolated_database, job, generation, tmp_path, sandbox, monkeypatch
            )
        isolated_database.connection.execute(
            "UPDATE jobs SET lease_expires_at = clock_timestamp() - interval '1 second' "
            "WHERE job_id = %s",
            (job_uuid,),
        )
        claimed = state.claim_next(isolated_database.dsn, "retry-worker")
        assert claimed is not None
        generation = claimed["generation"]
    rows = isolated_database.connection.execute(
        "SELECT count(*) FROM attempts WHERE job_id = %s AND stage = 'execute' "
        "AND step_key = 'build:vulnerable'",
        (job_uuid,),
    ).fetchone()
    assert rows[0] == 2
    final = FakeSandbox()
    outcome = execution.run_execution(
        isolated_database.dsn,
        job_uuid,
        generation,
        run_root=tmp_path / "runs",
        sandbox=final,
    )
    assert final.builds == 0, "a third attempt must not run the target"
    assert outcome.state != "RUNNING"
    assert outcome.state in ("FAILED", "INCONCLUSIVE")


def _cases_with_material_subdirectory(tmp_path):
    root = copy_cases(tmp_path)
    materials = root / "materials"
    materials.mkdir()
    for entry in list(root.iterdir()):
        if entry.name in ("registry.json", "manifest.json", "materials"):
            continue
        shutil.move(str(entry), str(materials / entry.name))
    registry_path = root / "registry.json"
    registry = json.loads(registry_path.read_text(encoding="utf-8"))
    registry["material_root"] = "materials"
    registry_path.write_text(json.dumps(registry), encoding="utf-8")
    return root


def test_registry_material_root_subdirectory_executes_successfully(
    isolated_database, tmp_path, monkeypatch
):
    case_root = _cases_with_material_subdirectory(tmp_path)
    monkeypatch.setenv("DATACON_CASE_ROOT", str(case_root))
    job, _, generation = prepare_approved_job(isolated_database, tmp_path)
    sandbox = FakeSandbox()
    outcome = run_with_fake(
        isolated_database, job, generation, tmp_path, sandbox, monkeypatch
    )
    assert outcome.state == "REPRODUCED", outcome
    assert sandbox.builds == 2
    assert sandbox.replays == 6
    current = status(isolated_database.dsn, job["job_id"])
    assert current["evidence"]["available"] is True
    assert verify_bundle(current["evidence"]["path"]).manifest["verdict"] == "REPRODUCED"


def test_fault_injection_is_refused_outside_test_mode(
    isolated_database, tmp_path, monkeypatch
):
    job = submit(isolated_database.dsn, write_request(tmp_path))
    worker(isolated_database.dsn)
    digest = status(isolated_database.dsn, job["job_id"])["pending_plan"]["plan_digest"]
    accepted = review(
        isolated_database.dsn,
        job["job_id"],
        digest,
        "approve",
        env_extra={"DATACON_OPERATOR_ID": "reviewer-1"},
    )
    assert accepted.returncode == 0, accepted.stderr
    worker(isolated_database.dsn)
    assert status(isolated_database.dsn, job["job_id"])["state"] == "READY"
    monkeypatch.delenv("DATACON_TEST_MODE", raising=False)
    fault_env = {
        "DATACON_FAULT_AFTER_TOOL": "build:vulnerable",
        "DATACON_RUN_ROOT": str(tmp_path / "runs"),
        "DATACON_EVIDENCE_ROOT": str(tmp_path / "evidence"),
    }
    result = cli(
        "worker",
        "--once",
        database_url=isolated_database.dsn,
        env_extra=fault_env,
    )
    assert result.returncode == 1, result
    assert json.loads(result.stderr)["reason_code"] == "INVALID_CONFIGURATION"
    current = status(isolated_database.dsn, job["job_id"])
    # The refused worker must not claim the READY job or start any target step.
    assert current["state"] == "READY"
    rows = isolated_database.connection.execute(
        "SELECT count(*) FROM attempts WHERE job_id = %s AND stage = 'execute'",
        (UUID(job["job_id"]),),
    ).fetchone()
    assert rows[0] == 0


def test_fault_injection_is_allowed_only_with_test_mode(monkeypatch):
    from datacon import execution

    monkeypatch.setenv("DATACON_TEST_MODE", "1")
    monkeypatch.setenv("DATACON_FAULT_AFTER_TOOL", "build:vulnerable")
    execution.validate_test_hooks()
    monkeypatch.delenv("DATACON_TEST_MODE")
    with pytest.raises(RuntimeError, match="DATACON_TEST_MODE"):
        execution.validate_test_hooks()


def test_two_workers_claim_a_ready_job_exactly_once(
    isolated_database, tmp_path, monkeypatch
):
    from concurrent.futures import ThreadPoolExecutor

    job = submit(isolated_database.dsn, write_request(tmp_path))
    worker(isolated_database.dsn)  # prepare -> AWAITING_REVIEW
    digest = status(isolated_database.dsn, job["job_id"])["pending_plan"]["plan_digest"]
    accepted = review(
        isolated_database.dsn,
        job["job_id"],
        digest,
        "approve",
        env_extra={"DATACON_OPERATOR_ID": "reviewer-1"},
    )
    assert accepted.returncode == 0, accepted.stderr
    worker(isolated_database.dsn)  # finalize -> READY
    assert status(isolated_database.dsn, job["job_id"])["state"] == "READY"

    barrier = threading.Barrier(2)

    def claim(name):
        barrier.wait(timeout=10)
        return state.claim_next(isolated_database.dsn, name)

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(claim, ["ready-worker-1", "ready-worker-2"]))
    winners = [item for item in results if item is not None]
    assert len(winners) == 1, results
    claimed = winners[0]
    assert claimed["state"] == "RUNNING"
    assert sum(1 for item in results if item is None) == 1

    evidence_root = tmp_path / "evidence"
    monkeypatch.setenv("DATACON_EVIDENCE_ROOT", str(evidence_root))
    monkeypatch.setenv("DATACON_RUN_ROOT", str(tmp_path / "runs"))
    sandbox = FakeSandbox()
    outcome = execution.run_execution(
        isolated_database.dsn,
        UUID(job["job_id"]),
        claimed["generation"],
        run_root=tmp_path / "runs",
        sandbox=sandbox,
    )
    assert outcome.state == "REPRODUCED"
    assert sandbox.replays == 6
    assert len([path for path in evidence_root.iterdir() if path.is_dir()]) == 1
    rows = isolated_database.connection.execute(
        "SELECT step_key, count(*) FROM attempts WHERE job_id = %s "
        "AND stage = 'execute' AND step_key LIKE 'replay:%%' GROUP BY step_key",
        (UUID(job["job_id"]),),
    ).fetchall()
    assert len(rows) == 6
    assert all(row[1] == 1 for row in rows)


def test_legacy_plan_without_seccomp_digest_is_blocked_before_containers(
    isolated_database, tmp_path, monkeypatch
):
    from datacon import contracts

    job, _, generation = prepare_approved_job(isolated_database, tmp_path)
    job_uuid = UUID(job["job_id"])
    row = isolated_database.connection.execute(
        "SELECT plan FROM plans WHERE job_id = %s", (job_uuid,)
    ).fetchone()
    plan = row[0]
    plan["isolation"].pop("seccomp_profile_digest", None)
    legacy_digest = contracts.plan_digest(plan)
    isolated_database.connection.execute(
        "UPDATE plans SET plan = %s, plan_digest = %s WHERE job_id = %s",
        (json.dumps(plan), legacy_digest, job_uuid),
    )
    isolated_database.connection.execute(
        "UPDATE reviews SET plan_digest = %s WHERE job_id = %s",
        (legacy_digest, job_uuid),
    )
    sandbox = FakeSandbox()
    outcome = run_with_fake(
        isolated_database, job, generation, tmp_path, sandbox, monkeypatch
    )
    assert outcome.state == "BLOCKED", outcome
    assert outcome.reason_code == "POLICY_DENIED"
    assert sandbox.probes == 0
    assert sandbox.builds == 0
    assert sandbox.replays == 0


def test_report_size_cap_prevents_archiving_an_invalid_bundle(
    isolated_database, tmp_path, monkeypatch
):
    import datacon.evidence as evidence_module

    job, _, generation = prepare_approved_job(isolated_database, tmp_path)
    monkeypatch.setattr(evidence_module, "MAX_FILE_BYTES", 1)
    outcome = run_with_fake(
        isolated_database, job, generation, tmp_path, FakeSandbox(), monkeypatch
    )
    assert outcome.state == "FAILED", outcome
    assert outcome.reason_code == "EVIDENCE_WRITE_FAILED"
    current = status(isolated_database.dsn, job["job_id"])
    assert current["state"] == "FAILED"
    assert current["evidence"]["available"] is False
    assert current["evidence"]["status"] != "archived"
    assert current["evidence"]["error"]
    assert not (tmp_path / "evidence" / job["job_id"]).exists()


def test_attempt_result_metadata_is_bounded(isolated_database, tmp_path):
    job, _, generation = prepare_approved_job(isolated_database, tmp_path)
    with pytest.raises(state.StateError, match="metadata cap"):
        state.record_attempt(
            isolated_database.dsn,
            UUID(job["job_id"]),
            stage="execute",
            step_key="oversized",
            attempt_no=1,
            generation=generation,
            input_digest=None,
            status="completed",
            result={"blob": "x" * (600 * 1024)},
        )


def test_archive_only_without_evidence_is_inconclusive_not_blocked(
    isolated_database, tmp_path, monkeypatch
):
    job, _, generation = prepare_approved_job(isolated_database, tmp_path)
    job_uuid = UUID(job["job_id"])
    isolated_database.connection.execute(
        "UPDATE jobs SET state = 'ARCHIVING', stage = 'archive', "
        "lease_expires_at = clock_timestamp() + interval '10 minutes', "
        "execute_deadline_at = clock_timestamp() - interval '1 minute' "
        "WHERE job_id = %s",
        (job_uuid,),
    )

    class ExplodingSandbox:
        def __getattr__(self, name):
            def fail(*args, **kwargs):
                raise AssertionError(f"archive recovery started a container: {name}")

            return fail

    outcome = execution.run_execution(
        isolated_database.dsn,
        job_uuid,
        generation,
        run_root=tmp_path / "runs",
        sandbox=ExplodingSandbox(),
    )
    assert outcome.state == "INCONCLUSIVE", outcome
    assert outcome.reason_code == "EVIDENCE_INCOMPLETE"
    current = status(isolated_database.dsn, job["job_id"])
    assert current["state"] == "INCONCLUSIVE"
    assert current["reason_code"] == "EVIDENCE_INCOMPLETE"
    assert current["evidence"]["available"] is False
    assert current["evidence"]["error"]
