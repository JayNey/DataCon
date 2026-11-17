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
IMAGE_DIGEST = (
    "sha256:f5ce959d91f059acf5a4b3f1c19f46713c4b2881c7d7cd1d5143ca1d1412277f"
)


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
        self.build_material_dirs = []
        self.replay_paths = []

    def reclaim_job(self):
        self.reclaimed += 1
        return 0

    def probe(self, *, deadline_seconds):
        self.probes += 1
        return ProbeReport(
            ok=True,
            checks={
                "uid": "65534",
                "seccomp": "2",
                "seccomp_filters": "1",
                "no_new_privs": "1",
                "cap_eff": "0",
                "cgroup_version": "2",
                "routes": "",
                "errors": [],
            },
            compiler_version="Debian clang version 19.1.7",
            image_digest=IMAGE_DIGEST,
            raw="uid=65534\nseccomp=2\n",
            limits={
                "cpu": 2,
                "memory_mib": 2048,
                "pids": 128,
                "scratch_mib": 512,
            },
        )

    def build(
        self,
        version,
        *,
        materials_dir,
        compile_args,
        deadline_seconds,
        expected_materials=None,
    ):
        self.builds += 1
        self.build_material_dirs.append(Path(materials_dir))
        artifact = f"fake-{version}-binary".encode()
        recipe = Path(materials_dir) / "build.sh"
        return BuildResult(
            version=version,
            status="completed",
            exit_code=0,
            duration_seconds=0.01,
            container_id=f"fake-build-{version}",
            image_digest=IMAGE_DIGEST,
            compile_args=tuple(compile_args),
            artifact_digest=digest(artifact),
            log=b"",
            log_truncated=False,
            artifact=artifact,
            metadata={
                "build_recipe_digest": digest(recipe.read_bytes()),
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
        expected_artifact_digest=None,
        expected_input_digest=None,
    ):
        self.replays += 1
        self.replay_paths.append(
            (Path(artifact_path), Path(input_path))
        )
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
        elif self.case_id != "fixture-c-parser" and phase.startswith("candidate"):
            stdout = b"ABC\n"
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
                "image_digest": IMAGE_DIGEST,
                "asan_options": asan_options,
                "oom_killed": False,
                "limits_hit": [],
                "timeout_seconds": timeout_seconds,
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


def _archived_manifests(evidence_root: Path):
    """Return every published manifest below an evidence root, if any."""
    root = Path(evidence_root)
    if not root.exists() or not root.is_dir():
        return []
    return list(root.rglob("manifest.json"))


def test_reproduced_execution_archives_six_replays(isolated_database, tmp_path, monkeypatch):
    job, digest, generation = prepare_approved_job(isolated_database, tmp_path)
    sandbox = FakeSandbox()

    outcome = run_with_fake(
        isolated_database, job, generation, tmp_path, sandbox, monkeypatch
    )

    assert outcome.state == "REPRODUCED", (
        outcome,
        status(isolated_database.dsn, job["job_id"]),
    )
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


def _is_inside(path: Path, root: Path) -> bool:
    resolved = path.resolve()
    resolved_root = root.resolve()
    return resolved == resolved_root or resolved_root in resolved.parents


def test_targets_mount_staging_copies_outside_run_root(
    isolated_database, tmp_path, monkeypatch
):
    job, _, generation = prepare_approved_job(isolated_database, tmp_path)
    sandbox = FakeSandbox()
    outcome = run_with_fake(
        isolated_database, job, generation, tmp_path, sandbox, monkeypatch
    )
    assert outcome.state == "REPRODUCED", outcome
    run_root = tmp_path / "runs"
    assert sandbox.build_material_dirs
    assert sandbox.replay_paths
    for directory in sandbox.build_material_dirs:
        assert not _is_inside(directory, run_root)
    for artifact, input_file in sandbox.replay_paths:
        assert not _is_inside(artifact, run_root)
        assert not _is_inside(input_file, run_root)
    staging_root = tmp_path / ".datacon-staging"
    assert staging_root.is_dir()
    assert not list(staging_root.iterdir()), "per-attempt staging was not removed"


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
    assert current["verdict"] is None
    assert current["verdict_reason"] is None
    assert current["evidence"]["available"] is False
    assert current["evidence"]["error"]


def test_archive_failure_keeps_verdict_unset(
    isolated_database, tmp_path, monkeypatch
):
    """A failed archive must never publish the computed verdict."""
    job, _, generation = prepare_approved_job(isolated_database, tmp_path)
    evidence_file = tmp_path / "not-a-directory"
    evidence_file.write_text("occupied", encoding="utf-8")
    monkeypatch.setenv("DATACON_EVIDENCE_ROOT", str(evidence_file))
    outcome = execution.run_execution(
        isolated_database.dsn,
        UUID(job["job_id"]),
        generation,
        run_root=tmp_path / "runs",
        sandbox=FakeSandbox(),
    )
    assert outcome.state == "FAILED"
    assert outcome.reason_code == "EVIDENCE_WRITE_FAILED"
    assert outcome.verdict is None
    current = status(isolated_database.dsn, job["job_id"])
    assert current["state"] == "FAILED"
    assert current["verdict"] is None
    assert current["verdict_reason"] is None
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
    assert not _archived_manifests(evidence_root)


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

    isolated_database.connection.execute(
        "UPDATE jobs SET lease_expires_at = clock_timestamp() + interval '5 seconds' "
        "WHERE job_id = %s",
        (job_uuid,),
    )
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
    assert outcome.state == "INCONCLUSIVE"
    assert outcome.reason_code == "RUN_INCOMPLETE"
    assert outcome.evidence_path is not None
    assert verify_bundle(outcome.evidence_path).manifest["verdict"] == "INCONCLUSIVE"


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
    assert not _archived_manifests(tmp_path / "evidence")


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
    assert outcome.state == "INCONCLUSIVE", (
        outcome,
        status(isolated_database.dsn, job["job_id"]),
    )
    assert outcome.reason_code == "EVIDENCE_INCOMPLETE"
    current = status(isolated_database.dsn, job["job_id"])
    assert current["state"] == "INCONCLUSIVE"
    assert current["reason_code"] == "EVIDENCE_INCOMPLETE"
    assert current["evidence"]["available"] is False
    assert current["evidence"]["error"]


def test_materialized_build_recipe_tamper_is_blocked(
    isolated_database, tmp_path, monkeypatch
):
    job, _, generation = prepare_approved_job(isolated_database, tmp_path)
    original = execution._materialize

    def tampering_materialize(context, run_root, **kwargs):
        result = original(context, run_root)
        materials_dir = result[0]
        recipe = Path(materials_dir) / "build.sh"
        recipe.chmod(0o644)
        recipe.write_bytes(b"#!/bin/sh\nexit 0\n")
        return result

    monkeypatch.setattr(execution, "_materialize", tampering_materialize)
    sandbox = FakeSandbox()
    outcome = run_with_fake(
        isolated_database, job, generation, tmp_path, sandbox, monkeypatch
    )
    assert outcome.state != "REPRODUCED", outcome
    assert outcome.verdict != "REPRODUCED"
    assert sandbox.builds == 0, "a tampered build recipe must not reach the sandbox"
    current = status(isolated_database.dsn, job["job_id"])
    assert current["state"] != "REPRODUCED"


def test_replay_artifact_tamper_is_blocked(
    isolated_database, tmp_path, monkeypatch
):
    job, _, generation = prepare_approved_job(isolated_database, tmp_path)
    original = execution._persist_build
    tampered = {"count": 0}

    def tampering_persist(*args, **kwargs):
        payload = original(*args, **kwargs)
        context = args[1]
        artifact = payload.get("files", {}).get("artifact")
        if artifact:
            path = execution._work_root(context) / artifact
            path.chmod(0o644)
            path.write_bytes(b"tampered-parser")
            tampered["count"] += 1
        return payload

    monkeypatch.setattr(execution, "_persist_build", tampering_persist)
    sandbox = FakeSandbox()
    outcome = run_with_fake(
        isolated_database, job, generation, tmp_path, sandbox, monkeypatch
    )
    assert tampered["count"] == 2
    assert outcome.state != "REPRODUCED", outcome
    assert outcome.verdict != "REPRODUCED"
    assert sandbox.replays == 0, "a tampered parser must not reach replay"


def test_evidence_material_digest_matches_plan(
    isolated_database, tmp_path, monkeypatch
):
    job, _, generation = prepare_approved_job(isolated_database, tmp_path)
    outcome = run_with_fake(
        isolated_database, job, generation, tmp_path, FakeSandbox(), monkeypatch
    )
    assert outcome.state == "REPRODUCED", outcome
    current = status(isolated_database.dsn, job["job_id"])
    verified = verify_bundle(current["evidence"]["path"])
    plan = json.loads(verified.file_data["plan.json"])
    materials = {
        "harness.c": plan["harness_digest"],
        "build.sh": plan["build_recipe_digest"],
        "dependencies.lock": plan["dependencies_digest"],
        "fix.patch": plan["repository"]["patch_digest"],
        "inputs/normal.txt": plan["inputs"]["normal"],
        "inputs/candidate.txt": plan["inputs"]["candidate"],
    }
    for relative, expected in materials.items():
        data = verified.file_data[f"materials/{relative}"]
        assert digest(data) == expected, relative


class InputMismatchSandbox(FakeSandbox):
    """Persist a completed result whose input digest is not the plan's."""

    def replay(self, version, phase, **kwargs):
        from dataclasses import replace

        result = super().replay(version, phase, **kwargs)
        return replace(result, input_digest="sha256:" + "0" * 64)


def test_archive_fence_loss_returns_stale_without_publishing(
    isolated_database, tmp_path, monkeypatch
):
    job, _, generation = prepare_approved_job(isolated_database, tmp_path)

    def lose_fence(*args, **kwargs):
        raise state.StaleGeneration("the lease moved to another generation")

    monkeypatch.setattr(execution.state, "assert_archive_fence", lose_fence)
    outcome = run_with_fake(
        isolated_database, job, generation, tmp_path, FakeSandbox(), monkeypatch
    )
    assert outcome.state == "STALE", outcome
    current = status(isolated_database.dsn, job["job_id"])
    assert current["state"] == "ARCHIVING"
    assert current["verdict"] is None
    assert not _archived_manifests(tmp_path / "evidence")
    assert not list((tmp_path / "evidence").glob(".*.generation-*.tmp-*"))


def test_archive_only_does_not_promote_input_mismatch(
    isolated_database, tmp_path, monkeypatch
):
    job, _, generation = prepare_approved_job(isolated_database, tmp_path)
    sandbox = InputMismatchSandbox()
    outcome = run_with_fake(
        isolated_database, job, generation, tmp_path, sandbox, monkeypatch
    )
    assert outcome.state == "INCONCLUSIVE", outcome
    assert outcome.verdict is None
    assert outcome.verdict_reason is None
    assert outcome.reason_code == "EVIDENCE_INCOMPLETE"
    current = status(isolated_database.dsn, job["job_id"])
    assert current["state"] == "INCONCLUSIVE"
    assert current["verdict"] is None
    assert current["reason_code"] == "EVIDENCE_INCOMPLETE"
    assert current["evidence"]["available"] is False

    # The same completed results must not be promoted when archive-only
    # recovery takes over the job.
    job_uuid = UUID(job["job_id"])
    current_generation = state.load_job(isolated_database.dsn, job_uuid)["generation"]
    isolated_database.connection.execute(
        "UPDATE jobs SET state = 'ARCHIVING', stage = 'archive', "
        "lease_owner = 'archive-only', lease_expires_at = now() + interval '10 minutes', "
        "execute_deadline_at = now() - interval '1 minute' WHERE job_id = %s",
        (job_uuid,),
    )

    class ExplodingSandbox:
        def __getattr__(self, name):
            def fail(*args, **kwargs):
                raise AssertionError(f"archive recovery started a container: {name}")

            return fail

    recovered = execution.run_execution(
        isolated_database.dsn,
        job_uuid,
        current_generation,
        run_root=tmp_path / "runs",
        sandbox=ExplodingSandbox(),
    )
    assert recovered.state == "INCONCLUSIVE", recovered
    assert recovered.verdict is None
    assert recovered.reason_code == "EVIDENCE_INCOMPLETE"
    current = status(isolated_database.dsn, job["job_id"])
    assert current["state"] != "REPRODUCED"
    assert current["verdict"] is None
    assert current["evidence"]["available"] is False


def test_archive_only_rejects_completed_result_with_other_plan(
    isolated_database, tmp_path, monkeypatch
):
    job, _, generation = prepare_approved_job(isolated_database, tmp_path)
    outcome = run_with_fake(
        isolated_database, job, generation, tmp_path, FakeSandbox(), monkeypatch
    )
    assert outcome.state == "REPRODUCED", outcome
    job_uuid = UUID(job["job_id"])
    row = isolated_database.connection.execute(
        "SELECT result FROM attempts WHERE job_id = %s AND stage = 'execute' "
        "AND step_key = 'replay:vulnerable:candidate_1'",
        (job_uuid,),
    ).fetchone()
    result = row[0]
    result["plan_digest"] = "sha256:" + "0" * 64
    isolated_database.connection.execute(
        "UPDATE attempts SET result = %s WHERE job_id = %s AND stage = 'execute' "
        "AND step_key = 'replay:vulnerable:candidate_1'",
        (json.dumps(result), job_uuid),
    )
    current_generation = state.load_job(isolated_database.dsn, job_uuid)["generation"]
    isolated_database.connection.execute(
        "UPDATE jobs SET state = 'ARCHIVING', stage = 'archive', "
        "lease_owner = 'archive-only', lease_expires_at = now() + interval '10 minutes', "
        "execute_deadline_at = now() - interval '1 minute' WHERE job_id = %s",
        (job_uuid,),
    )

    class ExplodingSandbox:
        def __getattr__(self, name):
            def fail(*args, **kwargs):
                raise AssertionError(f"archive recovery started a container: {name}")

            return fail

    recovered = execution.run_execution(
        isolated_database.dsn,
        job_uuid,
        current_generation,
        run_root=tmp_path / "runs",
        sandbox=ExplodingSandbox(),
    )
    assert recovered.state == "INCONCLUSIVE", recovered
    assert recovered.verdict != "REPRODUCED"
    current = status(isolated_database.dsn, job["job_id"])
    assert current["state"] != "REPRODUCED"


def test_work_paths_include_generation(isolated_database, tmp_path, monkeypatch):
    job, _, generation = prepare_approved_job(isolated_database, tmp_path)
    outcome = run_with_fake(
        isolated_database, job, generation, tmp_path, FakeSandbox(), monkeypatch
    )
    assert outcome.state == "REPRODUCED", outcome
    rows = isolated_database.connection.execute(
        "SELECT step_key, result FROM attempts WHERE job_id = %s AND stage = 'execute' "
        "AND step_key IN ('build:vulnerable', 'replay:vulnerable:candidate_1')",
        (UUID(job["job_id"]),),
    ).fetchall()
    assert rows
    for row in rows:
        files = row[1].get("files") or {}
        for relative in files.values():
            if relative:
                assert f"generation-{generation}/" in relative, (row[0], relative)


def test_staging_root_inside_run_root_fails_closed(
    isolated_database, tmp_path, monkeypatch
):
    job, _, generation = prepare_approved_job(isolated_database, tmp_path)
    run_root = tmp_path / "runs"
    monkeypatch.setenv("DATACON_RUN_ROOT", str(run_root))
    monkeypatch.setenv("DATACON_EVIDENCE_ROOT", str(tmp_path / "evidence"))
    monkeypatch.setenv("DATACON_STAGING_ROOT", str(run_root / "staging"))
    monkeypatch.delenv("DATACON_JOURNAL_SECRET_FILE", raising=False)
    sandbox = FakeSandbox()
    outcome = execution.run_execution(
        isolated_database.dsn,
        UUID(job["job_id"]),
        generation,
        run_root=run_root,
        sandbox=sandbox,
    )
    assert outcome.state in ("BLOCKED", "FAILED")
    assert outcome.reason_code == "EVIDENCE_WRITE_FAILED"
    assert sandbox.probes == 0
    assert sandbox.builds == 0
    assert sandbox.replays == 0
    current = status(isolated_database.dsn, job["job_id"])
    assert current["state"] in ("BLOCKED", "FAILED")
    assert current["evidence"]["error"]
    assert not (run_root / "staging").exists()


def test_journal_secret_inside_run_root_fails_closed(
    isolated_database, tmp_path, monkeypatch
):
    job, _, generation = prepare_approved_job(isolated_database, tmp_path)
    run_root = tmp_path / "runs"
    monkeypatch.setenv("DATACON_RUN_ROOT", str(run_root))
    monkeypatch.setenv("DATACON_EVIDENCE_ROOT", str(tmp_path / "evidence"))
    monkeypatch.setenv("DATACON_JOURNAL_SECRET_FILE", str(run_root / "secret"))
    sandbox = FakeSandbox()
    outcome = execution.run_execution(
        isolated_database.dsn,
        UUID(job["job_id"]),
        generation,
        run_root=run_root,
        sandbox=sandbox,
    )
    assert sandbox.probes == 0
    assert sandbox.builds == 0
    assert sandbox.replays == 0
    assert outcome.state in ("BLOCKED", "FAILED")
    current = status(isolated_database.dsn, job["job_id"])
    assert current["state"] in ("BLOCKED", "FAILED")
    assert current["evidence"]["error"]
    assert not (run_root / "secret").exists()


def test_nested_evidence_root_inside_run_root_fails_closed(
    isolated_database, tmp_path, monkeypatch
):
    job, _, generation = prepare_approved_job(isolated_database, tmp_path)
    run_root = tmp_path / "runs"
    monkeypatch.setenv("DATACON_RUN_ROOT", str(run_root))
    monkeypatch.setenv("DATACON_EVIDENCE_ROOT", str(run_root / "evidence"))
    monkeypatch.delenv("DATACON_JOURNAL_SECRET_FILE", raising=False)
    sandbox = FakeSandbox()
    outcome = execution.run_execution(
        isolated_database.dsn,
        UUID(job["job_id"]),
        generation,
        run_root=run_root,
        sandbox=sandbox,
    )
    assert sandbox.probes == 0
    assert sandbox.builds == 0
    assert sandbox.replays == 0
    assert outcome.state in ("BLOCKED", "FAILED")
    current = status(isolated_database.dsn, job["job_id"])
    assert current["state"] in ("BLOCKED", "FAILED")
    assert current["evidence"]["error"]


def test_archive_only_rejects_nested_evidence_root(
    isolated_database, tmp_path, monkeypatch
):
    job, _, generation = prepare_approved_job(isolated_database, tmp_path)
    job_uuid = UUID(job["job_id"])
    isolated_database.connection.execute(
        "UPDATE jobs SET state = 'ARCHIVING', stage = 'archive', "
        "lease_owner = 'archive-only', lease_expires_at = now() + interval '10 minutes', "
        "execute_deadline_at = now() - interval '1 minute' WHERE job_id = %s",
        (job_uuid,),
    )
    run_root = tmp_path / "runs"
    monkeypatch.setenv("DATACON_RUN_ROOT", str(run_root))
    monkeypatch.setenv("DATACON_EVIDENCE_ROOT", str(run_root / "evidence"))
    monkeypatch.delenv("DATACON_JOURNAL_SECRET_FILE", raising=False)

    class ExplodingSandbox:
        def __init__(self):
            self.calls = []

        def __getattr__(self, name):
            def fail(*args, **kwargs):
                self.calls.append(name)
                raise AssertionError(
                    f"archive recovery started a container: {name}"
                )

            return fail

    sandbox = ExplodingSandbox()
    outcome = execution.run_execution(
        isolated_database.dsn,
        job_uuid,
        generation,
        run_root=run_root,
        sandbox=sandbox,
    )
    assert sandbox.calls == []
    assert outcome.state == "FAILED", outcome
    assert outcome.reason_code == "EVIDENCE_WRITE_FAILED"
    current = status(isolated_database.dsn, job["job_id"])
    assert current["state"] == "FAILED"
    assert current["reason_code"] == "EVIDENCE_WRITE_FAILED"
    assert current["evidence"]["available"] is False
    assert "EVIDENCE_WRITE_FAILED" in current["evidence"]["error"]
    assert not (run_root / "evidence").exists()
    assert not _archived_manifests(run_root / "evidence")


def test_default_secret_outside_run_root_still_works(
    isolated_database, tmp_path, monkeypatch
):
    job, _, generation = prepare_approved_job(isolated_database, tmp_path)
    outcome = run_with_fake(
        isolated_database, job, generation, tmp_path, FakeSandbox(), monkeypatch
    )
    assert outcome.state == "REPRODUCED", outcome
    assert (tmp_path / ".datacon-journal-secret").is_file()


class ProbePolicySandbox(FakeSandbox):
    def probe(self, *, deadline_seconds):
        raise SandboxPolicyError("injected isolation failure")


class BuildFailureSandbox(FakeSandbox):
    def build(self, *args, **kwargs):
        raise execution.ExecutionFailed("BUILD_FAILED", "injected build failure")


def _finish_returns_false(monkeypatch):
    monkeypatch.setattr(
        execution.state, "finish_execution", lambda *args, **kwargs: False
    )


def _archive_error(monkeypatch):
    calls = []

    def fail(*args, **kwargs):
        calls.append(True)
        return (None, None, "EVIDENCE_WRITE_FAILED: injected archive failure")

    monkeypatch.setattr(execution, "_archive", fail)
    return calls


def test_evidence_path_failure_returns_stale_when_finish_is_not_committed(
    isolated_database, tmp_path, monkeypatch
):
    job, _, generation = prepare_approved_job(isolated_database, tmp_path)
    run_root = tmp_path / "runs"
    monkeypatch.setenv("DATACON_RUN_ROOT", str(run_root))
    monkeypatch.setenv("DATACON_EVIDENCE_ROOT", str(run_root / "evidence"))
    monkeypatch.delenv("DATACON_JOURNAL_SECRET_FILE", raising=False)
    _finish_returns_false(monkeypatch)

    outcome = execution.run_execution(
        isolated_database.dsn,
        UUID(job["job_id"]),
        generation,
        run_root=run_root,
        sandbox=FakeSandbox(),
    )

    assert outcome.state == "STALE"
    current = status(isolated_database.dsn, job["job_id"])
    assert current["state"] == "RUNNING"
    assert not _archived_manifests(run_root / "evidence")


def test_blocked_context_reload_failure_returns_stale_when_finish_is_not_committed(
    isolated_database, tmp_path, monkeypatch
):
    job, _, generation = prepare_approved_job(isolated_database, tmp_path)

    def block(*args, **kwargs):
        raise execution.ExecutionBlocked("POLICY_DENIED", "injected block")

    monkeypatch.setattr(execution, "_load_context", block)
    _finish_returns_false(monkeypatch)

    outcome = execution.run_execution(
        isolated_database.dsn,
        UUID(job["job_id"]),
        generation,
        run_root=tmp_path / "runs",
        sandbox=FakeSandbox(),
    )

    assert outcome.state == "STALE"
    current = status(isolated_database.dsn, job["job_id"])
    assert current["state"] == "RUNNING"


def test_archive_only_incomplete_returns_stale_when_finish_is_not_committed(
    isolated_database, tmp_path, monkeypatch
):
    job, _, generation = prepare_approved_job(isolated_database, tmp_path)
    job_uuid = UUID(job["job_id"])
    isolated_database.connection.execute(
        "UPDATE jobs SET state = 'ARCHIVING', stage = 'archive', "
        "lease_owner = 'archive-only', lease_expires_at = now() + interval '10 minutes', "
        "execute_deadline_at = now() - interval '1 minute' WHERE job_id = %s",
        (job_uuid,),
    )
    run_root = tmp_path / "runs"
    monkeypatch.setenv("DATACON_EVIDENCE_ROOT", str(tmp_path / "evidence"))
    monkeypatch.delenv("DATACON_JOURNAL_SECRET_FILE", raising=False)
    _finish_returns_false(monkeypatch)

    class ExplodingSandbox:
        def __getattr__(self, name):
            def fail(*args, **kwargs):
                raise AssertionError(f"archive recovery started a container: {name}")

            return fail

    outcome = execution.run_execution(
        isolated_database.dsn,
        job_uuid,
        generation,
        run_root=run_root,
        sandbox=ExplodingSandbox(),
    )

    assert outcome.state == "STALE"
    current = status(isolated_database.dsn, job["job_id"])
    assert current["state"] == "ARCHIVING"


def test_archive_only_archive_error_returns_stale_when_finish_is_not_committed(
    isolated_database, tmp_path, monkeypatch
):
    job, _, generation = prepare_approved_job(isolated_database, tmp_path)
    first = run_with_fake(
        isolated_database, job, generation, tmp_path, FakeSandbox(), monkeypatch
    )
    assert first.state == "REPRODUCED", first
    job_uuid = UUID(job["job_id"])
    isolated_database.connection.execute(
        "UPDATE jobs SET state = 'ARCHIVING', stage = 'archive', generation = %s, "
        "lease_owner = 'archive-only', lease_expires_at = now() + interval '10 minutes', "
        "execute_deadline_at = now() - interval '1 minute' WHERE job_id = %s",
        (generation, job_uuid),
    )
    archive_calls = _archive_error(monkeypatch)
    _finish_returns_false(monkeypatch)

    outcome = execution.run_execution(
        isolated_database.dsn,
        job_uuid,
        generation,
        run_root=tmp_path / "runs",
        sandbox=FakeSandbox(),
    )

    assert outcome.state == "STALE"
    assert archive_calls
    current = status(isolated_database.dsn, job["job_id"])
    assert current["state"] == "ARCHIVING"


def test_blocked_archive_error_returns_stale_when_finish_is_not_committed(
    isolated_database, tmp_path, monkeypatch
):
    job, _, generation = prepare_approved_job(isolated_database, tmp_path)
    archive_calls = _archive_error(monkeypatch)
    _finish_returns_false(monkeypatch)

    outcome = run_with_fake(
        isolated_database,
        job,
        generation,
        tmp_path,
        ProbePolicySandbox(),
        monkeypatch,
    )

    assert outcome.state == "STALE"
    assert archive_calls
    current = status(isolated_database.dsn, job["job_id"])
    assert current["state"] == "RUNNING"


def test_failed_archive_error_returns_stale_when_finish_is_not_committed(
    isolated_database, tmp_path, monkeypatch
):
    job, _, generation = prepare_approved_job(isolated_database, tmp_path)
    archive_calls = _archive_error(monkeypatch)
    _finish_returns_false(monkeypatch)

    outcome = run_with_fake(
        isolated_database,
        job,
        generation,
        tmp_path,
        BuildFailureSandbox(),
        monkeypatch,
    )

    assert outcome.state == "STALE"
    assert archive_calls
    current = status(isolated_database.dsn, job["job_id"])
    assert current["state"] == "RUNNING"


def test_normal_archive_error_returns_stale_when_finish_is_not_committed(
    isolated_database, tmp_path, monkeypatch
):
    job, _, generation = prepare_approved_job(isolated_database, tmp_path)
    archive_calls = _archive_error(monkeypatch)
    _finish_returns_false(monkeypatch)

    outcome = run_with_fake(
        isolated_database, job, generation, tmp_path, FakeSandbox(), monkeypatch
    )

    assert outcome.state == "STALE"
    assert archive_calls
    current = status(isolated_database.dsn, job["job_id"])
    assert current["state"] == "RUNNING"


def test_blocked_reload_uses_the_callers_run_root(
    isolated_database, tmp_path, monkeypatch
):
    job, _, generation = prepare_approved_job(isolated_database, tmp_path)
    run_root = tmp_path / "custom-runs"
    evidence_root = run_root / "evidence"
    monkeypatch.setenv("DATACON_EVIDENCE_ROOT", str(evidence_root))
    monkeypatch.delenv("DATACON_JOURNAL_SECRET_FILE", raising=False)
    real_load = execution._load_context
    calls = []

    def fail_once(dsn, job_id, generation_value, *, case_root, run_root):
        calls.append({"case_root": case_root, "run_root": run_root})
        if len(calls) == 1:
            raise execution.ExecutionBlocked("POLICY_DENIED", "transient block")
        return real_load(
            dsn,
            job_id,
            generation_value,
            case_root=case_root,
            run_root=run_root,
        )

    monkeypatch.setattr(execution, "_load_context", fail_once)

    outcome = execution.run_execution(
        isolated_database.dsn,
        UUID(job["job_id"]),
        generation,
        run_root=run_root,
        sandbox=FakeSandbox(),
    )

    assert outcome.state == "FAILED"
    assert outcome.reason_code == "EVIDENCE_WRITE_FAILED"
    assert len(calls) >= 2
    assert calls[1]["run_root"] == run_root
    current = status(isolated_database.dsn, job["job_id"])
    assert current["state"] == "FAILED"
    assert current["evidence"]["available"] is False
    assert "EVIDENCE_WRITE_FAILED" in current["evidence"]["error"]
    assert not evidence_root.exists()
    assert not _archived_manifests(run_root / "evidence")


def test_failed_archive_clears_the_current_verdict(
    isolated_database, tmp_path, monkeypatch
):
    job, _, generation = prepare_approved_job(isolated_database, tmp_path)
    first = run_with_fake(
        isolated_database, job, generation, tmp_path, FakeSandbox(), monkeypatch
    )
    assert first.state == "REPRODUCED", first
    current = status(isolated_database.dsn, job["job_id"])
    assert current["verdict"] == "REPRODUCED"
    assert current["verdict_current"] is True

    job_uuid = UUID(job["job_id"])
    isolated_database.connection.execute(
        "UPDATE jobs SET state = 'RUNNING', stage = 'execute', generation = %s, "
        "lease_owner = 'retrying-worker', "
        "lease_expires_at = now() + interval '10 minutes', "
        "execute_deadline_at = now() + interval '10 minutes', "
        "workflow_synced = false WHERE job_id = %s",
        (generation + 1, job_uuid),
    )
    evidence_file = tmp_path / "not-a-directory"
    evidence_file.write_text("occupied", encoding="utf-8")
    monkeypatch.setenv("DATACON_EVIDENCE_ROOT", str(evidence_file))
    second = execution.run_execution(
        isolated_database.dsn,
        job_uuid,
        generation + 1,
        run_root=tmp_path / "runs",
        sandbox=FakeSandbox(),
    )
    assert second.state == "FAILED", second
    assert second.reason_code == "EVIDENCE_WRITE_FAILED"

    current = status(isolated_database.dsn, job["job_id"])
    assert current["state"] == "FAILED"
    assert current["evidence"]["available"] is False
    assert current["verdict"] is None
    assert current["verdict_reason"] is None
    assert current["verdict_current"] is False
    # A non-archived terminal must not keep the previous generation's
    # authoritative verdict in the row; status() and export() both rely on the
    # archived+path+digest invariant.
    row = isolated_database.connection.execute(
        "SELECT verdict, verdict_reason, evidence_status, evidence_path, "
        "evidence_digest FROM jobs WHERE job_id = %s",
        (job_uuid,),
    ).fetchone()
    assert row == (None, None, "failed", None, None)


# ---------------------------------------------------------------------------
# B1/SF8: evidence is generation-scoped and rolled back when the terminal row
# was not committed.
# ---------------------------------------------------------------------------


def test_archive_publish_then_finish_false_rolls_back_generation_bundle(
    isolated_database, tmp_path, monkeypatch
):
    job, _, generation = prepare_approved_job(isolated_database, tmp_path)
    evidence_root = tmp_path / "evidence"
    _finish_returns_false(monkeypatch)

    outcome = run_with_fake(
        isolated_database, job, generation, tmp_path, FakeSandbox(), monkeypatch
    )

    assert outcome.state == "STALE", outcome
    current = status(isolated_database.dsn, job["job_id"])
    assert current["state"] == "ARCHIVING"
    assert current["verdict"] is None
    assert current["evidence"] is None or current["evidence"]["available"] is False

    row = isolated_database.connection.execute(
        "SELECT state, evidence_path, evidence_status, verdict FROM jobs "
        "WHERE job_id = %s",
        (UUID(job["job_id"]),),
    ).fetchone()
    assert row[0] == "ARCHIVING"
    assert row[1] is None
    assert row[2] is None
    assert row[3] is None

    # The published generation directory was this worker's own; it must be
    # removed, and no other generation directory may exist.
    job_root = evidence_root / job["job_id"]
    assert not (job_root / f"generation-{generation}").exists()
    assert not _archived_manifests(evidence_root)


# ---------------------------------------------------------------------------
# S2: reclaim failures are visible in the archived report, not swallowed.
# ---------------------------------------------------------------------------


def test_reclaim_failure_is_visible_in_the_report(
    isolated_database, tmp_path, monkeypatch
):
    class ReclaimFailingSandbox(FakeSandbox):
        def reclaim_job(self):
            raise SandboxError("reclaim could not remove an old container")

    job, _, generation = prepare_approved_job(isolated_database, tmp_path)
    outcome = run_with_fake(
        isolated_database,
        job,
        generation,
        tmp_path,
        ReclaimFailingSandbox(),
        monkeypatch,
    )
    assert outcome.state == "REPRODUCED", outcome
    current = status(isolated_database.dsn, job["job_id"])
    report = json.loads(
        verify_bundle(current["evidence"]["path"]).file_data["report.json"]
    )
    assert report["cleanup_errors"] == [
        "reclaim: reclaim could not remove an old container"
    ]



@pytest.mark.parametrize("reason_code", ["TIMEOUT", "RUN_INCOMPLETE"])
def test_s1_finish_failed_timeout_and_run_incomplete_archive_partial_inconclusive(
    isolated_database, tmp_path, monkeypatch, reason_code
):
    class FailingBuildSandbox(FakeSandbox):
        def build(self, version, **kwargs):
            if reason_code == "TIMEOUT":
                raise SandboxError(
                    "docker build wait timed out", reason_code="TIMEOUT"
                )
            raise execution.ExecutionFailed(
                "RUN_INCOMPLETE",
                f"step build:{version} consumed both attempts without a usable result",
            )

    job, _, generation = prepare_approved_job(isolated_database, tmp_path)
    outcome = run_with_fake(
        isolated_database,
        job,
        generation,
        tmp_path,
        FailingBuildSandbox(),
        monkeypatch,
    )
    assert outcome.state == "INCONCLUSIVE", outcome
    assert outcome.verdict == "INCONCLUSIVE"
    assert outcome.verdict_reason == reason_code
    assert outcome.reason_code == reason_code
    assert outcome.evidence_path is not None

    current = status(isolated_database.dsn, job["job_id"])
    assert current["state"] == "INCONCLUSIVE"
    assert current["verdict"] == "INCONCLUSIVE"
    assert current["verdict_reason"] == reason_code
    assert current["reason_code"] == reason_code
    assert current["evidence"]["available"] is True
    verified = verify_bundle(current["evidence"]["path"])
    assert verified.manifest["verdict"] == "INCONCLUSIVE"
    assert verified.manifest["reason_code"] == reason_code
    report = json.loads(verified.file_data["report.json"])
    assert report["rule"] is None
    assert report["missing"]
    assert report["evidence_complete"] is False
