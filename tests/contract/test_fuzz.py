"""T12 B (改9): frozen fuzz material, campaign search and crash-seed provenance.

Coordinates are registered in docs/spec/v0.2/test-plan-delta.md (T12, 改9 增补).
Contract group (``not postgres and not asan``): an in-memory state double, a
fake sandbox and a fake step clock; no Docker daemon, no PostgreSQL, no sleep.
"""

from __future__ import annotations

from copy import deepcopy
from dataclasses import replace
import json
from pathlib import Path
import shutil
from typing import Any

import pytest

from datacon import contracts, evidence, execution, fuzz, jsonutil
from datacon.tools.sandbox import FuzzResult
from datacon.verdict import RunObservation, VerdictPolicy, decide_verdict

from test_build_spec_execution import (
    FIXTURE_CASES,
    _cmake_compile_commands_bytes,
    _cmake_spec,
    _configure_isolated_roots,
    _FakeSandbox,
    _InMemoryState,
    _setup_fixture_plan_and_job,
)

CAMPAIGN_OUTPUTS = ["parser", "fuzzer"]
FACE_FLAGS = ["-fsanitize=address", "-g", "-O1", "-I../include", "-D_GNU_SOURCE"]


class _FakeCampaignSandbox(_FakeSandbox):
    """The build/probe fake plus a recorded, deterministic libFuzzer search."""

    def __init__(
        self,
        *,
        crashes: tuple[bytes, ...] = (),
        clock=None,
        fixed_candidate_stdout: bytes | None = None,
        **kwargs,
    ):
        super().__init__(**kwargs)
        self.crashes = tuple(crashes)
        self.clock = clock
        self.fixed_candidate_stdout = fixed_candidate_stdout
        self.fuzz_calls: list[dict[str, Any]] = []

    def replay(self, version: str, phase: str, **kwargs: Any):
        result = super().replay(version, phase, **kwargs)
        if (
            self.fixed_candidate_stdout is not None
            and version == "fixed"
            and phase != "normal"
        ):
            # A real crash seed prints its own token on the fixed build.
            return replace(result, stdout=self.fixed_candidate_stdout)
        return result

    def fuzz(self, **kwargs: Any) -> FuzzResult:
        corpus_dir = Path(kwargs["corpus_dir"])
        corpus = {
            path.name: path.read_bytes() for path in sorted(corpus_dir.iterdir())
        }
        fuzzer = Path(kwargs["fuzzer_path"]).read_bytes()
        self.fuzz_calls.append({**kwargs, "corpus": corpus, "fuzzer": fuzzer})
        if self.clock is not None:
            self.clock.advance(float(kwargs["max_total_time"]))
        log = (
            f"INFO: Seed: {kwargs['rng_seed']}\n"
            f"#1 INITED corp: {len(corpus)}\n"
        ).encode("utf-8")
        for data in self.crashes:
            log += b"==1==ERROR: AddressSanitizer: heap-buffer-overflow\n"
            log += b"Test unit written to /work/crashes/crash-" + data.hex().encode() + b"\n"
        return FuzzResult(
            status="completed",
            exit_code=1 if self.crashes else 0,
            duration_seconds=float(kwargs["max_total_time"]),
            container_id="fake-fuzz",
            rng_seed=kwargs["rng_seed"],
            max_total_time_seconds=kwargs["max_total_time"],
            log=log,
            log_truncated=False,
            crashes=self.crashes,
            crash_truncated=False,
            metadata={"image_digest": self.image_digest},
        )


class _Clock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


def _copy_case_root(tmp_path: Path) -> Path:
    root = tmp_path / "cases"
    shutil.copytree(FIXTURE_CASES, root)
    return root


def guided_campaign_plan(
    *,
    envelope_harness_digest: str | None = None,
    max_fuzz_seconds: int = 120,
):
    """A guided campaign plan, its approved envelope and family review.

    Shared with the postgres worker coordinates: the fixture case's real
    materials, the reviewed shim pair and the registered seed corpus.
    """
    job, plan, _plan_digest, review = _setup_fixture_plan_and_job(
        version=2,
        build_spec=_cmake_spec(outputs=list(CAMPAIGN_OUTPUTS)),
        round_no=None,
        job_kind="campaign",
    )
    manifest = json.loads((FIXTURE_CASES / "manifest.json").read_text())
    materials = manifest["materials"]
    harness_file_digest = materials[manifest["harness"]]
    pair = fuzz.guided_harness_digest(
        harness_file_digest, fuzz.FUZZ_SHIM_REVIEWED_DIGEST
    )
    corpus = [
        fuzz.SeedCorpusEntry(
            name=Path(relative).name, path=relative, digest=materials[relative]
        )
        for relative in (
            manifest["cases"]["B01"]["inputs"]["normal"],
            manifest["cases"]["B01"]["inputs"]["candidate"],
        )
    ]
    envelope = contracts.guided_envelope(
        allowed_mutation_families=["byte_flip", "length_boundary"],
        mutation_limits={
            "allowed_ops": ["append", "truncate", "byte_flip"],
            "max_input_bytes": 4096,
        },
        seed_corpus_digest=fuzz.seed_corpus_digest(corpus),
        toolchain_image_digest=plan["image_digest"],
        harness_digest=envelope_harness_digest or pair,
        max_rounds=8,
        max_total_seconds=900,
        max_fuzz_seconds=max_fuzz_seconds,
        accepted_signature_set=[dict(manifest["asan_signature"])],
    )
    plan["harness_digest"] = envelope["harness_digest"]
    plan["envelope_digest"] = contracts.envelope_digest(envelope)
    plan_digest = contracts.plan_digest(plan)
    review["plan_digest"] = plan_digest
    job["envelope"] = deepcopy(envelope)
    job["request"]["exploration"] = {"mode": "guided"}
    return job, plan, plan_digest, review, envelope


def _campaign_setup(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    case_root: Path | None = None,
    envelope_harness_digest: str | None = None,
    max_fuzz_seconds: int = 120,
):
    """A RUNNING guided campaign child with an approved guided envelope."""
    run_root, _ = _configure_isolated_roots(tmp_path, monkeypatch)
    job, plan, plan_digest, review, envelope = guided_campaign_plan(
        envelope_harness_digest=envelope_harness_digest,
        max_fuzz_seconds=max_fuzz_seconds,
    )
    mem_state = _InMemoryState(job, plan, plan_digest, review)
    mem_state.install(monkeypatch)
    clock = _Clock()
    monkeypatch.setattr(execution, "STEP_CLOCK", clock)
    return {
        "run_root": run_root,
        "case_root": case_root or FIXTURE_CASES,
        "job": job,
        "plan": plan,
        "plan_digest": plan_digest,
        "state": mem_state,
        "clock": clock,
        "envelope": envelope,
    }


def _sandbox(setup, *, crashes: tuple[bytes, ...] = ()) -> _FakeCampaignSandbox:
    return _FakeCampaignSandbox(
        crashes=crashes,
        clock=setup["clock"],
        image_digest=setup["plan"]["image_digest"],
        build_recipe_digest=setup["plan"]["build_recipe_digest"],
        faces={
            version: _cmake_compile_commands_bytes(flags=list(FACE_FLAGS))
            for version in ("vulnerable", "fixed")
        },
        face_name="compile_commands.json",
    )


def _run(setup, sandbox):
    return execution.run_execution(
        "dsn",
        setup["job"]["job_id"],
        1,
        case_root=str(setup["case_root"]),
        run_root=setup["run_root"],
        sandbox=sandbox,
    )


def _reached_sandbox(sandbox: _FakeCampaignSandbox) -> bool:
    return bool(sandbox.probe_calls or sandbox.build_calls or sandbox.fuzz_calls)


@pytest.mark.parametrize("tamper", ["harness", "shim", "unbound_pair"])
def test_frozen_harness_rejects_model_generated_material(
    tmp_path, monkeypatch, tamper
):
    """A rewritten harness, an unreviewed shim or an unbound pair never runs."""
    case_root = None
    envelope_harness_digest = None
    if tamper == "harness":
        # A model "improved" the frozen harness on disk: same name, new bytes.
        case_root = _copy_case_root(tmp_path)
        harness = case_root / "harness.c"
        harness.chmod(0o644)
        harness.write_text(
            harness.read_text() + "\n/* model-generated fuzz entry */\n"
        )
    elif tamper == "shim":
        forged = tmp_path / "forged_shim.c"
        forged.write_bytes(fuzz.FUZZ_SHIM_PATH.read_bytes() + b"/* rewritten */\n")
        monkeypatch.setattr(fuzz, "FUZZ_SHIM_PATH", forged)
    else:
        # The envelope approved only the harness file, not the {harness,
        # fuzz_shim} pair the campaign would actually link.
        manifest = json.loads((FIXTURE_CASES / "manifest.json").read_text())
        envelope_harness_digest = manifest["materials"][manifest["harness"]]
    setup = _campaign_setup(
        tmp_path,
        monkeypatch,
        case_root=case_root,
        envelope_harness_digest=envelope_harness_digest,
    )
    sandbox = _sandbox(setup, crashes=(b"ABCD",))

    result = _run(setup, sandbox)

    assert not _reached_sandbox(sandbox), "model-generated harness reached sandbox"
    assert result.state == "BLOCKED", result
    assert result.reason_code == "HARNESS_REJECTED"
    finished = setup["state"].finished_calls[-1]
    assert finished["state"] == "BLOCKED"
    assert finished["reason_code"] == "HARNESS_REJECTED"
    assert finished["verdict"] is None
    assert setup["state"].budget_charges == []


def test_crash_seed_requires_provenance_and_six_replays(tmp_path, monkeypatch):
    """A crash seed is frozen with provenance and is never itself a conclusion."""
    setup = _campaign_setup(tmp_path, monkeypatch)
    sandbox = _sandbox(setup, crashes=(b"WXYZ\n", b"WXYZ\n", b"\\\\,,"))

    result = _run(setup, sandbox)

    # The campaign ends COMPLETED with no verdict even though it crashed.
    assert result.state == "COMPLETED", result
    assert result.verdict is None, "verdict emitted before six replays"
    assert result.reason_code is None
    finished = setup["state"].finished_calls[-1]
    assert finished["state"] == "COMPLETED"
    assert finished["verdict"] is None and finished["verdict_reason"] is None
    assert sandbox.replay_calls == [], "a campaign must not run the six replays"
    assert len(sandbox.fuzz_calls) == 1

    verified = evidence.verify_bundle(result.evidence_path)
    manifest = verified.manifest
    assert manifest["bundle_kind"] == "campaign"
    assert manifest["verdict"] is None and manifest["reason_code"] is None
    report = json.loads(verified.file_data["report.json"])
    assert report["verdict"] is None and report["state"] is None
    provenance = json.loads(verified.file_data[fuzz.FUZZ_PROVENANCE_PATH])
    fuzz_log = verified.file_data[fuzz.FUZZ_LOG_PATH]
    seeds = provenance["crash_seeds"]
    # Duplicate crash bytes are frozen once; discovery order is kept.
    assert [seed["sha256"] for seed in seeds] == [
        jsonutil.digest_bytes(b"WXYZ\n"),
        jsonutil.digest_bytes(b"\\\\,,"),
    ]
    roles = {entry["path"]: entry["role"] for entry in manifest["files"]}
    for seed in seeds:
        data = verified.file_data[seed["path"]]
        assert roles[seed["path"]] == "crash_seed"
        fuzz.validate_crash_seed_record(
            seed, data=data, campaign_job_id=str(setup["job"]["job_id"])
        )
        assert seed["fuzz_log_digest"] == jsonutil.digest_bytes(fuzz_log)
        assert seed["rng_seed"] == fuzz.campaign_rng_seed(
            str(setup["job"]["job_id"]), setup["plan_digest"]
        )
    assert provenance["rng_seed"] == sandbox.fuzz_calls[0]["rng_seed"]

    # Provenance is mandatory: each field missing is refused.
    for field in fuzz.CRASH_SEED_PROVENANCE_FIELDS:
        partial = {key: value for key, value in seeds[0].items() if key != field}
        with pytest.raises(ValueError, match=field):
            fuzz.validate_crash_seed_record(partial)
    # Bytes that do not match the recorded digest are refused.
    with pytest.raises(ValueError, match="do not match"):
        fuzz.validate_crash_seed_record(seeds[0], data=b"other")
    # A campaign bundle that claims crash seeds without crash_seed files fails.
    root = Path(result.evidence_path)
    copy = tmp_path / "tampered"
    shutil.copytree(root, copy)
    for path in copy.rglob("*"):
        path.chmod(0o755 if path.is_dir() else 0o644)
    tampered_manifest = json.loads((copy / "manifest.json").read_text())
    tampered_manifest["files"] = [
        entry for entry in tampered_manifest["files"] if entry["role"] != "crash_seed"
    ]
    for seed in seeds:
        (copy / seed["path"]).unlink()
    (copy / "manifest.json").write_bytes(
        evidence.canonical_manifest_bytes(tampered_manifest) + b"\n"
    )
    with pytest.raises(evidence.BundleError, match="crash_seed"):
        evidence.verify_bundle(copy)

    # Without the six replays no conclusion can be drawn from a crash seed:
    # the vulnerable candidate crashes alone are EVIDENCE_INCOMPLETE.
    policy = VerdictPolicy(
        signature=dict(setup["plan"]["asan_signature"]),
        expected_exit=dict(setup["plan"]["expected_exit"]),
        expected_stdout={},
    )
    partial_runs = [
        RunObservation(
            version="vulnerable",
            phase=phase,
            status="completed",
            exit_code=86,
            stdout="",
            stderr="ERROR: AddressSanitizer: heap-buffer-overflow",
            signature=None,
            input_digest=seeds[0]["sha256"],
        )
        for phase in ("candidate_1", "candidate_2")
    ]
    decision = decide_verdict(policy, partial_runs)
    assert decision.verdict == "INCONCLUSIVE"
    assert decision.reason_code == "EVIDENCE_INCOMPLETE"


def test_zero_crash_campaign_completes_without_crash_seed(tmp_path, monkeypatch):
    """Zero crashes: COMPLETED, fuzz_log + fuzz_provenance, no crash_seed."""
    setup = _campaign_setup(tmp_path, monkeypatch, max_fuzz_seconds=45)
    sandbox = _sandbox(setup)

    result = _run(setup, sandbox)

    assert result.state == "COMPLETED", result
    verified = evidence.verify_bundle(result.evidence_path)
    roles = [entry["role"] for entry in verified.manifest["files"]]
    assert "crash_seed" not in roles
    assert roles.count("fuzz_log") == 1 and roles.count("fuzz_provenance") == 1
    assert not any(path.startswith("replay/") for path in verified.file_data)
    # Each version was built once and archived both products.
    assert sorted(call["version"] for call in sandbox.build_calls) == [
        "fixed",
        "vulnerable",
    ]
    for version in ("vulnerable", "fixed"):
        for output in CAMPAIGN_OUTPUTS:
            path = f"build/{version}/{output}"
            assert path in verified.file_data
            assert {e["path"]: e["role"] for e in verified.manifest["files"]}[
                path
            ] == "build_artifact"
    call = sandbox.fuzz_calls[0]
    # The fixed shim was staged next to the frozen materials for the build.
    for build_call in sandbox.build_calls:
        assert fuzz.FUZZ_SHIM_STAGED_NAME in build_call["staged_files"]
    # The vulnerable fuzzer searched the registered normal+candidate corpus.
    assert call["fuzzer"] == b"ELF-vulnerable-fuzzer"
    assert sorted(call["corpus"]) == ["candidate.txt", "normal.txt"]
    assert call["max_len"] == 4096
    # The fuzz step was charged against both budgets, within the fuzz ceiling.
    fuzz_charges = [
        charge
        for charge in setup["state"].budget_charges
        if charge["charge_kind"] == "fuzz"
    ]
    assert len(fuzz_charges) == 1
    assert fuzz_charges[0]["seconds"] == fuzz_charges[0]["fuzz_seconds"]
    assert 1 <= fuzz_charges[0]["fuzz_seconds"] <= 45
    provenance = json.loads(verified.file_data[fuzz.FUZZ_PROVENANCE_PATH])
    assert provenance["crash_count"] == 0 and provenance["crash_seeds"] == []
    assert provenance["harness_digest"]["fuzz_shim"] == fuzz.FUZZ_SHIM_REVIEWED_DIGEST


@pytest.mark.parametrize(
    ("ceiling", "value", "sub_reason"),
    [
        ("CORPUS_MAX_FILE_COUNT", 1, fuzz.CORPUS_FILE_COUNT_EXCEEDED),
        ("CORPUS_MAX_FILE_BYTES", 3, fuzz.CORPUS_FILE_BYTES_EXCEEDED),
        ("CORPUS_MAX_TOTAL_BYTES", 5, fuzz.CORPUS_TOTAL_BYTES_EXCEEDED),
    ],
)
def test_campaign_corpus_ceiling_is_policy_denied_with_sub_reason(
    tmp_path, monkeypatch, ceiling, value, sub_reason
):
    """Corpus over a §5 ceiling: POLICY_DENIED + CORPUS_* sub_reason, no container."""
    # Pure rule first (real ceilings), then the runtime path (shrunk ceilings).
    with pytest.raises(fuzz.CorpusPolicyDenied) as raised:
        if sub_reason == fuzz.CORPUS_FILE_COUNT_EXCEEDED:
            fuzz.check_corpus_limits([1] * (fuzz.CORPUS_MAX_FILE_COUNT + 1))
        elif sub_reason == fuzz.CORPUS_FILE_BYTES_EXCEEDED:
            fuzz.check_corpus_limits([fuzz.CORPUS_MAX_FILE_BYTES + 1])
        else:
            fuzz.check_corpus_limits([fuzz.CORPUS_MAX_FILE_BYTES] * 9)
    assert raised.value.sub_reason == sub_reason
    fuzz.check_corpus_limits(
        [fuzz.CORPUS_MAX_FILE_BYTES] * 8
    )  # exactly at every ceiling is allowed

    monkeypatch.setattr(fuzz, ceiling, value)
    setup = _campaign_setup(tmp_path, monkeypatch)
    sandbox = _sandbox(setup)

    result = _run(setup, sandbox)

    assert not _reached_sandbox(sandbox)
    assert result.state == "BLOCKED" and result.reason_code == "POLICY_DENIED"
    finished = setup["state"].finished_calls[-1]
    assert finished["reason_code"] == "POLICY_DENIED"
    assert finished["audit_detail"]["sub_reason"] == sub_reason


def test_seed_corpus_digest_is_name_and_bytes_only():
    entries = [
        fuzz.SeedCorpusEntry(name="b.txt", path="inputs/b.txt", digest="sha256:" + "1" * 64),
        fuzz.SeedCorpusEntry(name="a.txt", path="x/a.txt", digest="sha256:" + "2" * 64),
    ]
    moved = [
        fuzz.SeedCorpusEntry(name="a.txt", path="elsewhere/a.txt", digest="sha256:" + "2" * 64),
        fuzz.SeedCorpusEntry(name="b.txt", path="b.txt", digest="sha256:" + "1" * 64),
    ]
    assert fuzz.seed_corpus_digest(entries) == fuzz.seed_corpus_digest(moved)
    renamed = [entries[0], fuzz.SeedCorpusEntry("c.txt", "x/a.txt", entries[1].digest)]
    assert fuzz.seed_corpus_digest(renamed) != fuzz.seed_corpus_digest(entries)
    # The fixture registry registers normal + candidate explicitly.
    registry = json.loads((FIXTURE_CASES / "registry.json").read_text())
    registered = registry["exploration_ceilings"]["fixture-c-parser"]["seed_corpus"]
    assert [item["name"] for item in registered] == ["normal.txt", "candidate.txt"]
    # The shim on disk is the reviewed one.
    assert fuzz.load_fuzz_shim() == fuzz.FUZZ_SHIM_PATH.read_bytes()


def test_default_campaign_runner_searches_through_the_injected_fuzzer():
    """The graph's campaign node runs a real search when given a fuzz executor."""
    from types import SimpleNamespace

    from datacon.orchestration import DefaultCampaignRunner

    calls: list[dict[str, Any]] = []

    def _executor(**kwargs: Any) -> Any:
        calls.append(kwargs)
        return SimpleNamespace(
            status="completed", crashes=(b"WXYZ\n", b"WXYZ\n"), duration_seconds=7.0
        )

    clock = _Clock()
    clock.timestamp = lambda: "2099-01-01T00:00:00Z"  # type: ignore[attr-defined]
    runner = DefaultCampaignRunner(
        clock=clock, fuzz_duration_seconds=20, fuzz_executor=_executor
    )
    artifacts = {
        "vulnerable": {
            "artifact_digest": "sha256:" + "1" * 64,
            "fuzzer_path": "/staged/fuzzer",
            "fuzzer_digest": "sha256:" + "2" * 64,
            "corpus_dir": "/staged/corpus",
        },
        "fixed": {"artifact_digest": "sha256:" + "3" * 64},
    }
    first = runner.run_campaign(job_id="job", family_id="family", build_artifacts=artifacts)
    second = runner.run_campaign(job_id="job", family_id="family", build_artifacts=artifacts)

    assert first.candidate_seeds == (b"WXYZ\n",)
    assert first.fuzz_seconds_used == 7.0
    assert clock.now == 1014.0  # the injected clock moved by both searches
    assert calls[0]["rng_seed"] == calls[1]["rng_seed"] == fuzz.campaign_rng_seed(
        "job", "family"
    )
    assert calls[0]["max_total_time"] == 20
    assert first.campaign_bundle_digest == second.campaign_bundle_digest
    assert first.metadata["engine"] == "libfuzzer"
    with pytest.raises(ValueError, match="fuzzer"):
        runner.run_campaign(
            job_id="job", family_id="family", build_artifacts={"vulnerable": {}}
        )
