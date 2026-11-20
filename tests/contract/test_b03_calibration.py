"""Contract tests for the authorized B03 calibration and admission freeze."""

from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
import sys

import pytest

from datacon import release
from datacon.asan import parse_asan
from datacon.tools.sandbox import BuildResult, ReplayResult

REPO_ROOT = Path(__file__).resolve().parents[2]
CASES = REPO_ROOT / "tests" / "fixtures" / "cases"
ADMISSION_PATH = CASES / "B03-admission.json"


def _load_script(name: str):
    path = REPO_ROOT / "scripts" / f"{name}.py"
    spec = importlib.util.spec_from_file_location(f"_datacon_{name}", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


calibrate_b03 = _load_script("calibrate_b03")
freeze_b03 = _load_script("freeze_b03_admission")


def _sha(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _case_root(tmp_path: Path) -> Path:
    root = tmp_path / "b03-case"
    root.mkdir(parents=True, exist_ok=True)
    for name in ("harness.c", "build.sh", "dependencies.lock", "fix.patch"):
        shutil.copy2(CASES / name, root / name)
    admission = json.loads(ADMISSION_PATH.read_text(encoding="utf-8"))
    advisory = json.loads((CASES / "advisory.json").read_text(encoding="utf-8"))
    advisory["cve_id"] = admission["cve_id"]
    advisory["vulnerable_commit"] = admission["versions"]["vulnerable"]["commit"]
    advisory["fixed_commit"] = admission["versions"]["fixed"]["commit"]
    for source in advisory.get("sources", []):
        source["vulnerable_commit"] = advisory["vulnerable_commit"]
        source["fixed_commit"] = advisory["fixed_commit"]
    (root / "advisory.json").write_text(
        json.dumps(advisory, indent=2) + "\n", encoding="utf-8"
    )
    shutil.copy2(CASES / "fixture-repo.bundle", root / "b03-repo.bundle")
    for version in ("vulnerable", "fixed"):
        (root / version).mkdir(exist_ok=True)
        shutil.copy2(CASES / version / "parser.c", root / version / "parser.c")
    (root / "inputs").mkdir(exist_ok=True)
    shutil.copy2(CASES / "inputs" / "normal.txt", root / "inputs" / "normal.txt")
    shutil.copy2(CASES / "inputs" / "candidate.txt", root / "inputs" / "candidate.txt")
    return root


def _admission() -> dict:
    admission = json.loads(ADMISSION_PATH.read_text(encoding="utf-8"))
    admission["repository"]["source_path"] = "parser.c"
    # The checked-in fixture is a frozen real lab record. These unit tests
    # exercise the pending -> frozen transition with a synthetic calibration,
    # so reset only the state the freeze script is expected to replace.
    admission["asan_signature"]["status"] = "expected_pending_t05_replay"
    admission["expected_verdict_status"] = "pending_t05_replay"
    admission["harness"].pop("candidate_clean_exit_code", None)
    admission["harness"].pop("expected_stdout", None)
    for entry in admission["checks"]:
        if entry.get("id") == "asan_replay":
            entry.clear()
            entry.update(
                {
                    "id": "asan_replay",
                    "status": "deferred",
                    "owner_task": "T05",
                    "evidence": "pending lab calibration",
                    "verification": "execution_deferred",
                }
            )
    return admission


_ASAN_STDERR = (
    b"==1==ERROR: AddressSanitizer: heap-use-after-free on address 0x602000000010\n"
    b"WRITE of size 8 at 0x602000000010 thread T0\n"
    b"    #0 0x401234 in onig_new_deluxe /work/src/regext.c:120:5\n"
    b"    #1 0x401999 in main /work/harness.c:42:3\n"
)


class FakeCalibrationSandbox:
    def __init__(
        self,
        *,
        vulnerable_asan: bool = True,
        clean_asan: bool = False,
        build_status: str = "completed",
    ):
        self.vulnerable_asan = vulnerable_asan
        self.clean_asan = clean_asan
        self.build_status = build_status
        self.builds: list[str] = []
        self.replays: list[tuple[str, str]] = []

    def build(self, version: str, **kwargs) -> BuildResult:
        self.builds.append(version)
        artifact = f"harness-{version}".encode("utf-8")
        return BuildResult(
            version=version,
            status=self.build_status,
            exit_code=0,
            duration_seconds=0.1,
            container_id=f"build-{version}",
            image_digest=release.TOOLCHAIN_IMAGE_DIGEST,
            compile_args=(),
            artifact_digest=(
                _sha(artifact) if self.build_status == "completed" else None
            ),
            log=b"build ok\n",
            log_truncated=False,
            artifact=artifact if self.build_status == "completed" else b"",
            metadata={},
        )

    def replay(self, version: str, phase: str, **kwargs) -> ReplayResult:
        self.replays.append((version, phase))
        input_digest = _sha(Path(kwargs["input_path"]).read_bytes())
        if phase == "normal":
            stdout, stderr = b"OK\n", b""
            exit_code, signature = 0, None
        elif version == "vulnerable" and self.vulnerable_asan:
            stdout, stderr = b"", _ASAN_STDERR
            exit_code, signature = 86, parse_asan(_ASAN_STDERR.decode("utf-8"))
        elif self.clean_asan:
            stdout, stderr = b"", _ASAN_STDERR
            exit_code, signature = 86, parse_asan(_ASAN_STDERR.decode("utf-8"))
        else:
            stdout, stderr = b"MISMATCH_REJECTED\n", b""
            exit_code, signature = 0, None
        return ReplayResult(
            version=version,
            phase=phase,
            status="completed",
            exit_code=exit_code,
            duration_seconds=0.1,
            container_id=f"replay-{version}-{phase}",
            input_digest=input_digest,
            stdout=stdout,
            stderr=stderr,
            signature=signature,
            timed_out=False,
            quota_hit=False,
            log_truncated=False,
            metadata={},
        )


def _calibration(tmp_path: Path, sandbox=None) -> dict:
    return calibrate_b03.calibrate(
        case_root=_case_root(tmp_path),
        admission=_admission(),
        sandbox=sandbox or FakeCalibrationSandbox(),
        work_root=tmp_path / "work",
    )


def test_calibration_schema_and_real_replay_values(tmp_path):
    sandbox = FakeCalibrationSandbox()
    document = _calibration(tmp_path, sandbox)
    assert document["schema_version"] == 1
    assert document["benchmark_id"] == "B03"
    assert document["cve_id"] == "CVE-2019-13224"
    assert document["toolchain_image_digest"] == release.TOOLCHAIN_IMAGE_DIGEST
    assert document["versions"]["vulnerable"] == _admission()["versions"][
        "vulnerable"
    ]["commit"]
    assert document["versions"]["fixed"] == _admission()["versions"]["fixed"][
        "commit"
    ]
    signature = document["asan_signature"]
    assert signature == {
        "error": "heap-use-after-free",
        "operation": "WRITE",
        "access_size": 8,
        "function": "onig_new_deluxe",
        "source": "/work/src/regext.c",
    }
    assert document["expected_exit"] == {
        "normal": 0,
        "candidate_clean": 0,
        "candidate_asan": 86,
    }
    assert document["expected_stdout"] == {
        "normal": "OK\n",
        "candidate_clean": "MISMATCH_REJECTED\n",
    }
    assert sorted(sandbox.builds) == ["fixed", "vulnerable"]
    assert sorted(sandbox.replays) == sorted(
        [
            ("vulnerable", "normal"),
            ("vulnerable", "candidate"),
            ("fixed", "normal"),
            ("fixed", "candidate"),
        ]
    )
    assert len(document["runs"]) == 4
    by_pair = {(run["version"], run["phase"]): run for run in document["runs"]}
    assert by_pair[("vulnerable", "candidate")]["signature"] == signature
    assert by_pair[("vulnerable", "candidate")]["exit_code"] == 86
    assert by_pair[("vulnerable", "normal")]["stdout_sha256"] == _sha(b"OK\n")
    assert by_pair[("fixed", "candidate")]["stdout_sha256"] == _sha(
        b"MISMATCH_REJECTED\n"
    )
    for pair, run in by_pair.items():
        if pair != ("vulnerable", "candidate"):
            assert run["signature"] is None


def test_calibration_fails_closed_without_a_real_signature(tmp_path):
    with pytest.raises(calibrate_b03.CalibrationError, match="no ASan diagnostic"):
        _calibration(
            tmp_path, FakeCalibrationSandbox(vulnerable_asan=False)
        )


def test_calibration_fails_closed_on_build_failure(tmp_path):
    with pytest.raises(release.ReleaseGateError, match="build did not complete"):
        _calibration(
            tmp_path, FakeCalibrationSandbox(build_status="build_failed")
        )


def test_calibration_rejects_asan_in_a_clean_control(tmp_path):
    with pytest.raises(
        calibrate_b03.CalibrationError, match="unexpected ASan diagnostic"
    ):
        _calibration(tmp_path, FakeCalibrationSandbox(clean_asan=True))


def test_calibration_rejects_admission_exit_drift(tmp_path):
    admission = _admission()
    admission["harness"]["candidate_asan_exit_code"] = 1
    with pytest.raises(
        calibrate_b03.CalibrationError, match="candidate_asan_exit_code"
    ):
        calibrate_b03.calibrate(
            case_root=_case_root(tmp_path),
            admission=admission,
            sandbox=FakeCalibrationSandbox(),
            work_root=tmp_path / "work",
        )


def test_calibrate_cli_fails_closed_without_writing(tmp_path):
    out = tmp_path / "calibration.json"
    code = calibrate_b03.main(
        [
            "--case-root",
            str(tmp_path / "missing-case"),
            "--admission",
            str(tmp_path / "missing-admission.json"),
            "--out",
            str(out),
        ]
    )
    assert code == 1
    assert not out.exists()


def test_freeze_pending_to_frozen_and_validates(tmp_path):
    calibration = _calibration(tmp_path)
    frozen = freeze_b03.freeze(
        admission=_admission(), calibration=calibration
    )
    validated = release._validate_b03_admission(frozen)
    assert validated["asan_signature"] == {
        "error": "heap-use-after-free",
        "operation": "WRITE",
        "access_size": 8,
        "function": "onig_new_deluxe",
        "source": "/work/src/regext.c",
    }
    assert frozen["asan_signature"]["status"] == "frozen"
    assert frozen["expected_verdict_status"] == "frozen"
    assert frozen["harness"]["candidate_clean_exit_code"] == 0
    assert frozen["harness"]["normal_exit_code"] == 0
    assert frozen["harness"]["candidate_asan_exit_code"] == 86
    assert frozen["harness"]["expected_stdout"] == {
        "normal": "OK\n",
        "candidate_clean": "MISMATCH_REJECTED\n",
    }
    checks = {entry["id"]: entry for entry in frozen["checks"]}
    assert checks["asan_replay"]["status"] == "pass"
    assert checks["asan_replay"]["evidence"].strip()
    assert "heap-use-after-free" in checks["asan_replay"]["evidence"]

    root = _case_root(tmp_path)
    materials = release.B03CaseMaterials.load(root)
    prepared = release.prepare_b03_plan(
        admission=frozen,
        materials=materials,
        normal_input=materials.normal_input,
        candidate_input=materials.candidate_input,
    )
    assert prepared["plan_digest"].startswith("sha256:")

    # Freezing the frozen record again is byte-for-byte idempotent.
    again = freeze_b03.freeze(admission=frozen, calibration=calibration)
    assert again == frozen


def test_freeze_cli_writes_the_fixture_and_secret_document(tmp_path):
    calibration = _calibration(tmp_path)
    admission_path = tmp_path / "admission.json"
    calibration_path = tmp_path / "calibration.json"
    out_path = tmp_path / "frozen.json"
    admission_path.write_text(
        json.dumps(_admission(), indent=2) + "\n", encoding="utf-8"
    )
    calibration_path.write_text(
        json.dumps(calibration, indent=2) + "\n", encoding="utf-8"
    )
    code = freeze_b03.main(
        [
            "--admission",
            str(admission_path),
            "--calibration",
            str(calibration_path),
            "--out",
            str(out_path),
        ]
    )
    assert code == 0
    frozen = json.loads(out_path.read_text(encoding="utf-8"))
    assert frozen["asan_signature"]["status"] == "frozen"
    assert frozen["expected_verdict_status"] == "frozen"
    release._validate_b03_admission(frozen)


def test_freeze_rejects_inconsistent_calibration(tmp_path):
    calibration = _calibration(tmp_path)

    bad_cve = json.loads(json.dumps(calibration))
    bad_cve["cve_id"] = "CVE-2020-0001"
    with pytest.raises(freeze_b03.FreezeError, match="cve_id"):
        freeze_b03.freeze(admission=_admission(), calibration=bad_cve)

    bad_commit = json.loads(json.dumps(calibration))
    bad_commit["versions"]["fixed"] = "f" * 40
    with pytest.raises(freeze_b03.FreezeError, match="commit"):
        freeze_b03.freeze(admission=_admission(), calibration=bad_commit)

    bad_toolchain = json.loads(json.dumps(calibration))
    bad_toolchain["toolchain_image_digest"] = "sha256:" + "0" * 64
    with pytest.raises(freeze_b03.FreezeError, match="toolchain"):
        freeze_b03.freeze(admission=_admission(), calibration=bad_toolchain)


def test_freeze_refuses_to_overwrite_a_frozen_signature(tmp_path):
    calibration = _calibration(tmp_path)
    frozen = freeze_b03.freeze(admission=_admission(), calibration=calibration)
    changed = json.loads(json.dumps(calibration))
    changed["asan_signature"]["function"] = "different_function"
    changed["runs"][1]["signature"]["function"] = "different_function"
    with pytest.raises(freeze_b03.FreezeError, match="frozen|overwrite"):
        freeze_b03.freeze(admission=frozen, calibration=changed)


def test_freeze_refuses_an_unknown_admission_status(tmp_path):
    admission = _admission()
    admission["asan_signature"]["status"] = "rejected"
    with pytest.raises(freeze_b03.FreezeError, match="pending|frozen"):
        freeze_b03.freeze(
            admission=admission, calibration=_calibration(tmp_path)
        )
