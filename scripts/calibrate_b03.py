#!/usr/bin/env python3
"""Calibrate the real B03 ASan signature on an authorized Linux lab host.

This script is the only supported producer of the values that
``scripts/freeze_b03_admission.py`` freezes into an admission record. It never
writes the database, an evidence bundle, or repository metadata; it only emits
a sanitized JSON calibration document from four real replays:

* vulnerable / normal
* vulnerable / candidate
* fixed / normal
* fixed / candidate

The real ASan fields and the exact control exits/stdout come from the pinned
sandbox. Nothing is synthesized: a missing signature, a failed replay, a
truncated capture, or an admission mismatch fails closed.

Usage:
    python scripts/calibrate_b03.py \
        --case-root /srv/datacon/b03-case \
        --admission /srv/datacon/B03-admission.json \
        --out /srv/datacon/b03-calibration.json
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys
import tempfile
import uuid
from typing import Any, Mapping

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT / "src") not in sys.path:
    sys.path.insert(0, str(REPO_ROOT / "src"))

from datacon import contracts, fileio, jsonutil, release  # noqa: E402
from datacon.asan import has_asan_diagnostic  # noqa: E402
from datacon.tools.sandbox import MAX_LOG_BYTES  # noqa: E402


class CalibrationError(RuntimeError):
    """A real B03 calibration could not be produced without inventing values."""


# Keep in lock-step with release.prepare_b03_plan. It is duplicated here only
# because calibration must run before the admission signature is frozen; a
# frozen plan cannot be built yet.
_ISOLATION = {
    "network": "none",
    "user": "65534:65534",
    "read_only_root": True,
    "cap_drop": ["ALL"],
    "no_new_privileges": True,
    "seccomp": "runtime/default",
    "seccomp_profile_digest": release.SECCOMP_PROFILE_DIGEST,
}
_REQUIRED_RUNS = (
    ("vulnerable", "normal"),
    ("vulnerable", "candidate"),
    ("fixed", "normal"),
    ("fixed", "candidate"),
)
_ASAN_FIELDS = ("error", "operation", "access_size", "function", "source")


def _load_json(path: Path | str, label: str) -> Mapping[str, Any]:
    try:
        data = fileio.read_regular_file_bounded(path, max_bytes=4 * 1024 * 1024)
        document = jsonutil.loads_strict(data)
    except (fileio.UnsafeFileError, jsonutil.StrictJsonError) as error:
        raise CalibrationError(f"{label} is not a readable JSON file") from error
    if not isinstance(document, Mapping):
        raise CalibrationError(f"{label} must be a JSON object")
    return document


def _admission_binding(admission: Mapping[str, Any]) -> dict[str, Any]:
    if admission.get("benchmark_id") != "B03":
        raise CalibrationError("admission benchmark_id must be B03")
    cve_id = admission.get("cve_id")
    if not isinstance(cve_id, str) or not release._CVE_ID.fullmatch(cve_id):
        raise CalibrationError("admission cve_id must be a CVE identifier")
    versions = admission.get("versions")
    if not isinstance(versions, Mapping):
        raise CalibrationError("admission versions must be an object")
    commits: dict[str, str] = {}
    for role in ("vulnerable", "fixed"):
        entry = versions.get(role)
        if not isinstance(entry, Mapping):
            raise CalibrationError(f"admission versions.{role} must be an object")
        commit = entry.get("commit")
        if not isinstance(commit, str) or not release._GIT_SHA40.fullmatch(commit):
            raise CalibrationError(
                f"admission versions.{role}.commit must be a 40-char lowercase Git SHA"
            )
        commits[role] = commit
    build = admission.get("build")
    if not isinstance(build, Mapping):
        raise CalibrationError("admission build must be an object")
    toolchain = build.get("toolchain_image")
    if toolchain != release.TOOLCHAIN_IMAGE:
        raise CalibrationError(
            "admission toolchain image does not match the pinned B03 toolchain"
        )
    harness = admission.get("harness")
    if not isinstance(harness, Mapping):
        raise CalibrationError("admission harness must be an object")
    asan_options = harness.get("asan_options")
    if not isinstance(asan_options, str) or not asan_options.strip():
        raise CalibrationError("admission harness.asan_options must be set")
    repository = admission.get("repository")
    if not isinstance(repository, Mapping):
        raise CalibrationError("admission repository must be an object")
    source_path = repository.get("source_path", "src/regext.c")
    if not isinstance(source_path, str) or not source_path.strip():
        raise CalibrationError("admission repository.source_path must be set")
    return {
        "cve_id": cve_id,
        "vulnerable_commit": commits["vulnerable"],
        "fixed_commit": commits["fixed"],
        "toolchain_image": toolchain,
        "toolchain_image_digest": toolchain.split("@", 1)[1],
        "asan_options": asan_options,
        "source_path": source_path,
    }


def _validate_admission_observations(
    admission: Mapping[str, Any],
    *,
    signature: Mapping[str, Any],
    expected_exit: Mapping[str, int],
    expected_stdout: Mapping[str, str],
) -> None:
    """Reject a pending calibration that contradicts explicit admission values."""
    harness = admission.get("harness")
    if isinstance(harness, Mapping):
        pairs = (
            ("normal_exit_code", "normal"),
            ("candidate_clean_exit_code", "candidate_clean"),
            ("candidate_asan_exit_code", "candidate_asan"),
        )
        for key, observed_key in pairs:
            if key not in harness:
                continue
            declared = harness[key]
            if type(declared) is not int:
                raise CalibrationError(f"admission harness.{key} must be an integer")
            if declared != expected_exit[observed_key]:
                raise CalibrationError(
                    f"admission harness.{key} does not match the real replay"
                )
        declared_stdout = harness.get("expected_stdout")
        if declared_stdout is not None:
            if not isinstance(declared_stdout, Mapping):
                raise CalibrationError(
                    "admission harness.expected_stdout must be an object"
                )
            for key in ("normal", "candidate_clean"):
                if key not in declared_stdout:
                    continue
                declared = declared_stdout[key]
                if not isinstance(declared, str):
                    raise CalibrationError(
                        f"admission harness.expected_stdout.{key} must be a string"
                    )
                if declared != expected_stdout[key]:
                    raise CalibrationError(
                        f"admission harness.expected_stdout.{key} does not match "
                        "the real replay"
                    )

    declared_signature = admission.get("asan_signature")
    if isinstance(declared_signature, Mapping):
        status = declared_signature.get("status")
        if status in {"frozen", "verified"}:
            for field in _ASAN_FIELDS:
                if field not in declared_signature:
                    continue
                if declared_signature[field] != signature[field]:
                    raise CalibrationError(
                        f"admission asan_signature.{field} does not match the "
                        "real replay; refusing to overwrite a frozen signature"
                    )


def _check_replay(result: Any, version: str, phase: str) -> None:
    label = f"{version}/{phase}"
    if getattr(result, "status", None) != "completed":
        raise CalibrationError(f"B03 replay {label} did not complete")
    if getattr(result, "timed_out", True):
        raise CalibrationError(f"B03 replay {label} timed out")
    if getattr(result, "quota_hit", True):
        raise CalibrationError(f"B03 replay {label} hit a resource limit")
    if getattr(result, "log_truncated", True):
        raise CalibrationError(f"B03 replay {label} output was truncated")
    if getattr(result, "capture_error", "missing") is not None:
        raise CalibrationError(f"B03 replay {label} output was not captured")
    if type(getattr(result, "exit_code", None)) is not int:
        raise CalibrationError(f"B03 replay {label} has no exit code")
    if len(getattr(result, "stdout", b"")) > MAX_LOG_BYTES:
        raise CalibrationError(f"B03 replay {label} stdout exceeds the capture budget")


def _decode_stdout(result: Any, label: str) -> str:
    try:
        return result.stdout.decode("utf-8")
    except UnicodeDecodeError as error:
        raise CalibrationError(f"B03 replay {label} stdout is not UTF-8") from error


def _replay(
    sandbox: Any,
    *,
    version: str,
    phase: str,
    artifact_path: Path,
    input_path: Path,
    asan_options: str,
    timeout_seconds: float,
    artifact_digest: str,
) -> Any:
    return sandbox.replay(
        version,
        phase,
        artifact_path=artifact_path,
        input_path=input_path,
        asan_options=asan_options,
        timeout_seconds=timeout_seconds,
        expected_artifact_digest=artifact_digest,
        expected_input_digest=release._sha256_bytes(input_path.read_bytes()),
    )


def _stage_materials(
    materials: release.B03CaseMaterials,
    staging_root: Path,
    *,
    normal_input: bytes,
    candidate_input: bytes,
) -> dict[str, str]:
    """Reuse the exact staging contract from run_b03_acceptance."""
    _write = release._write_readonly_staged_file
    _write(staging_root / "harness.c", materials.harness)
    _write(staging_root / "build.sh", materials.build_recipe)
    _write(staging_root / "dependencies.lock", materials.dependencies)
    _write(staging_root / "fix.patch", materials.patch)
    _write(staging_root / "b03-repo.bundle", materials.repository_bundle)
    _write(staging_root / "advisory.json", materials.advisory)
    for prefix, sources in (
        ("vulnerable", materials.vulnerable_sources),
        ("fixed", materials.fixed_sources),
    ):
        for relative, data in sources.items():
            _write(staging_root / prefix / relative, data)
    _write(staging_root / "inputs" / "normal.txt", normal_input)
    _write(staging_root / "inputs" / "candidate.txt", candidate_input)
    release._chmod_tree(staging_root, dir_mode=0o755, file_mode=0o444)
    staged = dict(materials.digests)
    staged["inputs/normal.txt"] = release._sha256_bytes(normal_input)
    staged["inputs/candidate.txt"] = release._sha256_bytes(candidate_input)
    return staged


def calibrate(
    *,
    case_root: Path | str,
    admission: Mapping[str, Any],
    sandbox: Any | None = None,
    docker: str = "docker",
    work_root: Path | str | None = None,
) -> dict[str, Any]:
    """Run the four real replays and return a sanitized calibration document."""
    materials = release.B03CaseMaterials.load(case_root)
    binding = _admission_binding(admission)
    try:
        advisory = jsonutil.loads_strict(materials.advisory)
    except jsonutil.StrictJsonError as error:
        raise CalibrationError("case advisory.json is invalid JSON") from error
    release._validate_b03_advisory(
        advisory,
        cve_id=binding["cve_id"],
        vulnerable_commit=binding["vulnerable_commit"],
        fixed_commit=binding["fixed_commit"],
    )
    release._b03_source_bytes(
        materials.vulnerable_sources, binding["source_path"]
    )

    normal_input = materials.normal_input
    candidate_input = materials.candidate_input
    limits = dict(contracts.DEFAULT_LIMITS)
    compile_args = list(release._extract_compile_args(materials.build_recipe))

    temp_parent = Path(work_root) if work_root is not None else Path(tempfile.gettempdir())
    temp_parent.mkdir(parents=True, exist_ok=True)
    working = Path(tempfile.mkdtemp(prefix="datacon-b03-calibrate-", dir=temp_parent))
    try:
        staging_root = working / "materials"
        staging_root.mkdir()
        staged = _stage_materials(
            materials,
            staging_root,
            normal_input=normal_input,
            candidate_input=candidate_input,
        )
        normal_file = working / "normal.txt"
        candidate_file = working / "candidate.txt"
        release._write_readonly_staged_file(normal_file, normal_input)
        release._write_readonly_staged_file(candidate_file, candidate_input)

        if sandbox is None:
            plan_shim = {
                "image_digest": binding["toolchain_image_digest"],
                "platform": "linux/amd64",
                "isolation": dict(_ISOLATION),
                "limits": limits,
            }
            sandbox = release.build_b03_sandbox(
                plan_shim,
                image=binding["toolchain_image"],
                job_id=str(uuid.uuid4()),
                run_root=working / "runs",
                docker=docker,
            )

        artifacts: dict[str, Path] = {}
        build_digests: dict[str, str] = {}
        for version in ("vulnerable", "fixed"):
            build = sandbox.build(
                version,
                materials_dir=staging_root,
                compile_args=compile_args,
                expected_materials=staged,
            )
            release._require_build(build, version)
            artifact = working / f"artifact-{version}"
            artifact.write_bytes(bytes(build.artifact))
            artifact.chmod(0o555)
            artifacts[version] = artifact
            build_digests[version] = build.artifact_digest

        observations: dict[tuple[str, str], Any] = {}
        for version, phase in _REQUIRED_RUNS:
            input_path = normal_file if phase == "normal" else candidate_file
            result = _replay(
                sandbox,
                version=version,
                phase=phase,
                artifact_path=artifacts[version],
                input_path=input_path,
                asan_options=binding["asan_options"],
                timeout_seconds=float(limits["replay_seconds"]),
                artifact_digest=build_digests[version],
            )
            _check_replay(result, version, phase)
            observations[(version, phase)] = result

        normal_vuln = observations[("vulnerable", "normal")]
        normal_fixed = observations[("fixed", "normal")]
        candidate_vuln = observations[("vulnerable", "candidate")]
        candidate_fixed = observations[("fixed", "candidate")]

        if normal_vuln.exit_code != normal_fixed.exit_code:
            raise CalibrationError("the two normal controls have different exit codes")
        normal_stdout = _decode_stdout(normal_vuln, "vulnerable/normal")
        fixed_normal_stdout = _decode_stdout(normal_fixed, "fixed/normal")
        if normal_stdout != fixed_normal_stdout:
            raise CalibrationError("the two normal controls have different stdout")

        for version, result in (
            ("vulnerable", normal_vuln),
            ("fixed", normal_fixed),
            ("fixed", candidate_fixed),
        ):
            if result.signature is not None or has_asan_diagnostic(
                result.stderr.decode("utf-8", "replace")
            ):
                raise CalibrationError(
                    f"unexpected ASan diagnostic in the {version} control replay"
                )

        if candidate_vuln.signature is None:
            raise CalibrationError(
                "vulnerable/candidate produced no ASan diagnostic; refusing to "
                "invent a signature"
            )
        signature = candidate_vuln.signature.as_dict()
        for field in _ASAN_FIELDS:
            value = signature.get(field)
            if field == "access_size":
                if type(value) is not int or value <= 0:
                    raise CalibrationError(
                        "ASan signature has no positive access_size"
                    )
            elif not isinstance(value, str) or not value.strip():
                raise CalibrationError(f"ASan signature has no {field}")
        if signature["operation"] not in ("READ", "WRITE"):
            raise CalibrationError(
                f"ASan signature has an unexpected operation: {signature['operation']!r}"
            )

        candidate_clean_stdout = _decode_stdout(candidate_fixed, "fixed/candidate")
        expected_exit = {
            "normal": normal_vuln.exit_code,
            "candidate_clean": candidate_fixed.exit_code,
            "candidate_asan": candidate_vuln.exit_code,
        }
        expected_stdout = {
            "normal": normal_stdout,
            "candidate_clean": candidate_clean_stdout,
        }
        _validate_admission_observations(
            admission,
            signature=signature,
            expected_exit=expected_exit,
            expected_stdout=expected_stdout,
        )

        runs = []
        for version, phase in _REQUIRED_RUNS:
            result = observations[(version, phase)]
            runs.append(
                {
                    "version": version,
                    "phase": phase,
                    "exit_code": result.exit_code,
                    "stdout_sha256": release._sha256_bytes(result.stdout),
                    "signature": (
                        result.signature.as_dict() if result.signature else None
                    ),
                }
            )
        document = {
            "schema_version": 1,
            "benchmark_id": "B03",
            "cve_id": binding["cve_id"],
            "toolchain_image_digest": binding["toolchain_image_digest"],
            "versions": {
                "vulnerable": binding["vulnerable_commit"],
                "fixed": binding["fixed_commit"],
            },
            "asan_signature": signature,
            "expected_exit": expected_exit,
            "expected_stdout": expected_stdout,
            "runs": runs,
        }
        return document
    finally:
        import shutil

        shutil.rmtree(working, ignore_errors=True)


def _write_json(path: Path | str, document: Mapping[str, Any]) -> None:
    out = Path(path)
    out.parent.mkdir(parents=True, exist_ok=True)
    jsonutil.reject_symlink_ancestors(
        out.parent, label="calibration output directory", error_cls=CalibrationError
    )
    payload = (
        json.dumps(document, indent=2, ensure_ascii=False) + "\n"
    ).encode("utf-8")
    try:
        fileio.write_regular_file(out, payload, mode=0o644)
    except fileio.UnsafeFileError as error:
        raise CalibrationError("calibration output cannot be written safely") from error


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="calibrate_b03",
        description="Produce a sanitized B03 calibration from four real replays.",
    )
    parser.add_argument("--case-root", required=True, type=Path)
    parser.add_argument("--admission", required=True, type=Path)
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument("--docker", default=os.environ.get("DATACON_DOCKER", "docker"))
    args = parser.parse_args(argv)
    try:
        admission = _load_json(args.admission, "admission")
        document = calibrate(
            case_root=args.case_root,
            admission=admission,
            docker=args.docker,
        )
        _write_json(args.out, document)
    except Exception as error:  # fail closed without printing logs or host paths
        print(
            f"calibration failed ({type(error).__name__}); no output written",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
