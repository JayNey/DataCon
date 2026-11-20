#!/usr/bin/env python3
"""Freeze a real B03 calibration into an admission record.

Inputs are a pending (or consistently frozen) admission and the sanitized
calibration produced by ``scripts/calibrate_b03.py``. The output is the single
JSON document that is both the repository admission fixture and the
``DATACON_B03_ADMISSION`` secret.

The script never invents a signature and never silently overwrites a frozen
value: a mismatched CVE, commit, toolchain, exit code, stdout, or ASan field
fails closed. It writes no database row and no evidence bundle.

Usage:
    python scripts/freeze_b03_admission.py \
        --admission /srv/datacon/B03-admission.json \
        --calibration /srv/datacon/b03-calibration.json \
        --out /srv/datacon/B03-admission.frozen.json
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
from pathlib import Path
import sys
from typing import Any, Mapping

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT / "src") not in sys.path:
    sys.path.insert(0, str(REPO_ROOT / "src"))

from datacon import fileio, jsonutil, release  # noqa: E402


class FreezeError(RuntimeError):
    """The calibration and admission cannot be frozen without guessing."""


_ASAN_FIELDS = ("error", "operation", "access_size", "function", "source")
_EXPECTED_EXIT_FIELDS = ("normal", "candidate_clean", "candidate_asan")
_EXPECTED_STDOUT_FIELDS = ("normal", "candidate_clean")
_RUN_PAIRS = (
    ("vulnerable", "normal"),
    ("vulnerable", "candidate"),
    ("fixed", "normal"),
    ("fixed", "candidate"),
)
_SHA256 = release._SHA256


def _load_json(path: Path | str, label: str) -> Mapping[str, Any]:
    try:
        data = fileio.read_regular_file_bounded(path, max_bytes=16 * 1024 * 1024)
        document = jsonutil.loads_strict(data)
    except (fileio.UnsafeFileError, jsonutil.StrictJsonError) as error:
        raise FreezeError(f"{label} is not a readable JSON file") from error
    if not isinstance(document, Mapping):
        raise FreezeError(f"{label} must be a JSON object")
    return document


def _sha256_bytes(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _pending(value: Any) -> bool:
    return isinstance(value, str) and value.strip().lower().startswith(
        ("pending", "expected_pending")
    )


def _string(container: Mapping[str, Any], key: str, label: str) -> str:
    value = container.get(key)
    if not isinstance(value, str) or not value.strip():
        raise FreezeError(f"{label}.{key} must be a non-empty string")
    return value


def _int(container: Mapping[str, Any], key: str, label: str) -> int:
    value = container.get(key)
    if type(value) is not int:
        raise FreezeError(f"{label}.{key} must be an integer")
    return value


def _validate_calibration(calibration: Mapping[str, Any]) -> dict[str, Any]:
    if type(calibration.get("schema_version")) is not int or calibration.get(
        "schema_version"
    ) != 1:
        raise FreezeError("calibration schema_version must be 1")
    if calibration.get("benchmark_id") != "B03":
        raise FreezeError("calibration benchmark_id must be B03")
    cve_id = _string(calibration, "cve_id", "calibration")
    toolchain_digest = calibration.get("toolchain_image_digest")
    if not isinstance(toolchain_digest, str) or not _SHA256.fullmatch(
        toolchain_digest
    ):
        raise FreezeError("calibration toolchain_image_digest must be a sha256 digest")
    if toolchain_digest != release.TOOLCHAIN_IMAGE_DIGEST:
        raise FreezeError(
            "calibration toolchain_image_digest does not match the pinned toolchain"
        )
    versions = calibration.get("versions")
    if not isinstance(versions, Mapping):
        raise FreezeError("calibration versions must be an object")
    commits: dict[str, str] = {}
    for role in ("vulnerable", "fixed"):
        commit = versions.get(role)
        if not isinstance(commit, str) or not release._GIT_SHA40.fullmatch(commit):
            raise FreezeError(
                f"calibration versions.{role} must be a 40-char lowercase Git SHA"
            )
        commits[role] = commit

    signature = calibration.get("asan_signature")
    if not isinstance(signature, Mapping):
        raise FreezeError("calibration asan_signature must be an object")
    signature_doc: dict[str, Any] = {}
    for field in _ASAN_FIELDS:
        value = signature.get(field)
        if field == "access_size":
            if type(value) is not int or value <= 0:
                raise FreezeError(
                    "calibration asan_signature.access_size must be a positive integer"
                )
        elif not isinstance(value, str) or not value.strip():
            raise FreezeError(
                f"calibration asan_signature.{field} must be a non-empty string"
            )
        signature_doc[field] = value
    if signature_doc["operation"] not in ("READ", "WRITE"):
        raise FreezeError(
            "calibration asan_signature.operation must be READ or WRITE"
        )

    expected_exit = calibration.get("expected_exit")
    if not isinstance(expected_exit, Mapping):
        raise FreezeError("calibration expected_exit must be an object")
    exit_doc = {
        key: _int(expected_exit, key, "calibration expected_exit")
        for key in _EXPECTED_EXIT_FIELDS
    }
    expected_stdout = calibration.get("expected_stdout")
    if not isinstance(expected_stdout, Mapping):
        raise FreezeError("calibration expected_stdout must be an object")
    stdout_doc: dict[str, str] = {}
    for key in _EXPECTED_STDOUT_FIELDS:
        value = expected_stdout.get(key)
        if not isinstance(value, str):
            raise FreezeError(
                f"calibration expected_stdout.{key} must be a string"
            )
        stdout_doc[key] = value

    runs = calibration.get("runs")
    if not isinstance(runs, list) or len(runs) != len(_RUN_PAIRS):
        raise FreezeError("calibration runs must contain exactly four replay records")
    indexed: dict[tuple[str, str], Mapping[str, Any]] = {}
    for index, run in enumerate(runs):
        if not isinstance(run, Mapping):
            raise FreezeError(f"calibration runs[{index}] must be an object")
        version = run.get("version")
        phase = run.get("phase")
        if not isinstance(version, str) or not isinstance(phase, str):
            raise FreezeError(
                f"calibration runs[{index}] version and phase must be strings"
            )
        pair = (version, phase)
        if pair not in _RUN_PAIRS:
            raise FreezeError(
                f"calibration runs[{index}] has an unexpected version/phase pair"
            )
        if pair in indexed:
            raise FreezeError(
                f"calibration runs[{index}] duplicates {version}/{phase}"
            )
        exit_code = run.get("exit_code")
        if type(exit_code) is not int:
            raise FreezeError(
                f"calibration runs[{index}].exit_code must be an integer"
            )
        stdout_sha256 = run.get("stdout_sha256")
        if not isinstance(stdout_sha256, str) or not _SHA256.fullmatch(stdout_sha256):
            raise FreezeError(
                f"calibration runs[{index}].stdout_sha256 must be a sha256 digest"
            )
        indexed[pair] = run
    for pair in _RUN_PAIRS:
        if pair not in indexed:
            raise FreezeError(f"calibration is missing replay {pair[0]}/{pair[1]}")

    normal_exit = indexed[("vulnerable", "normal")]["exit_code"]
    clean_exit = indexed[("fixed", "candidate")]["exit_code"]
    asan_exit = indexed[("vulnerable", "candidate")]["exit_code"]
    if exit_doc != {
        "normal": normal_exit,
        "candidate_clean": clean_exit,
        "candidate_asan": asan_exit,
    }:
        raise FreezeError("calibration expected_exit does not match its runs")
    if indexed[("fixed", "normal")]["exit_code"] != normal_exit:
        raise FreezeError("calibration normal controls have different exit codes")
    for key, pair in (
        ("normal", ("vulnerable", "normal")),
        ("candidate_clean", ("fixed", "candidate")),
    ):
        observed = _sha256_bytes(stdout_doc[key].encode("utf-8"))
        if observed != indexed[pair]["stdout_sha256"]:
            raise FreezeError(
                f"calibration expected_stdout.{key} does not match its run digest"
            )
    if indexed[("fixed", "normal")]["stdout_sha256"] != indexed[
        ("vulnerable", "normal")
    ]["stdout_sha256"]:
        raise FreezeError("calibration normal controls have different stdout")

    asan_run_signature = indexed[("vulnerable", "candidate")].get("signature")
    if not isinstance(asan_run_signature, Mapping):
        raise FreezeError(
            "calibration vulnerable/candidate run must record the real ASan signature"
        )
    if dict(asan_run_signature) != signature_doc:
        raise FreezeError(
            "calibration asan_signature does not match the vulnerable/candidate run"
        )
    for pair in _RUN_PAIRS:
        if pair == ("vulnerable", "candidate"):
            continue
        if indexed[pair].get("signature") is not None:
            raise FreezeError(
                f"calibration run {pair[0]}/{pair[1]} unexpectedly has an ASan signature"
            )
    return {
        "cve_id": cve_id,
        "toolchain_image_digest": toolchain_digest,
        "versions": commits,
        "asan_signature": signature_doc,
        "expected_exit": exit_doc,
        "expected_stdout": stdout_doc,
    }


def _validate_binding(
    admission: Mapping[str, Any], calibration: Mapping[str, Any]
) -> None:
    if admission.get("benchmark_id") != "B03":
        raise FreezeError("admission benchmark_id must be B03")
    if _string(admission, "cve_id", "admission") != calibration["cve_id"]:
        raise FreezeError("calibration cve_id does not match the admission")
    versions = admission.get("versions")
    if not isinstance(versions, Mapping):
        raise FreezeError("admission versions must be an object")
    for role in ("vulnerable", "fixed"):
        entry = versions.get(role)
        if not isinstance(entry, Mapping):
            raise FreezeError(f"admission versions.{role} must be an object")
        if entry.get("commit") != calibration["versions"][role]:
            raise FreezeError(
                f"calibration {role} commit does not match the admission"
            )
    build = admission.get("build")
    if not isinstance(build, Mapping):
        raise FreezeError("admission build must be an object")
    toolchain = build.get("toolchain_image")
    if not isinstance(toolchain, str) or "@" not in toolchain:
        raise FreezeError("admission build.toolchain_image must be pinned by digest")
    if toolchain.split("@", 1)[1] != calibration["toolchain_image_digest"]:
        raise FreezeError(
            "calibration toolchain does not match the admission toolchain"
        )


def _evidence(calibration: Mapping[str, Any]) -> str:
    signature = calibration["asan_signature"]
    exits = calibration["expected_exit"]
    return (
        f"ASan {signature['error']} {signature['operation']} of size "
        f"{signature['access_size']} in {signature['function']} at "
        f"{signature['source']}; vulnerable/candidate exited "
        f"{exits['candidate_asan']} with the real diagnostic, both normal "
        f"controls exited {exits['normal']} with identical stdout, and "
        f"fixed/candidate exited {exits['candidate_clean']} cleanly."
    )


def _merge_asan_replay_check(
    checks: list[Any],
    *,
    evidence: str,
) -> list[Any]:
    updated = copy.deepcopy(checks)
    matches = [
        index
        for index, entry in enumerate(updated)
        if isinstance(entry, Mapping) and entry.get("id") == "asan_replay"
    ]
    if len(matches) > 1:
        raise FreezeError("admission has duplicate asan_replay checks")
    if not matches:
        updated.append(
            {
                "id": "asan_replay",
                "status": "pass",
                "evidence": evidence,
                "verification": "calibrated_replay",
            }
        )
        return updated
    index = matches[0]
    existing = updated[index]
    if not isinstance(existing, Mapping):
        raise FreezeError("admission asan_replay check must be an object")
    if existing.get("status") == "pass":
        existing_evidence = existing.get("evidence")
        if (
            not isinstance(existing_evidence, str)
            or not existing_evidence.strip()
            or existing_evidence != evidence
        ):
            raise FreezeError(
                "admission asan_replay check is already passed with different "
                "evidence; refusing to overwrite it"
            )
        return updated
    updated[index] = {
        "id": "asan_replay",
        "status": "pass",
        "evidence": evidence,
        "verification": "calibrated_replay",
    }
    return updated


def freeze(
    *,
    admission: Mapping[str, Any],
    calibration: Mapping[str, Any],
) -> dict[str, Any]:
    """Return the frozen admission JSON without mutating the inputs."""
    if not isinstance(admission, Mapping):
        raise FreezeError("admission must be an object")
    if not isinstance(calibration, Mapping):
        raise FreezeError("calibration must be an object")
    checked = _validate_calibration(calibration)
    _validate_binding(admission, checked)
    result = copy.deepcopy(dict(admission))
    signature = result.get("asan_signature")
    if not isinstance(signature, dict):
        raise FreezeError("admission asan_signature must be an object")
    status = signature.get("status")
    if status == "frozen":
        for field in _ASAN_FIELDS:
            if signature.get(field) != checked["asan_signature"][field]:
                raise FreezeError(
                    f"admission asan_signature.{field} is frozen to a different "
                    "value; refusing to overwrite it"
                )
    elif _pending(status):
        for field in _ASAN_FIELDS:
            signature[field] = checked["asan_signature"][field]
    elif status == "verified":
        raise FreezeError(
            "admission asan_signature.status is 'verified'; refusing to downgrade "
            "or silently re-freeze it"
        )
    else:
        raise FreezeError(
            "admission asan_signature.status must be a pending status or 'frozen'"
        )
    signature["status"] = "frozen"

    verdict_status = result.get("expected_verdict_status")
    if verdict_status == "verified":
        raise FreezeError(
            "admission expected_verdict_status is 'verified'; refusing to re-freeze it"
        )
    if not (_pending(verdict_status) or verdict_status == "frozen"):
        raise FreezeError(
            "admission expected_verdict_status must be a pending status or 'frozen'"
        )
    result["expected_verdict_status"] = "frozen"

    harness = result.get("harness")
    if not isinstance(harness, dict):
        raise FreezeError("admission harness must be an object")
    exit_keys = (
        ("normal_exit_code", "normal"),
        ("candidate_clean_exit_code", "candidate_clean"),
        ("candidate_asan_exit_code", "candidate_asan"),
    )
    for field, observed in exit_keys:
        if field in harness:
            if type(harness[field]) is not int:
                raise FreezeError(f"admission harness.{field} must be an integer")
            if harness[field] != checked["expected_exit"][observed]:
                raise FreezeError(
                    f"admission harness.{field} conflicts with the calibration"
                )
        else:
            harness[field] = checked["expected_exit"][observed]
    declared_stdout = harness.get("expected_stdout")
    if declared_stdout is None:
        declared_stdout = {}
    if not isinstance(declared_stdout, dict):
        raise FreezeError("admission harness.expected_stdout must be an object")
    extra_stdout = set(declared_stdout) - set(_EXPECTED_STDOUT_FIELDS)
    if extra_stdout:
        raise FreezeError(
            "admission harness.expected_stdout has unexpected keys: "
            + ", ".join(sorted(extra_stdout))
        )
    for key in _EXPECTED_STDOUT_FIELDS:
        if key in declared_stdout and declared_stdout[key] != checked["expected_stdout"][key]:
            raise FreezeError(
                f"admission harness.expected_stdout.{key} conflicts with the "
                "calibration"
            )
    harness["expected_stdout"] = dict(checked["expected_stdout"])

    checks = result.get("checks")
    if isinstance(checks, list):
        result["checks"] = _merge_asan_replay_check(
            checks, evidence=_evidence(checked)
        )
    elif isinstance(checks, Mapping):
        existing = checks.get("asan_replay")
        if isinstance(existing, Mapping) and existing.get("status") == "pass":
            previous = existing.get("evidence")
            if previous != _evidence(checked):
                raise FreezeError(
                    "admission asan_replay check is already passed with different "
                    "evidence; refusing to overwrite it"
                )
        merged = copy.deepcopy(dict(checks))
        merged["asan_replay"] = {
            "status": "pass",
            "evidence": _evidence(checked),
            "verification": "calibrated_replay",
        }
        result["checks"] = merged
    else:
        raise FreezeError("admission checks must be a list or object")

    try:
        release._validate_b03_admission(result)
    except release.ReleaseGateError as error:
        raise FreezeError(f"frozen admission is not admissible: {error}") from error
    return result


def _write_json(path: Path | str, document: Mapping[str, Any]) -> None:
    out = Path(path)
    out.parent.mkdir(parents=True, exist_ok=True)
    jsonutil.reject_symlink_ancestors(
        out.parent, label="frozen admission output directory", error_cls=FreezeError
    )
    payload = (
        json.dumps(document, indent=2, ensure_ascii=False) + "\n"
    ).encode("utf-8")
    try:
        fileio.write_regular_file(out, payload, mode=0o644)
    except fileio.UnsafeFileError as error:
        raise FreezeError("frozen admission output cannot be written safely") from error


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="freeze_b03_admission",
        description="Freeze a real B03 calibration into an admission record.",
    )
    parser.add_argument("--admission", required=True, type=Path)
    parser.add_argument("--calibration", required=True, type=Path)
    parser.add_argument("--out", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        admission = _load_json(args.admission, "admission")
        calibration = _load_json(args.calibration, "calibration")
        document = freeze(admission=admission, calibration=calibration)
        _write_json(args.out, document)
    except Exception as error:  # fail closed without printing secret material
        print(
            f"freeze failed ({type(error).__name__}); no output written",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
