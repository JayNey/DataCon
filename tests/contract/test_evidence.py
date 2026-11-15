"""TC-08: offline evidence manifests, export and verification (REQ-08)."""

from __future__ import annotations

from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import stat
from uuid import uuid4

import pytest

from datacon import jsonutil
from datacon.contracts import plan_digest
from datacon.evidence import (
    BundleError,
    _control_mismatch,
    canonical_manifest_digest,
    export_bundle,
    verify_bundle,
    write_bundle,
)
from datacon.verdict import reason_allowed
JOB_ID = str(uuid4())
REASONS = {"REPRODUCED": "ASAN_SIGNATURE_MATCHED"}

# A complete bundle is built from a plan whose case-config digest is
# recomputed from the same materials that the bundle ships. This is the real
# shape produced by execution: the verifier can bind every material byte back
# to the frozen plan instead of trusting report.json.
ASAN_LOG = """\
==7==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x502000000014
WRITE of size 1 at 0x502000000014 thread T0
    #0 0x55555565fadf in parse_token /fixture/vulnerable/parser.c:22:17
    #1 0x55555565fc67 in main /fixture/harness.c:14:19
SUMMARY: AddressSanitizer: heap-buffer-overflow /fixture/vulnerable/parser.c:22:17 in parse_token
"""
MATERIALS = {
    "harness.c": b"int main(void) { return 0; }\n",
    "build.sh": (
        b"#!/bin/sh\nset -eu\n"
        b"clang -std=c11 -g -O0 -fno-omit-frame-pointer -fsanitize=address "
        b"/fixture/harness.c -o /work/parser\n"
    ),
    "dependencies.lock": b"clang=19.1.7\n",
    "fix.patch": b"--- a/parser.c\n+++ b/parser.c\n",
    "vulnerable/parser.c": b"char *parse_token(void) { return 0; }\n",
    "fixed/parser.c": b"char *parse_token(void) { return 0; }\n",
    "inputs/normal.txt": b"normal\n",
    "inputs/candidate.txt": b"ABCD\n",
}
MATERIAL_DIGESTS = {
    path: "sha256:" + hashlib.sha256(data).hexdigest()
    for path, data in MATERIALS.items()
}
MATERIAL_ROLES = {
    "harness.c": "material_harness",
    "build.sh": "material_build_recipe",
    "dependencies.lock": "material_dependencies",
    "fix.patch": "material_patch",
    "vulnerable/parser.c": "material_source_vulnerable",
    "fixed/parser.c": "material_source_fixed",
    "inputs/normal.txt": "material_input_normal",
    "inputs/candidate.txt": "material_input_candidate",
}
COMPILE_ARGS = [
    "-std=c11",
    "-g",
    "-O0",
    "-fno-omit-frame-pointer",
    "-fsanitize=address",
    "-o",
]

from test_plan import PLAN as BASE_PLAN

PLAN = deepcopy(BASE_PLAN)
PLAN["harness_digest"] = MATERIAL_DIGESTS["harness.c"]
PLAN["build_recipe_digest"] = MATERIAL_DIGESTS["build.sh"]
PLAN["dependencies_digest"] = MATERIAL_DIGESTS["dependencies.lock"]
PLAN["repository"]["patch_digest"] = MATERIAL_DIGESTS["fix.patch"]
PLAN["inputs"] = {
    "normal": MATERIAL_DIGESTS["inputs/normal.txt"],
    "candidate": MATERIAL_DIGESTS["inputs/candidate.txt"],
}

CASE_CONFIG = {
    "case_id": PLAN["case_id"],
    "cve_id": PLAN["cve_id"],
    "benchmark_id": "B01",
    "registry_entry": {
        "cve_id": PLAN["cve_id"],
        "benchmark_id": "B01",
        "repository": {
            "origin": PLAN["repository"]["origin"],
            "bundle": "fixture-repo.bundle",
            "bundle_digest": PLAN["repository"]["bundle_digest"],
            "commits": dict(PLAN["revisions"]),
            "patch": "fix.patch",
        },
    },
    "manifest_case": {
        "case_id": PLAN["case_id"],
        "inputs": {
            "normal": "inputs/normal.txt",
            "candidate": "inputs/candidate.txt",
        },
        "expected_exit": dict(PLAN["expected_exit"]),
        "expected_stdout": {"normal": "OK\n", "candidate_clean": "ABCD\n"},
    },
    "materials": dict(MATERIAL_DIGESTS),
    "image": "silkeh/clang:19-bookworm@" + PLAN["image_digest"],
    "platform": PLAN["platform"],
    "toolchain": dict(PLAN["toolchain"]),
    "asan_options": PLAN["asan_options"],
    "asan_signature": dict(PLAN["asan_signature"]),
}
PLAN["case_config_digest"] = jsonutil.digest_json(CASE_CONFIG)
PLAN_DIGEST = plan_digest(PLAN)


def digest(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def build_record(version: str) -> dict:
    artifact = f"parser-{version}".encode()
    log = f"{version} build\n".encode()
    return {
        "tool_id": "sandbox.build",
        "job_id": JOB_ID,
        "generation": 1,
        "plan_digest": PLAN_DIGEST,
        "input_digest": PLAN["analysis_digest"],
        "status": "completed",
        "version": version,
        "container_id": f"build-{version}",
        "artifact_digest": digest(artifact),
        "attempt_no": 1,
        "files": {
            "log": f"generation-1/build/{version}/build.log",
            "artifact": f"generation-1/build/{version}/parser",
        },
        "file_digests": {"log": digest(log), "artifact": digest(artifact)},
        "exit_code": 0,
        "duration_seconds": 0.1,
        "image_digest": PLAN["image_digest"],
        "compile_args": list(COMPILE_ARGS),
        "log_digest": digest(log),
        "log_truncated": False,
        "build_recipe_digest": PLAN["build_recipe_digest"],
        "build_command": ["/bin/sh", "/fixture/build.sh", version],
        "staged_materials": dict(MATERIAL_DIGESTS),
    }


def replay_record(version: str, phase: str) -> dict:
    from datacon.asan import parse_asan

    if version == "vulnerable" and phase.startswith("candidate"):
        stdout = b""
        stderr = ASAN_LOG.encode()
        exit_code = PLAN["expected_exit"]["candidate_asan"]
    elif version == "fixed" and phase.startswith("candidate"):
        stdout = b"ABCD\n"
        stderr = b""
        exit_code = PLAN["expected_exit"]["candidate_clean"]
    else:
        stdout = b"OK\n"
        stderr = b""
        exit_code = PLAN["expected_exit"]["normal"]
    signature = parse_asan(stderr.decode("utf-8", "replace"))
    input_digest = (
        PLAN["inputs"]["normal"]
        if phase == "normal"
        else PLAN["inputs"]["candidate"]
    )
    return {
        "tool_id": "sandbox.replay",
        "job_id": JOB_ID,
        "generation": 1,
        "plan_digest": PLAN_DIGEST,
        "input_digest": input_digest,
        "status": "completed",
        "version": version,
        "phase": phase,
        "container_id": f"replay-{version}-{phase}",
        "signature": signature.as_dict() if signature else None,
        "attempt_no": 1,
        "files": {
            "stdout": f"generation-1/replay/{version}/{phase}/stdout.log",
            "stderr": f"generation-1/replay/{version}/{phase}/stderr.log",
        },
        "file_digests": {"stdout": digest(stdout), "stderr": digest(stderr)},
        "exit_code": exit_code,
        "duration_seconds": 0.1,
        "stdout_sha256": digest(stdout),
        "stdout_bytes": len(stdout),
        "stdout_preview": stdout[:512].decode("utf-8", "replace"),
        "stderr_sha256": digest(stderr),
        "stderr_bytes": len(stderr),
        "stderr_preview": stderr[:512].decode("utf-8", "replace"),
        "timed_out": False,
        "quota_hit": False,
        "log_truncated": False,
        "image_digest": PLAN["image_digest"],
        "asan_options": PLAN["asan_options"],
        "limits_hit": [],
    }


BUILDS = [build_record(version) for version in ("vulnerable", "fixed")]
REPLAYS = [
    replay_record(version, phase)
    for version in ("vulnerable", "fixed")
    for phase in ("normal", "candidate_1", "candidate_2")
]

REPORT = {
    "schema_version": 1,
    "job_id": JOB_ID,
    "plan_digest": PLAN_DIGEST,
    "cve_id": PLAN["cve_id"],
    "case_id": PLAN["case_id"],
    "verdict": "REPRODUCED",
    "reason_code": REASONS["REPRODUCED"],
    "repository": dict(PLAN["repository"]),
    "versions": dict(PLAN["revisions"]),
    "inputs": dict(PLAN["inputs"]),
    "signature": dict(PLAN["asan_signature"]),
    "environment": {
        "image_digest": PLAN["image_digest"],
        "platform": PLAN["platform"],
        "toolchain": dict(PLAN["toolchain"]),
        "asan_options": PLAN["asan_options"],
        "compile_args": list(COMPILE_ARGS),
        "probe": {"checks": {"seccomp": "2"}},
    },
    "builds": BUILDS,
    "replays": REPLAYS,
    "missing": [],
}

REVIEW = {
    "reviewer_id": "reviewer-1",
    "decision": "approve",
    "plan_digest": PLAN_DIGEST,
    "decided_at": "2026-01-02T00:00:00Z",
}


def canonical(data) -> bytes:
    return jsonutil.canonical_bytes(data) + b"\n"


def full_artifacts() -> dict[str, tuple[str, bytes]]:
    artifacts: dict[str, tuple[str, bytes]] = {
        "plan.json": ("plan", canonical(PLAN)),
        "review.json": ("review", canonical(REVIEW)),
        "metadata/execution.json": (
            "execution_metadata",
            canonical(
                {
                    "job_id": JOB_ID,
                    "plan_digest": PLAN_DIGEST,
                    "generation": 1,
                }
            ),
        ),
        "metadata/probe.json": ("probe", b'{"checks":{"seccomp":"2"}}\n'),
        "metadata/case.json": (
            "case_config",
            canonical({"case_config": CASE_CONFIG}),
        ),
    }
    for build in BUILDS:
        version = build["version"]
        artifacts[f"build/{version}/build.log"] = (
            "build_log",
            f"{version} build\n".encode(),
        )
        artifacts[f"build/{version}/parser"] = (
            "build_artifact",
            f"parser-{version}".encode(),
        )
        artifacts[f"build/{version}/metadata.json"] = (
            "build_metadata",
            canonical(build),
        )
    for replay in REPLAYS:
        directory = f"replay/{replay['version']}/{replay['phase']}"
        artifacts[f"{directory}/stdout.log"] = (
            "replay_stdout" if replay["phase"] != "normal" else "normal_output",
            replay["stdout_preview"].encode(),
        )
        artifacts[f"{directory}/stderr.log"] = (
            "asan_log"
            if replay["version"] == "vulnerable"
            and replay["phase"].startswith("candidate")
            else "replay_stderr",
            replay["stderr_preview"].encode(),
        )
        artifacts[f"{directory}/metadata.json"] = (
            "replay_metadata",
            canonical(replay),
        )
    for relative, data in MATERIALS.items():
        artifacts[f"materials/{relative}"] = (
            MATERIAL_ROLES[relative],
            data,
        )
    return artifacts


def make_bundle(
    tmp_path: Path,
    *,
    extra=None,
    report=None,
    plan=None,
    review=None,
    full=True,
    name="bundle",
):
    report_value = deepcopy(REPORT if report is None else report)
    plan_value = deepcopy(PLAN if plan is None else plan)
    review_value = deepcopy(REVIEW if review is None else review)
    artifacts: dict[str, tuple[str, bytes]] = {}
    if full:
        artifacts.update(full_artifacts())
    else:
        artifacts["metadata/execution.json"] = (
            "execution_metadata",
            b'{"generation":1}\n',
        )
    artifacts["plan.json"] = ("plan", canonical(plan_value))
    artifacts["review.json"] = ("review", canonical(review_value))
    if extra:
        artifacts.update(extra)
    return write_bundle(
        tmp_path / name,
        job_id=report_value["job_id"],
        plan_digest=report_value["plan_digest"],
        report=report_value,
        report_markdown="# report\n",
        artifacts=artifacts,
    )


def _rewrite_manifested_file(root: Path, relative: str, data: bytes) -> None:
    """Replace a file and make its manifest entry match the new bytes.

    This isolates semantic checks from the plain digest check: an attacker who
    can rewrite the manifest must still not be able to smuggle in a different
    plan, review or report.
    """
    target = root / relative
    target.write_bytes(data)
    manifest_path = root / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    for entry in manifest["files"]:
        if entry["path"] == relative:
            entry["size_bytes"] = len(data)
            entry["sha256"] = hashlib.sha256(data).hexdigest()
            break
    else:
        raise AssertionError(f"{relative} is not listed in the manifest")
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")


def _replace_report(root: Path, **changes) -> None:
    report = deepcopy(REPORT)
    report.update(changes)
    _rewrite_manifested_file(root, "report.json", canonical(report))


def test_valid_bundle_round_trips_and_exports(tmp_path):
    info = make_bundle(tmp_path)
    verified = verify_bundle(info.root)
    assert verified.manifest_digest == info.manifest_digest
    assert verified.manifest["job_id"] == JOB_ID
    assert verified.manifest["verdict"] == "REPRODUCED"
    assert verified.manifest["files"]
    assert all(
        set(entry) == {"path", "role", "size_bytes", "sha256"}
        for entry in verified.manifest["files"]
    )
    assert verified.file_data["report.json"].startswith(b"{")
    # Every replay phase has its own stdout/stderr/metadata evidence.
    paths = {entry["path"] for entry in verified.manifest["files"]}
    for version in ("vulnerable", "fixed"):
        for phase in ("normal", "candidate_1", "candidate_2"):
            for name in ("stdout.log", "stderr.log", "metadata.json"):
                assert f"replay/{version}/{phase}/{name}" in paths

    exported = export_bundle(info.root, tmp_path / "exported")
    assert exported.manifest_digest == info.manifest_digest
    assert (tmp_path / "exported" / "manifest.json").is_file()
    assert (tmp_path / "exported" / "report.md").read_text() == "# report\n"


def test_verify_rejects_reproduced_when_candidate_asan_is_absent(tmp_path):
    """A plan without candidate_asan cannot support REPRODUCED.

    Both vulnerable candidates carry a matching ASan log but a null exit code.
    The old bare equality compared ``None == None`` and accepted the bundle as
    the reviewed signature hit; the rule engine classifies it as OTHER_CRASH.
    """
    info = make_bundle(tmp_path)
    plan, case_config, variant_digest = _plan_without_candidate_asan()
    _rebind_bundle_to_plan(info.root, plan, case_config, variant_digest)
    for phase in ("candidate_1", "candidate_2"):
        _update_replay(info.root, "vulnerable", phase, exit_code=None)
    with pytest.raises(BundleError) as caught:
        verify_bundle(info.root)
    assert caught.value.reason_code == "INVALID_MANIFEST"


def test_verify_still_accepts_reproduced_with_expected_candidate_asan(tmp_path):
    """The strict predicate must not reject a genuine planned ASan exit."""
    info = make_bundle(tmp_path)
    report = json.loads((info.root / "report.json").read_text(encoding="utf-8"))
    assert {
        replay["exit_code"]
        for replay in report["replays"]
        if replay["version"] == "vulnerable"
        and replay["phase"].startswith("candidate")
    } == {PLAN["expected_exit"]["candidate_asan"]}
    verified = verify_bundle(info.root)
    assert verified.manifest["verdict"] == "REPRODUCED"
    assert verified.manifest["reason_code"] == "ASAN_SIGNATURE_MATCHED"


@pytest.mark.parametrize("value", [False, 0.0])
def test_verify_rejects_non_integer_control_exit_code(tmp_path, value):
    """true == 1 and 0.0 == 0 must not satisfy the planned control exit."""
    info = make_bundle(tmp_path)
    _update_replay(info.root, "vulnerable", "normal", exit_code=value)
    with pytest.raises(BundleError) as caught:
        verify_bundle(info.root)
    assert caught.value.reason_code == "INVALID_MANIFEST"


@pytest.mark.parametrize("value", [True, 0.0])
def test_control_mismatch_uses_the_strict_integer_predicate(value):
    control = {
        "status": "completed",
        "exit_code": value,
        "stdout": "OK\n",
        "stderr": "",
    }
    expected_exit = {"normal": 1 if value is True else 0}
    expected_stdout = {"normal": "OK\n", "candidate_clean": "ABCD\n"}
    assert (
        _control_mismatch(control, expected_exit, expected_stdout) == "exit"
    )


def test_verify_accepts_valid_reproduced_bundle(tmp_path):
    info = make_bundle(tmp_path)
    verified = verify_bundle(info.root)
    assert verified.manifest["verdict"] == "REPRODUCED"
    report = json.loads(verified.file_data["report.json"])
    assert report["replays"]
    assert len(report["replays"]) == 6
    assert len(report["builds"]) == 2
    for relative in MATERIALS:
        assert f"materials/{relative}" in verified.file_data


def _mutate_report(root: Path, mutate) -> None:
    report = json.loads((root / "report.json").read_text(encoding="utf-8"))
    mutate(report)
    _rewrite_manifested_file(root, "report.json", canonical(report))


def _set_manifest_reason(root: Path, reason: str | None) -> None:
    manifest_path = root / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["reason_code"] = reason
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")


def _set_verdict(root: Path, verdict: str, reason: str | None) -> None:
    manifest_path = root / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["verdict"] = verdict
    manifest["reason_code"] = reason
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    report = json.loads((root / "report.json").read_text(encoding="utf-8"))
    report["verdict"] = verdict
    report["reason_code"] = reason
    _rewrite_manifested_file(root, "report.json", canonical(report))


_UNSET = object()


def _update_replay(
    root: Path,
    version: str,
    phase: str,
    *,
    stdout: bytes | object = _UNSET,
    stderr: bytes | object = _UNSET,
    **fields,
) -> None:
    """Rewrite a replay record together with its evidence files and metadata."""
    from datacon.asan import parse_asan

    report = json.loads((root / "report.json").read_text(encoding="utf-8"))
    item = next(
        replay
        for replay in report["replays"]
        if replay["version"] == version and replay["phase"] == phase
    )
    if stdout is not _UNSET:
        data = bytes(stdout)
        _rewrite_manifested_file(
            root, f"replay/{version}/{phase}/stdout.log", data
        )
        item["stdout_sha256"] = digest(data)
        item["stdout_bytes"] = len(data)
        item["stdout_preview"] = data[:512].decode("utf-8", "replace")
        item.setdefault("file_digests", {})["stdout"] = digest(data)
    if stderr is not _UNSET:
        data = bytes(stderr)
        _rewrite_manifested_file(
            root, f"replay/{version}/{phase}/stderr.log", data
        )
        item["stderr_sha256"] = digest(data)
        item["stderr_bytes"] = len(data)
        item["stderr_preview"] = data[:512].decode("utf-8", "replace")
        item.setdefault("file_digests", {})["stderr"] = digest(data)
        parsed = parse_asan(data.decode("utf-8", "replace"))
        item["signature"] = parsed.as_dict() if parsed else None
    item.update(fields)
    if "status" in fields and "timed_out" not in fields:
        item["timed_out"] = fields["status"] == "timeout"
    _rewrite_manifested_file(
        root, f"replay/{version}/{phase}/metadata.json", canonical(item)
    )
    _rewrite_manifested_file(root, "report.json", canonical(report))


def _update_build(root: Path, version: str, **fields) -> None:
    report = json.loads((root / "report.json").read_text(encoding="utf-8"))
    item = next(
        build for build in report["builds"] if build["version"] == version
    )
    item.update(fields)
    _rewrite_manifested_file(
        root, f"build/{version}/metadata.json", canonical(item)
    )
    _rewrite_manifested_file(root, "report.json", canonical(report))


def _plan_without_candidate_asan() -> tuple[dict, dict, str]:
    """Return a valid plan/case config whose expected_exit has no ASan code."""
    plan = deepcopy(PLAN)
    expected = dict(plan["expected_exit"])
    expected.pop("candidate_asan")
    plan["expected_exit"] = expected
    case_config = deepcopy(CASE_CONFIG)
    case_config["manifest_case"]["expected_exit"] = dict(expected)
    plan["case_config_digest"] = jsonutil.digest_json(case_config)
    return plan, case_config, plan_digest(plan)


def _rebind_bundle_to_plan(
    root: Path, plan: dict, case_config: dict, digest_value: str
) -> None:
    """Rewrite every plan-bound document and manifest entry consistently."""
    _rewrite_manifested_file(root, "plan.json", canonical(plan))
    _rewrite_manifested_file(
        root,
        "metadata/case.json",
        canonical({"case_config": case_config}),
    )
    review = deepcopy(REVIEW)
    review["plan_digest"] = digest_value
    _rewrite_manifested_file(root, "review.json", canonical(review))
    report = json.loads((root / "report.json").read_text(encoding="utf-8"))
    report["plan_digest"] = digest_value
    for build in report["builds"]:
        build["plan_digest"] = digest_value
        _rewrite_manifested_file(
            root,
            f"build/{build['version']}/metadata.json",
            canonical(build),
        )
    for replay in report["replays"]:
        replay["plan_digest"] = digest_value
        _rewrite_manifested_file(
            root,
            f"replay/{replay['version']}/{replay['phase']}/metadata.json",
            canonical(replay),
        )
    _rewrite_manifested_file(root, "report.json", canonical(report))
    _rewrite_manifested_file(
        root,
        "metadata/execution.json",
        canonical(
            {
                "job_id": JOB_ID,
                "plan_digest": digest_value,
                "generation": 1,
            }
        ),
    )
    manifest_path = root / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["plan_digest"] = digest_value
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")


def _make_not_reproduced_bundle(tmp_path: Path, *, name: str):
    info = make_bundle(tmp_path, name=name)
    _set_verdict(info.root, "NOT_REPRODUCED", "CANDIDATE_CLEAN")
    for version in ("vulnerable", "fixed"):
        for phase in ("candidate_1", "candidate_2"):
            _update_replay(
                info.root,
                version,
                phase,
                stdout=b"ABCD\n",
                stderr=b"",
                status="completed",
                exit_code=0,
                timed_out=False,
            )
    return info


def test_verify_rejects_report_evidence_digest_mismatch(tmp_path):
    info = make_bundle(tmp_path)
    _rewrite_manifested_file(
        info.root,
        "replay/vulnerable/candidate_1/stderr.log",
        ASAN_LOG.encode() + b"tampered trailing data\n",
    )
    with pytest.raises(BundleError) as caught:
        verify_bundle(info.root)
    assert caught.value.reason_code in ("DIGEST_MISMATCH", "INVALID_MANIFEST")


def test_verify_rejects_build_metadata_not_matching_plan(tmp_path):
    info = make_bundle(tmp_path)

    def mutate(report):
        report["builds"][0]["image_digest"] = "sha256:" + "9" * 64

    _mutate_report(info.root, mutate)
    with pytest.raises(BundleError) as caught:
        verify_bundle(info.root)
    assert caught.value.reason_code in ("DIGEST_MISMATCH", "INVALID_MANIFEST")


def test_verify_rejects_build_staged_material_not_matching_plan(tmp_path):
    info = make_bundle(tmp_path)
    staged = dict(MATERIAL_DIGESTS)
    staged["harness.c"] = "sha256:" + "9" * 64
    _update_build(info.root, "vulnerable", staged_materials=staged)
    with pytest.raises(BundleError) as caught:
        verify_bundle(info.root)
    assert caught.value.reason_code == "DIGEST_MISMATCH"


@pytest.mark.parametrize(
    ("field", "value", "reason"),
    [
        ("image_digest", "sha256:" + "9" * 64, "DIGEST_MISMATCH"),
        ("asan_options", "detect_leaks=1:halt_on_error=1", "INVALID_MANIFEST"),
    ],
)
def test_verify_rejects_replay_environment_not_matching_plan(
    tmp_path, field, value, reason
):
    info = make_bundle(tmp_path)
    _update_replay(info.root, "fixed", "candidate_2", **{field: value})
    with pytest.raises(BundleError) as caught:
        verify_bundle(info.root)
    assert caught.value.reason_code == reason


@pytest.mark.parametrize(
    ("step", "field", "value"),
    [
        ("build", "plan_digest", "sha256:" + "9" * 64),
        ("build", "job_id", str(uuid4())),
        ("replay", "plan_digest", "sha256:" + "9" * 64),
        ("replay", "job_id", str(uuid4())),
    ],
)
def test_verify_rejects_build_or_replay_plan_provenance_mismatch(
    tmp_path, step, field, value
):
    info = make_bundle(tmp_path)
    if step == "build":
        _update_build(info.root, "vulnerable", **{field: value})
    else:
        _update_replay(info.root, "vulnerable", "candidate_1", **{field: value})
    with pytest.raises(BundleError) as caught:
        verify_bundle(info.root)
    assert caught.value.reason_code == "INVALID_MANIFEST"


def test_verify_rejects_execution_metadata_not_bound_to_manifest(tmp_path):
    info = make_bundle(tmp_path)
    _rewrite_manifested_file(
        info.root,
        "metadata/execution.json",
        canonical({"job_id": str(uuid4()), "plan_digest": PLAN_DIGEST}),
    )
    with pytest.raises(BundleError) as caught:
        verify_bundle(info.root)
    assert caught.value.reason_code == "INVALID_MANIFEST"


def test_verify_rejects_rule_trace_that_disagrees_with_report(tmp_path):
    info = make_bundle(tmp_path)
    rule = {
        "verdict": "INCONCLUSIVE",
        "reason_code": "OTHER_CRASH",
        "message": "mismatched audit attachment",
    }
    _replace_report(info.root, rule=rule)
    with pytest.raises(BundleError) as caught:
        verify_bundle(info.root)
    assert caught.value.reason_code == "INVALID_MANIFEST"


def test_verify_rejects_material_digest_not_matching_plan(tmp_path):
    info = make_bundle(tmp_path)
    _rewrite_manifested_file(info.root, "materials/build.sh", b"#!/bin/sh\nexit 0\n")
    with pytest.raises(BundleError) as caught:
        verify_bundle(info.root)
    assert caught.value.reason_code in ("DIGEST_MISMATCH", "INVALID_MANIFEST")


def test_verify_rejects_replay_signature_not_matching_log(tmp_path):
    info = make_bundle(tmp_path)

    def mutate(report):
        replay = next(
            item
            for item in report["replays"]
            if item["version"] == "vulnerable"
            and item["phase"] == "candidate_1"
        )
        replay["signature"] = {
            "error": "use-after-free",
            "function": "other_function",
        }

    _mutate_report(info.root, mutate)
    with pytest.raises(BundleError) as caught:
        verify_bundle(info.root)
    assert caught.value.reason_code in ("DIGEST_MISMATCH", "INVALID_MANIFEST")


def test_verify_rejects_reproduced_with_timeout_replays(tmp_path):
    info = make_bundle(tmp_path)

    def mutate(report):
        for replay in report["replays"]:
            if replay["version"] == "vulnerable" and replay["phase"].startswith(
                "candidate"
            ):
                replay["status"] = "timeout"
                replay["timed_out"] = True

    _mutate_report(info.root, mutate)
    with pytest.raises(BundleError) as caught:
        verify_bundle(info.root)
    assert caught.value.reason_code in ("DIGEST_MISMATCH", "INVALID_MANIFEST")


def test_verify_rejects_empty_builds_for_reproduced(tmp_path):
    info = make_bundle(tmp_path)
    _mutate_report(info.root, lambda report: report.update({"builds": []}))
    with pytest.raises(BundleError) as caught:
        verify_bundle(info.root)
    assert caught.value.reason_code in ("DIGEST_MISMATCH", "INVALID_MANIFEST")


def test_verify_rejects_replay_input_mismatch(tmp_path):
    info = make_bundle(tmp_path)

    def mutate(report):
        replay = next(
            item
            for item in report["replays"]
            if item["version"] == "fixed" and item["phase"] == "candidate_2"
        )
        replay["input_digest"] = PLAN["inputs"]["normal"]

    _mutate_report(info.root, mutate)
    with pytest.raises(BundleError) as caught:
        verify_bundle(info.root)
    assert caught.value.reason_code in ("DIGEST_MISMATCH", "INVALID_MANIFEST")


def test_verify_rejects_manifest_reason_not_in_verdict_set(tmp_path):
    info = make_bundle(tmp_path)
    _mutate_report(info.root, lambda report: report.update({"reason_code": "TIMEOUT"}))
    _set_manifest_reason(info.root, "TIMEOUT")
    with pytest.raises(BundleError) as caught:
        verify_bundle(info.root)
    assert caught.value.reason_code in ("DIGEST_MISMATCH", "INVALID_MANIFEST")


def test_verify_rejects_null_manifest_reason_for_full_verdict(tmp_path):
    info = make_bundle(tmp_path)
    _set_manifest_reason(info.root, None)
    with pytest.raises(BundleError) as caught:
        verify_bundle(info.root)
    assert caught.value.reason_code in ("DIGEST_MISMATCH", "INVALID_MANIFEST")


def test_verify_rejects_unknown_replay_status(tmp_path):
    info = make_bundle(tmp_path)

    def mutate(report):
        report["replays"][0]["status"] = "definitely-not-a-status"

    _mutate_report(info.root, mutate)
    with pytest.raises(BundleError) as caught:
        verify_bundle(info.root)
    assert caught.value.reason_code in ("DIGEST_MISMATCH", "INVALID_MANIFEST")


def test_verify_bundle_rejects_oversized_file_before_read(tmp_path, monkeypatch):
    info = make_bundle(tmp_path)
    manifest = json.loads((info.root / "manifest.json").read_text(encoding="utf-8"))
    entry = next(
        item for item in manifest["files"] if item["path"] == "plan.json"
    )
    target = info.root / "plan.json"
    os.truncate(target, entry["size_bytes"] + 1024)

    def forbidden_read_bytes(self):
        raise AssertionError(f"read_bytes must not be used for {self}")

    monkeypatch.setattr(Path, "read_bytes", forbidden_read_bytes)
    with pytest.raises(BundleError) as caught:
        verify_bundle(info.root)
    assert caught.value.reason_code in ("DIGEST_MISMATCH", "FILE_TOO_LARGE")


def test_verify_bundle_rejects_total_size_over_cap(tmp_path, monkeypatch):
    import datacon.evidence as evidence_module

    info = make_bundle(tmp_path)
    monkeypatch.setattr(evidence_module, "MAX_TOTAL_BYTES", 1, raising=False)
    with pytest.raises(BundleError) as caught:
        verify_bundle(info.root)
    assert caught.value.reason_code == "FILE_TOO_LARGE"


def test_manifest_verdict_must_match_report(tmp_path):
    info = make_bundle(tmp_path)
    manifest_path = info.root / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["verdict"] = "NOT_REPRODUCED"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    with pytest.raises(BundleError) as caught:
        verify_bundle(info.root)
    assert caught.value.reason_code == "INVALID_MANIFEST"


def test_report_verdict_must_be_a_known_value(tmp_path):
    info = make_bundle(tmp_path)
    _replace_report(info.root, verdict="PROBABLY_FIXED")
    with pytest.raises(BundleError) as caught:
        verify_bundle(info.root)
    assert caught.value.reason_code == "INVALID_MANIFEST"


def test_replaced_plan_content_fails_semantic_digest_check(tmp_path):
    info = make_bundle(tmp_path)
    changed = deepcopy(PLAN)
    changed["case_id"] = "fixture-c-parser-clean"
    _rewrite_manifested_file(info.root, "plan.json", canonical(changed))
    with pytest.raises(BundleError) as caught:
        verify_bundle(info.root)
    assert caught.value.reason_code == "INVALID_MANIFEST"


def test_report_plan_digest_must_match_recomputed_plan(tmp_path):
    info = make_bundle(tmp_path)
    _replace_report(info.root, plan_digest="sha256:" + ("0" * 64))
    with pytest.raises(BundleError) as caught:
        verify_bundle(info.root)
    assert caught.value.reason_code == "INVALID_MANIFEST"


def test_review_must_approve_the_manifest_plan(tmp_path):
    info = make_bundle(tmp_path)
    rejected = deepcopy(REVIEW)
    rejected["decision"] = "reject"
    _rewrite_manifested_file(info.root, "review.json", canonical(rejected))
    with pytest.raises(BundleError) as caught:
        verify_bundle(info.root)
    assert caught.value.reason_code == "INVALID_MANIFEST"


def test_review_must_bind_the_same_plan(tmp_path):
    info = make_bundle(tmp_path)
    other = deepcopy(REVIEW)
    other["plan_digest"] = "sha256:" + ("1" * 64)
    _rewrite_manifested_file(info.root, "review.json", canonical(other))
    with pytest.raises(BundleError) as caught:
        verify_bundle(info.root)
    assert caught.value.reason_code == "INVALID_MANIFEST"


@pytest.mark.parametrize("count", [0, 5])
def test_incomplete_replay_report_is_rejected(tmp_path, count):
    info = make_bundle(tmp_path)
    _replace_report(info.root, replays=deepcopy(REPORT["replays"][:count]))
    with pytest.raises(BundleError) as caught:
        verify_bundle(info.root)
    assert caught.value.reason_code == "INVALID_MANIFEST"


def test_unknown_replay_phase_is_rejected(tmp_path):
    info = make_bundle(tmp_path)
    replays = deepcopy(REPORT["replays"])
    replays[0]["phase"] = "candidate_9"
    _replace_report(info.root, replays=replays)
    with pytest.raises(BundleError) as caught:
        verify_bundle(info.root)
    assert caught.value.reason_code == "INVALID_MANIFEST"


def test_duplicate_replay_phase_is_rejected(tmp_path):
    info = make_bundle(tmp_path)
    replays = deepcopy(REPORT["replays"])
    replays[1] = deepcopy(replays[0])
    _replace_report(info.root, replays=replays)
    with pytest.raises(BundleError) as caught:
        verify_bundle(info.root)
    assert caught.value.reason_code == "INVALID_MANIFEST"


def test_report_job_id_must_match_manifest(tmp_path):
    info = make_bundle(tmp_path)
    _replace_report(info.root, job_id=str(uuid4()))
    with pytest.raises(BundleError) as caught:
        verify_bundle(info.root)
    assert caught.value.reason_code == "INVALID_MANIFEST"


def test_missing_execution_evidence_is_rejected(tmp_path):
    info = make_bundle(tmp_path)
    (info.root / "metadata" / "probe.json").unlink()
    with pytest.raises(BundleError) as caught:
        verify_bundle(info.root)
    assert caught.value.reason_code == "MISSING_FILE"


def test_reproduced_bundle_with_only_four_base_roles_is_rejected(tmp_path):
    info = make_bundle(tmp_path, full=False)
    with pytest.raises(BundleError) as caught:
        verify_bundle(info.root)
    assert caught.value.reason_code == "INVALID_MANIFEST"


@pytest.mark.parametrize("verdict", ["BLOCKED", "FAILED"])
def test_minimal_blocked_or_failed_bundle_is_accepted(tmp_path, verdict):
    report = deepcopy(REPORT)
    report["verdict"] = verdict
    report["reason_code"] = "POLICY_DENIED" if verdict == "BLOCKED" else "EVIDENCE_WRITE_FAILED"
    report["replays"] = []
    report["builds"] = []
    info = make_bundle(tmp_path, report=report, full=False)
    verified = verify_bundle(info.root)
    assert verified.manifest["verdict"] == verdict


def test_missing_file_is_rejected(tmp_path):
    info = make_bundle(tmp_path)
    (info.root / "replay" / "vulnerable" / "candidate_1" / "stderr.log").unlink()
    with pytest.raises(BundleError) as caught:
        verify_bundle(info.root)
    assert caught.value.reason_code == "MISSING_FILE"


def test_digest_mismatch_is_rejected(tmp_path):
    info = make_bundle(tmp_path)
    target = info.root / "plan.json"
    target.write_bytes(b'{"case_id":"tampered"}\n')
    with pytest.raises(BundleError) as caught:
        verify_bundle(info.root)
    assert caught.value.reason_code == "DIGEST_MISMATCH"
    assert "plan.json" in str(caught.value)


def test_extra_file_is_rejected(tmp_path):
    info = make_bundle(tmp_path)
    (info.root / "surprise.txt").write_text("extra", encoding="utf-8")
    with pytest.raises(BundleError) as caught:
        verify_bundle(info.root)
    assert caught.value.reason_code == "EXTRA_FILE"


def test_symlink_inside_bundle_is_rejected(tmp_path):
    info = make_bundle(tmp_path)
    (info.root / "link.log").symlink_to(info.root / "plan.json")
    with pytest.raises(BundleError) as caught:
        verify_bundle(info.root)
    assert caught.value.reason_code == "SYMLINK"


def test_symlinked_bundle_root_is_rejected(tmp_path):
    info = make_bundle(tmp_path)
    link = tmp_path / "bundle-link"
    link.symlink_to(info.root, target_is_directory=True)
    with pytest.raises(BundleError) as caught:
        verify_bundle(link)
    assert caught.value.reason_code == "SYMLINK"


def _tamper_manifest(tmp_path: Path, entry: dict) -> Path:
    info = make_bundle(tmp_path)
    manifest = json.loads((info.root / "manifest.json").read_text(encoding="utf-8"))
    manifest["files"].append(entry)
    (info.root / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    return info.root


@pytest.mark.parametrize(
    "path",
    [
        "../outside",
        "/etc/passwd",
        "a/../../b",
        "a\\..\\b",
        "./plan.json",
        "C:/windows/system32/config",
        "C:\\windows\\system32\\config",
        "//server/share/plan.json",
    ],
    ids=[
        "parent",
        "absolute",
        "nested-parent",
        "backslash",
        "dot-segment",
        "windows-drive-slash",
        "windows-drive-backslash",
        "unc",
    ],
)
def test_unsafe_manifest_paths_are_rejected(tmp_path, path):
    root = _tamper_manifest(
        tmp_path,
        {
            "path": path,
            "role": "plan",
            "size_bytes": 0,
            "sha256": "0" * 64,
        },
    )
    with pytest.raises(BundleError) as caught:
        verify_bundle(root)
    assert caught.value.reason_code == "UNSAFE_PATH"


def test_duplicate_manifest_entries_are_rejected(tmp_path):
    info = make_bundle(tmp_path)
    manifest = json.loads((info.root / "manifest.json").read_text(encoding="utf-8"))
    manifest["files"].append(dict(manifest["files"][0]))
    (info.root / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    with pytest.raises(BundleError) as caught:
        verify_bundle(info.root)
    assert caught.value.reason_code == "DUPLICATE_ENTRY"


@pytest.mark.parametrize(
    "mutation",
    [
        lambda manifest: manifest.update({"schema_version": 2}),
        lambda manifest: manifest.pop("files"),
        lambda manifest: manifest.update({"job_id": "not-a-uuid"}),
        lambda manifest: manifest.update({"plan_digest": "bad"}),
        lambda manifest: manifest["files"][0].update({"size_bytes": -1}),
        lambda manifest: manifest["files"][0].update({"sha256": "xyz"}),
        lambda manifest: manifest.update({"verdict": "UNKNOWN"}),
    ],
    ids=["schema", "files", "job-id", "plan-digest", "size", "sha", "verdict"],
)
def test_malformed_manifest_is_rejected(tmp_path, mutation):
    info = make_bundle(tmp_path)
    manifest = json.loads((info.root / "manifest.json").read_text(encoding="utf-8"))
    mutation(manifest)
    (info.root / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    with pytest.raises(BundleError) as caught:
        verify_bundle(info.root)
    assert caught.value.reason_code == "INVALID_MANIFEST"


def test_export_refuses_non_empty_destination(tmp_path):
    info = make_bundle(tmp_path)
    destination = tmp_path / "occupied"
    destination.mkdir()
    (destination / "existing").write_text("keep", encoding="utf-8")
    with pytest.raises(BundleError) as caught:
        export_bundle(info.root, destination)
    assert caught.value.reason_code == "EXPORT_TARGET_NOT_EMPTY"
    assert (destination / "existing").read_text() == "keep"


def test_export_accepts_an_existing_empty_directory(tmp_path):
    info = make_bundle(tmp_path)
    destination = tmp_path / "empty"
    destination.mkdir()
    exported = export_bundle(info.root, destination)
    assert exported.manifest_digest == info.manifest_digest
    assert (destination / "report.json").is_file()


def test_export_rejects_a_destination_inside_the_bundle(tmp_path):
    info = make_bundle(tmp_path)
    with pytest.raises(BundleError) as caught:
        export_bundle(info.root, info.root / "nested")
    assert caught.value.reason_code == "EXPORT_TARGET_NOT_EMPTY"


def test_export_rejects_expected_digest_mismatch_without_leftovers(tmp_path):
    info = make_bundle(tmp_path)
    destination = tmp_path / "exported"
    with pytest.raises(BundleError) as caught:
        export_bundle(
            info.root,
            destination,
            expected_manifest_digest="sha256:" + ("0" * 64),
        )
    assert caught.value.reason_code == "DIGEST_MISMATCH"
    assert not destination.exists()
    assert not list(tmp_path.glob(".exported.export-*"))


def test_export_detects_source_replacement_between_verify_and_copy(
    tmp_path, monkeypatch
):
    info = make_bundle(tmp_path)
    destination = tmp_path / "copy"
    original = verify_bundle

    def verify_then_replace(root):
        verified = original(root)
        manifest_path = Path(root) / "manifest.json"
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        manifest["verdict"] = "INCONCLUSIVE"
        manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
        return verified

    monkeypatch.setattr("datacon.evidence.verify_bundle", verify_then_replace)
    with pytest.raises(BundleError) as caught:
        export_bundle(info.root, destination)
    assert caught.value.reason_code == "DIGEST_MISMATCH"
    assert not destination.exists()


def test_export_copies_verified_manifest_bytes_not_a_reread(tmp_path, monkeypatch):
    info = make_bundle(tmp_path)
    original = verify_bundle

    def verify_then_replace(root):
        verified = original(root)
        # Replace the on-disk manifest with a valid-looking different one.
        manifest_path = Path(root) / "manifest.json"
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        manifest["created_at"] = "2030-01-01T00:00:00Z"
        manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
        return verified

    monkeypatch.setattr("datacon.evidence.verify_bundle", verify_then_replace)
    with pytest.raises(BundleError):
        export_bundle(info.root, tmp_path / "copy")


def test_export_verifies_the_copied_bundle(tmp_path, monkeypatch):
    info = make_bundle(tmp_path)
    original = verify_bundle

    def broken(root):
        raise BundleError("DIGEST_MISMATCH", "copy failed")

    monkeypatch.setattr("datacon.evidence.verify_bundle", broken)
    with pytest.raises(BundleError):
        export_bundle(info.root, tmp_path / "copy")
    assert original is not broken


def test_canonical_manifest_digest_is_stable_under_key_order(tmp_path):
    first = {"schema_version": 1, "job_id": JOB_ID, "files": []}
    second = {"files": [], "job_id": JOB_ID, "schema_version": 1}
    assert canonical_manifest_digest(first) == canonical_manifest_digest(second)


def test_manifest_does_not_list_itself(tmp_path):
    info = make_bundle(tmp_path)
    paths = {entry["path"] for entry in info.manifest["files"]}
    assert "manifest.json" not in paths


def test_report_bytes_obey_the_evidence_size_cap(tmp_path, monkeypatch):
    import datacon.evidence as evidence

    monkeypatch.setattr(evidence, "MAX_FILE_BYTES", 4096)
    report = deepcopy(REPORT)
    report["error"] = "x" * 8192
    with pytest.raises(BundleError) as caught:
        write_bundle(
            tmp_path / "oversized",
            job_id=report["job_id"],
            plan_digest=report["plan_digest"],
            report=report,
            report_markdown="# report\n",
            artifacts={
                "plan.json": ("plan", canonical(PLAN)),
                "review.json": ("review", canonical(REVIEW)),
            },
        )
    assert caught.value.reason_code == "FILE_TOO_LARGE"
    assert not (tmp_path / "oversized").exists()


def test_report_markdown_obeys_the_evidence_size_cap(tmp_path, monkeypatch):
    import datacon.evidence as evidence

    monkeypatch.setattr(evidence, "MAX_FILE_BYTES", 4096)
    with pytest.raises(BundleError) as caught:
        write_bundle(
            tmp_path / "oversized",
            job_id=REPORT["job_id"],
            plan_digest=REPORT["plan_digest"],
            report=REPORT,
            report_markdown="# " + ("x" * 8192),
            artifacts={
                "plan.json": ("plan", canonical(PLAN)),
                "review.json": ("review", canonical(REVIEW)),
            },
        )
    assert caught.value.reason_code == "FILE_TOO_LARGE"


# ---------------------------------------------------------------------------
# R2: inconclusive timeout/resource/infra controls are valid evidence.
# ---------------------------------------------------------------------------


def test_inconclusive_timeout_accepts_timed_out_normal_control(tmp_path):
    info = make_bundle(tmp_path, name="timeout-control")
    _set_verdict(info.root, "INCONCLUSIVE", "TIMEOUT")
    _update_replay(
        info.root,
        "vulnerable",
        "normal",
        status="timeout",
        exit_code=None,
        timed_out=True,
    )
    verified = verify_bundle(info.root)
    assert verified.manifest["reason_code"] == "TIMEOUT"


def test_inconclusive_resource_limited_accepts_limited_normal_control(tmp_path):
    info = make_bundle(tmp_path, name="resource-control")
    _set_verdict(info.root, "INCONCLUSIVE", "RESOURCE_LIMITED")
    _update_replay(
        info.root,
        "fixed",
        "normal",
        status="resource_limited",
        exit_code=137,
        timed_out=False,
    )
    verified = verify_bundle(info.root)
    assert verified.manifest["reason_code"] == "RESOURCE_LIMITED"


def test_inconclusive_evidence_incomplete_accepts_infra_error_control(tmp_path):
    info = make_bundle(tmp_path, name="infra-control")
    _set_verdict(info.root, "INCONCLUSIVE", "EVIDENCE_INCOMPLETE")
    _update_replay(
        info.root,
        "vulnerable",
        "normal",
        status="infra_error",
        exit_code=None,
        timed_out=False,
    )
    verified = verify_bundle(info.root)
    assert verified.manifest["reason_code"] == "EVIDENCE_INCOMPLETE"


def test_reproduced_rejects_timed_out_normal_control(tmp_path):
    info = make_bundle(tmp_path, name="reproduced-timeout-control")
    _update_replay(
        info.root,
        "vulnerable",
        "normal",
        status="timeout",
        exit_code=None,
        timed_out=True,
    )
    with pytest.raises(BundleError) as caught:
        verify_bundle(info.root)
    assert caught.value.reason_code in ("DIGEST_MISMATCH", "INVALID_MANIFEST")


# ---------------------------------------------------------------------------
# R3: truncated logs are evidence only for an inconclusive reason.
# ---------------------------------------------------------------------------


def test_inconclusive_not_comparable_accepts_truncated_build_log(tmp_path):
    info = make_bundle(tmp_path, name="truncated-build")
    _set_verdict(info.root, "INCONCLUSIVE", "NOT_COMPARABLE")
    _update_build(info.root, "vulnerable", log_truncated=True)
    verified = verify_bundle(info.root)
    assert verified.manifest["verdict"] == "INCONCLUSIVE"


def test_inconclusive_evidence_incomplete_accepts_truncated_replay_log(tmp_path):
    info = make_bundle(tmp_path, name="truncated-replay")
    _set_verdict(info.root, "INCONCLUSIVE", "EVIDENCE_INCOMPLETE")
    _update_replay(
        info.root, "vulnerable", "candidate_1", log_truncated=True
    )
    verified = verify_bundle(info.root)
    assert verified.manifest["verdict"] == "INCONCLUSIVE"


def test_reproduced_rejects_truncated_build_log(tmp_path):
    info = make_bundle(tmp_path, name="reproduced-truncated-build")
    _update_build(info.root, "fixed", log_truncated=True)
    with pytest.raises(BundleError) as caught:
        verify_bundle(info.root)
    assert caught.value.reason_code == "INVALID_MANIFEST"


def test_reproduced_rejects_truncated_replay_log(tmp_path):
    info = make_bundle(tmp_path, name="reproduced-truncated-replay")
    _update_replay(info.root, "fixed", "candidate_2", log_truncated=True)
    with pytest.raises(BundleError) as caught:
        verify_bundle(info.root)
    assert caught.value.reason_code == "INVALID_MANIFEST"


def test_truncated_replay_still_must_match_the_parsed_signature(tmp_path):
    info = make_bundle(tmp_path, name="truncated-signature")
    _set_verdict(info.root, "INCONCLUSIVE", "EVIDENCE_INCOMPLETE")
    _update_replay(
        info.root,
        "vulnerable",
        "candidate_1",
        log_truncated=True,
        signature={"error": "use-after-free", "function": "other_function"},
    )
    with pytest.raises(BundleError) as caught:
        verify_bundle(info.root)
    assert caught.value.reason_code == "INVALID_MANIFEST"


def test_truncated_build_log_still_must_match_its_digest(tmp_path):
    info = make_bundle(tmp_path, name="truncated-build-digest")
    _set_verdict(info.root, "INCONCLUSIVE", "NOT_COMPARABLE")
    _update_build(info.root, "vulnerable", log_truncated=True)
    _rewrite_manifested_file(
        info.root, "build/vulnerable/build.log", b"different build log\n"
    )
    with pytest.raises(BundleError) as caught:
        verify_bundle(info.root)
    assert caught.value.reason_code == "DIGEST_MISMATCH"


# ---------------------------------------------------------------------------
# R4: expected stdout is part of the offline semantic check.
# ---------------------------------------------------------------------------


def test_reproduced_rejects_wrong_fixed_candidate_stdout(tmp_path):
    info = make_bundle(tmp_path, name="wrong-fixed-stdout")
    _update_replay(info.root, "fixed", "candidate_1", stdout=b"WRONG\n")
    with pytest.raises(BundleError) as caught:
        verify_bundle(info.root)
    assert caught.value.reason_code == "INVALID_MANIFEST"


def test_reproduced_rejects_wrong_normal_stdout(tmp_path):
    info = make_bundle(tmp_path, name="wrong-normal-stdout")
    _update_replay(info.root, "vulnerable", "normal", stdout=b"WRONG\n")
    with pytest.raises(BundleError) as caught:
        verify_bundle(info.root)
    assert caught.value.reason_code == "INVALID_MANIFEST"


def test_not_reproduced_accepts_matching_candidate_stdout(tmp_path):
    info = _make_not_reproduced_bundle(tmp_path, name="clean-stdout")
    verified = verify_bundle(info.root)
    assert verified.manifest["verdict"] == "NOT_REPRODUCED"


def test_not_reproduced_rejects_wrong_candidate_stdout(tmp_path):
    info = _make_not_reproduced_bundle(tmp_path, name="wrong-clean-stdout")
    _update_replay(info.root, "vulnerable", "candidate_2", stdout=b"WRONG\n")
    with pytest.raises(BundleError) as caught:
        verify_bundle(info.root)
    assert caught.value.reason_code == "INVALID_MANIFEST"


# ---------------------------------------------------------------------------
# R5: BLOCKED reason set includes material I/O failures.
# ---------------------------------------------------------------------------


def test_blocked_material_io_error_bundle_verifies(tmp_path):
    report = deepcopy(REPORT)
    report["verdict"] = "BLOCKED"
    report["reason_code"] = "MATERIAL_IO_ERROR"
    report["replays"] = []
    report["builds"] = []
    info = make_bundle(tmp_path, report=report, full=False, name="blocked-io")
    verified = verify_bundle(info.root)
    assert verified.manifest["verdict"] == "BLOCKED"
    assert verified.manifest["reason_code"] == "MATERIAL_IO_ERROR"


def test_blocked_reason_set_stays_closed():
    assert reason_allowed("BLOCKED", "MATERIAL_IO_ERROR")
    assert not reason_allowed("BLOCKED", "NOT_A_REAL_REASON")
    assert not reason_allowed("FAILED", "MATERIAL_IO_ERROR")


def test_truncated_replay_log_still_must_match_its_output_digests(tmp_path):
    info = make_bundle(tmp_path, name="truncated-replay-digest")
    _set_verdict(info.root, "INCONCLUSIVE", "EVIDENCE_INCOMPLETE")
    _update_replay(
        info.root, "vulnerable", "candidate_1", log_truncated=True
    )
    _rewrite_manifested_file(
        info.root,
        "replay/vulnerable/candidate_1/stdout.log",
        b"different stdout\n",
    )
    with pytest.raises(BundleError) as caught:
        verify_bundle(info.root)
    assert caught.value.reason_code == "DIGEST_MISMATCH"
