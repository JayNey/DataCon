"""T13 / TC-15 / TC-06 / TC-03: build provenance, effective flags and BuildSpec contracts.

Test coordinates are anchored to docs/spec/v0.2/test-plan-delta.md §2 (T13),
docs/spec/v0.2/interface-contract-delta.md §5 & §8, and ADR-005.
"""

from __future__ import annotations

from copy import deepcopy
import hashlib
import json
from pathlib import Path
from typing import Any
from uuid import uuid4

import pytest
from test_plan import PLAN as BASE_PLAN_V1

from datacon import build_provenance as provenance, contracts, evidence, jsonutil

PROVENANCE_FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "provenance"
REPO_ROOT = "/work/repo"

BASE_DECLARED_FLAGS = [
    "-fsanitize=address",
    "-g",
    "-O1",
    "-Iinclude",
    "-D_GNU_SOURCE",
]


def _fixture_bytes(name: str) -> bytes:
    path = PROVENANCE_FIXTURES / name
    assert path.is_file(), f"missing provenance test fixture: {path}"
    return path.read_bytes()


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _make_build_spec(
    *,
    kind: str = "cmake",
    declared_compile_flags: list[str] | None = None,
    env: dict[str, str] | None = None,
    configure: list[str] | None = None,
    build: list[str] | None = None,
    shell_recipe_digest: str | None = None,
    shell_face_digest: str | None = None,
    shell_face_review: dict[str, Any] | None = None,
) -> dict[str, Any]:
    flags = (
        list(declared_compile_flags)
        if declared_compile_flags is not None
        else list(BASE_DECLARED_FLAGS)
    )
    spec: dict[str, Any] = {
        "kind": kind,
        "build": (
            list(build)
            if build is not None
            else (
                ["cmake", "--build", "build", "--target", "parser"]
                if kind == "cmake"
                else ["make", "-C", "src", "parser"]
            )
        ),
        "install": [],
        "env": env
        if env is not None
        else {
            "CC": "/opt/datacon/cc-shim" if kind == "make" else "clang",
            "CFLAGS": " ".join(flags),
        },
        "outputs": ["build/parser" if kind == "cmake" else "src/parser"],
        "declared_compile_flags": flags,
        "shell_recipe_digest": shell_recipe_digest,
        "shell_face_digest": shell_face_digest,
        "shell_face_review": shell_face_review,
    }
    if kind == "cmake":
        spec["configure"] = (
            list(configure)
            if configure is not None
            else [
                "cmake",
                "-S",
                ".",
                "-B",
                "build",
                "-DCMAKE_BUILD_TYPE=RelWithDebInfo",
                "-DCMAKE_C_COMPILER=clang",
            ]
        )
    return spec


def _make_plan_v2(*, rules_version: str = "build-provenance-v1") -> dict[str, Any]:
    family_id = str(uuid4())
    build_spec = _make_build_spec(kind="cmake")
    plan = deepcopy(BASE_PLAN_V1)
    plan.update(
        {
            "schema_version": 2,
            "family_id": family_id,
            "parent_job_id": family_id,
            "round_no": 1,
            "parent_approval_digest": None,
            "envelope_digest": "sha256:" + "5" * 64,
            "build_ref": None,
            "build_spec": build_spec,
            "compile_flags": list(BASE_DECLARED_FLAGS),
            "build_recipe_digest": jsonutil.digest_json(build_spec),
            "experiment_digest": None,
            "build_provenance_rules_version": rules_version,
            "policy_version": "policy-v2.0",
        }
    )
    return plan


def _write_v2_bundle(
    root: Path,
    *,
    bundle_kind: str,
    provenance_versions: tuple[str, ...] = ("vulnerable", "fixed"),
    report_rules_version: str | None = None,
) -> Path:
    root.mkdir(parents=True, exist_ok=False)
    family_id = str(uuid4())
    job_id = str(uuid4())
    plan = _make_plan_v2()
    plan["family_id"] = family_id
    plan["parent_job_id"] = family_id
    if bundle_kind == "campaign":
        plan["round_no"] = None
        plan["inputs"] = None

    envelope = {
        "mode": "guided" if bundle_kind == "campaign" else "fixed",
        "allowed_mutation_families": ["byte_flip"] if bundle_kind == "campaign" else [],
        "mutation_limits": (
            {"allowed_ops": ["byte_flip"], "max_input_bytes": 4096}
            if bundle_kind == "campaign"
            else {"allowed_ops": [], "max_input_bytes": 0}
        ),
        "seed_corpus_digest": "sha256:" + "1" * 64 if bundle_kind == "campaign" else None,
        "fuzz_image_digest": plan["image_digest"] if bundle_kind == "campaign" else None,
        "harness_digest": plan["harness_digest"],
        "max_rounds": 4 if bundle_kind == "campaign" else 1,
        "max_total_seconds": 900,
        "max_fuzz_seconds": 300 if bundle_kind == "campaign" else 0,
        "accepted_signature_set": [plan["asan_signature"]],
        "admission_predicate_version": "admission-v1",
    }
    envelope_digest = jsonutil.digest_json(envelope)
    envelope_bytes = jsonutil.canonical_bytes(envelope) + b"\n"

    plan["envelope_digest"] = envelope_digest
    plan_digest = jsonutil.digest_json(
        {key: value for key, value in plan.items() if key != "analysis"}
    )
    plan_bytes = jsonutil.canonical_bytes(plan) + b"\n"

    review_doc = {
        "job_id": family_id,
        "plan_digest": plan_digest,
        "decision": "approve",
        "reviewer_id": "reviewer-01",
        "decided_at": "2099-01-01T00:00:00.000000Z",
    }
    report_review = {
        "reviewer_id": review_doc["reviewer_id"],
        "decision": review_doc["decision"],
        "plan_digest": review_doc["plan_digest"],
        "decided_at": review_doc["decided_at"],
    }

    replays_list: list[dict[str, Any]] = []
    if bundle_kind == "execution":
        for version in ("vulnerable", "fixed"):
            for phase in ("normal", "candidate_1", "candidate_2"):
                input_digest = (
                    plan["inputs"]["normal"]
                    if phase == "normal"
                    else plan["inputs"]["candidate"]
                )
                replays_list.append(
                    {
                        "version": version,
                        "phase": phase,
                        "status": "completed",
                        "input_digest": input_digest,
                    }
                )

    verdict = None if bundle_kind == "campaign" else "INCONCLUSIVE"
    reason_code = None if bundle_kind == "campaign" else "EVIDENCE_INCOMPLETE"
    report_md = (
        f"# DataCon Report\n\n"
        f"- Verdict: **{verdict or 'PENDING'}**\n"
        f"- Reason: `{reason_code or ''}`\n"
    ).encode("utf-8")

    effective_report_rules = (
        report_rules_version
        if report_rules_version is not None
        else plan["build_provenance_rules_version"]
    )
    report_doc: dict[str, Any] = {
        "schema_version": 2,
        "bundle_kind": bundle_kind,
        "family_id": family_id,
        "job_id": job_id,
        "parent_job_id": family_id,
        "round_no": None if bundle_kind == "campaign" else 1,
        "case_id": plan["case_id"],
        "cve_id": plan["cve_id"],
        "plan_digest": plan_digest,
        "envelope_digest": envelope_digest,
        "verdict": verdict,
        "state": verdict,
        "reason_code": reason_code,
        "review": report_review,
        "build_ref": None,
        "reuse_origin": None,
        "experiment_digest": None,
        "build_provenance_rules_version": effective_report_rules,
        "build_provenance": {
            "vulnerable": {
                "face": "compile_commands.json",
                "declared": list(BASE_DECLARED_FLAGS),
                "effective": list(BASE_DECLARED_FLAGS),
            },
            "fixed": {
                "face": "compile_commands.json",
                "declared": list(BASE_DECLARED_FLAGS),
                "effective": list(BASE_DECLARED_FLAGS),
            },
            "comparable": True,
        },
        "admissions": [],
        "experiments": [],
        "budget": {
            "max_total_seconds": 900,
            "max_fuzz_seconds": 300 if bundle_kind == "campaign" else 0,
            "spent_seconds": 10,
            "spent_fuzz_seconds": 5 if bundle_kind == "campaign" else 0,
            "remaining_seconds": 890,
            "remaining_fuzz_seconds": 295 if bundle_kind == "campaign" else 0,
        },
        "missing": [],
        "error": None,
        "evidence_complete": True,
        "report_markdown_sha256": _sha256_hex(report_md),
    }
    if bundle_kind == "execution":
        report_doc["replays"] = replays_list

    files_spec: dict[str, tuple[str, bytes]] = {
        "report.json": ("report_json", jsonutil.canonical_bytes(report_doc) + b"\n"),
        "report.md": ("report_markdown", report_md),
        "plan.json": ("plan", plan_bytes),
        "review.json": ("review", jsonutil.canonical_bytes(review_doc) + b"\n"),
        "envelope.json": ("envelope", envelope_bytes),
        "budget/snapshot.json": (
            "budget_snapshot",
            jsonutil.canonical_bytes(report_doc["budget"]) + b"\n",
        ),
        "metadata/execution.json": (
            "execution_metadata",
            jsonutil.canonical_bytes(
                {"job_id": job_id, "plan_digest": plan_digest, "generation": 1}
            )
            + b"\n",
        ),
        "metadata/probe.json": (
            "probe",
            jsonutil.canonical_bytes({"status": "completed"}) + b"\n",
        ),
        "metadata/case.json": (
            "case_config",
            jsonutil.canonical_bytes({"case_id": plan["case_id"]}) + b"\n",
        ),
    }

    for version, fixture_name in (
        ("vulnerable", "cmake_comparable_vulnerable.compile_commands.json"),
        ("fixed", "cmake_comparable_fixed.compile_commands.json"),
    ):
        files_spec[f"build/{version}/metadata.json"] = (
            "build_metadata",
            jsonutil.canonical_bytes({"version": version, "status": "completed"}) + b"\n",
        )
        files_spec[f"build/{version}/build.log"] = (
            "build_log",
            f"build {version} ok\n".encode("utf-8"),
        )
        files_spec[f"build/{version}/parser"] = (
            "build_artifact",
            f"elf-{version}".encode("utf-8"),
        )
        if version in provenance_versions:
            files_spec[f"build/{version}/build_provenance/compile_commands.json"] = (
                "build_provenance",
                _fixture_bytes(fixture_name),
            )

    if bundle_kind == "campaign":
        files_spec["fuzz/fuzz.log"] = ("fuzz_log", b"libFuzzer campaign ok\n")
        files_spec["fuzz/provenance.json"] = (
            "fuzz_provenance",
            jsonutil.canonical_bytes({"rng_seed": 42, "crashes": 0}) + b"\n",
        )
    else:
        for replay_item in replays_list:
            version = replay_item["version"]
            phase = replay_item["phase"]
            stdout_role = "normal_output" if phase == "normal" else "replay_stdout"
            stderr_role = "normal_error" if phase == "normal" else "asan_log"
            files_spec[f"replay/{version}/{phase}/stdout.log"] = (
                stdout_role,
                b"OK\n",
            )
            files_spec[f"replay/{version}/{phase}/stderr.log"] = (
                stderr_role,
                b"",
            )
            files_spec[f"replay/{version}/{phase}/metadata.json"] = (
                "replay_metadata",
                jsonutil.canonical_bytes(replay_item) + b"\n",
            )

    entries: list[dict[str, Any]] = []
    for rel_path, (role, payload) in sorted(files_spec.items()):
        dest = root / rel_path
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(payload)
        entries.append(
            {
                "path": rel_path,
                "role": role,
                "size_bytes": len(payload),
                "sha256": _sha256_hex(payload),
            }
        )

    manifest = {
        "schema_version": 2,
        "bundle_kind": bundle_kind,
        "family_id": family_id,
        "job_id": job_id,
        "parent_job_id": family_id,
        "round_no": None if bundle_kind == "campaign" else 1,
        "plan_digest": plan_digest,
        "envelope_digest": envelope_digest,
        "experiment_digest": None,
        "build_provenance_rules_version": plan["build_provenance_rules_version"],
        "verdict": verdict,
        "reason_code": reason_code,
        "created_at": "2099-01-01T00:00:00Z",
        "build_ref": None,
        "reuse_origin": None,
        "files": entries,
    }
    (root / "manifest.json").write_bytes(jsonutil.canonical_bytes(manifest) + b"\n")
    return root


def _rewrite_bundle_json(root: Path, relative: str, mutate) -> None:
    """Rewrite one JSON file of a written bundle and re-seal its manifest entry."""
    path = root / relative
    document = json.loads(path.read_text(encoding="utf-8"))
    mutate(document)
    payload = jsonutil.canonical_bytes(document) + b"\n"
    path.write_bytes(payload)
    manifest_path = root / "manifest.json"
    manifest_doc = json.loads(manifest_path.read_text(encoding="utf-8"))
    for entry in manifest_doc["files"]:
        if entry["path"] == relative:
            entry["size_bytes"] = len(payload)
            entry["sha256"] = _sha256_hex(payload)
    manifest_path.write_bytes(jsonutil.canonical_bytes(manifest_doc) + b"\n")


def test_declared_flags_must_be_subset_of_effective_flags():
    vulnerable_face = _fixture_bytes("cmake_comparable_vulnerable.compile_commands.json")
    missing_declared_face = _fixture_bytes(
        "cmake_missing_declared_flag.compile_commands.json"
    )

    result = provenance.verify_build_provenance(
        kind="cmake",
        declared_compile_flags=BASE_DECLARED_FLAGS,
        vulnerable_face=vulnerable_face,
        fixed_face=missing_declared_face,
        repo_root=REPO_ROOT,
    )

    assert result.comparable is False, (
        "declared flag absent from effective set was accepted as comparable"
    )
    assert result.reason_code == "BUILD_PROVENANCE_MISSING", (
        f"expected reason_code='BUILD_PROVENANCE_MISSING' when declared flag is missing, "
        f"got {result.reason_code!r}"
    )
    assert "-D_GNU_SOURCE" in result.error_detail and "fixed" in result.error_detail, (
        f"failure detail must locate version and missing declared flag: {result.error_detail!r}"
    )

    # §5 Rule 8: declared ⊆ effective is multiset inclusion, not plain set inclusion.
    # cmake_flags_connected has 2 CUs each carrying `-lfoo` once, so 3 occurrences in
    # declared_compile_flags exceeds effective multiplicity under both per-CU and flattened counts.
    connected_face = _fixture_bytes("cmake_flags_connected.compile_commands.json")
    multiset_result = provenance.verify_build_provenance(
        kind="cmake",
        declared_compile_flags=[
            "-fsanitize=address",
            "-g",
            "-O1",
            "-lfoo",
            "-lfoo",
            "-lfoo",
        ],
        vulnerable_face=connected_face,
        fixed_face=connected_face,
        repo_root=REPO_ROOT,
    )
    assert multiset_result.comparable is False, (
        "declared flag multiplicity exceeding effective count was accepted (set vs multiset)"
    )
    assert multiset_result.reason_code == "BUILD_PROVENANCE_MISSING", (
        "expected BUILD_PROVENANCE_MISSING when declared multiset count exceeds effective count, "
        f"got {multiset_result.reason_code!r}"
    )


def test_two_versions_must_have_equal_effective_flags():
    vuln_cmake = _fixture_bytes("cmake_comparable_vulnerable.compile_commands.json")
    unequal_fixed_cmake = _fixture_bytes(
        "cmake_unequal_effective_fixed.compile_commands.json"
    )
    missing_unit_fixed_cmake = _fixture_bytes(
        "cmake_missing_unit_fixed.compile_commands.json"
    )

    unequal_result = provenance.verify_build_provenance(
        kind="cmake",
        declared_compile_flags=BASE_DECLARED_FLAGS,
        vulnerable_face=vuln_cmake,
        fixed_face=unequal_fixed_cmake,
        repo_root=REPO_ROOT,
    )
    assert unequal_result.comparable is False, (
        "unequal effective flags (-O1 vs -O2 on src/parser.c) were treated as comparable"
    )
    assert unequal_result.reason_code == "BUILD_PROVENANCE_MISSING", (
        f"expected BUILD_PROVENANCE_MISSING for unequal effective flags, got {unequal_result.reason_code!r}"
    )
    assert "src/parser.c" in unequal_result.error_detail, (
        f"diff summary must locate differing compilation unit src/parser.c: {unequal_result.error_detail!r}"
    )

    missing_unit_result = provenance.verify_build_provenance(
        kind="cmake",
        declared_compile_flags=BASE_DECLARED_FLAGS,
        vulnerable_face=vuln_cmake,
        fixed_face=missing_unit_fixed_cmake,
        repo_root=REPO_ROOT,
    )
    assert missing_unit_result.comparable is False, (
        "single-version missing compilation unit (src/lexer.c) was treated as comparable"
    )
    assert missing_unit_result.reason_code == "BUILD_PROVENANCE_MISSING", (
        f"expected BUILD_PROVENANCE_MISSING for unexplained missing CU, got {missing_unit_result.reason_code!r}"
    )

    make_vuln = _fixture_bytes("make_comparable_vulnerable.cc-shim.log")
    make_unequal_fixed = _fixture_bytes("make_unequal_effective_fixed.cc-shim.log")
    make_result = provenance.verify_build_provenance(
        kind="make",
        declared_compile_flags=BASE_DECLARED_FLAGS,
        vulnerable_face=make_vuln,
        fixed_face=make_unequal_fixed,
        repo_root=REPO_ROOT,
    )
    assert make_result.comparable is False and (
        make_result.reason_code == "BUILD_PROVENANCE_MISSING"
    ), f"Make two-version effective flag difference must fail closed: {make_result!r}"


def test_include_order_is_significant():

    ab_norm = provenance.normalize_compile_flags(
        ["-fsanitize=address", "-g", "-O1", "-I", "a", "-I", "b"],
        repo_root=REPO_ROOT,
    )
    ba_norm = provenance.normalize_compile_flags(
        ["-fsanitize=address", "-g", "-O1", "-I", "b", "-I", "a"],
        repo_root=REPO_ROOT,
    )
    assert ab_norm != ba_norm, (
        f"include order was normalized away: ab={ab_norm!r}, ba={ba_norm!r}"
    )
    assert ab_norm == ["-fsanitize=address", "-g", "-O1", "-Ia", "-Ib"], (
        f"unexpected normalized sequence for -I a -I b: {ab_norm!r}"
    )
    assert ba_norm == ["-fsanitize=address", "-g", "-O1", "-Ib", "-Ia"], (
        f"unexpected normalized sequence for -I b -I a: {ba_norm!r}"
    )

    # §5 Rule 1: never reorder -D macros by name (-DB=2 -DA=1 != -DA=1 -DB=2).
    db_da_norm = provenance.normalize_compile_flags(
        ["-DB=2", "-DA=1"],
        repo_root=REPO_ROOT,
    )
    da_db_norm = provenance.normalize_compile_flags(
        ["-DA=1", "-DB=2"],
        repo_root=REPO_ROOT,
    )
    assert db_da_norm != da_db_norm, (
        f"-D macro order was normalized away: db_da={db_da_norm!r}, da_db={da_db_norm!r}"
    )
    assert db_da_norm == ["-DB=2", "-DA=1"], (
        f"unexpected normalized sequence for -DB=2 -DA=1: {db_da_norm!r}"
    )
    assert da_db_norm == ["-DA=1", "-DB=2"], (
        f"unexpected normalized sequence for -DA=1 -DB=2: {da_db_norm!r}"
    )

    # §5 Rule 5 & Rule 6: duplicate -I keeps first occurrence only; -L/-l/-isystem/-include
    # must never be deduplicated or reordered.
    dedup_norm = provenance.normalize_compile_flags(
        [
            "-I",
            "a",
            "-I",
            "b",
            "-Ia",
            "-L",
            "lib",
            "-Llib",
            "-l",
            "foo",
            "-lbar",
            "-lfoo",
            "-isystem",
            "/opt/s1",
            "-isystem/opt/s1",
            "-include",
            "include/a.h",
            "-includeinclude/a.h",
        ],
        repo_root=REPO_ROOT,
    )
    assert dedup_norm == [
        "-Ia",
        "-Ib",
        "-Llib",
        "-Llib",
        "-lfoo",
        "-lbar",
        "-lfoo",
        "-isystem",
        "/opt/s1",
        "-isystem",
        "/opt/s1",
        "-include",
        "include/a.h",
        "-include",
        "include/a.h",
    ], (
        "duplicate -I must keep first occurrence only while -L/-l/-isystem/-include "
        f"must not be deduplicated or reordered: {dedup_norm!r}"
    )

    face_ab = _fixture_bytes("cmake_include_order_ab.compile_commands.json")
    face_ba = _fixture_bytes("cmake_include_order_ba.compile_commands.json")
    result = provenance.verify_build_provenance(
        kind="cmake",
        declared_compile_flags=["-fsanitize=address", "-g", "-O1"],
        vulnerable_face=face_ab,
        fixed_face=face_ba,
        repo_root=REPO_ROOT,
    )
    assert result.comparable is False, (
        "two versions with reversed -I a -I b vs -I b -I a were treated as comparable"
    )
    assert result.reason_code == "BUILD_PROVENANCE_MISSING", (
        f"expected BUILD_PROVENANCE_MISSING for reversed include order, got {result.reason_code!r}"
    )


def test_connected_and_split_flag_forms_are_equivalent():

    split_tokens = [
        "-fsanitize=address",
        "-g",
        "-O1",
        "-I",
        "/work/repo/include",
        "-L",
        "/work/repo/lib",
        "-l",
        "foo",
        "-D",
        "FOO=1",
        "-U",
        "BAR",
        "-isystem",
        "/opt/sysinc",
        "-include",
        "/work/repo/include/config.h",
    ]
    connected_tokens = [
        "-fsanitize=address",
        "-g",
        "-O1",
        "-I/work/repo/include",
        "-L/work/repo/lib",
        "-lfoo",
        "-DFOO=1",
        "-UBAR",
        "-isystem/opt/sysinc",
        "-include/work/repo/include/config.h",
    ]
    expected_canonical = [
        "-fsanitize=address",
        "-g",
        "-O1",
        "-Iinclude",
        "-Llib",
        "-lfoo",
        "-DFOO=1",
        "-UBAR",
        "-isystem",
        "/opt/sysinc",
        "-include",
        "include/config.h",
    ]

    norm_split = provenance.normalize_compile_flags(split_tokens, repo_root=REPO_ROOT)
    norm_connected = provenance.normalize_compile_flags(
        connected_tokens, repo_root=REPO_ROOT
    )
    assert norm_split == norm_connected == expected_canonical, (
        f"split and joined flag forms were treated as different or non-canonical: "
        f"split={norm_split!r}, connected={norm_connected!r}, expected={expected_canonical!r}"
    )

    # §5 Rule 3 closed-set boundary: options outside {-I,-L,-l,-D,-U,-isystem,-include}
    # must not be merged across adjacent tokens.
    non_closed = ["-fsanitize=address", "-O", "1", "-std", "c11"]
    norm_non_closed = provenance.normalize_compile_flags(
        non_closed, repo_root=REPO_ROOT
    )
    assert norm_non_closed == ["-fsanitize=address", "-O", "1", "-std", "c11"], (
        "options outside the closed 7-item set must not be merged: "
        f"got {norm_non_closed!r}"
    )

    cmake_result = provenance.verify_build_provenance(
        kind="cmake",
        declared_compile_flags=expected_canonical,
        vulnerable_face=_fixture_bytes("cmake_flags_split.compile_commands.json"),
        fixed_face=_fixture_bytes("cmake_flags_connected.compile_commands.json"),
        repo_root=REPO_ROOT,
    )
    assert cmake_result.comparable is True and cmake_result.reason_code is None, (
        f"CMake split vs connected 7-flag forms must be comparable: {cmake_result!r}"
    )

    make_result = provenance.verify_build_provenance(
        kind="make",
        declared_compile_flags=expected_canonical,
        vulnerable_face=_fixture_bytes("make_flags_split.cc-shim.log"),
        fixed_face=_fixture_bytes("make_flags_connected.cc-shim.log"),
        repo_root=REPO_ROOT,
    )
    assert make_result.comparable is True and make_result.reason_code is None, (
        f"Make split vs connected 7-flag forms must be comparable: {make_result!r}"
    )


def test_declared_flags_are_normalized_before_compare():
    connected_face = _fixture_bytes("cmake_flags_connected.compile_commands.json")

    declared_split_and_quoted = [
        "-fsanitize=address",
        '"-g"',
        "-O1",
        "-I",
        "include",
        "-L",
        "lib",
        "-l",
        "foo",
        "-D",
        "FOO=1",
        "-U",
        "BAR",
        "-isystem",
        "/opt/sysinc",
        "-include",
        "include/config.h",
    ]
    result = provenance.verify_build_provenance(
        kind="cmake",
        declared_compile_flags=declared_split_and_quoted,
        vulnerable_face=connected_face,
        fixed_face=connected_face,
        repo_root=REPO_ROOT,
    )

    assert result.comparable is True and result.reason_code is None, (
        f"declared flags were compared without normalization: {result!r}"
    )
    assert result.normalized_declared == [
        "-fsanitize=address",
        "-g",
        "-O1",
        "-Iinclude",
        "-Llib",
        "-lfoo",
        "-DFOO=1",
        "-UBAR",
        "-isystem",
        "/opt/sysinc",
        "-include",
        "include/config.h",
    ], f"normalized declared flags mismatch: {result.normalized_declared!r}"


def test_cmake_and_make_success_faces_are_captured():

    cmake_vuln = _fixture_bytes("cmake_comparable_vulnerable.compile_commands.json")
    cmake_fixed = _fixture_bytes("cmake_comparable_fixed.compile_commands.json")
    cmake_parsed = provenance.parse_provenance_face(
        kind="cmake",
        raw_face=cmake_vuln,
        repo_root=REPO_ROOT,
    )
    assert list(cmake_parsed.units.keys()) == [
        "src/lexer.c",
        "src/parser.c",
        "src/util.cpp",
    ], (
        "CMake multi-CU parser must filter pure link commands and sort source units "
        f"ascending by repo-relative path: got {list(cmake_parsed.units.keys())!r}"
    )
    cmake_entry = provenance.archive_face_entry(
        kind="cmake",
        version="vulnerable",
        raw_face=cmake_vuln,
    )
    assert cmake_entry.path == "build/vulnerable/build_provenance/compile_commands.json", (
        f"unexpected CMake build_provenance archive path: {cmake_entry.path!r}"
    )
    assert cmake_entry.role == "build_provenance", (
        f"expected role='build_provenance', got {cmake_entry.role!r}"
    )
    expected_cmake_sha = _sha256_hex(cmake_vuln)
    assert cmake_entry.sha256 == expected_cmake_sha, (
        f"expected bare 64-hex sha256 matching evidence manifest, got {cmake_entry.sha256!r}"
    )
    assert cmake_entry.as_dict()["sha256"] == expected_cmake_sha, (
        f"archive_face_entry.as_dict()['sha256'] mismatch: {cmake_entry.as_dict()!r}"
    )
    assert len(cmake_entry.sha256) == 64 and cmake_entry.sha256 == cmake_entry.sha256.lower()
    assert not cmake_entry.sha256.startswith("sha256:")

    make_vuln = _fixture_bytes("make_comparable_vulnerable.cc-shim.log")
    make_fixed = _fixture_bytes("make_comparable_fixed.cc-shim.log")
    make_parsed = provenance.parse_provenance_face(
        kind="make",
        raw_face=make_vuln,
        repo_root=REPO_ROOT,
    )
    assert list(make_parsed.units.keys()) == ["src/lexer.c", "src/parser.c"], (
        "Make cc-shim multi-CU parser must exclude pure link commands and sort "
        f"source units ascending: got {list(make_parsed.units.keys())!r}"
    )
    make_entry = provenance.archive_face_entry(
        kind="make",
        version="fixed",
        raw_face=make_fixed,
    )
    assert make_entry.path == "build/fixed/build_provenance/cc-shim.log", (
        f"unexpected Make build_provenance archive path: {make_entry.path!r}"
    )
    assert make_entry.role == "build_provenance", (
        f"expected role='build_provenance', got {make_entry.role!r}"
    )
    expected_make_sha = _sha256_hex(make_fixed)
    assert make_entry.sha256 == expected_make_sha, (
        f"expected bare 64-hex sha256 matching evidence manifest, got {make_entry.sha256!r}"
    )
    assert make_entry.as_dict()["sha256"] == expected_make_sha, (
        f"archive_face_entry.as_dict()['sha256'] mismatch: {make_entry.as_dict()!r}"
    )
    assert len(make_entry.sha256) == 64 and make_entry.sha256 == make_entry.sha256.lower()
    assert not make_entry.sha256.startswith("sha256:")

    cmake_cmp = provenance.verify_build_provenance(
        kind="cmake",
        declared_compile_flags=BASE_DECLARED_FLAGS,
        vulnerable_face=cmake_vuln,
        fixed_face=cmake_fixed,
        repo_root=REPO_ROOT,
    )
    make_cmp = provenance.verify_build_provenance(
        kind="make",
        declared_compile_flags=BASE_DECLARED_FLAGS,
        vulnerable_face=make_vuln,
        fixed_face=make_fixed,
        repo_root=REPO_ROOT,
    )
    assert cmake_cmp.comparable is True and make_cmp.comparable is True, (
        f"comparable CMake/Make pairs must pass: cmake={cmake_cmp!r}, make={make_cmp!r}"
    )

    # §8 closed report.build_provenance schema (no extra diagnostic keys mixed in).
    for cmp_result, expected_face in (
        (cmake_cmp, "compile_commands.json"),
        (make_cmp, "cc-shim.log"),
    ):
        summary = cmp_result.report_summary
        assert set(summary.keys()) == {"vulnerable", "fixed", "comparable"}, (
            f"report_summary must follow closed §8 schema: got keys {sorted(summary)}"
        )
        assert summary["comparable"] is True
        for version in ("vulnerable", "fixed"):
            assert set(summary[version].keys()) == {"face", "declared", "effective"}, (
                f"report_summary.{version} must follow closed §8 schema: "
                f"got keys {sorted(summary[version])}"
            )
            assert summary[version]["face"] == expected_face
        diag = cmp_result.diagnostic_summary()
        assert set(diag.keys()) == {
            "rules_version",
            "comparable",
            "reason_code",
            "error_detail",
            "vulnerable_units",
            "fixed_units",
            "report_summary",
        }
        assert diag["report_summary"] == summary

    # Make single-step compile+link (without -c) is captured; pure .o link and -E are excluded.
    single_step_make_log = "\n".join(
        [
            json.dumps(
                {
                    "cwd": REPO_ROOT,
                    "compiler": "clang",
                    "argv": [
                        "clang",
                        "-fsanitize=address",
                        "-g",
                        "-O1",
                        "-Iinclude",
                        "src/a.c",
                        "-o",
                        "build/app",
                    ],
                }
            ),
            json.dumps(
                {
                    "cwd": REPO_ROOT,
                    "compiler": "clang",
                    "argv": [
                        "clang",
                        "-E",
                        "-Iinclude",
                        "src/preproc.c",
                        "-o",
                        "build/preproc.i",
                    ],
                }
            ),
            json.dumps(
                {
                    "cwd": REPO_ROOT,
                    "compiler": "clang",
                    "argv": ["clang", "build/a.o", "build/b.o", "-o", "build/linked"],
                }
            ),
        ]
    ).encode("utf-8")
    single_step_parsed = provenance.parse_provenance_face(
        kind="make",
        raw_face=single_step_make_log,
        repo_root=REPO_ROOT,
    )
    assert single_step_parsed.units == {
        "src/a.c": ["-fsanitize=address", "-g", "-O1", "-Iinclude"]
    }, (
        "Make parser must capture single-step compile+link without -c while excluding "
        f"preprocessor-only (-E) and pure .o link lines: got {single_step_parsed.units!r}"
    )


def test_validation_bundle_requires_build_provenance(tmp_path: Path):
    complete_exec = _write_v2_bundle(
        tmp_path / "exec-complete",
        bundle_kind="execution",
        provenance_versions=("vulnerable", "fixed"),
    )
    verified = evidence.verify_bundle(complete_exec)
    assert verified.manifest["schema_version"] == 2, (
        f"expected v2 execution bundle with build_provenance to verify, got {verified.manifest!r}"
    )

    complete_campaign = _write_v2_bundle(
        tmp_path / "campaign-complete",
        bundle_kind="campaign",
        provenance_versions=("vulnerable", "fixed"),
    )
    verified_campaign = evidence.verify_bundle(complete_campaign)
    assert (
        verified_campaign.manifest["schema_version"] == 2
        and verified_campaign.manifest["bundle_kind"] == "campaign"
    ), (
        "expected v2 campaign bundle with both build_provenance faces to verify, "
        f"got {verified_campaign.manifest!r}"
    )

    missing_exec = _write_v2_bundle(
        tmp_path / "exec-missing-provenance",
        bundle_kind="execution",
        provenance_versions=(),
    )
    with pytest.raises(evidence.BundleError, match="build_provenance"):
        evidence.verify_bundle(missing_exec)

    single_missing_exec = _write_v2_bundle(
        tmp_path / "exec-single-missing-provenance",
        bundle_kind="execution",
        provenance_versions=("vulnerable",),
    )
    with pytest.raises(evidence.BundleError, match="build_provenance"):
        evidence.verify_bundle(single_missing_exec)

    missing_campaign = _write_v2_bundle(
        tmp_path / "campaign-missing-provenance",
        bundle_kind="campaign",
        provenance_versions=(),
    )
    with pytest.raises(evidence.BundleError, match="build_provenance"):
        evidence.verify_bundle(missing_campaign)

    # Campaign with only one archived face (nit: the per-version face is
    # required for campaign bundles exactly as for execution bundles).
    single_missing_campaign = _write_v2_bundle(
        tmp_path / "campaign-single-missing-provenance",
        bundle_kind="campaign",
        provenance_versions=("fixed",),
    )
    with pytest.raises(evidence.BundleError, match="build_provenance"):
        evidence.verify_bundle(single_missing_campaign)

    # B-2 (§8, D4/D39): a complete execution only reaches a rule-backed
    # verdict after provenance compared, so the production writer always
    # records comparable=true there. comparable=false on a complete bundle
    # is a contradiction and must fail closed.
    for verdict, reason in (
        ("INCONCLUSIVE", "EVIDENCE_INCOMPLETE"),
        ("REPRODUCED", None),
        ("NOT_REPRODUCED", None),
    ):
        bundle = _write_v2_bundle(
            tmp_path / f"exec-not-comparable-{verdict.lower()}",
            bundle_kind="execution",
            provenance_versions=("vulnerable", "fixed"),
        )

        def _not_comparable(report, verdict=verdict, reason=reason):
            report["verdict"] = verdict
            report["state"] = verdict
            report["reason_code"] = reason
            report["build_provenance"]["comparable"] = False

        _rewrite_bundle_json(bundle, "report.json", _not_comparable)

        def _manifest_verdict(manifest, verdict=verdict, reason=reason):
            manifest["verdict"] = verdict
            manifest["reason_code"] = reason

        manifest_path = bundle / "manifest.json"
        manifest_doc = json.loads(manifest_path.read_text(encoding="utf-8"))
        _manifest_verdict(manifest_doc)
        manifest_path.write_bytes(jsonutil.canonical_bytes(manifest_doc) + b"\n")
        with pytest.raises(evidence.BundleError, match="comparable"):
            evidence.verify_bundle(bundle)

    campaign_not_comparable = _write_v2_bundle(
        tmp_path / "campaign-not-comparable",
        bundle_kind="campaign",
        provenance_versions=("vulnerable", "fixed"),
    )
    _rewrite_bundle_json(
        campaign_not_comparable,
        "report.json",
        lambda report: report["build_provenance"].__setitem__("comparable", False),
    )
    with pytest.raises(evidence.BundleError, match="comparable"):
        evidence.verify_bundle(campaign_not_comparable)


def test_build_provenance_rules_version_is_bound_in_plan(tmp_path: Path):
    plan_v1_rules = _make_plan_v2(rules_version="build-provenance-v1")
    plan_v2_rules = deepcopy(plan_v1_rules)
    plan_v2_rules["build_provenance_rules_version"] = "build-provenance-v2"

    digest_v1 = contracts.plan_digest(plan_v1_rules)
    digest_v2 = contracts.plan_digest(plan_v2_rules)
    assert digest_v1 != digest_v2, (
        "changing build_provenance_rules_version did not change plan_digest: "
        f"digest_v1={digest_v1}, digest_v2={digest_v2}"
    )

    canonical_doc = json.loads(
        contracts.canonical_plan_bytes(plan_v1_rules).decode("utf-8")
    )
    assert (
        canonical_doc.get("build_provenance_rules_version") == "build-provenance-v1"
    ), (
        "build_provenance_rules_version missing from canonical Plan v2 bytes: "
        f"keys={sorted(canonical_doc)}"
    )

    missing_rules = deepcopy(plan_v1_rules)
    del missing_rules["build_provenance_rules_version"]
    with pytest.raises(ValueError, match="build_provenance_rules_version"):
        contracts.plan_digest(missing_rules)

    # §8 & test-plan-delta.md L145: build_provenance_rules_version is also bound in report.json.
    ok_bundle = _write_v2_bundle(
        tmp_path / "rules-bound-ok",
        bundle_kind="execution",
        provenance_versions=("vulnerable", "fixed"),
    )
    verified = evidence.verify_bundle(ok_bundle)
    report_doc = json.loads(verified.file_data["report.json"].decode("utf-8"))
    assert report_doc.get("build_provenance_rules_version") == "build-provenance-v1", (
        "report.json must bind build_provenance_rules_version matching plan.json: "
        f"got {report_doc.get('build_provenance_rules_version')!r}"
    )

    drifted_report_bundle = _write_v2_bundle(
        tmp_path / "rules-report-drifted",
        bundle_kind="execution",
        provenance_versions=("vulnerable", "fixed"),
        report_rules_version="build-provenance-v2",
    )
    with pytest.raises(evidence.BundleError, match="build_provenance_rules_version"):
        evidence.verify_bundle(drifted_report_bundle)

    # plan.json drift relative to manifest/report must also fail closed.
    drifted_plan_bundle = _write_v2_bundle(
        tmp_path / "rules-plan-drifted",
        bundle_kind="execution",
        provenance_versions=("vulnerable", "fixed"),
    )
    plan_path = drifted_plan_bundle / "plan.json"
    plan_doc = json.loads(plan_path.read_text(encoding="utf-8"))
    plan_doc["build_provenance_rules_version"] = "build-provenance-v2"
    plan_bytes = (json.dumps(plan_doc, sort_keys=True) + "\n").encode("utf-8")
    plan_path.write_bytes(plan_bytes)
    manifest_path = drifted_plan_bundle / "manifest.json"
    manifest_doc = json.loads(manifest_path.read_text(encoding="utf-8"))
    for entry in manifest_doc["files"]:
        if entry["path"] == "plan.json":
            entry["size_bytes"] = len(plan_bytes)
            entry["sha256"] = _sha256_hex(plan_bytes)
    manifest_path.write_text(json.dumps(manifest_doc, sort_keys=True) + "\n", encoding="utf-8")
    with pytest.raises(evidence.BundleError, match="build_provenance_rules_version"):
        evidence.verify_bundle(drifted_plan_bundle)

    # Campaign bundles enforce the same build_provenance_rules_version binding.
    drifted_campaign_bundle = _write_v2_bundle(
        tmp_path / "rules-campaign-report-drifted",
        bundle_kind="campaign",
        provenance_versions=("vulnerable", "fixed"),
        report_rules_version="build-provenance-v2",
    )
    with pytest.raises(evidence.BundleError, match="build_provenance_rules_version"):
        evidence.verify_bundle(drifted_campaign_bundle)

    # S-1: an archived plan's build_spec is checked independently of plan
    # freeze (imported bundles never went through contracts): a non-object
    # build_spec or one without ``kind`` fails closed instead of skipping the
    # build_spec.kind face binding.
    for label, build_spec in (
        ("not-object", "not-an-object"),
        ("no-kind", {"build": ["make"]}),
    ):
        bundle = _write_v2_bundle(
            tmp_path / f"rules-build-spec-{label}",
            bundle_kind="execution",
            provenance_versions=("vulnerable", "fixed"),
        )

        def _bad_build_spec(plan, build_spec=build_spec):
            plan["build_spec"] = build_spec

        _rewrite_bundle_json(bundle, "plan.json", _bad_build_spec)
        with pytest.raises(evidence.BundleError, match="build_spec"):
            evidence.verify_bundle(bundle)

    # S-1: a rules version with surrounding whitespace is not the same version.
    padded = _write_v2_bundle(
        tmp_path / "rules-padded",
        bundle_kind="execution",
        provenance_versions=("vulnerable", "fixed"),
        report_rules_version="  build-provenance-v1  ",
    )
    for relative in ("plan.json",):
        _rewrite_bundle_json(
            padded,
            relative,
            lambda doc: doc.__setitem__(
                "build_provenance_rules_version", "  build-provenance-v1  "
            ),
        )
    manifest_path = padded / "manifest.json"
    manifest_doc = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest_doc["build_provenance_rules_version"] = "  build-provenance-v1  "
    manifest_path.write_bytes(jsonutil.canonical_bytes(manifest_doc) + b"\n")
    with pytest.raises(evidence.BundleError, match="build_provenance_rules_version"):
        evidence.verify_bundle(padded)


def test_missing_face_blocks_plan_freeze():

    # §3 L132-160 canonical CMake BuildSpec (without explicit -DCMAKE_EXPORT_COMPILE_COMMANDS=ON;
    # the fixed executor template injects export flags) and §5 Make BuildSpec with CC shim must freeze.
    valid_cmake = _make_build_spec(kind="cmake")
    valid_cmake_decision = provenance.validate_build_spec_for_freeze(valid_cmake)
    assert valid_cmake_decision.ok is True and valid_cmake_decision.reason_code is None, (
        f"valid §3 CMake BuildSpec must be allowed to freeze: {valid_cmake_decision!r}"
    )

    valid_make = _make_build_spec(kind="make")
    valid_make_decision = provenance.validate_build_spec_for_freeze(valid_make)
    assert valid_make_decision.ok is True and valid_make_decision.reason_code is None, (
        f"valid §5 Make BuildSpec with CC shim must be allowed to freeze: {valid_make_decision!r}"
    )

    make_without_shim = _make_build_spec(
        kind="make",
        env={"CC": "clang", "CFLAGS": "-fsanitize=address -g -O1"},
    )
    make_decision = provenance.validate_build_spec_for_freeze(make_without_shim)
    assert make_decision.ok is False, (
        "Make BuildSpec without env.CC shim was allowed to freeze"
    )
    assert make_decision.reason_code == "BUILD_PROVENANCE_MISSING", (
        f"expected BUILD_PROVENANCE_MISSING for Make without CC shim, got {make_decision.reason_code!r}"
    )

    cmake_empty_configure = _make_build_spec(kind="cmake", configure=[])
    cmake_empty_decision = provenance.validate_build_spec_for_freeze(cmake_empty_configure)
    assert cmake_empty_decision.ok is False, (
        "CMake BuildSpec with empty configure was allowed to freeze"
    )
    assert cmake_empty_decision.reason_code == "BUILD_PROVENANCE_MISSING", (
        "expected BUILD_PROVENANCE_MISSING for CMake with empty configure, "
        f"got {cmake_empty_decision.reason_code!r}"
    )

    cmake_missing_configure = _make_build_spec(kind="cmake")
    del cmake_missing_configure["configure"]
    cmake_missing_decision = provenance.validate_build_spec_for_freeze(cmake_missing_configure)
    assert cmake_missing_decision.ok is False, (
        "CMake BuildSpec missing configure field was allowed to freeze"
    )
    assert cmake_missing_decision.reason_code == "BUILD_PROVENANCE_MISSING", (
        "expected BUILD_PROVENANCE_MISSING for CMake missing configure, "
        f"got {cmake_missing_decision.reason_code!r}"
    )

    cmake_export_disabled = _make_build_spec(
        kind="cmake",
        configure=[
            "cmake",
            "-S",
            ".",
            "-B",
            "build",
            "-DCMAKE_EXPORT_COMPILE_COMMANDS=OFF",
            "-DCMAKE_C_COMPILER=clang",
        ],
    )
    cmake_disabled_decision = provenance.validate_build_spec_for_freeze(cmake_export_disabled)
    assert cmake_disabled_decision.ok is False, (
        "CMake BuildSpec explicitly disabling compile_commands.json export was allowed to freeze"
    )
    assert cmake_disabled_decision.reason_code == "BUILD_PROVENANCE_MISSING", (
        "expected BUILD_PROVENANCE_MISSING when CMake explicitly sets "
        f"CMAKE_EXPORT_COMPILE_COMMANDS=OFF, got {cmake_disabled_decision.reason_code!r}"
    )

    legacy_make_env = _make_build_spec(kind="make")
    legacy_make_env["make_env"] = {"CC": "/opt/datacon/cc-shim"}
    make_env_decision = provenance.validate_build_spec_for_freeze(legacy_make_env)
    assert make_env_decision.ok is False, (
        "deprecated make_env field in BuildSpec must be rejected at freeze"
    )
    assert make_env_decision.reason_code == "BUILD_PROVENANCE_MISSING", (
        "expected BUILD_PROVENANCE_MISSING for deprecated make_env, "
        f"got {make_env_decision.reason_code!r}"
    )


def test_shell_recipe_requires_separate_face_review():
    baseline_log = _fixture_bytes("shell_face_baseline.shell-face.log")
    same_norm_log = _fixture_bytes("shell_face_same_normalized.shell-face.log")
    drifted_log = _fixture_bytes("shell_face_drifted.shell-face.log")

    unreviewed_shell = _make_build_spec(
        kind="shell",
        build=["sh", "./build.sh"],
        env={"CC": "clang"},
        shell_recipe_digest="sha256:" + "c" * 64,
        shell_face_digest=None,
        shell_face_review=None,
    )
    freeze_unreviewed = provenance.validate_build_spec_for_freeze(unreviewed_shell)
    assert freeze_unreviewed.ok is False, (
        "unreviewed shell recipe with only shell_recipe_digest counted as comparable"
    )
    assert freeze_unreviewed.reason_code == "BUILD_PROVENANCE_MISSING", (
        f"expected BUILD_PROVENANCE_MISSING when shell_face_review/digest missing, "
        f"got {freeze_unreviewed.reason_code!r}"
    )

    baseline_digest = provenance.shell_face_digest(
        baseline_log, repo_root="/work/run-0001/repo"
    )

    # Half-present shell provenance: digest without review or review without digest must block freeze.
    digest_without_review = _make_build_spec(
        kind="shell",
        build=["sh", "./build.sh"],
        env={"CC": "clang"},
        shell_recipe_digest="sha256:" + "c" * 64,
        shell_face_digest=baseline_digest,
        shell_face_review=None,
    )
    freeze_no_review = provenance.validate_build_spec_for_freeze(digest_without_review)
    assert freeze_no_review.ok is False and (
        freeze_no_review.reason_code == "BUILD_PROVENANCE_MISSING"
    ), (
        "shell BuildSpec with shell_face_digest but missing shell_face_review must fail freeze: "
        f"{freeze_no_review!r}"
    )

    review_without_digest = _make_build_spec(
        kind="shell",
        build=["sh", "./build.sh"],
        env={"CC": "clang"},
        shell_recipe_digest="sha256:" + "c" * 64,
        shell_face_digest=None,
        shell_face_review={
            "reviewer_id": "reviewer-01",
            "reviewed_at": "2099-01-01T00:00:00Z",
            "face_kind": "build_log",
        },
    )
    freeze_no_digest = provenance.validate_build_spec_for_freeze(review_without_digest)
    assert freeze_no_digest.ok is False and (
        freeze_no_digest.reason_code == "BUILD_PROVENANCE_MISSING"
    ), (
        "shell BuildSpec with shell_face_review but missing shell_face_digest must fail freeze: "
        f"{freeze_no_digest!r}"
    )

    reviewed_shell = _make_build_spec(
        kind="shell",
        build=["sh", "./build.sh"],
        env={"CC": "clang"},
        shell_recipe_digest="sha256:" + "c" * 64,
        shell_face_digest=baseline_digest,
        shell_face_review={
            "reviewer_id": "reviewer-01",
            "reviewed_at": "2099-01-01T00:00:00Z",
            "face_kind": "build_log",
        },
    )
    freeze_reviewed = provenance.validate_build_spec_for_freeze(reviewed_shell)
    assert freeze_reviewed.ok is True, (
        f"reviewed shell BuildSpec with shell_face_digest and shell_face_review must freeze: "
        f"{freeze_reviewed!r}"
    )

    same_check = provenance.verify_shell_face(
        build_spec=reviewed_shell,
        actual_log=same_norm_log,
        repo_root="/work/run-9999/repo",
    )
    assert same_check.comparable is True and same_check.reason_code is None, (
        f"shell log differing only in path/timestamp must match pre-reviewed baseline: {same_check!r}"
    )

    drifted_check = provenance.verify_shell_face(
        build_spec=reviewed_shell,
        actual_log=drifted_log,
        repo_root="/work/run-9999/repo",
    )
    assert drifted_check.comparable is False, (
        "drifted shell build log (-O2 vs -O1) must not match pre-reviewed shell_face_digest"
    )
    assert drifted_check.reason_code == "BUILD_PROVENANCE_MISSING", (
        f"expected BUILD_PROVENANCE_MISSING for drifted shell log, got {drifted_check.reason_code!r}"
    )
