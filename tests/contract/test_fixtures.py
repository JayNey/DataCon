import hashlib
import json
from pathlib import Path
import re

import pytest

from datacon.contracts import parse_request

CASES = Path(__file__).resolve().parents[1] / "fixtures" / "cases"
DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
GIT_OID = re.compile(r"[0-9a-f]{40}")
CVE = re.compile(r"CVE-[0-9]{4}-[0-9]{4,}")


def load(name):
    return json.loads((CASES / name).read_text(encoding="utf-8"))


def verify_material(path, expected_digest):
    actual = "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()
    if actual != expected_digest:
        raise ValueError(f"fixture digest mismatch: {path.name}")


def test_manifest_materials_and_cases_are_consistent():
    manifest = load("manifest.json")
    assert manifest["schema_version"] == 1
    assert manifest["source_mode"] == "fixture"
    assert CVE.fullmatch(manifest["cve_id"])
    assert manifest["versions"]["fixed"] != manifest["versions"]["vulnerable"]
    assert DIGEST.fullmatch(manifest["image"].split("@", 1)[1])
    assert manifest["toolchain"]["sanitizer"] == "address"

    for name, digest in manifest["materials"].items():
        verify_material(CASES / name, digest)

    referenced = {
        *manifest["versions"].values(),
        manifest["harness"],
        manifest["build_recipe"],
        manifest["dependencies"],
        manifest["patch"],
    }
    for case in manifest["cases"].values():
        referenced.update(case["inputs"].values())
    assert set(manifest["materials"]) == referenced
    assert set(manifest["cases"]) == {"B01", "B02"}

    assert manifest["asan_signature"]["operation"] == "WRITE"
    assert manifest["cases"]["B01"]["expected_exit"]["candidate_asan"] == 86
    assert manifest["cases"]["B01"]["expected_verdict"] == "REPRODUCED"
    assert any(
        "candidate_asan" in case["expected_exit"]
        for case in manifest["cases"].values()
    )
    assert manifest["cases"]["B02"]["expected_verdict"] == "NOT_REPRODUCED"
    assert "candidate_asan" not in manifest["cases"]["B02"]["expected_exit"]


def test_case_requests_use_registered_case_ids_and_manifest_limits():
    manifest = load("manifest.json")
    for case in manifest["cases"].values():
        request = parse_request(
            json.dumps(
                {
                    "schema_version": 1,
                    "cve_id": manifest["cve_id"],
                    "target": {
                        "kind": "source",
                        "case_id": case["case_id"],
                        "goal": "fixture admission",
                    },
                }
            )
        )
        assert request["limits"] == manifest["limits"]


def test_build_lock_references_the_same_toolchain_image():
    manifest = load("manifest.json")
    lock = (CASES / manifest["dependencies"]).read_text(encoding="utf-8")
    assert f"image={manifest['image']}" in lock
    assert "additional_dependencies=none" in lock


def test_missing_and_tampered_material_is_detected(tmp_path):
    manifest = load("manifest.json")
    name = manifest["versions"]["vulnerable"]
    expected = manifest["materials"][name]

    with pytest.raises(FileNotFoundError):
        verify_material(tmp_path / "parser.c", expected)

    copy = tmp_path / "parser.c"
    copy.write_bytes((CASES / name).read_bytes() + b"\n")
    with pytest.raises(ValueError, match="fixture digest mismatch"):
        verify_material(copy, expected)


def test_b03_admission_record_is_traceable_and_defers_real_execution():
    record = load("B03-admission.json")
    assert record["schema_version"] == 1
    assert record["benchmark_id"] == "B03"
    assert record["status"] == "conditional_admission"
    assert record["decision"] == "admit_to_planning"
    assert CVE.fullmatch(record["cve_id"])
    assert GIT_OID.fullmatch(record["fix_commit"])
    assert GIT_OID.fullmatch(record["versions"]["vulnerable"]["commit"])
    assert record["versions"]["vulnerable"]["commit"] != record["fix_commit"]
    assert record["versions"]["fixed"]["parent"] == record["versions"]["vulnerable"]["commit"]
    assert record["repository"]["license"] == "BSD-2-Clause"
    assert record["repository"]["url"].startswith("https://")
    assert record["advisory"]["nvd"].startswith("https://")
    assert re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}", record["advisory"]["published"])

    checks = {check["id"]: check for check in record["checks"]}
    assert set(checks) == {
        "public_advisory",
        "fixed_commit",
        "offline_build",
        "license",
        "shared_harness",
        "asan_replay",
    }
    assert all(checks[name]["status"] == "pass" for name in checks if name != "asan_replay")
    assert checks["asan_replay"]["status"] == "deferred"
    assert checks["asan_replay"]["owner_task"] == "T05"
    assert checks["asan_replay"]["verification"] == "execution_deferred"
    assert checks["offline_build"]["verification"] == "design"
    assert checks["public_advisory"]["verification"] == "public_metadata"
    assert record["asan_signature"]["status"] == "expected_pending_t05_replay"
    assert record["expected_verdict"] == "REPRODUCED"
    assert record["expected_verdict_status"] == "pending_t05_replay"
    assert "No real-case input" in record["usage_boundary"]

    markdown = (CASES / "B03-admission.md").read_text(encoding="utf-8")
    assert record["cve_id"] in markdown
    assert "T05" in markdown
