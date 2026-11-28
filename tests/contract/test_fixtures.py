import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess

import pytest

from datacon.cases import CaseConfigurationError, load_registry
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
    assert "host clang" in manifest["toolchain"]["local_smoke"]
    assert manifest["toolchain"]["pinned_image_verified_in"] == "T05"
    assert manifest["toolchain"]["image_digest_verified_local"] is False

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
    assert manifest["asan_signature"]["access_size"] == 1
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
    lock_text = (CASES / manifest["dependencies"]).read_text(encoding="utf-8")
    lock = {}
    for line in lock_text.splitlines():
        if not line or line.startswith("#"):
            continue
        key, value = line.split("=", 1)
        lock[key] = value

    assert lock["image"] == manifest["image"]
    assert lock["target"] == manifest["platform"]
    assert lock["scope"] == "T05-replay"
    assert lock["clang"] == manifest["toolchain"]["pinned_image_version"]
    assert lock["additional_dependencies"] == "none"
    image_major = manifest["toolchain"]["pinned_image_version"].split(".", 1)[0]
    assert manifest["image"].startswith(f"silkeh/clang:{image_major}-")


def test_fix_patch_applies_to_vulnerable_and_matches_fixed(tmp_path):
    manifest = load("manifest.json")
    patch_tool = shutil.which("patch")
    if patch_tool is None:
        pytest.skip("patch(1) is required to verify the fixture patch")

    target = tmp_path / "parser.c"
    target.write_bytes((CASES / manifest["versions"]["vulnerable"]).read_bytes())
    result = subprocess.run(
        [patch_tool, "-p1", "-i", str(CASES / manifest["patch"])],
        cwd=tmp_path,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert target.read_bytes() == (CASES / manifest["versions"]["fixed"]).read_bytes()


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


def test_b03_admission_record_is_traceable_and_pending_or_frozen():
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
    asan_replay = checks["asan_replay"]
    if asan_replay["status"] == "deferred":
        # The public fixture stays pending until the authorized lab freezes it.
        assert asan_replay["owner_task"] == "T05"
        assert asan_replay["verification"] == "execution_deferred"
        assert record["asan_signature"]["status"] == "expected_pending_t05_replay"
        assert record["expected_verdict_status"] == "pending_t05_replay"
    else:
        # The same fixture must remain valid after freeze_b03_admission.py
        # replaces the pending placeholders with real lab values.
        assert asan_replay["status"] == "pass"
        assert isinstance(asan_replay.get("evidence"), str)
        assert asan_replay["evidence"].strip()
        assert record["asan_signature"]["status"] in {"frozen", "verified"}
        assert record["expected_verdict_status"] in {"frozen", "verified"}
        for field in ("error", "operation", "access_size", "function", "source"):
            assert field in record["asan_signature"], field
        assert record["asan_signature"]["operation"] in {"READ", "WRITE"}
        assert type(record["asan_signature"]["access_size"]) is int
        assert record["asan_signature"]["access_size"] > 0
        assert type(record["harness"]["candidate_clean_exit_code"]) is int
        expected_stdout = record["harness"]["expected_stdout"]
        assert isinstance(expected_stdout, dict)
        assert isinstance(expected_stdout.get("normal"), str)
        assert isinstance(expected_stdout.get("candidate_clean"), str)
    assert checks["offline_build"]["verification"] == "design"
    assert checks["public_advisory"]["verification"] == "public_metadata"
    assert record["expected_verdict"] == "REPRODUCED"
    assert "No real-case input" in record["usage_boundary"]

    markdown = (CASES / "B03-admission.md").read_text(encoding="utf-8")
    assert record["cve_id"] in markdown
    assert "T05" in markdown


FIXTURE_SOURCE_URLS = {
    "fixture-c-parser": "https://example.invalid/datacon/B01",
    "fixture-c-parser-clean": "https://example.invalid/datacon/B02",
}


def test_registry_advisory_requires_intel_license_fields(tmp_path):
    """Every advisory entry must carry the T15 intel source fields.

    cases.py only checks key presence. Value eligibility (an https source
    URL, ``reproduction`` inside ``permitted_uses``) stays with
    ``intel_fetch.public_source_url`` and ``intel_fetch.license_rejection``
    at the gate, and ``license`` may be null when a source declares no
    license. The field names mirror the intel license document
    (``intel_evidence.LICENSE_DOCUMENT_FIELDS``).
    """
    for missing in ("source_url", "license", "permitted_uses"):
        root = tmp_path / f"missing-{missing}"
        shutil.copytree(CASES, root)
        registry_path = root / "registry.json"
        document = json.loads(registry_path.read_text(encoding="utf-8"))
        # Minimal legal case entry: the fixture entry with exactly one
        # advisory intel field removed.
        entry = dict(document["cases"]["fixture-c-parser"])
        entry["advisory"] = {
            key: value
            for key, value in entry["advisory"].items()
            if key != missing
        }
        document["cases"] = {"fixture-c-parser": entry}
        registry_path.write_text(
            json.dumps(document, indent=2) + "\n", encoding="utf-8"
        )

        with pytest.raises(CaseConfigurationError) as caught:
            load_registry(str(root))

        assert missing in caught.value.message, caught.value.message

    registry = load("registry.json")
    assert set(registry["cases"]) == set(FIXTURE_SOURCE_URLS)
    for case_id, entry in registry["cases"].items():
        advisory = entry["advisory"]
        assert advisory["source_url"] == FIXTURE_SOURCE_URLS[case_id]
        assert "license" in advisory
        assert advisory["license"] == "CC0-1.0"
        assert advisory["permitted_uses"] == ["reproduction"]

    loaded = load_registry(str(CASES))
    assert set(loaded.document["cases"]) == set(FIXTURE_SOURCE_URLS)
    for case_id, entry in loaded.document["cases"].items():
        advisory = entry["advisory"]
        assert advisory["path"] == "advisory.json"
        assert advisory["source_url"] == FIXTURE_SOURCE_URLS[case_id]
        assert advisory["license"] == "CC0-1.0"
        assert advisory["permitted_uses"] == ["reproduction"]
