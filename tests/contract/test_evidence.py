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
    canonical_manifest_digest,
    export_bundle,
    verify_bundle,
    write_bundle,
)
from test_plan import PLAN

JOB_ID = str(uuid4())
PLAN_DIGEST = plan_digest(PLAN)
REASONS = {"REPRODUCED": "ASAN_SIGNATURE_MATCHED"}

REPORT = {
    "schema_version": 1,
    "job_id": JOB_ID,
    "plan_digest": PLAN_DIGEST,
    "cve_id": "CVE-2099-0001",
    "case_id": "fixture-c-parser",
    "verdict": "REPRODUCED",
    "reason_code": REASONS["REPRODUCED"],
    "builds": [],
    "replays": [
        {"version": version, "phase": phase, "status": "completed"}
        for version in ("vulnerable", "fixed")
        for phase in ("normal", "candidate_1", "candidate_2")
    ],
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
        "metadata/execution.json": ("execution_metadata", b'{"generation":1}\n'),
        "metadata/probe.json": ("probe", b'{"checks":{"seccomp":"2"}}\n'),
    }
    for version in ("vulnerable", "fixed"):
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
            canonical({"version": version, "status": "completed"}),
        )
    for version in ("vulnerable", "fixed"):
        for phase in ("normal", "candidate_1", "candidate_2"):
            directory = f"replay/{version}/{phase}"
            artifacts[f"{directory}/stdout.log"] = (
                "replay_stdout" if phase != "normal" else "normal_output",
                b"OK\n",
            )
            artifacts[f"{directory}/stderr.log"] = (
                "asan_log"
                if (version, phase) == ("vulnerable", "candidate_1")
                else "replay_stderr",
                b"",
            )
            artifacts[f"{directory}/metadata.json"] = (
                "replay_metadata",
                canonical({"version": version, "phase": phase, "status": "completed"}),
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
