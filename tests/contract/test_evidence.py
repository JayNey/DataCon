"""TC-08: offline evidence manifests, export and verification (REQ-08)."""

from __future__ import annotations

import json
import os
from pathlib import Path
import stat
from uuid import uuid4

import pytest

from datacon.evidence import (
    BundleError,
    canonical_manifest_digest,
    export_bundle,
    verify_bundle,
    write_bundle,
)


REPORT = {
    "schema_version": 1,
    "job_id": str(uuid4()),
    "plan_digest": "sha256:" + ("a" * 64),
    "cve_id": "CVE-2099-0001",
    "case_id": "fixture-c-parser",
    "verdict": "REPRODUCED",
    "reason_code": "ASAN_SIGNATURE_MATCHED",
    "builds": [],
    "replays": [],
    "missing": [],
}


def make_bundle(tmp_path: Path, *, extra=None):
    artifacts = {
        "plan.json": ("plan", b'{"case_id":"fixture-c-parser"}\n'),
        "review.json": ("review", b'{"decision":"approve"}\n'),
        "metadata/execution.json": ("execution_metadata", b'{"runs":[]}\n'),
        "replay/vulnerable/candidate_1/stderr.log": (
            "asan_log",
            b"ERROR: AddressSanitizer: heap-buffer-overflow\n",
        ),
    }
    if extra:
        artifacts.update(extra)
    return write_bundle(
        tmp_path / "bundle",
        job_id=REPORT["job_id"],
        plan_digest=REPORT["plan_digest"],
        report=REPORT,
        report_markdown="# report\n",
        artifacts=artifacts,
    )


def test_valid_bundle_round_trips_and_exports(tmp_path):
    info = make_bundle(tmp_path)
    verified = verify_bundle(info.root)
    assert verified.manifest_digest == info.manifest_digest
    assert verified.manifest["job_id"] == REPORT["job_id"]
    assert verified.manifest["files"]
    assert all(
        set(entry) == {"path", "role", "size_bytes", "sha256"}
        for entry in verified.manifest["files"]
    )
    assert verified.file_data["report.json"].startswith(b"{")

    exported = export_bundle(info.root, tmp_path / "exported")
    assert exported.manifest_digest == info.manifest_digest
    assert (tmp_path / "exported" / "manifest.json").is_file()
    assert (tmp_path / "exported" / "report.md").read_text() == "# report\n"


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
    ["../outside", "/etc/passwd", "a/../../b", "a\\..\\b", "./plan.json"],
    ids=["parent", "absolute", "nested-parent", "backslash", "dot-segment"],
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
    ],
    ids=["schema", "files", "job-id", "plan-digest", "size", "sha"],
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
    first = {"schema_version": 1, "job_id": REPORT["job_id"], "files": []}
    second = {"files": [], "job_id": REPORT["job_id"], "schema_version": 1}
    assert canonical_manifest_digest(first) == canonical_manifest_digest(second)


def test_manifest_does_not_list_itself(tmp_path):
    info = make_bundle(tmp_path)
    paths = {entry["path"] for entry in info.manifest["files"]}
    assert "manifest.json" not in paths
