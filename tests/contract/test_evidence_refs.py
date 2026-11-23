"""TC-16/T10: v2 evidence references ``log/build`` and ``log/fuzz``.

The grammar is frozen in interface-contract-delta §11. These tests exercise
both halves of the contract: ``analysis_digest`` binds a parsed reference and
its line numbers into the plan digest, and ``resolve_evidence_ref`` reads the
bundle manifest, verifies the referenced log digest and 1-based line range, and
only then returns the selected lines. Out-of-range, missing or digest-mismatched
references are unresolvable and fail closed.
"""

from copy import deepcopy
import hashlib
import json
from pathlib import Path
from uuid import uuid4

import pytest

from test_plan import ANALYSIS

from datacon import evidence
from datacon.contracts import analysis_digest
from datacon.evidence import BundleError

VALID_REFS = [
    "git:diff/a..b/parser.c",
    "log/build:vulnerable#L12",
    "log/build:fixed#L3-9",
    "log/fuzz:0#L7",
    "log/fuzz:12#L1",
]

INVALID_REFS = [
    "log/build:both#L1",
    "log/build:vulnerable#L0",
    "log/build:vulnerable#L9-4",
    "log/build:vulnerable#L1-L2",
    "log/build:vulnerable#L",
    "log/build:#L1",
    "log/fuzz:00#L3",
    "log/fuzz:-1#L3",
    "log/fuzz:0#L0",
    "log/fuzz:0#L3-4",
]

BUILD_LOG = "".join(f"build line {number}\n" for number in range(1, 13)).encode()
FUZZ_LOG = "".join(f"fuzz line {number}\n" for number in range(1, 9)).encode()


def _analysis_with(*refs):
    analysis = deepcopy(ANALYSIS)
    analysis["findings"][1]["evidence_refs"] = list(refs)
    return analysis


def test_log_build_and_log_fuzz_refs_resolve_to_frozen_lines():
    valid = _analysis_with(*VALID_REFS)
    digest = analysis_digest(valid)
    assert digest.startswith("sha256:")

    # The referenced line range is frozen material: moving it must move the
    # digest, otherwise a report could point at different bytes.
    moved = _analysis_with(
        "git:diff/a..b/parser.c",
        "log/build:vulnerable#L13",
        "log/build:fixed#L3-9",
        "log/fuzz:0#L7",
        "log/fuzz:12#L1",
    )
    assert analysis_digest(moved) != digest, (
        "log/build line numbers are not bound by the analysis digest"
    )

    for ref in INVALID_REFS:
        with pytest.raises(ValueError):
            analysis_digest(_analysis_with(ref))


def _manifest(files):
    entries = []
    for relative, (role, data) in sorted(files.items()):
        entries.append(
            {
                "path": relative,
                "role": role,
                "size_bytes": len(data),
                "sha256": hashlib.sha256(data).hexdigest(),
            }
        )
    return {
        "schema_version": 2,
        "bundle_kind": "blocked",
        "job_id": str(uuid4()),
        "family_id": None,
        "parent_job_id": None,
        "round_no": None,
        "plan_digest": None,
        "envelope_digest": None,
        "experiment_digest": None,
        "build_provenance_rules_version": None,
        "verdict": "BLOCKED",
        "reason_code": "REVIEW_REJECTED",
        "build_ref": None,
        "reuse_origin": None,
        "created_at": "2099-01-01T00:00:00Z",
        "files": entries,
    }


def _write_bundle(tmp_path: Path, files):
    root = tmp_path / f"refs-{uuid4().hex}"
    root.mkdir()
    for relative, (_role, data) in files.items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
    (root / "manifest.json").write_text(
        json.dumps(_manifest(files)), encoding="utf-8"
    )
    return root


def _log_files():
    return {
        "report.json": ("report_json", b"{}"),
        "report.md": ("report_markdown", b"# blocked\n"),
        "build/vulnerable/build.log": ("build_log", BUILD_LOG),
        "build/fixed/build.log": ("build_log", BUILD_LOG),
        "fuzz/fuzz.log": ("fuzz_log", FUZZ_LOG),
    }


def test_resolve_evidence_ref_returns_single_line_and_inclusive_range(tmp_path):
    root = _write_bundle(tmp_path, _log_files())

    assert evidence.resolve_evidence_ref(root, "log/build:vulnerable#L12") == [
        "build line 12"
    ]
    assert evidence.resolve_evidence_ref(root, "log/build:fixed#L3-5") == [
        "build line 3",
        "build line 4",
        "build line 5",
    ]
    assert evidence.resolve_evidence_ref(root, "log/fuzz:0#L7") == ["fuzz line 7"]


@pytest.mark.parametrize(
    "ref",
    [
        "log/build:vulnerable#L13",
        "log/build:vulnerable#L1-13",
        "log/fuzz:0#L9",
    ],
)
def test_resolve_evidence_ref_rejects_out_of_range_lines(tmp_path, ref):
    root = _write_bundle(tmp_path, _log_files())

    with pytest.raises(evidence.EvidenceRefError) as raised:
        evidence.resolve_evidence_ref(root, ref)
    assert raised.value.reason_code == "LINE_OUT_OF_RANGE"
    assert isinstance(raised.value, BundleError)


@pytest.mark.parametrize(
    "ref",
    [
        "log/build:vulnerable#L1",
        "log/fuzz:0#L1",
    ],
)
def test_resolve_evidence_ref_rejects_missing_log_role(tmp_path, ref):
    files = _log_files()
    del files["build/vulnerable/build.log"]
    del files["fuzz/fuzz.log"]
    root = _write_bundle(tmp_path, files)

    with pytest.raises(evidence.EvidenceRefError) as raised:
        evidence.resolve_evidence_ref(root, ref)
    assert raised.value.reason_code == "MISSING_LOG"


def test_resolve_evidence_ref_rejects_wrong_role_at_build_path(tmp_path):
    files = _log_files()
    files["build/fixed/build.log"] = ("build_metadata", BUILD_LOG)
    root = _write_bundle(tmp_path, files)

    with pytest.raises(evidence.EvidenceRefError) as raised:
        evidence.resolve_evidence_ref(root, "log/build:fixed#L1")
    assert raised.value.reason_code == "MISSING_LOG"


def test_resolve_evidence_ref_rejects_digest_mismatch(tmp_path):
    root = _write_bundle(tmp_path, _log_files())
    (root / "build/vulnerable/build.log").write_bytes(
        BUILD_LOG.replace(b"build line 1\n", b"tampered line 1\n", 1)
    )

    with pytest.raises(evidence.EvidenceRefError) as raised:
        evidence.resolve_evidence_ref(root, "log/build:vulnerable#L1")
    assert raised.value.reason_code == "DIGEST_MISMATCH"


@pytest.mark.parametrize("ref", INVALID_REFS + ["git:diff/a..b/parser.c"])
def test_resolve_evidence_ref_rejects_malformed_syntax(tmp_path, ref):
    root = _write_bundle(tmp_path, _log_files())

    with pytest.raises(evidence.EvidenceRefError) as raised:
        evidence.resolve_evidence_ref(root, ref)
    assert raised.value.reason_code == "INVALID_REFERENCE"
