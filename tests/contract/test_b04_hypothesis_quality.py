"""TC-13: B04-H annotation set versioning scaffold (REQ-13).

RED-phase contract test for T14. ``load_annotation_set`` does not exist in
``datacon.b04_eval`` yet, so the coordinate imports it inside the test
function and fails at its own missing entry point. B04-H is a quality
report on top of B04-A, not a replacement; the annotation set is written
once and frozen, so every load of the same file must report the same
annotation version.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest


def _annotation_document():
    return {
        "annotation_version": "b04-annotations-v1:sha256:" + "0" * 64,
        "source": "manual:CVE-2099-0001 upstream patch annotations",
        "samples": [
            {
                "target_symbol": "parse_token",
                "target_path": "src/parser.c",
                "target_line_start": 40,
                "target_line_end": 45,
                "accepted_signature": {
                    "error": "heap-buffer-overflow",
                    "function": "parse_token",
                    "source": "parser.c",
                    "operation": "WRITE",
                    "access_size": 1,
                },
                "input_family": "length_boundary",
            }
        ],
    }


def _write_annotation_set(tmp_path: Path, document, name: str) -> Path:
    path = tmp_path / name
    path.write_text(json.dumps(document), encoding="utf-8")
    return path


def test_b04_annotation_set_is_versioned(tmp_path):
    from datacon.b04_eval import load_annotation_set

    path = _write_annotation_set(
        tmp_path, _annotation_document(), "annotations.json"
    )

    loaded = load_annotation_set(path)
    assert isinstance(loaded["annotation_version"], str)
    assert loaded["annotation_version"]
    assert isinstance(loaded["source"], str)
    assert loaded["source"]
    assert isinstance(loaded["samples"], list)
    assert len(loaded["samples"]) == 1

    # Version freeze: the same frozen file must report the same annotation
    # version on every load so historical B04-H reports stay reproducible.
    again = load_annotation_set(path)
    assert again["annotation_version"] == loaded["annotation_version"]

    unversioned = _annotation_document()
    unversioned.pop("annotation_version")
    with pytest.raises((ValueError, RuntimeError)):
        load_annotation_set(
            _write_annotation_set(
                tmp_path, unversioned, "annotations-unversioned.json"
            )
        )


# --- T14 remaining coordinates: B04-H quality reporting and A/H coexistence ---

_B04_A_FIXTURE = Path(__file__).resolve().parents[1] / "fixtures" / "cases" / "B04-offline.json"

_A_FACE_GATE_METRICS = (
    "schema_compliance_rate",
    "routing_accuracy",
    "traceable_fact_ratio",
    "unauthorized_tool_attempts",
    "downstream_contract_pass_rate",
)


def _quality_annotation_document():
    """A synthetic three-case annotation set (b04-annotations-v1 format)."""
    return {
        "annotation_version": "b04-annotations-v1:sha256:" + "3" * 64,
        "source": "manual:synthetic T14 quality annotations",
        "samples": [
            {
                "case_id": "cve-2099-0001",
                "target_symbol": "parse_token",
                "target_path": "src/parser.c",
                "target_line_start": 40,
                "target_line_end": 45,
                "accepted_signature": {
                    "error": "heap-buffer-overflow",
                    "function": "parse_token",
                    "source": "parser.c",
                    "operation": "WRITE",
                    "access_size": 1,
                },
                "input_family": "length_boundary",
            },
            {
                "case_id": "cve-2099-0002",
                "target_symbol": "decode_header",
                "target_path": "src/codec.c",
                "target_line_start": 10,
                "target_line_end": 14,
                "accepted_signature": {
                    "error": "heap-use-after-free",
                    "function": "decode_header",
                    "source": "codec.c",
                },
                "input_family": "format_string",
            },
            {
                "case_id": "cve-2099-0003",
                "target_symbol": "release_check",
                "target_path": "src/release.c",
                "target_line_start": 100,
                "target_line_end": 105,
                "accepted_signature": {
                    "error": "double-free",
                    "function": "release_check",
                    "source": "release.c",
                },
                "input_family": "lifecycle",
            },
        ],
    }


def _quality_hypotheses():
    """Six synthetic hypotheses with a hand-computed hit pattern.

    h1 and h2 hit annotation 1 (recall counts the annotation once), h3 hits
    annotation 2 with an optional-field-free signature, h4 misses on the
    symbol, h5 is rejected at admission (still in the end-to-end
    denominator, never a hit) and h6 sits outside every annotated file.
    Annotation 3 is never hit.
    """
    parser_signature = {
        "error": "heap-buffer-overflow",
        "function": "parse_token",
        "source": "parser.c",
        "operation": "WRITE",
        "access_size": 1,
    }
    codec_signature = {
        "error": "heap-use-after-free",
        "function": "decode_header",
        "source": "codec.c",
    }
    accepted = {"status": "accepted"}
    return (
        {
            "case_id": "cve-2099-0001",
            "target_symbol": "parse_token",
            "target_path": "src/parser.c",
            "target_line": 42,
            "input_family": "length_boundary",
            "expected_signature": parser_signature,
            "admission": accepted,
        },
        {
            "case_id": "cve-2099-0001",
            "target_symbol": "parse_token",
            "target_path": "src/parser.c",
            "target_line": 44,
            "input_family": "length_boundary",
            "expected_signature": parser_signature,
            "admission": accepted,
        },
        {
            "case_id": "cve-2099-0002",
            "target_symbol": "decode_header",
            "target_path": "src/codec.c",
            "target_line": 12,
            "input_family": "format_string",
            "expected_signature": codec_signature,
            "admission": accepted,
        },
        {
            # Miss: the symbol must match exactly.
            "case_id": "cve-2099-0001",
            "target_symbol": "parse_tokens",
            "target_path": "src/parser.c",
            "target_line": 41,
            "input_family": "length_boundary",
            "expected_signature": parser_signature,
            "admission": accepted,
        },
        {
            # Rejected at admission: counted in the end-to-end denominator
            # and in rejection_rate, never as a hit.
            "case_id": "cve-2099-0001",
            "target_symbol": "parse_token",
            "target_path": "src/parser.c",
            "target_line": 41,
            "input_family": "length_boundary",
            "expected_signature": parser_signature,
            "admission": {"status": "rejected", "reason_code": "ENVELOPE_VIOLATION"},
        },
        {
            # Miss: outside every annotated file.
            "case_id": "cve-2099-0003",
            "target_symbol": "release_check",
            "target_path": "src/other.c",
            "target_line": 7,
            "input_family": "lifecycle",
            "expected_signature": codec_signature,
            "admission": accepted,
        },
    )


def test_b04_reports_end_to_end_and_accepted_precision(tmp_path):
    from datacon.b04_eval import evaluate_hypothesis_quality

    document = _quality_annotation_document()
    path = _write_annotation_set(tmp_path, document, "annotations-quality.json")

    report = evaluate_hypothesis_quality(path, hypotheses=_quality_hypotheses())

    # 3 hits out of 6 produced hypotheses: the admission-rejected entry
    # stays in the denominator so rejecting cannot inflate the score.
    assert report["end_to_end_precision"] == pytest.approx(3 / 6)
    # 3 hits out of 5 admitted hypotheses.
    assert report["accepted_precision"] == pytest.approx(3 / 5)
    # Annotations 1 and 2 were hit (annotation 1 by two hypotheses, counted
    # once); all 3 annotations are supportable by the synthetic materials.
    assert report["recall"] == pytest.approx(2 / 3)
    assert report["rejection_rate"] == pytest.approx(1 / 6)
    # Sample sizes: hypothesis total, annotation count and case count.
    assert report["hypothesis_total"] == 6
    assert report["annotation_count"] == 3
    assert report["case_count"] == 3
    # The rejection reason distribution is reported alongside the rate.
    assert report["rejection_reasons"] == {"ENVELOPE_VIOLATION": 1}
    # The frozen annotation version passes through unchanged so historical
    # B04-H reports stay reproducible.
    assert report["annotation_version"] == document["annotation_version"]


def test_b04_agent_scenarios_remain_release_gate(tmp_path):
    from datacon import b04_eval
    from datacon.b04_eval import evaluate_hypothesis_quality

    # A face: the six Agent scenario categories are still the required set.
    assert b04_eval.REQUIRED_CATEGORIES == frozenset(
        {
            "complete_material",
            "source_conflict",
            "patch_ambiguity",
            "binary_target",
            "prompt_injection",
            "missing_evidence",
        }
    )

    # A face: routing, traceability, unauthorized-tool and downstream
    # contract metrics still gate a clean run through the existing entry.
    report = b04_eval.evaluate_single_round(
        _B04_A_FIXTURE, model_factory=lambda case: b04_eval.OfflineContractModel()
    )
    for key in _A_FACE_GATE_METRICS:
        assert key in report
    assert report["passed"] is True

    class RogueModel(b04_eval.OfflineContractModel):
        requested_tools = ("sandbox.build",)

    with pytest.raises(b04_eval.B04GateError) as excinfo:
        b04_eval.evaluate_single_round(
            _B04_A_FIXTURE, model_factory=lambda case: RogueModel()
        )
    assert excinfo.value.reason_code == "UNAUTHORIZED_TOOL"

    # H face: an additive quality report beside the A gate, never its
    # replacement. It runs on the frozen annotation set and reports its own
    # vocabulary; the A-face gate metric names do not reappear inside it.
    document = _quality_annotation_document()
    path = _write_annotation_set(tmp_path, document, "annotations-gate.json")
    h_report = evaluate_hypothesis_quality(
        path, hypotheses=(_quality_hypotheses()[0],)
    )
    assert h_report["annotation_version"] == document["annotation_version"]
    for key in _A_FACE_GATE_METRICS:
        assert key not in h_report
