"""TC-16/T10: v2 evidence references ``log/build`` and ``log/fuzz``.

The grammar is frozen in interface-contract-delta §11. These tests exercise
the parser through ``analysis_digest``: a v2 reference must be canonicalised
(and therefore line numbers are bound by the digest), while malformed
references must fail closed. Resolving a reference to bytes needs the v2 bundle
verifier and is registered for the bundle work; the grammar and binding live
here because they are pure contract.
"""

from copy import deepcopy

import pytest

from test_plan import ANALYSIS

from datacon.contracts import analysis_digest

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
