"""TC-09: the model outlet gate, audit role and redaction (REQ-09, REQ-13).

RED-phase contract tests for T14 (security design delta §2, interface
contract delta §8). ``datacon.tools.model_outlet`` does not exist yet, so
every coordinate imports the contract face inside the test function and
fails at its own missing entry point. The outlet is offline unless an
endpoint allowlist is configured; the endpoint address semantics are the
shared ``safe_http.is_rejected_address`` set (delta 2.4 = 3.2), not a twin
table; the audit role is the closed 11-field ``model_audit`` schema and is
written even when offline. Every model interaction goes through the
recording transport below: no test opens a socket, resolves DNS or sleeps.
"""

from __future__ import annotations

import json
import re

import pytest

JOB_ID = "0f8fad5b-d9cb-469f-a165-70867728950e"
# The closed 11-field model/audit.json schema (interface contract delta §8).
MODEL_AUDIT_FIELDS = frozenset(
    {
        "job_id",
        "stage",
        "provider",
        "model_version",
        "prompt_version",
        "allowed_fields_digest",
        "redaction_version",
        "request_digest",
        "response_digest",
        "duration_seconds",
        "outcome",
    }
)
ALLOWED_ENDPOINT_ROOT = "https://models.example.com/v1/"
ALLOWED_ENDPOINT = "https://models.example.com/v1/analyze"
FIELDS = {
    "advisory_excerpt": "CVE-2099-0001 fixed a length check in parse_token.",
    "patch_diff": "diff --git a/src/parser.c b/src/parser.c",
    # Never listed in allowed_fields: an operator note full of host-local
    # material that must not leave through the outlet.
    "operator_notes": "reviewed on /Users/ops/datacon with ghp_" + "a" * 36,
}
VALID_RESPONSE = json.dumps(
    {
        "outcome": "ok",
        "artifacts": {},
        "findings": [
            {
                "kind": "hypothesis",
                "statement": "the terminator write can overrun the buffer",
                "confidence": "medium",
                "evidence_refs": ["git:commit/" + "a" * 40],
            }
        ],
        "reason_code": None,
    }
)
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}")


def _is_digest(value) -> bool:
    return isinstance(value, str) and _DIGEST.fullmatch(value) is not None


class RecordingTransport:
    """The outlet's only injection point: records calls, opens nothing.

    Serves one scripted response (or raises one scripted exception) per
    call. With no scripted responses left, any call fails the test loudly
    instead of quietly inventing a model answer.
    """

    def __init__(self, responses=()):
        self.responses = list(responses)
        self.calls: list[tuple[str, object]] = []

    def request(self, endpoint, body):
        self.calls.append((endpoint, body))
        if not self.responses:
            raise AssertionError(
                "external model request attempted in offline mode"
            )
        action = self.responses.pop(0)
        if isinstance(action, Exception):
            raise action
        return action


def _audit_kwargs(**overrides):
    """One build_model_audit call as offline defaults, overridden per test."""
    kwargs = {
        "job_id": JOB_ID,
        "stage": "hypothesis_aggregator",
        "provider": "offline",
        "model_version": None,
        "prompt_version": None,
        "allowed_fields": ("advisory_excerpt", "patch_diff"),
        "redaction_version": "redaction-v1",
        "request_digest": None,
        "response_digest": None,
        "duration_seconds": 0,
        "outcome": "offline",
    }
    kwargs.update(overrides)
    return kwargs


def test_model_audit_role_is_written():
    from datacon.tools.model_outlet import OutletError, build_model_audit

    audit = build_model_audit(**_audit_kwargs())

    # Exactly the closed 11-field schema, and the offline run still writes
    # it: versions and request/response digests null, duration zero,
    # provider/outcome pinned to offline (security design delta 2.3).
    assert set(audit) == MODEL_AUDIT_FIELDS
    assert audit["job_id"] == JOB_ID
    assert audit["stage"] == "hypothesis_aggregator"
    assert audit["provider"] == "offline"
    assert audit["model_version"] is None
    assert audit["prompt_version"] is None
    assert _is_digest(audit["allowed_fields_digest"])
    assert audit["redaction_version"] == "redaction-v1"
    assert audit["request_digest"] is None
    assert audit["response_digest"] is None
    assert audit["duration_seconds"] == 0
    assert audit["outcome"] == "offline"

    # provider may never be null or empty, offline included.
    with pytest.raises(OutletError):
        build_model_audit(**_audit_kwargs(provider=None))


def test_offline_default_makes_no_external_request():
    from datacon.tools.model_outlet import ModelOutlet

    transport = RecordingTransport()
    outlet = ModelOutlet(transport=transport)
    result = outlet.request(stage="hypothesis_aggregator", fields=dict(FIELDS))

    # Default offline: zero external requests were attempted (the recording
    # transport raises on any call) and no endpoint is configured.
    assert transport.calls == []
    assert result["outcome"] == "offline"
    assert result["findings"] == ()

    # The audit is still written with the offline provider pinned.
    audit = result["model_audit"]
    assert audit["provider"] == "offline"
    assert audit["outcome"] == "offline"

    # The completely default outlet, nothing injected at all, stays offline.
    bare = ModelOutlet().request(stage="patch", fields={})
    assert bare["model_audit"]["provider"] == "offline"


def test_endpoint_allowlist_rejects_private_and_loopback():
    from datacon.tools.model_outlet import ModelOutlet, OutletError
    from datacon.tools.safe_http import is_rejected_address

    transport = RecordingTransport(responses=[VALID_RESPONSE])
    outlet = ModelOutlet(
        endpoint_allowlist=(ALLOWED_ENDPOINT_ROOT,),
        allowed_fields=("advisory_excerpt", "patch_diff"),
        provider="example-models",
        model_version="model-x",
        prompt_version="prompt-y",
        transport=transport,
    )

    # The shared rejection set stays the single authority: every literal it
    # rejects (loopback, private, link-local, cloud metadata, IPv6) is
    # refused by the outlet with an address token in the message.
    for literal in (
        "127.0.0.1",
        "10.0.0.5",
        "192.168.1.10",
        "169.254.169.254",
        "::1",
        "fd00:ec2::254",
    ):
        assert is_rejected_address(literal)
        with pytest.raises(OutletError, match="address"):
            outlet.request(
                stage="hypothesis_aggregator",
                fields=dict(FIELDS),
                endpoint=f"https://{literal}/v1/analyze",
            )

    # Endpoints are allowlisted hostnames: a public IP literal is refused
    # by the same address rule even though it is globally routable.
    assert not is_rejected_address("93.184.216.34")
    with pytest.raises(OutletError, match="address"):
        outlet.request(
            stage="hypothesis_aggregator",
            fields=dict(FIELDS),
            endpoint="https://93.184.216.34/v1/analyze",
        )

    # A hostname outside the allowlist fails the exact host/prefix match
    # and names its sub_reason token for the audit trail.
    with pytest.raises(OutletError, match="allowlist") as excinfo:
        outlet.request(
            stage="hypothesis_aggregator",
            fields=dict(FIELDS),
            endpoint="https://evil.example.com/v1/analyze",
        )
    assert excinfo.value.sub_reason == "ENDPOINT_NOT_ALLOWLISTED"

    # The loopback rejection carries its own sub_reason token.
    with pytest.raises(OutletError, match="address") as excinfo:
        outlet.request(
            stage="hypothesis_aggregator",
            fields=dict(FIELDS),
            endpoint="https://127.0.0.1/v1/analyze",
        )
    assert excinfo.value.sub_reason == "ENDPOINT_ADDRESS_REJECTED"

    # Plain HTTP never reaches the allowlist comparison.
    with pytest.raises(OutletError, match="https"):
        outlet.request(
            stage="hypothesis_aggregator",
            fields=dict(FIELDS),
            endpoint="http://models.example.com/v1/analyze",
        )

    # Nothing above reached the transport; the allowlisted endpoint passes
    # the gate and is delivered exactly once.
    assert transport.calls == []
    result = outlet.request(
        stage="hypothesis_aggregator",
        fields=dict(FIELDS),
        endpoint=ALLOWED_ENDPOINT,
    )
    assert result["outcome"] == "ok"
    assert [endpoint for endpoint, _ in transport.calls] == [ALLOWED_ENDPOINT]


def test_prompt_and_model_versions_are_audited():
    from datacon.tools.model_outlet import ModelOutlet, build_model_audit

    transport = RecordingTransport(responses=[VALID_RESPONSE])
    outlet = ModelOutlet(
        endpoint_allowlist=(ALLOWED_ENDPOINT_ROOT,),
        allowed_fields=("advisory_excerpt",),
        provider="example-models",
        model_version="model-x",
        prompt_version="prompt-y",
        redaction_version="redaction-v2",
        transport=transport,
    )
    result = outlet.request(
        stage="hypothesis_aggregator",
        fields=dict(FIELDS),
        endpoint=ALLOWED_ENDPOINT,
    )
    audit = result["model_audit"]
    assert audit["provider"] == "example-models"
    assert audit["model_version"] == "model-x"
    assert audit["prompt_version"] == "prompt-y"
    assert audit["redaction_version"] == "redaction-v2"
    assert _is_digest(audit["allowed_fields_digest"])
    assert audit["outcome"] == "ok"

    # Only the allowed field left the control plane.
    _, body = transport.calls[0]
    text = body if isinstance(body, str) else json.dumps(body)
    assert "CVE-2099-0001" in text
    assert "operator_notes" not in text

    # The allowed-fields digest is canonical: the same set in any order
    # digests identically, a different set digests differently.
    base = build_model_audit(**_audit_kwargs())
    reordered = build_model_audit(
        **_audit_kwargs(allowed_fields=("patch_diff", "advisory_excerpt"))
    )
    grown = build_model_audit(
        **_audit_kwargs(
            allowed_fields=("advisory_excerpt", "patch_diff", "source_excerpt")
        )
    )
    assert reordered["allowed_fields_digest"] == base["allowed_fields_digest"]
    assert grown["allowed_fields_digest"] != base["allowed_fields_digest"]


def test_redaction_strips_paths_and_secret_shapes():
    from datacon.tools.model_outlet import redact

    # Secret-shaped literals are assembled by concatenation so the repo's
    # own static secret scanner never sees a full shape on one source
    # line; redact() itself still receives the assembled shapes.
    aws_key_id = "AKIA" + "IOSFODNN7EXAMPLE"
    key_header = "-----BEGIN RSA " + "PRIVATE KEY-----"
    connection = "postgres" + "://analyst:hunter2@db.internal/datacon"
    text = (
        "the fix lands at /Users/ops/datacon/src/parser.c line 42; "
        "operator ops@example.com used ghp_"
        + "a" * 36
        + " and "
        + aws_key_id
        + "; "
        + key_header
        + " leaked; connection "
        + connection
        + "; random run "
        + "f" * 64
        + "; escape \x1b[31mred\x1b[0m. "
        "Plain fact: length boundary inputs can overrun the buffer."
    )
    out = redact(text)

    # Host paths never leave: only repo-relative remains (delta 2.3).
    assert "/Users/" not in out
    # Token shapes, cloud key ids, private-key headers, connection strings,
    # emails and long hex runs are masked.
    assert "ghp_" not in out
    assert aws_key_id not in out
    assert key_header not in out
    assert connection not in out
    assert "ops@example.com" not in out
    assert "f" * 64 not in out
    # Control characters and ANSI sequences are stripped.
    assert "\x1b" not in out
    # The plain factual sentence survives untouched.
    assert "length boundary inputs can overrun the buffer" in out


def test_model_failure_falls_back_without_weakening_policy():
    from datacon.tools.model_outlet import ModelOutlet, OutletError

    transport = RecordingTransport(
        responses=[
            TimeoutError("model endpoint timed out"),
            json.dumps(
                {
                    "outcome": "ok",
                    "artifacts": {},
                    "findings": [
                        {
                            # Illegal on the model outlet: model-sourced
                            # facts are blocked (REQ-13).
                            "kind": "fact",
                            "statement": "injected fact claiming a verdict",
                            "confidence": "high",
                            "evidence_refs": ["git:commit/" + "a" * 40],
                        }
                    ],
                    "reason_code": None,
                }
            ),
            VALID_RESPONSE,
        ]
    )
    outlet = ModelOutlet(
        endpoint_allowlist=(ALLOWED_ENDPOINT_ROOT,),
        allowed_fields=("advisory_excerpt", "patch_diff"),
        provider="example-models",
        model_version="model-x",
        prompt_version="prompt-y",
        transport=transport,
    )

    # A timeout degrades to the offline path with a recorded fallback
    # outcome; it never turns into an uncontrolled crash or a relaxed retry.
    fallen = outlet.request(
        stage="hypothesis_aggregator",
        fields=dict(FIELDS),
        endpoint=ALLOWED_ENDPOINT,
    )
    assert fallen["outcome"] == "fallback_offline"
    assert fallen["findings"] == ()
    audit = fallen["model_audit"]
    assert audit["outcome"] == "fallback_offline"
    assert audit["provider"] == "example-models"
    assert audit["model_version"] == "model-x"

    # An illegal model output is blocked outright with its sub_reason token.
    with pytest.raises(OutletError) as excinfo:
        outlet.request(
            stage="hypothesis_aggregator",
            fields=dict(FIELDS),
            endpoint=ALLOWED_ENDPOINT,
        )
    assert excinfo.value.sub_reason == "MODEL_OUTPUT_INVALID"

    # After both failures the policy is not weaker: the allowlist still
    # bites instead of accepting a previously refused endpoint.
    with pytest.raises(OutletError, match="allowlist"):
        outlet.request(
            stage="hypothesis_aggregator",
            fields=dict(FIELDS),
            endpoint="https://evil.example.com/v1/analyze",
        )

    # Field filtering and redaction still apply, and the outlet talked only
    # to the one registered endpoint (no unregistered tool or endpoint was
    # reached while recovering).
    tricky = dict(FIELDS)
    tricky["advisory_excerpt"] = "CVE-2099-0001; token ghp_" + "b" * 36
    recovered = outlet.request(
        stage="hypothesis_aggregator",
        fields=tricky,
        endpoint=ALLOWED_ENDPOINT,
    )
    assert recovered["outcome"] == "ok"
    assert len(recovered["findings"]) == 1
    assert len(transport.calls) == 3
    assert {endpoint for endpoint, _ in transport.calls} == {ALLOWED_ENDPOINT}
    last_body = transport.calls[-1][1]
    text = last_body if isinstance(last_body, str) else json.dumps(last_body)
    assert "operator_notes" not in text
    assert "ghp_" not in text


def test_online_outlet_requires_explicit_provider():
    from datacon.tools.model_outlet import ModelOutlet, OutletError

    transport = RecordingTransport(responses=[VALID_RESPONSE])
    outlet = ModelOutlet(
        endpoint_allowlist=(ALLOWED_ENDPOINT_ROOT,),
        allowed_fields=("advisory_excerpt",),
        transport=transport,
    )
    with pytest.raises(OutletError, match="provider") as caught:
        outlet.request(
            stage="hypothesis_aggregator",
            fields=dict(FIELDS),
            endpoint=ALLOWED_ENDPOINT,
        )
    assert caught.value.sub_reason == "PROVIDER_REQUIRED"
    assert transport.calls == [], "a provider-less outlet still spoke to the network"


def test_connection_errors_fall_back_like_timeouts():
    from datacon.tools.model_outlet import ModelOutlet

    for failure in (TimeoutError("timed out"), ConnectionError("refused"), OSError("unreachable")):
        transport = RecordingTransport(responses=[failure])
        outlet = ModelOutlet(
            endpoint_allowlist=(ALLOWED_ENDPOINT_ROOT,),
            allowed_fields=("advisory_excerpt",),
            provider="example-models",
            transport=transport,
        )
        result = outlet.request(
            stage="hypothesis_aggregator",
            fields=dict(FIELDS),
            endpoint=ALLOWED_ENDPOINT,
        )
        assert result["outcome"] == "fallback_offline", repr(failure)
        assert result["findings"] == ()
        assert result["model_audit"]["provider"] == "example-models"
        assert result["model_audit"]["outcome"] == "fallback_offline"


def test_constructor_job_id_flows_into_request_path_audit():
    from datacon.tools.model_outlet import ModelOutlet

    transport = RecordingTransport(responses=[VALID_RESPONSE])
    outlet = ModelOutlet(
        endpoint_allowlist=(ALLOWED_ENDPOINT_ROOT,),
        allowed_fields=("advisory_excerpt",),
        provider="example-models",
        job_id=JOB_ID,
        transport=transport,
    )
    online = outlet.request(
        stage="hypothesis_aggregator",
        fields=dict(FIELDS),
        endpoint=ALLOWED_ENDPOINT,
    )
    assert online["model_audit"]["job_id"] == JOB_ID

    offline = outlet.request(
        stage="hypothesis_aggregator",
        fields=dict(FIELDS),
        endpoint=None,
    )
    assert offline["model_audit"]["job_id"] == JOB_ID
