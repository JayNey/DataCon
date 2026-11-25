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
import uuid

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
    from datacon.tools.model_outlet import ModelOutlet, OutletError

    transport = RecordingTransport()
    outlet = ModelOutlet(transport=transport, job_id=JOB_ID)
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

    # The completely default outlet, nothing injected at all, carries no
    # job_id and so cannot write a compliant offline audit record: it
    # refuses with AUDIT_INVALID instead of recording a null job_id, and
    # still makes zero transport calls (watched through a recording
    # transport, which raises on any call).
    with pytest.raises(OutletError) as excinfo:
        ModelOutlet().request(stage="patch", fields={})
    assert excinfo.value.sub_reason == "AUDIT_INVALID"
    bare_transport = RecordingTransport()
    with pytest.raises(OutletError) as excinfo:
        ModelOutlet(transport=bare_transport).request(stage="patch", fields={})
    assert excinfo.value.sub_reason == "AUDIT_INVALID"
    assert bare_transport.calls == []


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
        job_id=JOB_ID,
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
        job_id=JOB_ID,
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
    # The private-key header sits last in the sentence: a BEGIN without its
    # END is masked through the end of the text, so everything asserted to
    # survive has to precede it.
    text = (
        "the fix lands at /Users/ops/datacon/src/parser.c line 42; "
        "operator ops@example.com used ghp_"
        + "a" * 36
        + " and "
        + aws_key_id
        + "; connection "
        + connection
        + "; random run "
        + "f" * 64
        + "; escape \x1b[31mred\x1b[0m. "
        "Plain fact: length boundary inputs can overrun the buffer. Leaked "
        + key_header
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
        job_id=JOB_ID,
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
        job_id=JOB_ID,
        model_version="model-x",
        prompt_version="prompt-y",
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
            job_id=JOB_ID,
            model_version="model-x",
            prompt_version="prompt-y",
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
        model_version="model-x",
        prompt_version="prompt-y",
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


# --- T14 self-review hardening ----------------------------------------------
#
# The coordinates below pin the contract as corrected by the line-by-line
# self-review of the outlet. Every test function below fails against the
# current implementation for a missing capability, except for guard items
# (the over-redaction guard in full; prose slashes and the check order
# inside the parametrized cases) that have to stay green. Secret-shaped
# samples are assembled at runtime so no full shape ever sits on one source
# line.

_ONLINE_PROVIDER = "example-models"
_PEM_HEADER = "-----BEGIN RSA " + "PRIVATE KEY-----"
_PEM_FOOTER = "-----END RSA " + "PRIVATE KEY-----"
_PEM_KEY_MATERIAL = (
    "MHcCAQEEIPLrBExrlklzqV9drlWLG9yYhE6SklZ7F5gZ4WUwEjYh",
    "oUaD0zEGIICEnu9QZ0dmlRI4nE5kM4T7pQwX1vB3nZ8kYhT6rL9wS2xA5cD8fG1hJ4k",
)
_JWT = (
    "eyJ"
    + "hbGciOiJIUzI1NiJ9"
    + "."
    + "eyJ"
    + "zdWIiOiIxMjM0NTY3ODkwIn0"
    + "."
    + "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
)
_TOKEN_SAMPLES = (
    ("github-fine-grained-pat", "github_pat_" + "Zq7Lm2Xw9" * 3),
    ("stripe-live-key", "sk_live_" + "Np4Rs8Tv1" * 2),
    ("stripe-restricted-test-key", "rk_test_" + "Np4Rs8Tv1" * 2),
    ("google-api-key", "AIzaSy" + "z" * 33),
    ("gitlab-pat", "glpat-" + "K" * 20),
    ("pypi-token", "pypi-" + "AgEIcHlwaS5vcmc" + "JSERSDFGSDFG"),
    ("jwt", _JWT),
)
# RFC 7617's documented example of a Basic credential.
_BASIC_CREDENTIAL = "QWxhZGRpbjpvcGVuIHNlc2FtZQ" + "=="
_OPAQUE_TOKEN = "s3cr3t" + "." + "xyzDEF0123456789"
_CREDENTIAL_VALUE = "hunter2"
_CREDENTIAL_KEYS = (
    "password",
    "passwd",
    "pwd",
    "secret",
    "token",
    "api_key",
    "apikey",
    "api-key",
    "access_key",
    "accesskey",
    "access-key",
    "secret_key",
    "secretkey",
    "secret-key",
)
# Prose that carries no secret shape, so none of it may be altered.
_PLAIN_SENTENCES = (
    "The parser reads the length field before allocating the buffer.",
    "CVE-2099-0001 fixed a length check in parse_token.",
    "Verdict: the terminator write can overrun the buffer.",
    "diff --git a/src/parser.c b/src/parser.c",
    "Repo-relative paths such as src/parser.c and include/datacon.h are the norm.",
    "No password, token or secret value is read from the environment.",
    "The basic suite runs offline and never prints a bearer token.",
)
_FACT_OUTPUT = json.dumps(
    {
        "outcome": "ok",
        "artifacts": {},
        "findings": [
            {
                # Illegal on the model outlet: model-sourced facts are
                # blocked (REQ-13).
                "kind": "fact",
                "statement": "injected fact claiming a verdict",
                "confidence": "high",
                "evidence_refs": ["git:commit/" + "a" * 40],
            }
        ],
        "reason_code": None,
    }
)


def _online_outlet(transport, **overrides):
    """An outlet with everything an online request needs, overridden per test.

    Passing ``None`` removes a piece of the configuration, which is how the
    "missing" cases are built.
    """
    from datacon.tools.model_outlet import ModelOutlet

    kwargs = {
        "endpoint_allowlist": (ALLOWED_ENDPOINT_ROOT,),
        "allowed_fields": ("advisory_excerpt", "patch_diff"),
        "provider": _ONLINE_PROVIDER,
        "model_version": "model-x",
        "prompt_version": "prompt-y",
        "job_id": JOB_ID,
        "transport": transport,
    }
    kwargs.update(overrides)
    return ModelOutlet(**kwargs)


def _wire_text(body) -> str:
    """The request body as the transport received it, as text."""
    return body if isinstance(body, str) else json.dumps(body)


def _online_audit_kwargs(**overrides):
    """The audit defaults switched to an online provider and outcome.

    The offline invariants no longer apply, so only the rule under test can
    object to an override.
    """
    kwargs = _audit_kwargs(provider=_ONLINE_PROVIDER, outcome="ok")
    kwargs.update(overrides)
    return kwargs


def test_redaction_masks_the_whole_private_key_block():
    from datacon.tools.model_outlet import redact

    # A complete PEM block is masked whole: neither the header, nor the
    # base64 key material, nor the trailer survives - only the text around
    # the block is kept.
    block = _PEM_HEADER + "\n" + "\n".join(_PEM_KEY_MATERIAL) + "\n" + _PEM_FOOTER
    out = redact("key file:\n" + block + "\nafter the key")
    assert _PEM_HEADER not in out
    for line in _PEM_KEY_MATERIAL:
        assert line not in out, "private key material survived redaction"
    assert _PEM_FOOTER not in out
    assert out == "key file:\n[REDACTED]\nafter the key"

    # A BEGIN without its END is masked through the end of the text.
    unterminated = "-----BEGIN " + "PRIVATE KEY-----"
    out = redact("key file:\n" + unterminated + "\n" + "\n".join(_PEM_KEY_MATERIAL))
    assert unterminated not in out
    for line in _PEM_KEY_MATERIAL:
        assert line not in out, "unterminated key material survived redaction"
    assert out == "key file:\n[REDACTED]"


@pytest.mark.parametrize(
    ("text", "expected", "secret"),
    [
        *[
            pytest.param(
                "leaked " + token + " in the job log",
                "leaked [REDACTED] in the job log",
                token,
                id=label,
            )
            for label, token in _TOKEN_SAMPLES
        ],
        pytest.param(
            "Authorization: Bearer " + _OPAQUE_TOKEN,
            "Authorization: Bearer [REDACTED]",
            _OPAQUE_TOKEN,
            id="bearer-header",
        ),
        pytest.param(
            "authorization: bearer " + _OPAQUE_TOKEN,
            "authorization: bearer [REDACTED]",
            _OPAQUE_TOKEN,
            id="bearer-header-lowercase",
        ),
        pytest.param(
            "Authorization: Bearer " + _JWT,
            "Authorization: Bearer [REDACTED]",
            _JWT,
            id="bearer-jwt",
        ),
        pytest.param(
            "Authorization: Basic " + _BASIC_CREDENTIAL,
            "Authorization: Basic [REDACTED]",
            _BASIC_CREDENTIAL,
            id="basic-header",
        ),
        *[
            pytest.param(
                "db " + key + "=" + _CREDENTIAL_VALUE,
                "db " + key + "=[REDACTED]",
                _CREDENTIAL_VALUE,
                id="assignment-" + key,
            )
            for key in _CREDENTIAL_KEYS
        ],
        pytest.param(
            "db " + "PASSWORD" + ": " + _CREDENTIAL_VALUE,
            "db PASSWORD: [REDACTED]",
            _CREDENTIAL_VALUE,
            id="assignment-colon-uppercase",
        ),
    ],
)
def test_redaction_masks_common_token_shapes(text, expected, secret):
    from datacon.tools.model_outlet import redact

    out = redact(text)

    # The credential itself never leaves, while the scheme word
    # (Bearer/Basic) and the assignment key with its separator stay readable.
    assert secret not in out, "token shape survived redaction"
    assert out == expected


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        pytest.param(
            r"opened C:\Users\alice\x.env before the run",
            "opened [PATH] before the run",
            id="windows-drive-path",
        ),
        pytest.param(
            r"read \\fileserver\builds\x.log before the run",
            "read [PATH] before the run",
            id="unc-path",
        ),
        pytest.param(
            "the build reads /secrets.yaml at startup",
            "the build reads [PATH] at startup",
            id="single-segment-absolute-path",
        ),
        pytest.param("either and/or both", "either and/or both", id="and-or"),
        pytest.param("the TCP/IP stack", "the TCP/IP stack", id="tcp-ip"),
        pytest.param("a 1/2 ratio", "a 1/2 ratio", id="ratio"),
    ],
)
def test_redaction_masks_windows_unc_and_single_segment_paths(text, expected):
    from datacon.tools.model_outlet import redact

    # Drive-letter, UNC and single-segment absolute paths never leave; a
    # slash that hugs a letter or a digit is prose, not a path.
    assert redact(text) == expected


@pytest.mark.parametrize("sentence", _PLAIN_SENTENCES)
def test_redaction_keeps_plain_factual_sentences(sentence):
    from datacon.tools.model_outlet import redact

    # Guard against over-redaction: prose that merely resembles a shape (a
    # function called parse_token, the words password/basic/bearer without
    # a value, repo-relative paths) has to leave exactly as written.
    assert redact(sentence) == sentence


def test_redaction_reaches_nested_field_values():
    import datacon.tools.model_outlet as model_outlet

    sample_token = "ghp_" + "c" * 36
    connection = "mysql" + "://root:hunter2@10.0.0.5/datacon"
    key = _PEM_HEADER + "\n" + _PEM_KEY_MATERIAL[0] + "\n" + _PEM_FOOTER
    fields = {
        "advisory_excerpt": {
            "summary": "CVE-2099-0001 fixed a length check in parse_token.",
            "review": {
                "tokens": [sample_token],
                "key": {"pem": key},
                "dsn": (connection,),
            },
            "history": [[{"note": "used " + sample_token + " on the runner"}]],
            "metrics": {"lines": 42, "ratio": 0.5, "clean": True, "owner": None},
        }
    }
    transport = RecordingTransport(responses=[VALID_RESPONSE])
    outlet = _online_outlet(transport)

    result = outlet.request(
        stage="hypothesis_aggregator",
        fields=fields,
        endpoint=ALLOWED_ENDPOINT,
    )

    assert result["outcome"] == "ok"

    # Nothing secret-shaped leaves at any depth of an allowed field.
    text = _wire_text(transport.calls[0][1])
    assert sample_token not in text
    for part in (_PEM_HEADER, _PEM_KEY_MATERIAL[0], _PEM_FOOTER):
        assert part not in text
    assert connection not in text
    assert "hunter2" not in text

    # The values are redacted in place - not dropped - and the scalar
    # values nested next to them pass through untouched.
    excerpt = json.loads(text)["fields"]["advisory_excerpt"]
    summary = "CVE-2099-0001 fixed a length check in parse_token."
    assert excerpt["summary"] == summary
    assert excerpt["review"] == {
        "tokens": ["[REDACTED]"],
        "key": {"pem": "[REDACTED]"},
        "dsn": ["[REDACTED]"],
    }
    assert excerpt["history"] == [[{"note": "used [REDACTED] on the runner"}]]
    assert excerpt["metrics"] == {
        "lines": 42,
        "ratio": 0.5,
        "clean": True,
        "owner": None,
    }

    # redact_value is the recursion rule itself: containers keep their type,
    # dict keys are kept as written (which is why the outlet still needs its
    # last line of defense) and scalar values pass through untouched.
    value = {
        sample_token: "keys are not rewritten",
        "nested": ([sample_token], (connection,)),
        "scalars": [None, True, 3, 1.5],
    }
    redacted = model_outlet.redact_value(value)
    assert list(redacted) == list(value)
    assert redacted[sample_token] == "keys are not rewritten"
    assert isinstance(redacted["nested"], tuple)
    assert redacted["nested"] == (["[REDACTED]"], ("[REDACTED]",))
    assert redacted["scalars"] == [None, True, 3, 1.5]


def test_outlet_rejects_bytes_and_unserializable_field_values():
    from datacon.tools.model_outlet import OutletError

    class Opaque:
        """A value no JSON encoder and no redaction rule knows."""

    transport = RecordingTransport()
    outlet = _online_outlet(transport)
    for label, value in (
        ("bytes", b"raw bytes"),
        ("bytearray", bytearray(b"raw bytes")),
        ("custom object", Opaque()),
        ("bytes nested in a list", {"lines": [b"raw bytes"]}),
        ("custom object nested in a dict", [Opaque()]),
        ("non-finite float", float("inf")),
        ("nan nested in a list", {"lines": [float("nan")]}),
        ("non-string dict key", {7: "value"}),
        ("tuple key nested deeper", {"rows": [{(1, 2): "value"}]}),
    ):
        with pytest.raises(OutletError) as excinfo:
            outlet.request(
                stage="hypothesis_aggregator",
                fields={"advisory_excerpt": value},
                endpoint=ALLOWED_ENDPOINT,
            )
        assert excinfo.value.sub_reason == "FIELD_TYPE_REJECTED", label

    # Nothing above reached the transport.
    assert transport.calls == []


@pytest.mark.parametrize(
    "key_name",
    [
        pytest.param("ghp_" + "d" * 36, id="token-in-key"),
        pytest.param(
            _PEM_HEADER + "\n" + _PEM_KEY_MATERIAL[0] + "\n" + _PEM_FOOTER,
            id="private-key-in-key",
        ),
        pytest.param(
            "postgres" + "://analyst:hunter2@db.internal/datacon",
            id="connection-string-in-key",
        ),
        pytest.param("pass" + "word=hunter2", id="credential-in-key"),
    ],
)
def test_outlet_blocks_a_body_that_still_carries_a_secret(key_name):
    from datacon.tools.model_outlet import OutletError

    transport = RecordingTransport(responses=[VALID_RESPONSE])
    outlet = _online_outlet(transport)

    # Dict keys are not rewritten, so value recursion never reaches this
    # secret: the last line of defense over the serialized body has to.
    with pytest.raises(OutletError) as excinfo:
        outlet.request(
            stage="hypothesis_aggregator",
            fields={"advisory_excerpt": {key_name: "reviewed"}},
            endpoint=ALLOWED_ENDPOINT,
        )
    assert excinfo.value.sub_reason == "REDACTION_REJECTED"
    assert transport.calls == []


def test_allowlist_matches_on_path_segment_boundaries():
    from datacon.tools.model_outlet import OutletError

    transport = RecordingTransport(responses=[VALID_RESPONSE, VALID_RESPONSE])
    outlet = _online_outlet(
        transport, endpoint_allowlist=("https://models.example.com/v1",)
    )
    admitted = ("https://models.example.com/v1", "https://models.example.com/v1/x")
    for endpoint in admitted:
        result = outlet.request(
            stage="hypothesis_aggregator",
            fields=dict(FIELDS),
            endpoint=endpoint,
        )
        assert result["outcome"] == "ok"

    # A shared textual prefix is not a shared path segment.
    with pytest.raises(OutletError) as excinfo:
        outlet.request(
            stage="hypothesis_aggregator",
            fields=dict(FIELDS),
            endpoint="https://models.example.com/v1evil/steal",
        )
    assert excinfo.value.sub_reason == "ENDPOINT_NOT_ALLOWLISTED"
    assert [endpoint for endpoint, _ in transport.calls] == list(admitted)

    # An entry without a path allowlists the whole host.
    transport = RecordingTransport(responses=[VALID_RESPONSE])
    outlet = _online_outlet(
        transport, endpoint_allowlist=("https://models.example.com",)
    )
    result = outlet.request(
        stage="hypothesis_aggregator",
        fields=dict(FIELDS),
        endpoint="https://models.example.com/any/where",
    )
    assert result["outcome"] == "ok"


def test_allowlist_entries_reject_userinfo_and_dot_segments():
    from datacon.tools.model_outlet import ModelOutlet, OutletError

    # The allowlist is configuration, not input, but a poisoned entry would
    # legitimize exactly the endpoints the gate exists to refuse, so the
    # constructor refuses it outright.
    for label, entry in (
        ("userinfo in the entry", f"https://admin:hunter2@{ALLOWED_ENDPOINT_ROOT.removeprefix('https://').rstrip('/')}/v1/"),
        ("dot-dot segment", f"https://{ALLOWED_ENDPOINT_ROOT.removeprefix('https://').rstrip('/')}/v1/../admin/"),
        ("percent-encoded dot", f"https://{ALLOWED_ENDPOINT_ROOT.removeprefix('https://').rstrip('/')}/v1/%2e%2e/admin/"),
        ("single dot segment", f"https://{ALLOWED_ENDPOINT_ROOT.removeprefix('https://').rstrip('/')}/v1/./x"),
    ):
        with pytest.raises(OutletError) as excinfo:
            ModelOutlet(
                endpoint_allowlist=(entry,),
                allowed_fields=("advisory_excerpt",),
                provider="example-models",
                model_version="m",
                prompt_version="p",
                job_id=JOB_ID,
            )
        assert excinfo.value.sub_reason == "ENDPOINT_NOT_ALLOWLISTED", label


def test_endpoint_rejects_userinfo_and_dot_segments():
    from datacon.tools.model_outlet import OutletError

    transport = RecordingTransport(responses=[VALID_RESPONSE])
    outlet = _online_outlet(transport)
    refused = (
        (
            "credentials in the endpoint",
            "https://" + "analyst:hunter2" + "@models.example.com/v1/analyze",
        ),
        ("dot segment", "https://models.example.com/v1/./analyze"),
        ("dot-dot segment", "https://models.example.com/v1/../admin"),
        ("encoded dot-dot", "https://models.example.com/v1/%2e%2e/admin"),
        ("encoded dot-dot, upper case", "https://models.example.com/v1/%2E%2E/admin"),
    )
    for label, endpoint in refused:
        with pytest.raises(OutletError) as excinfo:
            outlet.request(
                stage="hypothesis_aggregator",
                fields=dict(FIELDS),
                endpoint=endpoint,
            )
        assert excinfo.value.sub_reason == "ENDPOINT_NOT_ALLOWLISTED", label

    # Nothing above reached the transport; the clean endpoint on the same
    # host and path prefix is still delivered.
    assert transport.calls == []
    result = outlet.request(
        stage="hypothesis_aggregator",
        fields=dict(FIELDS),
        endpoint=ALLOWED_ENDPOINT,
    )
    assert result["outcome"] == "ok"


def test_allowlist_matches_the_port():
    from datacon.tools.model_outlet import OutletError

    default_port = "https://models.example.com/v1/analyze"
    other_port = "https://models.example.com:8443/v1/analyze"

    # An entry without a port means the default port: 443, written or not,
    # passes, another port on the same host does not.
    transport = RecordingTransport(responses=[VALID_RESPONSE, VALID_RESPONSE])
    outlet = _online_outlet(
        transport, endpoint_allowlist=("https://models.example.com/v1",)
    )
    for endpoint in (default_port, "https://models.example.com:443/v1/analyze"):
        result = outlet.request(
            stage="hypothesis_aggregator",
            fields=dict(FIELDS),
            endpoint=endpoint,
        )
        assert result["outcome"] == "ok"
    with pytest.raises(OutletError) as excinfo:
        outlet.request(
            stage="hypothesis_aggregator",
            fields=dict(FIELDS),
            endpoint=other_port,
        )
    assert excinfo.value.sub_reason == "ENDPOINT_NOT_ALLOWLISTED"
    assert len(transport.calls) == 2

    # An entry with an explicit port admits that port only.
    transport = RecordingTransport(responses=[VALID_RESPONSE])
    outlet = _online_outlet(
        transport, endpoint_allowlist=("https://models.example.com:8443/v1",)
    )
    result = outlet.request(
        stage="hypothesis_aggregator",
        fields=dict(FIELDS),
        endpoint=other_port,
    )
    assert result["outcome"] == "ok"
    with pytest.raises(OutletError) as excinfo:
        outlet.request(
            stage="hypothesis_aggregator",
            fields=dict(FIELDS),
            endpoint=default_port,
        )
    assert excinfo.value.sub_reason == "ENDPOINT_NOT_ALLOWLISTED"
    assert len(transport.calls) == 1


def test_model_audit_requires_a_job_id():
    from datacon.tools.model_outlet import OutletError, build_model_audit

    # The schema types job_id as a uuid: only a string that parses as one is
    # accepted - never null, a non-string or a loose identifier.
    for job_id in (None, "not-a-uuid", 123, uuid.UUID(JOB_ID)):
        with pytest.raises(OutletError) as excinfo:
            build_model_audit(**_audit_kwargs(job_id=job_id))
        assert excinfo.value.sub_reason == "AUDIT_INVALID", repr(job_id)

    assert build_model_audit(**_audit_kwargs())["job_id"] == JOB_ID


@pytest.mark.parametrize(
    "overrides",
    [
        pytest.param({"model_version": "model-x"}, id="model-version"),
        pytest.param({"prompt_version": "prompt-y"}, id="prompt-version"),
        pytest.param({"request_digest": "sha256:" + "a" * 64}, id="request-digest"),
        pytest.param({"response_digest": "sha256:" + "b" * 64}, id="response-digest"),
        pytest.param({"duration_seconds": 0.25}, id="non-zero-duration"),
        pytest.param({"outcome": "ok"}, id="ok-outcome"),
        pytest.param({"outcome": "fallback_offline"}, id="fallback-offline-outcome"),
    ],
)
def test_model_audit_enforces_the_offline_invariants(overrides):
    from datacon.tools.model_outlet import OutletError, build_model_audit

    # The offline record is pinned: no versions, no digests, no duration,
    # and both provider and outcome "offline". A field that tells another
    # story cannot be written as offline.
    with pytest.raises(OutletError) as excinfo:
        build_model_audit(**_audit_kwargs(**overrides))
    assert excinfo.value.sub_reason == "AUDIT_INVALID"


def test_model_audit_rejects_malformed_versions_and_outcomes():
    from datacon.tools.model_outlet import OutletError, build_model_audit

    malformed = (
        ("model_version is not a string", _online_audit_kwargs(model_version=123)),
        ("prompt_version is not a string", _online_audit_kwargs(prompt_version=123)),
        ("redaction_version is empty", _audit_kwargs(redaction_version="")),
        ("redaction_version is null", _audit_kwargs(redaction_version=None)),
        ("outcome is not in the closed set", _online_audit_kwargs(outcome="whatever")),
        ("duration is NaN", _online_audit_kwargs(duration_seconds=float("nan"))),
        ("duration is infinite", _online_audit_kwargs(duration_seconds=float("inf"))),
        ("duration is negative", _online_audit_kwargs(duration_seconds=-1)),
        ("duration is a bool", _online_audit_kwargs(duration_seconds=True)),
    )
    for label, kwargs in malformed:
        with pytest.raises(OutletError) as excinfo:
            build_model_audit(**kwargs)
        assert excinfo.value.sub_reason == "AUDIT_INVALID", label

    # What the rules admit is still admitted: string versions with an
    # online provider, and every outcome of the closed set.
    audited = build_model_audit(
        **_online_audit_kwargs(model_version="model-x", prompt_version="prompt-y")
    )
    assert audited["model_version"] == "model-x"
    outcomes = ("ok", "blocked", "error", "timeout", "rejected", "fallback_offline")
    for outcome in outcomes:
        audit = build_model_audit(**_online_audit_kwargs(outcome=outcome))
        assert audit["outcome"] == outcome


@pytest.mark.parametrize(
    ("overrides", "sub_reason"),
    [
        pytest.param(
            {"model_version": None}, "MODEL_VERSION_REQUIRED", id="no-model-version"
        ),
        pytest.param(
            {"prompt_version": None},
            "PROMPT_VERSION_REQUIRED",
            id="no-prompt-version",
        ),
        pytest.param(
            {"model_version": None, "prompt_version": None},
            "MODEL_VERSION_REQUIRED",
            id="model-version-is-reported-first",
        ),
        pytest.param(
            {"model_version": None, "prompt_version": None, "provider": None},
            "PROVIDER_REQUIRED",
            id="provider-is-reported-first",
        ),
    ],
)
def test_online_outlet_requires_model_and_prompt_versions(overrides, sub_reason):
    from datacon.tools.model_outlet import OutletError

    transport = RecordingTransport(responses=[VALID_RESPONSE])
    outlet = _online_outlet(transport, **overrides)

    # An online request is only auditable with both versions pinned, so a
    # missing one refuses before the transport is touched - and the checks
    # keep their order after the provider check.
    with pytest.raises(OutletError) as excinfo:
        outlet.request(
            stage="hypothesis_aggregator",
            fields=dict(FIELDS),
            endpoint=ALLOWED_ENDPOINT,
        )
    assert excinfo.value.sub_reason == sub_reason
    assert transport.calls == []


def test_outlet_requires_a_job_id_before_any_request():
    from datacon.tools.model_outlet import ModelOutlet, OutletError

    # Offline: no endpoint and no allowlist, so the audit record is the only
    # thing this request would write - and without a job_id it cannot.
    transport = RecordingTransport()
    outlet = ModelOutlet(transport=transport)
    with pytest.raises(OutletError) as excinfo:
        outlet.request(stage="hypothesis_aggregator", fields=dict(FIELDS))
    assert excinfo.value.sub_reason == "AUDIT_INVALID"
    assert transport.calls == []

    # Online: everything an online request needs except the job_id.
    transport = RecordingTransport(responses=[VALID_RESPONSE])
    outlet = _online_outlet(transport, job_id=None)
    with pytest.raises(OutletError) as excinfo:
        outlet.request(
            stage="hypothesis_aggregator",
            fields=dict(FIELDS),
            endpoint=ALLOWED_ENDPOINT,
        )
    assert excinfo.value.sub_reason == "AUDIT_INVALID"
    assert transport.calls == []


def test_address_denied_transport_failure_blocks_as_outlet_error():
    from datacon.tools.model_outlet import OutletError
    from datacon.tools.safe_http import SafeHttpError

    # The connection layer re-checked a resolved address and found it in the
    # shared rejection set (DNS rebinding): a policy hit, not an outage, so
    # it blocks with the address token instead of falling back offline.
    transport = RecordingTransport(
        responses=[
            SafeHttpError(
                "address answer is in the shared rejection set",
                reason="ADDRESS_DENIED",
            )
        ]
    )
    outlet = _online_outlet(transport)

    with pytest.raises(OutletError) as excinfo:
        outlet.request(
            stage="hypothesis_aggregator",
            fields=dict(FIELDS),
            endpoint=ALLOWED_ENDPOINT,
        )
    assert excinfo.value.sub_reason == "ENDPOINT_ADDRESS_REJECTED"
    assert len(transport.calls) == 1


@pytest.mark.parametrize(
    "reason",
    [
        "FETCH_FAILED",
        "CONTENT_TRUNCATED",
        "RESPONSE_HEAD_TOO_LARGE",
        "RESPONSE_UNFRAMED",
    ],
)
def test_other_safe_http_failures_fall_back_offline(reason):
    from datacon.tools.safe_http import SafeHttpError

    transport = RecordingTransport(
        responses=[SafeHttpError("guarded step failed", reason=reason)]
    )
    outlet = _online_outlet(transport)

    # Any other guarded-connection failure is an unreachable endpoint: the
    # request degrades to the offline path, exactly like a timeout.
    result = outlet.request(
        stage="hypothesis_aggregator",
        fields=dict(FIELDS),
        endpoint=ALLOWED_ENDPOINT,
    )
    assert result["outcome"] == "fallback_offline"
    assert result["findings"] == ()
    assert len(transport.calls) == 1

    audit = result["model_audit"]
    assert audit["outcome"] == "fallback_offline"
    assert audit["provider"] == _ONLINE_PROVIDER
    assert audit["model_version"] == "model-x"
    assert audit["prompt_version"] == "prompt-y"


@pytest.mark.parametrize(
    "failure",
    [
        pytest.param(RuntimeError("transport crashed"), id="runtime-error"),
        pytest.param(ValueError("unparseable wire frame"), id="value-error"),
    ],
)
def test_unexpected_transport_errors_block_as_outlet_errors(failure):
    from datacon import jsonutil
    from datacon.tools.model_outlet import OutletError

    transport = RecordingTransport(responses=[failure])
    outlet = _online_outlet(transport)

    # A transport bug is neither an offline fallback nor a crash: the raw
    # exception must not leak past the outlet, and the request was already
    # sent, so the block carries its audit trail.
    with pytest.raises(OutletError) as excinfo:
        outlet.request(
            stage="hypothesis_aggregator",
            fields=dict(FIELDS),
            endpoint=ALLOWED_ENDPOINT,
        )
    error = excinfo.value
    assert error.sub_reason == "TRANSPORT_FAILED"
    assert len(transport.calls) == 1
    audit = error.model_audit
    assert audit["outcome"] == "rejected"
    assert set(audit) == MODEL_AUDIT_FIELDS
    _, sent_body = transport.calls[0]
    assert audit["request_digest"] == jsonutil.digest_json(sent_body)

    # No response ever arrived, so there is nothing to digest.
    assert audit["response_digest"] is None


@pytest.mark.parametrize(
    "response",
    [
        pytest.param(_FACT_OUTPUT, id="model-sourced-fact"),
        pytest.param("<html>503 Service Unavailable</html>", id="not-json"),
    ],
)
def test_rejected_model_output_keeps_an_audit_trail(response):
    from datacon import jsonutil
    from datacon.tools.model_outlet import OutletError

    transport = RecordingTransport(responses=[response])
    outlet = _online_outlet(transport)

    with pytest.raises(OutletError) as excinfo:
        outlet.request(
            stage="hypothesis_aggregator",
            fields=dict(FIELDS),
            endpoint=ALLOWED_ENDPOINT,
        )

    # The request was already on the wire when the output was rejected: the
    # block must carry the audit trail of that very request.
    error = excinfo.value
    assert error.sub_reason == "MODEL_OUTPUT_INVALID"
    assert len(transport.calls) == 1
    audit = error.model_audit
    assert audit["outcome"] == "rejected"
    assert set(audit) == MODEL_AUDIT_FIELDS
    _, sent_body = transport.calls[0]
    assert audit["request_digest"] == jsonutil.digest_json(sent_body)
    assert audit["response_digest"] is None or _is_digest(audit["response_digest"])
    assert audit["job_id"] == JOB_ID
    assert audit["stage"] == "hypothesis_aggregator"
    assert audit["provider"] == _ONLINE_PROVIDER
    assert audit["model_version"] == "model-x"
    assert audit["prompt_version"] == "prompt-y"


def test_redaction_masks_command_line_credentials():
    from datacon.tools.model_outlet import redact

    # A credential handed to a tool on its command line is a credential like
    # any other, and README and shell-history excerpts carry it often.
    account = "admin:" + "hunter2"
    secret = "hunter2"
    for text, expected in (
        (
            f"curl -u {account} https://models.example.com/v1/analyze",
            "curl -u [REDACTED] https://models.example.com/v1/analyze",
        ),
        (
            f"curl --user {account} https://models.example.com/v1/analyze",
            "curl --user [REDACTED] https://models.example.com/v1/analyze",
        ),
        (
            f"psql --host db.internal --username admin --password={secret} -c x",
            "psql --host db.internal --username admin --password=[REDACTED] -c x",
        ),
    ):
        assert redact(text) == expected

    # Redaction is a fixed point: masking again changes nothing, so the last
    # line of defense does not trip on an already masked command.
    masked = redact(f"curl -u {account} https://models.example.com/v1/analyze")
    assert redact(masked) == masked

# --- AgentOutput v2: a model may only propose hypotheses (REQ-13, TC-13) ---
#
# The v0.1 parser (AgentOutput.from_mapping) keeps its frozen semantics:
# a stored v1 kind=fact record stays parseable read-only.

EVIDENCE = "git:commit/" + "a" * 40


def _model_payload(kind):
    return {
        "outcome": "ok",
        "artifacts": {},
        "findings": [
            {
                "kind": kind,
                "statement": "the terminator write can overrun the buffer",
                "confidence": "medium",
                "evidence_refs": [EVIDENCE],
            }
        ],
        "reason_code": None,
    }


def test_model_finding_must_be_hypothesis():
    from datacon.agent_contracts import (
        AgentOutput,
        ContractError,
        parse_model_output,
    )

    # Model-sourced kind=fact is blocked on the v2 port; the error names
    # the only allowed kind.
    with pytest.raises(ContractError, match="hypothesis"):
        parse_model_output(_model_payload("fact"))

    parsed = parse_model_output(_model_payload("hypothesis"))
    assert isinstance(parsed, AgentOutput)
    assert parsed.findings[0].kind == "hypothesis"

    # v1 compatibility must not regress: the frozen v0.1 parser still
    # accepts the same fact payload read-only.
    legacy = AgentOutput.from_mapping(_model_payload("fact"))
    assert legacy.findings[0].kind == "fact"
