"""The model outlet: outbound gate, audit role and redaction (T14, REQ-13).

Implements the T14 contract from the v0.2 security design delta section 2:
the control plane talks to an external analysis model through this one gate,
which stays offline unless an endpoint allowlist is explicitly configured.
Every outbound request carries only the allowed fields, is redacted by the
fixed rule set, and produces the closed 11-field ``model_audit`` record
(interface contract delta section 8) - offline runs included, with the
provider pinned to ``offline``. The endpoint gate is fail-closed and
ordered: HTTPS scheme first (plain HTTP never reaches the allowlist
comparison), then the shared ``safe_http.is_rejected_address`` set for
literal-IP hosts (allowlisted endpoints are hostnames, so a globally
routable IP literal is refused by the same address rule), then the exact
host plus path-prefix allowlist match. A timeout degrades to the offline
path with ``outcome="fallback_offline"``; an illegal model output blocks
outright. No failure path relaxes the allowlist, the field filter or the
redaction to "recover".

The module never opens a socket, resolves DNS or sleeps: the transport is
an injected interface, so offline cases stay offline and every failure path
is contract-testable. Model output is parsed with
``agent_contracts.parse_model_output`` - a model may only propose
hypotheses, and a model-sourced ``kind=fact`` is invalid output.
"""

from __future__ import annotations

import ipaddress
import re
import time
from typing import Any, Iterable, Mapping, Protocol
from urllib.parse import urlsplit

from datacon import jsonutil
from datacon.agent_contracts import ContractError, parse_model_output
from datacon.tools.safe_http import is_rejected_address

OFFLINE_PROVIDER = "offline"
DEFAULT_REDACTION_VERSION = "redaction-v1"

# The closed 11-field model_audit schema (interface contract delta 8).
MODEL_AUDIT_FIELDS = (
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
)


class OutletError(Exception):
    """A model outlet step failed closed.

    ``sub_reason`` carries the audit token for the failure path:
    ``ENDPOINT_NOT_ALLOWLISTED`` / ``ENDPOINT_ADDRESS_REJECTED`` /
    ``ENDPOINT_NOT_HTTPS`` for the endpoint gate, ``MODEL_OUTPUT_INVALID``
    for a blocked response, ``PROVIDER_MISSING`` / ``AUDIT_INVALID`` for a
    malformed audit record.
    """

    def __init__(self, message: str, *, sub_reason: str) -> None:
        super().__init__(message)
        self.sub_reason = sub_reason


class OutletTransport(Protocol):
    """The outlet's only injection point: one model request per call.

    The production adapter owns the guarded connection, timeouts and
    budgets; this module only hands it the validated endpoint and the
    redacted request body, so no test or offline run opens a socket.
    """

    def request(self, endpoint: str, body: object) -> object: ...


# --- Redaction (security design delta 2.3) ---------------------------------
#
# Fixed, ordering-dependent rules: escapes and control characters first, then
# the secret shapes (PEM headers, connection strings with userinfo, token
# shapes, emails, long hex runs), then host paths. The factual text between
# the masked shapes survives untouched.

_ANSI_ESCAPE = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]")
_CONTROL_CHARACTERS = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_PEM_HEADER = re.compile(r"-----BEGIN [A-Z0-9 ]*KEY-----")
_CONNECTION_STRING = re.compile(
    r"[A-Za-z][A-Za-z0-9+.-]*://[^\s:/?#]+:[^\s@/]+@[^\s]+"
)
_EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
_TOKEN_SHAPES = re.compile(
    r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{16,}\b"
    r"|\bAKIA[0-9A-Z]{16}\b"
    r"|\bxox[baprs]-[A-Za-z0-9-]{10,}\b"
    r"|\bsk-[A-Za-z0-9]{20,}\b"
)
_LONG_HEX_RUN = re.compile(r"\b[0-9a-fA-F]{32,}\b")
# Host home trees are rewritten repo-relative: /Users/<user>/<repo>/tail
# keeps only <tail>, matching "absolute paths become repo-relative paths".
_REPO_RELATIVE_PREFIX = re.compile(
    r"/(?:Users|home|root)/[A-Za-z0-9._-]+/[A-Za-z0-9._-]+/"
)
# Any other multi-segment absolute path never leaves; it is masked whole.
_ABSOLUTE_PATH = re.compile(r"(?<![\w:/])/[A-Za-z0-9._-]+(?:/[A-Za-z0-9._-]+)+")
_REDACTED = "[REDACTED]"


def redact(text: str) -> str:
    """Apply the fixed outbound redaction rules to ``text``.

    ANSI escapes and control characters are stripped; private-key headers,
    connection strings with userinfo, token shapes (``ghp_``/``AKIA``/...),
    emails and long hexadecimal runs are masked; absolute host paths are
    rewritten repo-relative or masked. Plain factual sentences survive.
    """
    redacted = _ANSI_ESCAPE.sub("", text)
    redacted = _CONTROL_CHARACTERS.sub("", redacted)
    redacted = _PEM_HEADER.sub(_REDACTED, redacted)
    redacted = _CONNECTION_STRING.sub(_REDACTED, redacted)
    redacted = _TOKEN_SHAPES.sub(_REDACTED, redacted)
    redacted = _EMAIL.sub(_REDACTED, redacted)
    redacted = _LONG_HEX_RUN.sub(_REDACTED, redacted)
    redacted = _REPO_RELATIVE_PREFIX.sub("", redacted)
    redacted = _ABSOLUTE_PATH.sub("[PATH]", redacted)
    return redacted


# --- Endpoint gate (security design delta 2.4) ------------------------------


def _endpoint_host(endpoint: str) -> str:
    """Extract ``endpoint``'s host without ``urlsplit``'s port mangling.

    A bare IPv6 literal such as ``::1`` is not a valid authority component,
    and ``urlsplit`` reads it as an empty host plus a bogus port (or only
    its first colon group). The netloc is therefore interpreted here:
    userinfo is dropped, a bracketed IPv6 literal is unbracketed, a single
    ``host:port`` pair is split, and anything with two or more colons is
    the literal itself. No DNS resolution happens.
    """
    netloc = urlsplit(endpoint).netloc
    if "@" in netloc:
        netloc = netloc.rsplit("@", 1)[1]
    if netloc.startswith("["):
        return netloc.partition("]")[0][1:]
    if netloc.count(":") == 1:
        host, _, port = netloc.partition(":")
        if port.isdigit():
            return host
    return netloc


def _is_ip_literal(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return False
    return True


def build_model_audit(
    *,
    job_id: str | None,
    stage: str,
    provider: str | None,
    model_version: str | None = None,
    prompt_version: str | None = None,
    allowed_fields: Iterable[str] = (),
    redaction_version: str = DEFAULT_REDACTION_VERSION,
    request_digest: str | None = None,
    response_digest: str | None = None,
    duration_seconds: float = 0,
    outcome: str = "offline",
) -> dict[str, Any]:
    """Build the closed 11-field ``model_audit`` record (delta 2.3 / 8).

    Exactly the ``MODEL_AUDIT_FIELDS`` keys are returned, never more. The
    provider may not be null or empty - offline runs pin it to
    ``"offline"``. ``allowed_fields_digest`` is the canonical digest of the
    normalized (sorted, deduplicated) allowed-field set, so the same set in
    any order digests identically; it is written online and offline alike.
    """
    if not isinstance(provider, str) or not provider:
        raise OutletError(
            "model_audit.provider must be a non-empty string; offline runs"
            ' pin it to "offline"',
            sub_reason="PROVIDER_MISSING",
        )
    if not isinstance(stage, str) or not stage:
        raise OutletError(
            "model_audit.stage must be a non-empty string",
            sub_reason="AUDIT_INVALID",
        )
    if (
        not isinstance(duration_seconds, (int, float))
        or isinstance(duration_seconds, bool)
        or duration_seconds < 0
    ):
        raise OutletError(
            "model_audit.duration_seconds must be a non-negative number,"
            f" not {duration_seconds!r}",
            sub_reason="AUDIT_INVALID",
        )
    if request_digest is not None and not jsonutil.is_digest(request_digest):
        raise OutletError(
            "model_audit.request_digest must be a sha256 digest or null",
            sub_reason="AUDIT_INVALID",
        )
    if response_digest is not None and not jsonutil.is_digest(response_digest):
        raise OutletError(
            "model_audit.response_digest must be a sha256 digest or null",
            sub_reason="AUDIT_INVALID",
        )
    return {
        "job_id": job_id,
        "stage": stage,
        "provider": provider,
        "model_version": model_version,
        "prompt_version": prompt_version,
        "allowed_fields_digest": jsonutil.digest_json(
            sorted(set(allowed_fields))
        ),
        "redaction_version": redaction_version,
        "request_digest": request_digest,
        "response_digest": response_digest,
        "duration_seconds": duration_seconds,
        "outcome": outcome,
    }


class ModelOutlet:
    """The single outbound gate for external analysis models (REQ-13).

    Offline unless ``endpoint_allowlist`` is configured: with no endpoint
    (or no allowlist) ``request`` never touches the transport and still
    writes the audit with the provider pinned to ``offline``.
    """

    def __init__(
        self,
        *,
        endpoint_allowlist: Iterable[str] = (),
        allowed_fields: Iterable[str] = (),
        provider: str | None = None,
        model_version: str | None = None,
        prompt_version: str | None = None,
        redaction_version: str = DEFAULT_REDACTION_VERSION,
        transport: OutletTransport | None = None,
        job_id: str | None = None,
    ) -> None:
        entries = tuple(endpoint_allowlist)
        for entry in entries:
            if urlsplit(entry).scheme != "https" or not _endpoint_host(entry):
                raise OutletError(
                    "endpoint allowlist entries must be HTTPS URLs with a"
                    f" host: {entry!r}",
                    sub_reason="ENDPOINT_NOT_ALLOWLISTED",
                )
        self._endpoint_allowlist = entries
        self._allowed_fields = tuple(allowed_fields)
        self._allowed_field_names = frozenset(self._allowed_fields)
        self._provider = provider
        self._model_version = model_version
        self._prompt_version = prompt_version
        self._redaction_version = redaction_version
        self._transport = transport
        self._job_id = job_id

    def request(
        self,
        *,
        stage: str,
        fields: Mapping[str, Any],
        endpoint: str | None = None,
    ) -> dict[str, Any]:
        """Send one analysis request through the gate; offline by default.

        Returns ``{"outcome", "findings", "reason_code", "model_audit"}``.
        Offline (no endpoint or no allowlist) makes zero transport calls.
        Online, the endpoint must pass the fail-closed gate, the body only
        carries the allowed fields (each redacted), a transport timeout
        degrades to ``fallback_offline`` with empty findings, and the
        response must parse as a hypothesis-only model output.
        """
        if endpoint is None or not self._endpoint_allowlist:
            return self._result("offline", (), None, self._audit(
                stage,
                provider=OFFLINE_PROVIDER,
                outcome="offline",
                request_digest=None,
                response_digest=None,
                duration_seconds=0,
                offline=True,
            ))
        self._validate_endpoint(endpoint)
        if not self._provider:
            # The audit must name a real provider identity; falling back to
            # the endpoint hostname would invent one (§2.3). Fail closed.
            raise OutletError(
                "an online model outlet requires an explicit provider; the"
                " endpoint hostname is not a provider identity",
                sub_reason="PROVIDER_REQUIRED",
            )
        provider = self._provider
        if self._transport is None:
            raise OutletError(
                "an allowlisted endpoint is configured but no transport is"
                " injected; refusing to invent a model call",
                sub_reason="TRANSPORT_MISSING",
            )
        body = self._build_body(stage, fields)
        request_digest = jsonutil.digest_json(body)
        started = time.monotonic()
        try:
            response = self._transport.request(endpoint, body)
        except (TimeoutError, ConnectionError, OSError):
            return self._result(
                "fallback_offline",
                (),
                None,
                self._audit(
                    stage,
                    provider=provider,
                    outcome="fallback_offline",
                    request_digest=request_digest,
                    response_digest=None,
                    duration_seconds=time.monotonic() - started,
                ),
            )
        duration = time.monotonic() - started
        response_digest, payload = _decode_response(response)
        try:
            parsed = parse_model_output(payload)
        except ContractError as error:
            raise OutletError(
                f"model output rejected: {error}",
                sub_reason="MODEL_OUTPUT_INVALID",
            ) from error
        return self._result(
            parsed.outcome,
            tuple(finding.as_dict() for finding in parsed.findings),
            parsed.reason_code,
            self._audit(
                stage,
                provider=provider,
                outcome=parsed.outcome,
                request_digest=request_digest,
                response_digest=response_digest,
                duration_seconds=duration,
            ),
        )

    def _validate_endpoint(self, endpoint: str) -> str:
        """Run the fail-closed endpoint gate; returns the endpoint host.

        Order matters and is frozen by the contract tests: HTTPS scheme
        first (plain HTTP never reaches the allowlist comparison), then the
        shared address rejection set for literal-IP hosts - allowlisted
        endpoints are hostnames, so even a globally routable IP literal is
        refused with an address token - then the exact host plus path
        prefix allowlist match.
        """
        parts = urlsplit(endpoint)
        if parts.scheme != "https":
            raise OutletError(
                f"model endpoints must use https, not"
                f" {parts.scheme or 'scheme-less'!r}: {endpoint!r}",
                sub_reason="ENDPOINT_NOT_HTTPS",
            )
        host = _endpoint_host(endpoint)
        if not host:
            raise OutletError(
                f"model endpoint has no host to allowlist: {endpoint!r}",
                sub_reason="ENDPOINT_NOT_ALLOWLISTED",
            )
        if _is_ip_literal(host):
            if is_rejected_address(host):
                raise OutletError(
                    f"model endpoint address {host!r} falls into the shared"
                    " address rejection set (private, loopback, link-local,"
                    " CGNAT, multicast, reserved, unspecified or cloud"
                    f" metadata): {endpoint!r}",
                    sub_reason="ENDPOINT_ADDRESS_REJECTED",
                )
            raise OutletError(
                f"model endpoint address {host!r} is an IP literal;"
                " allowlisted endpoints are hostnames, not addresses:"
                f" {endpoint!r}",
                sub_reason="ENDPOINT_ADDRESS_REJECTED",
            )
        for entry in self._endpoint_allowlist:
            entry_path = urlsplit(entry).path
            if host == _endpoint_host(entry) and parts.path.startswith(
                entry_path
            ):
                return host
        raise OutletError(
            f"model endpoint is not in the endpoint allowlist (exact host"
            f" plus path prefix match required): {endpoint!r}",
            sub_reason="ENDPOINT_NOT_ALLOWLISTED",
        )

    def _build_body(self, stage: str, fields: Mapping[str, Any]) -> dict[str, Any]:
        """Filter to the allowed fields and redact every outbound value."""
        filtered: dict[str, Any] = {}
        for name in sorted(fields):
            if name not in self._allowed_field_names:
                continue
            value = fields[name]
            filtered[name] = redact(value) if isinstance(value, str) else value
        return {"stage": stage, "fields": filtered}

    def _audit(
        self,
        stage: str,
        *,
        provider: str,
        outcome: str,
        request_digest: str | None,
        response_digest: str | None,
        duration_seconds: float,
        offline: bool = False,
    ) -> dict[str, Any]:
        return build_model_audit(
            job_id=self._job_id,
            stage=stage,
            provider=provider,
            model_version=None if offline else self._model_version,
            prompt_version=None if offline else self._prompt_version,
            allowed_fields=self._allowed_fields,
            redaction_version=self._redaction_version,
            request_digest=request_digest,
            response_digest=response_digest,
            duration_seconds=duration_seconds,
            outcome=outcome,
        )

    @staticmethod
    def _result(
        outcome: str,
        findings: tuple[dict[str, Any], ...],
        reason_code: str | None,
        audit: dict[str, Any],
    ) -> dict[str, Any]:
        return {
            "outcome": outcome,
            "findings": findings,
            "reason_code": reason_code,
            "model_audit": audit,
        }


def _decode_response(response: object) -> tuple[str, Any]:
    """Digest and decode one model response; text must be strict JSON."""
    if isinstance(response, (str, bytes)):
        raw = response.encode("utf-8") if isinstance(response, str) else response
        try:
            payload: Any = jsonutil.loads_strict(response)
        except jsonutil.StrictJsonError as error:
            raise OutletError(
                f"model response is not strict JSON: {error}",
                sub_reason="MODEL_OUTPUT_INVALID",
            ) from error
        return jsonutil.digest_bytes(raw), payload
    return jsonutil.digest_json(response), response
