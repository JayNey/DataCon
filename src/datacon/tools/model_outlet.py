"""The model outlet: outbound gate, audit role and redaction (T14, REQ-13).

Implements the T14 contract from the v0.2 security design delta section 2:
the control plane talks to an external analysis model through this one gate,
which stays offline unless an endpoint allowlist is explicitly configured.
Every outbound request carries only the allowed fields, is redacted by the
fixed rule set - recursively, at every depth of an allowed field - and is
scanned once more as a whole before it leaves, because dict keys are never
rewritten. Every request produces the closed 11-field ``model_audit`` record
(interface contract delta section 8) - offline runs included, with the
provider pinned to ``offline`` - and nothing is sent before it is certain
that this record can be written.

The endpoint gate is fail-closed and ordered: HTTPS scheme first (plain HTTP
never reaches the allowlist comparison), then the URL's own shape (no
userinfo, no dot segments, no whitespace or control characters), then the
shared ``safe_http.is_rejected_address`` set for literal-IP hosts
(allowlisted endpoints are hostnames, so a globally routable IP literal is
refused by the same address rule), then the host, port and path-segment
boundary allowlist match.

A failure after the transport was called is a degradation or a block, never
an uncontrolled crash: a timeout, a connection error or any other
guarded-connection failure degrades to the offline path with
``outcome="fallback_offline"``; an address refused by the connection layer,
a transport bug and an illegal model output block with an ``OutletError``
that carries the audit trail of that very request. No failure path relaxes
the allowlist, the field filter or the redaction to "recover".

The module never opens a socket, resolves DNS or sleeps: the transport is
an injected interface, so offline cases stay offline and every failure path
is contract-testable. Model output is parsed with
``agent_contracts.parse_model_output`` - a model may only propose
hypotheses, and a model-sourced ``kind=fact`` is invalid output.
"""

from __future__ import annotations

import ipaddress
import math
import re
import time
import uuid
from collections.abc import Callable, Iterable, Mapping
from functools import partial
from typing import Any, Protocol
from urllib.parse import unquote, urlsplit, urlunsplit

from datacon import jsonutil
from datacon.agent_contracts import parse_model_output
from datacon.tools.safe_http import SafeHttpError, is_rejected_address

OFFLINE_PROVIDER = "offline"
DEFAULT_REDACTION_VERSION = "redaction-v1"
# An allowlist entry without a written port means the default HTTPS port.
DEFAULT_HTTPS_PORT = 443

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
# The closed outcome set of that schema. ``timeout`` is admitted for the
# record only: a timed-out model call is recorded by this outlet as
# ``fallback_offline``.
MODEL_AUDIT_OUTCOMES = frozenset(
    {
        "offline",
        "ok",
        "blocked",
        "error",
        "timeout",
        "rejected",
        "fallback_offline",
    }
)

# ``SafeHttpError.reason`` for a resolved or connected address inside the
# shared rejection set: a policy hit, not an outage.
_ADDRESS_DENIED = "ADDRESS_DENIED"


class OutletError(Exception):
    """A model outlet step failed closed.

    ``sub_reason`` carries the audit token for the failure path:

    - ``AUDIT_INVALID``: the audit record cannot be written compliantly -
      a job_id that is not a UUID string is refused first of all, before
      anything else happens.
    - ``ENDPOINT_NOT_HTTPS`` / ``ENDPOINT_ADDRESS_REJECTED`` /
      ``ENDPOINT_NOT_ALLOWLISTED``: the endpoint gate. An allowlist entry
      that fails the same checks is always ``ENDPOINT_NOT_ALLOWLISTED``,
      whatever the defect.
    - ``PROVIDER_REQUIRED`` / ``MODEL_VERSION_REQUIRED`` /
      ``PROMPT_VERSION_REQUIRED`` / ``TRANSPORT_MISSING``: an online request
      without everything an auditable call needs.
    - ``FIELD_TYPE_REJECTED`` / ``REDACTION_REJECTED``: a request body that
      cannot be redacted recursively, or that still carries a secret shape
      (in a key, which redaction never rewrites).
    - ``TRANSPORT_FAILED`` / ``MODEL_OUTPUT_INVALID``: a block after the
      request was handed to the transport.
    - ``PROVIDER_MISSING``: ``build_model_audit`` called without a provider.

    ``model_audit`` is the audit record (``outcome="rejected"``) of a request
    that already reached the transport, or ``None`` when nothing left the
    control plane.
    """

    def __init__(
        self,
        message: str,
        *,
        sub_reason: str,
        model_audit: Mapping[str, Any] | None = None,
    ) -> None:
        super().__init__(message)
        self.sub_reason = sub_reason
        self.model_audit: dict[str, Any] | None = (
            None if model_audit is None else dict(model_audit)
        )


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
# the secret shapes (whole private-key blocks, scheme credentials, key-value
# credentials, connection strings with userinfo, token shapes), then the
# identifier shapes (emails, long hex runs), then host paths. The factual text
# between the masked shapes survives untouched.

_ANSI_ESCAPE = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]")
_CONTROL_CHARACTERS = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_REDACTED = "[REDACTED]"
_PATH = "[PATH]"
# A whole PEM block, from a BEGIN header to the END footer with the same
# label, both included - the PGP private key block included. A header whose
# footer never comes masks everything through the end of the text, so key
# material never survives a truncated block.
_PEM_BLOCK = re.compile(
    r"-----BEGIN ([A-Z0-9 ]*KEY(?: BLOCK)?)-----[\s\S]*?(?:-----END \1-----|\Z)"
)
# "Bearer <token>" and "Basic <credential>": the scheme word and the spacing
# stay, only the value is masked.
_AUTH_SCHEME_TOKEN = re.compile(
    r"\b(?i:bearer|basic)[ \t]+([A-Za-z0-9](?:[A-Za-z0-9._~+/=-]*[A-Za-z0-9=])?)"
)
# A scheme value carries a digit or one of these marks, or case mixed behind
# its first character as base64 does; a word after "basic" or "bearer" does
# neither ("the basic suite", "a bearer token", "basic HTTP authentication").
_TOKEN_VALUE_MARK = re.compile(r"[0-9._~+/=-]")
# "password=<value>": the key (in any spelling of case, underscore or hyphen,
# with or without a surrounding quote, also the backslash-escaped quote of a
# stringified JSON document), the separator and the opening quote stay, only
# the value is masked. There is no left boundary on purpose, so DB_PASSWORD
# and my_token are covered by the same rule.
_CREDENTIAL_ASSIGNMENT = (
    r"(?i)(?P<key>password|passwd|pwd|passphrase|secret(?:[-_]?key)?|token"
    r"|api[-_]?key|access[-_]?key|private[-_]?key)(?P<key_quote>\\?[\"']?)"
    r"(?P<separator>\s*[=:]\s*)"
)
# A value that opens with a quote runs to the closing quote on the same line,
# spaces included; an escaped quote inside it is part of it.
_QUOTED_CREDENTIAL = re.compile(
    _CREDENTIAL_ASSIGNMENT
    + r"(?P<value_quote>\\?[\"'])(?P<value>(?:\\[^\n]|[^\n\\])*?)(?P=value_quote)"
)
# A bare value runs to the end of the word, so a quote in its middle is part
# of it. A list separator ends it only where another ``key=`` follows, which
# keeps the neighbouring parameters of a query string readable, and a value
# that is already the placeholder ends there: the rule is idempotent, so a
# redacted value never trips the last line of defense.
_BARE_CREDENTIAL = re.compile(
    _CREDENTIAL_ASSIGNMENT
    + r"(?P<value_quote>\\?[\"']?)(?P<value>\S+?)"
    r"(?=\s|$|[,;&<>](?=\w+[=:])|\\?[\"'](?!\w)|(?<=\[REDACTED\]))"
)
# A scheme with a password in its userinfo. The account may be empty, as in
# the common Redis form, so only the password is required.
_CONNECTION_STRING = re.compile(
    r"[A-Za-z][A-Za-z0-9+.-]*://(?:[^\s:/?#]+)?:[^\s@/]+@[^\s]+"
)
_TOKEN_SHAPES = re.compile(
    # No left boundary: nothing in prose starts with one of these prefixes,
    # so a token glued to the character before it ("...cghp_...") still counts.
    r"(?:"
    r"(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{16,}"
    r"|AKIA[0-9A-Z]{16}"
    r"|xox[baprs]-[A-Za-z0-9-]{10,}"
    r"|github_pat_[A-Za-z0-9_]{16,}"
    r"|(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,}"
    r"|AIza[0-9A-Za-z_-]{35,}"
    r"|glpat-[0-9A-Za-z_-]{16,}"
    r"|pypi-[0-9A-Za-z_-]{16,}"
    # A JWT: the base64url of '{"' opens the header, then two to four more
    # base64url segments (a JWE carries five).
    r"|eyJ[0-9A-Za-z_-]{8,}(?:\.[0-9A-Za-z_-]{8,}){2,4}"
    r")"
    # "sk-" is the one prefix prose shares (task-, risk-, desk-), so it only
    # counts at the start of a token.
    r"|(?<![A-Za-z0-9_])sk-[A-Za-z0-9_-]{20,}"
)
_EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
_LONG_HEX_RUN = re.compile(r"\b[0-9a-fA-F]{32,}\b")
# Windows drive paths and UNC shares, backslash-separated.
_WINDOWS_SEGMENT = r'[^\\/:*?"<>|\s]'
_WINDOWS_DRIVE_PATH = re.compile(
    rf"(?<![A-Za-z0-9_])[A-Za-z]:[\\/](?:{_WINDOWS_SEGMENT}+[\\/])*"
    rf"{_WINDOWS_SEGMENT}*"
)
_UNC_PATH = re.compile(
    rf"(?<![A-Za-z0-9_\\/])\\\\{_WINDOWS_SEGMENT}+(?:\\{_WINDOWS_SEGMENT}+)+"
)
# The same share spelled with forward slashes.
_FORWARD_UNC_PATH = re.compile(
    r"(?<![A-Za-z0-9_:/])//[A-Za-z0-9._-]+(?:/[A-Za-z0-9._-]+)+"
)
# Host home trees are rewritten repo-relative: /Users/<user>/<repo>/tail
# keeps only <tail>, matching "absolute paths become repo-relative paths".
_REPO_RELATIVE_PREFIX = re.compile(
    r"/(?:Users|home|root)/[A-Za-z0-9._-]+/[A-Za-z0-9._-]+/"
)
# Any other absolute POSIX path never leaves, masked whole from its first
# segment on - a single segment such as a dotfile in the root counts. The
# slash must start a token: a slash that hugs a letter or a digit on its
# left is prose ("and/or", "TCP/IP", "1/2"), not a path.
_ABSOLUTE_PATH = re.compile(r"(?<![\w:/])/[A-Za-z0-9._-]+(?:/[A-Za-z0-9._-]+)*")


def _has_token_shape(value: str) -> bool:
    """Whether a scheme value looks like a credential rather than a word."""
    if _TOKEN_VALUE_MARK.search(value):
        return True
    return any(character.isupper() for character in value[1:]) and any(
        character.islower() for character in value
    )


def _mask_scheme_value(match: re.Match[str]) -> str:
    """Keep the scheme word and the spacing; mask only a token-shaped value."""
    value = match.group(1)
    if not _has_token_shape(value):
        return match.group(0)
    return match.group(0)[: -len(value)] + _REDACTED


def _mask_assignment(match: re.Match[str]) -> str:
    """Keep the key, its quotes, the separator and the closing quote.

    Only the value is masked. A value that is already the placeholder is
    left alone, so a redacted text is a fixed point of the rule.
    """
    if match.group("value") == _REDACTED:
        return match.group(0)
    whole = match.group(0)
    start = match.start("value") - match.start()
    end = match.end("value") - match.start()
    return whole[:start] + _REDACTED + whole[end:]


def _mask_assignments(text: str) -> str:
    """Mask every key-value credential: the quoted values first, then the rest."""
    quoted = _QUOTED_CREDENTIAL.sub(_mask_assignment, text)
    return _BARE_CREDENTIAL.sub(_mask_assignment, quoted)


# A credential handed to a tool on its command line: ``curl -u user:pass``,
# ``--password=pass`` and their spellings. The flag and its separator stay,
# only the value is masked. A flag that carries an account alone
# (``--username``) does not match: an account name is an identifier, not a
# credential.
_CLI_CREDENTIAL = re.compile(
    r"(?i)(?:^|(?<=\s))(?P<flag>--?(?:u|user|password|passwd|pwd)(?P<sep>[ =]))"
    r"(?P<value>[^\s]+)"
)


def _mask_cli_credential(match: re.Match[str]) -> str:
    """Keep the flag and its separator; mask the credential value."""
    return match.group("flag") + _REDACTED


# The secret rules. They mask field values and, as the last line of defense,
# are applied again over a whole serialized request body.
_SECRET_RULES: tuple[tuple[str, Callable[[str], str]], ...] = (
    ("private-key block", partial(_PEM_BLOCK.sub, _REDACTED)),
    ("scheme credential", partial(_AUTH_SCHEME_TOKEN.sub, _mask_scheme_value)),
    ("key-value credential", _mask_assignments),
    ("command-line credential", partial(_CLI_CREDENTIAL.sub, _mask_cli_credential)),
    ("connection string with userinfo", partial(_CONNECTION_STRING.sub, _REDACTED)),
    ("token shape", partial(_TOKEN_SHAPES.sub, _REDACTED)),
)
# Identifier shapes: masked in field values like the secret shapes, but not
# credentials, so they are not part of the last line of defense.
_IDENTIFIER_RULES: tuple[tuple[str, Callable[[str], str]], ...] = (
    ("email", partial(_EMAIL.sub, _REDACTED)),
    ("long hex run", partial(_LONG_HEX_RUN.sub, _REDACTED)),
)


def redact(text: str) -> str:
    """Apply the fixed outbound redaction rules to ``text``.

    ANSI escapes and control characters are stripped. A private-key block is
    masked whole, header and footer included; a header without its footer
    masks everything through the end of the text. ``Bearer``/``Basic`` values,
    key-value credentials, connection strings with userinfo, token shapes
    (GitHub, Stripe, Slack, Google, GitLab, PyPI, AWS, JWT), emails and long
    hexadecimal runs are masked, each rule keeping its scheme word or key
    name readable where there is one. Windows drive paths, UNC shares and
    absolute POSIX paths never leave: host home trees are rewritten
    repo-relative, anything else becomes ``[PATH]``. Plain factual sentences
    survive untouched.
    """
    redacted = _ANSI_ESCAPE.sub("", text)
    redacted = _CONTROL_CHARACTERS.sub("", redacted)
    for _, rule in _SECRET_RULES + _IDENTIFIER_RULES:
        redacted = rule(redacted)
    redacted = _WINDOWS_DRIVE_PATH.sub(_PATH, redacted)
    redacted = _UNC_PATH.sub(_PATH, redacted)
    redacted = _FORWARD_UNC_PATH.sub(_PATH, redacted)
    redacted = _REPO_RELATIVE_PREFIX.sub("", redacted)
    redacted = _ABSOLUTE_PATH.sub(_PATH, redacted)
    return redacted


def _secret_hits(text: str) -> tuple[str, ...]:
    """The secret rules that would alter ``text``, in rule order.

    This is the last line of defense over a whole serialized request body,
    keys included: ``redact_value`` never rewrites a dict key, so a
    secret-shaped key reaches this scan untouched. Only the secret rules
    take part - a path or an email in a key is not a credential.
    """
    hits: list[str] = []
    scanned = text
    for name, rule in _SECRET_RULES:
        masked = rule(scanned)
        if masked != scanned:
            hits.append(name)
            scanned = masked
    return tuple(hits)


def redact_value(value: Any) -> Any:
    """Apply ``redact`` to ``value`` recursively; containers keep their type.

    A string is redacted, a dict keeps its keys as written (they must be
    non-empty strings) with every value redacted, a list or a tuple redacts
    each item and stays a list or a tuple. ``None``, a bool, an int and a
    finite float pass through untouched.

    Anything else is refused with ``FIELD_TYPE_REJECTED``: bytes, a set, an
    object no JSON encoder knows, a non-finite float, a non-string or empty
    dict key. The message names the type only, never the value.
    """
    if isinstance(value, str):
        return redact(value)
    if isinstance(value, dict):
        redacted: dict[Any, Any] = {}
        for key, item in value.items():
            if not isinstance(key, str) or not key:
                raise OutletError(
                    "model outlet field objects need non-empty string keys,"
                    f" not {type(key).__name__}",
                    sub_reason="FIELD_TYPE_REJECTED",
                )
            redacted[key] = redact_value(item)
        return redacted
    if isinstance(value, list):
        return [redact_value(item) for item in value]
    if isinstance(value, tuple):
        return tuple(redact_value(item) for item in value)
    if value is None or isinstance(value, (bool, int)):
        return value
    if isinstance(value, float) and math.isfinite(value):
        return value
    raise OutletError(
        "model outlet field values must be strings, JSON containers, null,"
        f" bools, ints or finite floats, not {type(value).__name__}",
        sub_reason="FIELD_TYPE_REJECTED",
    )


def _jsonable(value: Any) -> Any:
    """A redacted value as JSON carries it: tuples become arrays."""
    if isinstance(value, dict):
        return {key: _jsonable(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_jsonable(item) for item in value]
    return value


def _canonical_text(value: Any) -> str:
    """``value`` as the canonical JSON text its digest is taken over.

    Refuses with ``FIELD_TYPE_REJECTED`` anything the strict encoder cannot
    carry, such as a lone surrogate from a permissively decoded log or an
    integer beyond the interpreter's conversion limit, instead of letting the
    encoder's own exception out of the outlet.
    """
    try:
        return jsonutil.canonical_bytes(value).decode("utf-8")
    except (TypeError, ValueError, RecursionError) as error:
        raise OutletError(
            "model outlet field values must be encodable as canonical JSON,"
            f" not {type(error).__name__}: {error}",
            sub_reason="FIELD_TYPE_REJECTED",
        ) from error


def _error_text(error: BaseException) -> str:
    """An exception as an error message may quote it: secret shapes masked."""
    try:
        return redact(str(error)) or type(error).__name__
    except Exception:
        return type(error).__name__


# --- Endpoint gate (security design delta 2.4) ------------------------------


def _is_ip_literal(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return False
    return True


def _has_unsafe_path(path: str) -> bool:
    """A path whose once-decoded form has a dot segment or a backslash.

    Covers ``.`` and ``..`` as written and every percent-encoded spelling of
    them (``%2e`` in any case or mix), so a normalization on the wire cannot
    turn an allowlisted prefix into another path.
    """
    decoded = unquote(path)
    return "\\" in decoded or any(
        segment in (".", "..") for segment in decoded.split("/")
    )


def _parse_authority(netloc: str) -> tuple[str, int | None]:
    """Read ``netloc`` as one host and its port, or ``None`` if none is written.

    A bare IPv6 literal such as ``::1`` is not a valid authority component,
    and ``urlsplit`` reads it as an empty host plus a bogus port (or only its
    first colon group), so ``SplitResult.port`` is never consulted. The
    netloc is interpreted here instead: a bracketed IPv6 literal is
    unbracketed, a single ``host:port`` pair is split, and anything with two
    or more colons is the literal itself. No DNS resolution happens.

    Raises ``ValueError`` for a port that is not 1-65535; an empty host is
    returned as such for the caller to refuse.
    """
    if netloc.startswith("["):
        host, bracket, rest = netloc[1:].partition("]")
        if not bracket or (rest and not rest.startswith(":")):
            raise ValueError("malformed bracketed host")
        port_text = rest[1:]
    elif netloc.count(":") == 1:
        host, _, port_text = netloc.partition(":")
    else:
        return netloc, None
    if not port_text:
        return host, None
    if (
        not (port_text.isascii() and port_text.isdigit())
        or not 1 <= int(port_text) <= 65535
    ):
        raise ValueError(f"port {port_text!r} is not 1-65535")
    return host, int(port_text)


def _describe(url: object) -> str:
    """``url`` as an error message may quote it.

    Userinfo, query and fragment are dropped and the rest is redacted, so a
    refused URL cannot carry the credential it contains into a log line.
    """
    if not isinstance(url, str):
        return f"<{type(url).__name__}>"
    try:
        parts = urlsplit(url)
    except ValueError:
        return "<unparseable URL>"
    host = parts.netloc.rsplit("@", 1)[-1]
    return redact(urlunsplit((parts.scheme, host, parts.path, "", "")))


def _check_url(
    label: str, url: object, *, scheme_refusal: str
) -> tuple[str, int | None, str]:
    """The structural checks shared by an endpoint and an allowlist entry.

    Returns ``(host, explicit port or None, path)``. The HTTPS scheme is
    checked first - plain HTTP never reaches anything else - and refuses
    with ``scheme_refusal``: ``ENDPOINT_NOT_HTTPS`` for a requested endpoint,
    ``ENDPOINT_NOT_ALLOWLISTED`` for an allowlist entry, which must be an
    HTTPS URL to begin with. Every other defect is refused as
    ``ENDPOINT_NOT_ALLOWLISTED``: a non-string, an unparseable URL,
    whitespace or control characters (``urlsplit`` silently drops tabs and
    newlines, so such a URL would be validated as a different URL than the
    one handed to the transport), userinfo, a missing host, an unusable
    port, and a path with a dot segment or a backslash.
    """
    if not isinstance(url, str):
        raise OutletError(
            f"{label} must be a URL string to pass the allowlist gate:"
            f" {_describe(url)}",
            sub_reason="ENDPOINT_NOT_ALLOWLISTED",
        )

    def refused(problem: str) -> OutletError:
        return OutletError(
            f"{label} {problem}: {_describe(url)!r}",
            sub_reason="ENDPOINT_NOT_ALLOWLISTED",
        )

    try:
        parts = urlsplit(url)
    except ValueError as error:
        raise refused("is not a valid URL and cannot be allowlisted") from error
    if parts.scheme != "https":
        raise OutletError(
            f"{label} must use https, not"
            f" {parts.scheme or 'scheme-less'!r}: {_describe(url)!r}",
            sub_reason=scheme_refusal,
        )
    if any(
        character.isspace() or not character.isprintable() for character in url
    ):
        raise refused(
            "must not contain whitespace or control characters (allowlist gate)"
        )
    if "@" in parts.netloc:
        raise refused(
            "must not carry userinfo (credentials in the URL; allowlist gate)"
        )
    try:
        host, port = _parse_authority(parts.netloc)
    except ValueError as error:
        raise refused(f"has an unusable authority ({error}); allowlist gate") from error
    if not host:
        raise refused("has no host to allowlist")
    if _has_unsafe_path(parts.path):
        raise refused(
            "path must not contain '.' or '..' segments, percent-encoded dots"
            " or backslashes (allowlist gate)"
        )
    return host, port, parts.path


# --- Audit role (security design delta 2.3 / interface contract 8) ----------


_UUID_HEX = frozenset("0123456789abcdefABCDEF")


def _require_uuid(value: object) -> str:
    """``value`` as a canonical UUID string; only a string that parses as one.

    Every standard spelling is accepted - upper case, hyphen-less, braced,
    ``urn:uuid:`` prefixed - and recorded in the canonical lower-case
    hyphenated form. The digits are counted on top of the parse, because
    ``uuid.UUID`` alone also reads a signed or damaged string and would turn
    it into a different valid ID. A UUID object, ``None`` or any other type
    is refused: the record stores the identifier as text.
    """
    if isinstance(value, str):
        digits = value.removeprefix("urn:uuid:").strip("{}").replace("-", "")
        if len(digits) == 32 and all(digit in _UUID_HEX for digit in digits):
            try:
                return str(uuid.UUID(value))
            except ValueError:
                pass
    raise OutletError(
        "model_audit.job_id must be a string that parses as a UUID, not"
        f" {type(value).__name__}",
        sub_reason="AUDIT_INVALID",
    )


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

    Anything a compliant record cannot carry is refused with
    ``AUDIT_INVALID``: a job_id that is not a string parsing as a UUID, an
    empty stage, a version that is neither a string nor null, an empty
    redaction_version, an outcome outside ``MODEL_AUDIT_OUTCOMES``, a
    duration that is negative, a bool or not finite, a digest that is not a
    sha256 digest or null.

    The offline record is pinned in both directions: ``provider="offline"``
    requires null versions, null digests, a zero duration and
    ``outcome="offline"``, and ``outcome="offline"`` requires the offline
    provider.
    """
    if not isinstance(provider, str) or not provider:
        raise OutletError(
            "model_audit.provider must be a non-empty string; offline runs"
            ' pin it to "offline"',
            sub_reason="PROVIDER_MISSING",
        )
    job_id = _require_uuid(job_id)
    if not isinstance(stage, str) or not stage:
        raise OutletError(
            "model_audit.stage must be a non-empty string",
            sub_reason="AUDIT_INVALID",
        )
    for label, version in (
        ("model_version", model_version),
        ("prompt_version", prompt_version),
    ):
        if version is not None and not isinstance(version, str):
            raise OutletError(
                f"model_audit.{label} must be a string or null,"
                f" not {type(version).__name__}",
                sub_reason="AUDIT_INVALID",
            )
    if not isinstance(redaction_version, str) or not redaction_version:
        raise OutletError(
            "model_audit.redaction_version must be a non-empty string",
            sub_reason="AUDIT_INVALID",
        )
    # The type is checked first: an unhashable outcome cannot be looked up in
    # the set at all.
    if not isinstance(outcome, str) or outcome not in MODEL_AUDIT_OUTCOMES:
        raise OutletError(
            "model_audit.outcome must be one of"
            f" {sorted(MODEL_AUDIT_OUTCOMES)}, not an outcome of type"
            f" {type(outcome).__name__}",
            sub_reason="AUDIT_INVALID",
        )
    # A duration is a finite non-negative number, an int or a float - never a
    # bool, NaN, infinity or an int beyond every finite float.
    duration_ok = False
    if isinstance(duration_seconds, (int, float)) and not isinstance(
        duration_seconds, bool
    ):
        try:
            duration_ok = math.isfinite(duration_seconds) and duration_seconds >= 0
        except OverflowError:
            duration_ok = False
    if not duration_ok:
        # The message names the type only: a value this strange may be
        # impossible to render, and an argument is never echoed.
        raise OutletError(
            "model_audit.duration_seconds must be a finite non-negative number"
            f" (an int or a float, never a bool), not"
            f" {type(duration_seconds).__name__}",
            sub_reason="AUDIT_INVALID",
        )
    for label, digest in (
        ("request_digest", request_digest),
        ("response_digest", response_digest),
    ):
        if digest is not None and not jsonutil.is_digest(digest):
            raise OutletError(
                f"model_audit.{label} must be a sha256 digest or null",
                sub_reason="AUDIT_INVALID",
            )
    offline = provider == OFFLINE_PROVIDER
    if (offline or outcome == "offline") and (
        not offline
        or model_version is not None
        or prompt_version is not None
        or request_digest is not None
        or response_digest is not None
        or duration_seconds != 0
        or outcome != "offline"
    ):
        raise OutletError(
            'an offline model_audit record needs provider="offline",'
            ' outcome="offline", null versions, null digests and a zero'
            " duration",
            sub_reason="AUDIT_INVALID",
        )
    names = []
    for name in allowed_fields:
        if not isinstance(name, str):
            raise OutletError(
                "model_audit.allowed_fields must contain strings only, not"
                f" {type(name).__name__}",
                sub_reason="AUDIT_INVALID",
            )
        names.append(name)
    return {
        "job_id": job_id,
        "stage": stage,
        "provider": provider,
        "model_version": model_version,
        "prompt_version": prompt_version,
        "allowed_fields_digest": jsonutil.digest_json(sorted(set(names))),
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

    ``job_id`` is not checked here but at the top of every ``request``: an
    outlet without one can be built, it just cannot write a compliant audit
    record, so it refuses with ``AUDIT_INVALID`` before anything else.
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
        """Validate the allowlist: a poisoned entry is refused outright.

        The allowlist is configuration, not input, but an entry carrying
        userinfo, a dot segment or anything else the gate refuses would
        legitimize exactly the endpoints the gate exists to refuse. Every
        entry must be an HTTPS URL with a host and passes the same
        structural checks as a requested endpoint; anything else raises
        ``OutletError(sub_reason="ENDPOINT_NOT_ALLOWLISTED")``.
        """
        entries: list[tuple[str, int, str]] = []
        for entry in endpoint_allowlist:
            host, port, path = _check_url(
                "endpoint allowlist entry",
                entry,
                scheme_refusal="ENDPOINT_NOT_ALLOWLISTED",
            )
            entries.append(
                (host, DEFAULT_HTTPS_PORT if port is None else port, path)
            )
        self._endpoint_allowlist = tuple(entries)
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

        Everything below happens before the transport is touched, in this
        order: the outlet's job_id must be a UUID string
        (``AUDIT_INVALID``); the endpoint must pass the gate; a provider, a
        model version, a prompt version and a transport must be configured
        (``PROVIDER_REQUIRED``, ``MODEL_VERSION_REQUIRED``,
        ``PROMPT_VERSION_REQUIRED``, ``TRANSPORT_MISSING``); the audit record
        must be writable; the body - only the allowed fields, each redacted
        at every depth - must survive the last line of defense
        (``FIELD_TYPE_REJECTED``, ``REDACTION_REJECTED``).

        A timeout, a connection error or any other guarded-connection
        failure degrades to ``fallback_offline`` with empty findings. An
        address refused by the connection layer, any other transport
        exception and a response that is not a hypothesis-only model output
        block with an ``OutletError`` carrying the audit of that request.
        """
        _require_uuid(self._job_id)
        if endpoint is None or not self._endpoint_allowlist:
            audit = self._audit(
                stage,
                provider=OFFLINE_PROVIDER,
                outcome="offline",
                request_digest=None,
                response_digest=None,
                duration_seconds=0,
                offline=True,
            )
            return self._result("offline", (), None, audit)
        self._validate_endpoint(endpoint)
        provider = self._provider
        if not provider:
            # The audit must name a real provider identity; falling back to
            # the endpoint hostname would invent one (§2.3). Fail closed.
            raise OutletError(
                "an online model outlet requires an explicit provider; the"
                " endpoint hostname is not a provider identity",
                sub_reason="PROVIDER_REQUIRED",
            )
        if not self._model_version:
            raise OutletError(
                "an online model outlet requires a model version; an"
                " unaudited model call is refused",
                sub_reason="MODEL_VERSION_REQUIRED",
            )
        if not self._prompt_version:
            raise OutletError(
                "an online model outlet requires a prompt version; an"
                " unaudited model call is refused",
                sub_reason="PROMPT_VERSION_REQUIRED",
            )
        transport = self._transport
        if transport is None:
            raise OutletError(
                "an allowlisted endpoint is configured but no transport is"
                " injected; refusing to invent a model call",
                sub_reason="TRANSPORT_MISSING",
            )
        # Nothing leaves before it is certain that its audit record can be
        # written: a malformed stage, version or redaction rule set is
        # refused here instead of surfacing after the request was sent.
        self._audit(
            stage,
            provider=provider,
            outcome="rejected",
            request_digest=None,
            response_digest=None,
            duration_seconds=0,
        )
        body = self._build_body(stage, fields)
        request_digest = jsonutil.digest_json(body)
        started = time.monotonic()

        def degraded() -> dict[str, Any]:
            """The offline result of a request that did not come back."""
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

        def blocked(
            message: str,
            sub_reason: str,
            response_digest: str | None = None,
        ) -> OutletError:
            """A refusal that carries the audit trail of the sent request."""
            return OutletError(
                message,
                sub_reason=sub_reason,
                model_audit=self._audit(
                    stage,
                    provider=provider,
                    outcome="rejected",
                    request_digest=request_digest,
                    response_digest=response_digest,
                    duration_seconds=time.monotonic() - started,
                ),
            )

        try:
            response = transport.request(endpoint, body)
        except SafeHttpError as error:
            if error.reason == _ADDRESS_DENIED:
                # The connection layer re-checked a resolved address and
                # found it in the shared rejection set (DNS rebinding): a
                # policy hit, not an outage, so it blocks instead of
                # degrading.
                raise blocked(
                    "the connection layer refused the model endpoint"
                    f" address: {_error_text(error)}",
                    "ENDPOINT_ADDRESS_REJECTED",
                ) from error
            return degraded()
        except (TimeoutError, ConnectionError, OSError):
            return degraded()
        except Exception as error:
            raise blocked(
                f"the model transport failed: {_error_text(error)}",
                "TRANSPORT_FAILED",
            ) from error
        # The response is untrusted: whatever it provokes while it is read
        # - not JSON, a structure the contract rejects, a type the contract
        # did not expect - is an invalid model output, never a raw exception.
        response_digest = _response_digest(response)
        try:
            parsed = parse_model_output(_decode_response(response))
            findings = tuple(finding.as_dict() for finding in parsed.findings)
        except Exception as error:
            raise blocked(
                f"model output rejected: {_error_text(error)}",
                "MODEL_OUTPUT_INVALID",
                response_digest,
            ) from error
        return self._result(
            parsed.outcome,
            findings,
            parsed.reason_code,
            self._audit(
                stage,
                provider=provider,
                outcome=parsed.outcome,
                request_digest=request_digest,
                response_digest=response_digest,
                duration_seconds=time.monotonic() - started,
            ),
        )

    def _validate_endpoint(self, endpoint: str) -> str:
        """Run the fail-closed endpoint gate; returns the endpoint host.

        Order matters and is frozen by the contract tests: the URL's scheme
        and shape first (plain HTTP never reaches the allowlist
        comparison), then the shared address rejection set for literal-IP
        hosts - allowlisted endpoints are hostnames, so even a globally
        routable IP literal is refused with an address token - then the
        allowlist match on the same host, the same port (443 unless written)
        and a path that is the entry path itself or one of its segments.
        """
        host, port, path = _check_url(
            "model endpoint", endpoint, scheme_refusal="ENDPOINT_NOT_HTTPS"
        )
        if _is_ip_literal(host):
            if is_rejected_address(host):
                raise OutletError(
                    f"model endpoint address {host!r} falls into the shared"
                    " address rejection set (private, loopback, link-local,"
                    " CGNAT, multicast, reserved, unspecified or cloud"
                    f" metadata): {_describe(endpoint)!r}",
                    sub_reason="ENDPOINT_ADDRESS_REJECTED",
                )
            raise OutletError(
                f"model endpoint address {host!r} is an IP literal;"
                " allowlisted endpoints are hostnames, not addresses:"
                f" {_describe(endpoint)!r}",
                sub_reason="ENDPOINT_ADDRESS_REJECTED",
            )
        if port is None:
            port = DEFAULT_HTTPS_PORT
        for entry_host, entry_port, entry_path in self._endpoint_allowlist:
            if host != entry_host or port != entry_port:
                continue
            prefix = entry_path.rstrip("/")
            if not entry_path or path == prefix or path.startswith(prefix + "/"):
                return host
        raise OutletError(
            "model endpoint is not in the endpoint allowlist (exact host,"
            f" port and path segment match required): {_describe(endpoint)!r}",
            sub_reason="ENDPOINT_NOT_ALLOWLISTED",
        )

    def _build_body(self, stage: str, fields: Mapping[str, Any]) -> dict[str, Any]:
        """Filter to the allowed fields, redact them, scan the whole body.

        The body is ``{"stage", "fields"}`` with only the allowed fields,
        each redacted at every depth and carried as JSON carries it. It is
        then serialized to the canonical JSON text the digest is taken over
        and that text is scanned once more with the secret rules: dict keys
        are never rewritten, so this is the only place a secret-shaped key is
        caught.
        """
        if not isinstance(fields, Mapping):
            raise OutletError(
                "model outlet fields must be a mapping of field name to"
                f" value, not {type(fields).__name__}",
                sub_reason="FIELD_TYPE_REJECTED",
            )
        filtered: dict[str, Any] = {}
        for name in sorted(self._allowed_field_names):
            if name not in fields:
                continue
            try:
                filtered[name] = _jsonable(redact_value(fields[name]))
            except RecursionError as error:
                raise OutletError(
                    "model outlet field values are nested too deeply to be"
                    " redacted",
                    sub_reason="FIELD_TYPE_REJECTED",
                ) from error
        body = {"stage": stage, "fields": filtered}
        hits = _secret_hits(_canonical_text(body))
        if hits:
            raise OutletError(
                "the request body still carries a secret shape after"
                f" redaction ({', '.join(hits)}); refusing to send it",
                sub_reason="REDACTION_REJECTED",
            )
        return body

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


def _decode_response(response: object) -> Any:
    """Decode one model response into its payload; text must be strict JSON.

    A text response is encoded to UTF-8 first, so a lone surrogate is
    refused instead of travelling on into the findings. Raises whatever the
    strict decoder raises; the caller turns it into a rejected output.
    """
    if isinstance(response, str):
        response = response.encode("utf-8")
    if isinstance(response, (bytes, bytearray)):
        return jsonutil.loads_strict(bytes(response))
    return response


def _response_digest(response: object) -> str | None:
    """Digest the raw response when it can be encoded, else ``None``.

    Text and bytes are digested as they arrived, so a response that turns
    out to be invalid still leaves its digest in the audit trail. An object
    that cannot be encoded has no digest to take.
    """
    try:
        if isinstance(response, str):
            return jsonutil.digest_bytes(response.encode("utf-8"))
        if isinstance(response, (bytes, bytearray)):
            return jsonutil.digest_bytes(bytes(response))
        return jsonutil.digest_json(response)
    except (TypeError, ValueError, RecursionError):
        return None
