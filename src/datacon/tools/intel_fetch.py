"""Online intel fetching, immutable snapshots and license gating (T15, D44).

Implements the T15 contract from the v0.2 security design delta section 3
(domain allowlist with explicit subdomains, unified IPv4/IPv6 address
rejection set, per-hop redirect revalidation, HTTPS-only transport with
connect/read/total budgets, streaming wire and decompression caps) and the
modified REQ-02 requirement that external advisories enter the system as
immutable, licensed snapshots. Reason tokens follow interface-contract-delta
section 10 and ride on ``IntelFetchError.sub_reason`` for audit mapping
(``MATERIAL_MISSING`` / ``SOURCE_CONFLICT`` / ``POLICY_DENIED``).

The module never opens a socket, resolves DNS or spawns a client on its own:
the pure fetch logic drives an injected ``transport``, and the shipped
``GuardedTransport`` adapter is equally injectable (its ``resolver``,
``socket_factory`` and ``clock`` are constructor arguments), so offline
cases stay offline and the fetch path is contract-testable. Address
rejection judgements live exactly once, in ``safe_http.is_rejected_address``;
this module only unwraps literal-IP hosts far enough to ask it. Validation
always runs before the transport is touched (fail closed, pre-connect), and
bodies are counted while they stream so an over-limit payload is cut
mid-flight instead of being buffered first.

Framing and status hardening on top of that: a hop must declare exactly one
integer ``Content-Length`` and deliver exactly that many wire bytes (more is
``RESPONSE_UNFRAMED``, fewer is ``CONTENT_TRUNCATED``), a final status
outside 2xx is ``HTTP_STATUS_REJECTED`` before a single body byte is read,
gzip is inflated step by step under a hard per-step output cap, and the
total budget is re-checked against the hop's final elapsed time once its
body has streamed. Every ``safe_http.SafeHttpError`` the guarded transport
raises surfaces here as ``IntelFetchError`` carrying the transport's reason
token, so callers only ever see this module's error type.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import ipaddress
import time
from types import MappingProxyType
from typing import Any, Callable, Iterator, Mapping, Protocol, Sequence
from urllib.parse import urljoin, urlsplit, urlunsplit
import zlib

from datacon.tools.safe_http import (
    GuardedConnection,
    GuardedResponse,
    Resolver,
    SafeHttpError,
    SocketFactory,
    connect_guarded,
    is_rejected_address,
)

CONNECT_TIMEOUT_SECONDS = 10
READ_TIMEOUT_SECONDS = 30
TOTAL_TIMEOUT_SECONDS = 60
MAX_WIRE_BYTES = 8 * 1024 * 1024
MAX_DECOMPRESSED_BYTES = 32 * 1024 * 1024
MAX_COMPRESSION_RATIO = 100
MAX_REDIRECT_HOPS = 5

# The one use this system makes of fetched advisories; the license gate
# checks that the source's registered license actually covers it.
SYSTEM_USE = "reproduction"
TOOL_VERSION = "datacon.intel_fetch/0.1.0"
# Prefixing external text keeps it out of the instruction channel: a payload
# wrapped this way never begins with a directive marker, while its factual
# content survives verbatim.
DATA_CHANNEL_MARKER = "[data] "


class IntelFetchError(ValueError):
    """An intel fetch or snapshot gate failed closed.

    ``sub_reason`` carries the audit token (interface contract delta section
    10, e.g. ``SIZE_LIMIT_EXCEEDED`` or ``LICENSE_REJECTED``) so callers can
    attribute the failure without parsing the human-readable message.
    """

    def __init__(self, sub_reason: str, message: str) -> None:
        super().__init__(message)
        self.sub_reason = sub_reason
        self.message = message


class Hop(Protocol):
    """One transport response: status line, headers, redirect target, body.

    ``elapsed_seconds`` is the transport-declared wall-clock cost of the hop;
    the fetch loop accumulates it against the total budget. ``body_stream``
    yields wire bytes chunk by chunk so limits are enforced while streaming.
    """

    @property
    def status(self) -> int: ...

    @property
    def headers(self) -> Mapping[str, str]: ...

    @property
    def location(self) -> str | None: ...

    @property
    def elapsed_seconds(self) -> float: ...

    def body_stream(self) -> Iterator[bytes]: ...


class Transport(Protocol):
    """Fetches one URL per call; connect/read timeouts are its job to raise."""

    def fetch(
        self, url: str, *, connect_timeout: float, read_timeout: float
    ) -> Hop: ...


@dataclass(frozen=True)
class FetchResult:
    """Body and metadata of one completed fetch."""

    body: bytes
    status: int
    hops: tuple[str, ...]


def _literal_address(host: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    """Return ``host`` as a literal IP address, or ``None`` for a name.

    No DNS resolution happens here: only syntactically literal hosts can be
    rechecked pre-connect. Name resolution and the post-resolution recheck
    belong to the transport integration round.
    """
    try:
        return ipaddress.ip_address(host)
    except ValueError:
        return None


def _check_literal_address(host: str, url: str) -> None:
    """Reject literal-IP hosts that hit the address rejection set.

    The rejection set has a single authoritative home,
    ``safe_http.is_rejected_address``: it unwraps IPv4-mapped IPv6 hosts
    first (``::ffff:127.0.0.1`` is judged as ``127.0.0.1``), matching the
    anti-rebinding rules in the security design delta, and this module asks
    it instead of keeping a twin table.
    """
    address = _literal_address(host)
    if address is None:
        return
    if is_rejected_address(address):
        raise IntelFetchError(
            "ADDRESS_DENIED",
            f"address recheck rejected {host!r} in {url!r}: it falls into a"
            " blocked network (private, loopback, link-local, CGNAT,"
            " multicast, reserved, unspecified or metadata)",
        )


def validate_source(url: str, allowlist: Sequence[str]) -> None:
    """Pre-flight validation of an intel source URL; returns ``None``.

    Checks run in fail-closed order before any transport call: HTTPS scheme,
    literal-IP address recheck against the rejection set, then exact-match
    domain allowlisting (subdomains must be listed explicitly; there is no
    wildcard). A registered HTTPS source passes; anything else raises
    ``IntelFetchError``.
    """
    parts = urlsplit(url)
    if parts.scheme != "https":
        raise IntelFetchError(
            "HTTPS_REQUIRED",
            f"intel source must be fetched over https, not"
            f" {parts.scheme or 'scheme-less'!r}: {url!r}",
        )
    host = parts.hostname
    if not host:
        raise IntelFetchError(
            "INVALID_SOURCE_URL",
            f"intel source URL has no host: {url!r}",
        )
    _check_literal_address(host, url)
    registered = {entry.lower() for entry in allowlist}
    if host.lower() not in registered:
        raise IntelFetchError(
            "ALLOWLIST_DENIED",
            f"host {host!r} is not in the intel source allowlist (subdomains"
            f" must be listed explicitly): {url!r}",
        )


def _enforce_decompression_budget(
    wire_bytes: int, decompressed_bytes: int
) -> None:
    """Cut a body that inflates past the decompressed-size or ratio caps."""
    if decompressed_bytes > MAX_DECOMPRESSED_BYTES:
        raise IntelFetchError(
            "DECOMPRESSION_BOMB",
            f"DECOMPRESSION_BOMB: decompressed {decompressed_bytes} bytes"
            f" from {wire_bytes} wire bytes, above the"
            f" {MAX_DECOMPRESSED_BYTES} byte cap",
        )
    if decompressed_bytes > wire_bytes * MAX_COMPRESSION_RATIO:
        raise IntelFetchError(
            "DECOMPRESSION_BOMB",
            f"DECOMPRESSION_BOMB: decompressed {decompressed_bytes} bytes"
            f" from {wire_bytes} wire bytes, above the"
            f" {MAX_COMPRESSION_RATIO}:1 compression ratio cap",
        )


def _read_body(hop: Hop) -> bytes:
    """Stream one hop's body under the wire and decompression budgets.

    The checks run in a fixed order, all while the body streams so an
    over-limit payload is cut mid-flight instead of being buffered first:

    1. the hop must declare exactly one integer ``content-length``: absent
       or malformed leaves the response ``RESPONSE_UNFRAMED`` (the declared
       length is never pre-rejected against the wire cap -- the stream
       itself gets cut mid-flight instead);
    2. wire bytes are counted as they arrive: past the declared length is
       ``RESPONSE_UNFRAMED``, fewer than declared once the stream ends is
       ``CONTENT_TRUNCATED``, and past ``MAX_WIRE_BYTES`` is
       ``SIZE_LIMIT_EXCEEDED``;
    3. only ``identity`` and ``gzip`` encodings are accepted; gzip is
       inflated one capped step at a time (``max_length`` never above
       ``MAX_DECOMPRESSED_BYTES + 1``) with the decompressor's own errors
       mapped to ``RESPONSE_UNFRAMED``, an incomplete member to
       ``CONTENT_TRUNCATED``, trailing bytes behind the member to
       ``RESPONSE_UNFRAMED``, and the accumulated output to the
       decompressed-size and ratio caps;
    4. a body that survives with zero decoded bytes is ``EMPTY_CONTENT``.
    """
    declared_raw = hop.headers.get("content-length")
    if declared_raw is None:
        raise IntelFetchError(
            "RESPONSE_UNFRAMED",
            "RESPONSE_UNFRAMED: response declares no content-length, so"
            " nothing says where its body ends",
        )
    declared = declared_raw.strip()
    if not declared.isascii() or not declared.isdigit():
        raise IntelFetchError(
            "RESPONSE_UNFRAMED",
            f"RESPONSE_UNFRAMED: content-length {declared_raw!r} is not a"
            " single decimal integer",
        )
    content_length = int(declared)
    encoding = (hop.headers.get("content-encoding") or "").strip().lower()
    if encoding not in ("", "identity", "gzip"):
        raise IntelFetchError(
            "CONTENT_ENCODING_REJECTED",
            f"unsupported content-encoding {encoding!r}: only identity and"
            " gzip are accepted for intel sources",
        )
    wire_bytes = 0
    parts: list[bytes] = []
    if encoding in ("", "identity"):
        for chunk in hop.body_stream():
            wire_bytes += len(chunk)
            if wire_bytes > MAX_WIRE_BYTES:
                raise IntelFetchError(
                    "SIZE_LIMIT_EXCEEDED",
                    f"SIZE_LIMIT_EXCEEDED: wire body reached {wire_bytes}"
                    f" bytes, above the {MAX_WIRE_BYTES} byte cap",
                )
            if wire_bytes > content_length:
                raise IntelFetchError(
                    "RESPONSE_UNFRAMED",
                    f"RESPONSE_UNFRAMED: wire body reached {wire_bytes}"
                    f" bytes, above the declared content-length"
                    f" {content_length}",
                )
            parts.append(chunk)
        if wire_bytes < content_length:
            raise IntelFetchError(
                "CONTENT_TRUNCATED",
                f"CONTENT_TRUNCATED: stream ended after {wire_bytes} of the"
                f" {content_length} declared body bytes",
            )
        body = b"".join(parts)
    else:
        decompressor = zlib.decompressobj(16 + zlib.MAX_WBITS)
        decompressed_bytes = 0
        member_finished = False

        def _count_output(piece: bytes) -> None:
            nonlocal decompressed_bytes
            if not piece:
                return
            parts.append(piece)
            decompressed_bytes += len(piece)
            _enforce_decompression_budget(wire_bytes, decompressed_bytes)

        for chunk in hop.body_stream():
            wire_bytes += len(chunk)
            if wire_bytes > MAX_WIRE_BYTES:
                raise IntelFetchError(
                    "SIZE_LIMIT_EXCEEDED",
                    f"SIZE_LIMIT_EXCEEDED: wire body reached {wire_bytes}"
                    f" bytes, above the {MAX_WIRE_BYTES} byte cap",
                )
            if wire_bytes > content_length:
                raise IntelFetchError(
                    "RESPONSE_UNFRAMED",
                    f"RESPONSE_UNFRAMED: wire body reached {wire_bytes}"
                    f" bytes, above the declared content-length"
                    f" {content_length}",
                )
            if member_finished:
                raise IntelFetchError(
                    "RESPONSE_UNFRAMED",
                    "RESPONSE_UNFRAMED: wire bytes arrived behind the end of"
                    " the gzip member",
                )
            # One inflate step may hand out at most MAX_DECOMPRESSED_BYTES+1
            # bytes; whatever the cap held back stays in unconsumed_tail and
            # is fed through the following rounds of this loop. Any of the
            # decompressor's own errors (a failed CRC, non-gzip garbage) is
            # an intact frame carrying the wrong payload, never this
            # module's error type: catch and translate.
            pending: bytes = chunk
            while pending:
                try:
                    piece = decompressor.decompress(
                        pending, MAX_DECOMPRESSED_BYTES + 1
                    )
                except zlib.error as error:
                    raise IntelFetchError(
                        "RESPONSE_UNFRAMED",
                        "RESPONSE_UNFRAMED: body promised content-encoding"
                        f" gzip but failed to decode ({error})",
                    ) from error
                _count_output(piece)
                if decompressor.eof:
                    if decompressor.unused_data:
                        raise IntelFetchError(
                            "RESPONSE_UNFRAMED",
                            "RESPONSE_UNFRAMED:"
                            f" {len(decompressor.unused_data)} trailing"
                            " bytes behind the end of the gzip member",
                        )
                    member_finished = True
                    break
                pending = decompressor.unconsumed_tail
        if wire_bytes < content_length:
            raise IntelFetchError(
                "CONTENT_TRUNCATED",
                f"CONTENT_TRUNCATED: stream ended after {wire_bytes} of the"
                f" {content_length} declared body bytes",
            )
        if not decompressor.eof:
            raise IntelFetchError(
                "CONTENT_TRUNCATED",
                "CONTENT_TRUNCATED: the gzip stream ended before its final"
                " member was complete",
            )
        body = b"".join(parts)
    if not body:
        raise IntelFetchError(
            "EMPTY_CONTENT",
            "EMPTY_CONTENT: the response body decoded to zero bytes",
        )
    return body


def fetch_intel(
    url: str, *, allowlist: Sequence[str], transport: Transport
) -> FetchResult:
    """Fetch ``url`` through ``transport`` under every T15 guard.

    The URL is validated before the first transport call, every redirect hop
    is revalidated before it is fetched, at most ``MAX_REDIRECT_HOPS``
    redirects are followed, declared per-hop ``elapsed_seconds`` accumulate
    against the total budget -- re-checked against the final hop's latest
    ``elapsed_seconds`` once its body has streamed, so the time a body takes
    to arrive counts too -- and the body is streamed through the wire and
    decompression caps. A final status outside 2xx is rejected on its status
    line without reading one byte of its body. ``SafeHttpError`` raised by a
    guarded transport surfaces as ``IntelFetchError`` carrying the
    transport's reason token; transport-raised connect/read timeouts
    propagate unchanged. A transport whose hops own a connection (``close``
    attr) has every hop released exactly once: after its redirect is
    followed, after its body is consumed, or when a raised limit abandons it
    mid-flight.
    """
    validate_source(url, allowlist)
    visited: list[str] = []
    redirects_followed = 0
    elapsed_seconds = 0.0
    current = url
    while True:
        visited.append(current)
        try:
            hop = transport.fetch(
                current,
                connect_timeout=CONNECT_TIMEOUT_SECONDS,
                read_timeout=READ_TIMEOUT_SECONDS,
            )
        except SafeHttpError as error:
            raise IntelFetchError(error.reason, str(error)) from error
        # Pure fake hops have no close(); connection-owning hops (e.g.
        # GuardedTransport's) are released here on every exit path.
        hop_close = getattr(hop, "close", None)
        try:
            head_elapsed = hop.elapsed_seconds
            elapsed_seconds += head_elapsed
            if elapsed_seconds > TOTAL_TIMEOUT_SECONDS:
                raise IntelFetchError(
                    "FETCH_TIMEOUT",
                    f"FETCH_TIMEOUT: {elapsed_seconds:.1f} seconds across"
                    f" {len(visited)} hops exceed the"
                    f" {TOTAL_TIMEOUT_SECONDS} second total budget",
                )
            if 300 <= hop.status < 400:
                location = hop.location
                if not location:
                    raise IntelFetchError(
                        "REDIRECT_WITHOUT_LOCATION",
                        f"hop {current!r} answered {hop.status} without a"
                        " Location header",
                    )
                redirects_followed += 1
                if redirects_followed > MAX_REDIRECT_HOPS:
                    raise IntelFetchError(
                        "REDIRECT_LIMIT_EXCEEDED",
                        f"REDIRECT_LIMIT_EXCEEDED: refusing to follow"
                        f" redirect {redirects_followed} to {location!r}"
                        f" after {len(visited)} hops"
                        f" (limit {MAX_REDIRECT_HOPS})",
                    )
                target = urljoin(current, location)
                validate_source(target, allowlist)
                current = target
                continue
            if not 200 <= hop.status < 300:
                raise IntelFetchError(
                    "HTTP_STATUS_REJECTED",
                    f"HTTP_STATUS_REJECTED: hop {current!r} answered"
                    f" {hop.status}, neither a 2xx success nor a redirect to"
                    " follow; its body was not read",
                )
            body = _read_body(hop)
            elapsed_seconds += hop.elapsed_seconds - head_elapsed
            if elapsed_seconds > TOTAL_TIMEOUT_SECONDS:
                raise IntelFetchError(
                    "FETCH_TIMEOUT",
                    f"FETCH_TIMEOUT: {elapsed_seconds:.1f} seconds across"
                    f" {len(visited)} hops exceed the"
                    f" {TOTAL_TIMEOUT_SECONDS} second total budget"
                    f" (the final hop's body streamed for"
                    f" {hop.elapsed_seconds:.1f} seconds)",
                )
            return FetchResult(
                body=body, status=hop.status, hops=tuple(visited)
            )
        except SafeHttpError as error:
            raise IntelFetchError(error.reason, str(error)) from error
        finally:
            if callable(hop_close):
                hop_close()


class _GuardedHop:
    """One ``safe_http`` response adapted to the ``Hop`` protocol.

    The hop owns its guarded connection so the connection closes exactly
    once and only after the hop is finished with the wire: when the body
    stream runs dry (the success path), or through ``close()`` when the
    fetch loop abandons the hop early -- a redirect whose body is never
    read, or a limit that cuts the stream mid-flight.

    ``elapsed_seconds`` is measured once when the response head arrives and
    re-measured (against the injected clock and the hop's start time,
    keeping the larger value) when the body stream ends or the hop is
    closed, so the time a body takes to stream counts against the total
    budget instead of vanishing at the head.
    """

    def __init__(
        self,
        connection: GuardedConnection,
        response: GuardedResponse,
        elapsed_seconds: float,
        *,
        clock: Callable[[], float] | None = None,
        started_at: float | None = None,
    ) -> None:
        self._connection = connection
        self._response = response
        self._elapsed_seconds = elapsed_seconds
        self._clock = clock
        self._started_at = started_at
        self._closed = False

    @property
    def status(self) -> int:
        return self._response.status

    @property
    def headers(self) -> Mapping[str, str]:
        return self._response.headers

    @property
    def location(self) -> str | None:
        found = self._response.headers.get("location")
        return found or None

    @property
    def elapsed_seconds(self) -> float:
        return self._elapsed_seconds

    def _remeasure_elapsed(self) -> None:
        """Re-measure against the clock, keeping the larger value.

        A clock that itself fails is never allowed to add a new exception
        onto whatever path is unwinding: the last good measurement stays.
        """
        if self._clock is None or self._started_at is None:
            return
        try:
            measured = self._clock() - self._started_at
        except Exception:
            return
        if measured > self._elapsed_seconds:
            self._elapsed_seconds = measured

    def body_stream(self) -> Iterator[bytes]:
        try:
            for chunk in self._response.body_chunks:
                yield chunk
        finally:
            self.close()

    def close(self) -> None:
        """Close the hop's connection; deliberately idempotent."""
        if not self._closed:
            self._closed = True
            self._remeasure_elapsed()
            self._connection.close()


class GuardedTransport:
    """``Transport`` adapter that runs every hop through ``safe_http``.

    Each ``fetch`` is one guarded hop: the URL's host is resolved through
    the injected ``resolver`` and validated against the shared rejection
    set, a fresh socket from the injected ``socket_factory`` is dialed
    directly with TLS SNI and the HTTP ``Host`` header pinned to the
    hostname, and the parsed response is wrapped into a ``Hop`` whose body
    streams wire chunk by wire chunk. ``elapsed_seconds`` is the difference
    of two ``clock`` calls taken around the response head, re-measured when
    the hop's body finishes streaming so an injected step clock measures
    pure fake time while the default ``time.monotonic`` measures real wall
    time.
    """

    def __init__(
        self,
        *,
        resolver: Resolver,
        socket_factory: SocketFactory,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._resolver = resolver
        self._socket_factory = socket_factory
        self._clock = clock

    def fetch(
        self, url: str, *, connect_timeout: float, read_timeout: float
    ) -> Hop:
        """Fetch ``url`` on one fresh guarded connection; returns its Hop."""
        started = self._clock()
        connection = connect_guarded(
            url,
            resolver=self._resolver,
            socket_factory=self._socket_factory,
            connect_timeout=connect_timeout,
            read_timeout=read_timeout,
        )
        try:
            parts = urlsplit(url)
            target = parts.path or "/"
            if parts.query:
                target = f"{target}?{parts.query}"
            connection.send_request("GET", target, headers={})
            response = connection.read_response()
        except BaseException:
            # The request head failed mid-flight; the hop that would own
            # this connection is never returned, so release it here.
            connection.close()
            raise
        return _GuardedHop(
            connection=connection,
            response=response,
            elapsed_seconds=self._clock() - started,
            clock=self._clock,
            started_at=started,
        )


def _sha256_digest(payload: bytes) -> str:
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def strip_url_credentials(url: str) -> str:
    """Return ``url`` without any ``user:password@`` part.

    Source URLs end up in snapshot records and in summaries that reach
    reports and audits. Credentials embedded in a URL carry nothing worth
    keeping there: the guarded transport never sends them (the ``Host``
    header is pinned to the hostname and no ``Authorization`` is derived
    from the URL), so only the disclosure would survive. Everything else
    -- scheme, host, port, path, query and fragment -- is kept as written.
    Raises ``ValueError`` when ``url`` cannot be split.
    """
    parts = urlsplit(url)
    return urlunsplit(
        (
            parts.scheme,
            parts.netloc.rpartition("@")[2],
            parts.path,
            parts.query,
            parts.fragment,
        )
    )


def build_snapshot(
    fetch_result: FetchResult, license_info: str | None
) -> Mapping[str, Any]:
    """Freeze a fetch into a read-only snapshot record keyed by content digest.

    The snapshot records the original source URL (without any embedded
    credentials), HTTP status, content digest, license identifier (kept
    ``None`` when unknown so the gap stays visible), redirect chain digest,
    fetch timestamp and tool version. The returned mapping is a
    ``MappingProxyType``: later writes cannot reshape the record; a new
    fetch produces a new snapshot. This is the record only: persisting it
    in a content-addressed store belongs to the snapshot-store adapter.
    """
    chain = tuple(fetch_result.hops)
    if not chain:
        raise IntelFetchError(
            "INVALID_FETCH_RESULT",
            "cannot snapshot a fetch result without hops",
        )
    snapshot: dict[str, Any] = {
        "source_url": strip_url_credentials(chain[0]),
        "http_status": fetch_result.status,
        "content_digest": _sha256_digest(fetch_result.body),
        "license": license_info,
        "redirect_chain_digest": _sha256_digest(
            "\n".join(chain).encode("utf-8")
        ),
        "fetched_at": datetime.now(timezone.utc).isoformat(),
        "tool_version": TOOL_VERSION,
    }
    return MappingProxyType(snapshot)


def check_license(
    snapshot_meta: Mapping[str, Any],
    case_registry: Mapping[str, Mapping[str, Any]],
) -> None:
    """Gate a snapshot against the case registry; returns ``None``.

    ``case_registry`` maps each registered source host to
    ``{"license": str, "permitted_uses": [str]}``. A snapshot without license
    information, an unregistered host, a license that conflicts with the
    registry, a ``permitted_uses`` grant that is not a list/tuple/set of use
    names (a bare string would let a substring pose as a permission), or a
    registered license that does not cover this system's use
    (``reproduction``) is rejected with ``LICENSE_REJECTED`` (POLICY_DENIED
    with that ``detail.sub_reason``) before any material can enter the
    reproduction workflow.
    """
    source_url = snapshot_meta.get("source_url")
    license_id = snapshot_meta.get("license")
    host = urlsplit(source_url).hostname if isinstance(source_url, str) else None
    entry = case_registry.get(host.lower()) if host else None
    if not isinstance(entry, Mapping):
        raise IntelFetchError(
            "LICENSE_REJECTED",
            f"LICENSE_REJECTED: source {source_url!r} has no license record"
            " in the case registry",
        )
    if not isinstance(license_id, str) or not license_id:
        raise IntelFetchError(
            "LICENSE_REJECTED",
            f"LICENSE_REJECTED: snapshot from {source_url!r} carries no"
            " license information",
        )
    registered_license = entry.get("license")
    if registered_license != license_id:
        raise IntelFetchError(
            "LICENSE_REJECTED",
            f"LICENSE_REJECTED: snapshot license {license_id!r} conflicts"
            f" with the registered license {registered_license!r} for"
            f" {host!r}",
        )
    permitted_uses = entry.get("permitted_uses")
    if permitted_uses is None:
        permitted_uses = ()
    if not isinstance(permitted_uses, (list, tuple, set, frozenset)):
        raise IntelFetchError(
            "LICENSE_REJECTED",
            f"LICENSE_REJECTED: registry entry for {host!r} carries"
            f" permitted_uses of type"
            f" {type(permitted_uses).__name__}; a permission grant must be"
            " a list, tuple, set or frozenset of use names, never a bare"
            " string or number",
        )
    if SYSTEM_USE not in permitted_uses:
        raise IntelFetchError(
            "LICENSE_REJECTED",
            f"LICENSE_REJECTED: registered license for {host!r} does not"
            f" permit {SYSTEM_USE!r} (permitted uses:"
            f" {sorted(str(use) for use in permitted_uses)})",
        )


# CR, LF and TAB are escaped in place so they stay visible in the text as
# two-character sequences instead of control bytes.
_ESCAPED_CHARACTERS: dict[str, str] = {
    "\r": "\\r",
    "\n": "\\n",
    "\t": "\\t",
}
# Every other C0 control (0x00-0x1F), DEL (0x7F) and the C1 range
# (0x80-0x9F), plus the bidi overrides and isolates (U+202A-U+202E,
# U+2066-U+2069) and the zero-width characters (U+200B-U+200F,
# U+2060-U+2064) that could reorder displayed text or silently split a word
# a log search looks for: all deleted on the way through ``as_data``.
_DELETED_CODE_POINTS = frozenset(
    code
    for low, high in (
        (0x00, 0x1F),
        (0x7F, 0x9F),
        (0x200B, 0x200F),
        (0x202A, 0x202E),
        (0x2060, 0x2064),
        (0x2066, 0x2069),
    )
    for code in range(low, high + 1)
)


def as_data(text: str) -> str:
    """Mark external ``text`` as inert data for the log, report and terminal channels.

    That is the extent of what this can be held to: the text stays inert
    *there*. CR, LF and TAB are escaped inline and every other control
    character is deleted, so a payload cannot break out into a line of its
    own in a log, drive a terminal through an escape sequence, or hide a
    spoof behind bidi and zero-width characters, while its facts survive
    verbatim behind the marker. It does not make an instruction unreadable
    to a model -- the directive itself travels through verbatim -- so
    nothing here claims that; the guarantee against it belongs to the
    downstream egress allowlist and output validation.
    """
    pieces: list[str] = []
    for char in text:
        escaped = _ESCAPED_CHARACTERS.get(char)
        if escaped is not None:
            pieces.append(escaped)
        elif ord(char) not in _DELETED_CODE_POINTS:
            pieces.append(char)
    return DATA_CHANNEL_MARKER + "".join(pieces)
