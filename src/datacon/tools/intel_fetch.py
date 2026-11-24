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
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import ipaddress
import time
from types import MappingProxyType
from typing import Any, Callable, Iterator, Mapping, Protocol, Sequence
from urllib.parse import urljoin, urlsplit
import zlib

from datacon.tools.safe_http import (
    GuardedConnection,
    GuardedResponse,
    Resolver,
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

    Chunks are counted as they arrive; an over-limit body raises before the
    next chunk is pulled, so the stream is cut mid-flight and never fully
    buffered. Only ``identity`` and ``gzip`` encodings are accepted; anything
    else fails closed.
    """
    encoding = (hop.headers.get("content-encoding") or "").strip().lower()
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
            parts.append(chunk)
        return b"".join(parts)
    if encoding != "gzip":
        raise IntelFetchError(
            "CONTENT_ENCODING_REJECTED",
            f"unsupported content-encoding {encoding!r}: only identity and"
            " gzip are accepted for intel sources",
        )
    decompressor = zlib.decompressobj(16 + zlib.MAX_WBITS)
    decompressed_bytes = 0
    for chunk in hop.body_stream():
        wire_bytes += len(chunk)
        if wire_bytes > MAX_WIRE_BYTES:
            raise IntelFetchError(
                "SIZE_LIMIT_EXCEEDED",
                f"SIZE_LIMIT_EXCEEDED: wire body reached {wire_bytes} bytes,"
                f" above the {MAX_WIRE_BYTES} byte cap",
            )
        piece = decompressor.decompress(chunk)
        if not piece:
            continue
        parts.append(piece)
        decompressed_bytes += len(piece)
        _enforce_decompression_budget(wire_bytes, decompressed_bytes)
    tail = decompressor.flush()
    if tail:
        parts.append(tail)
        decompressed_bytes += len(tail)
        _enforce_decompression_budget(wire_bytes, decompressed_bytes)
    return b"".join(parts)


def fetch_intel(
    url: str, *, allowlist: Sequence[str], transport: Transport
) -> FetchResult:
    """Fetch ``url`` through ``transport`` under every T15 guard.

    The URL is validated before the first transport call, every redirect hop
    is revalidated before it is fetched, at most ``MAX_REDIRECT_HOPS``
    redirects are followed, declared per-hop ``elapsed_seconds`` accumulate
    against the total budget, and the body is streamed through the wire and
    decompression caps. Transport-raised connect/read timeouts propagate
    unchanged. A transport whose hops own a connection (``close`` attr) has
    every hop released exactly once: after its redirect is followed, after
    its body is consumed, or when a raised limit abandons it mid-flight.
    """
    validate_source(url, allowlist)
    visited: list[str] = []
    redirects_followed = 0
    elapsed_seconds = 0.0
    current = url
    while True:
        visited.append(current)
        hop = transport.fetch(
            current,
            connect_timeout=CONNECT_TIMEOUT_SECONDS,
            read_timeout=READ_TIMEOUT_SECONDS,
        )
        # Pure fake hops have no close(); connection-owning hops (e.g.
        # GuardedTransport's) are released here on every exit path.
        hop_close = getattr(hop, "close", None)
        try:
            elapsed_seconds += hop.elapsed_seconds
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
            return FetchResult(
                body=_read_body(hop), status=hop.status, hops=tuple(visited)
            )
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
    """

    def __init__(
        self,
        connection: GuardedConnection,
        response: GuardedResponse,
        elapsed_seconds: float,
    ) -> None:
        self._connection = connection
        self._response = response
        self._elapsed_seconds = elapsed_seconds
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
            self._connection.close()


class GuardedTransport:
    """``Transport`` adapter that runs every hop through ``safe_http``.

    Each ``fetch`` is one guarded hop: the URL's host is resolved through
    the injected ``resolver`` and validated against the shared rejection
    set, a fresh socket from the injected ``socket_factory`` is dialed
    directly with TLS SNI and the HTTP ``Host`` header pinned to the
    hostname, and the parsed response is wrapped into a ``Hop`` whose body
    streams wire chunk by wire chunk. ``elapsed_seconds`` is the difference
    of two ``clock`` calls taken around the hop, so an injected step clock
    measures pure fake time while the default ``time.monotonic`` measures
    real wall time.
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
        )


def _sha256_digest(payload: bytes) -> str:
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def build_snapshot(
    fetch_result: FetchResult, license_info: str | None
) -> Mapping[str, Any]:
    """Freeze a fetch into a read-only, content-addressed snapshot mapping.

    The snapshot records the original source URL, HTTP status, content
    digest, license identifier (kept ``None`` when unknown so the gap stays
    visible), redirect chain digest, fetch timestamp and tool version. The
    returned mapping is a ``MappingProxyType``: later writes cannot reshape
    the record; a new fetch produces a new snapshot.
    """
    chain = tuple(fetch_result.hops)
    if not chain:
        raise IntelFetchError(
            "INVALID_FETCH_RESULT",
            "cannot snapshot a fetch result without hops",
        )
    snapshot: dict[str, Any] = {
        "source_url": chain[0],
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
    registry, or a registered license that does not cover this system's use
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
    permitted_uses = entry.get("permitted_uses") or ()
    if SYSTEM_USE not in permitted_uses:
        raise IntelFetchError(
            "LICENSE_REJECTED",
            f"LICENSE_REJECTED: registered license for {host!r} does not"
            f" permit {SYSTEM_USE!r} (permitted uses:"
            f" {sorted(str(use) for use in permitted_uses)})",
        )


def as_data(text: str) -> str:
    """Mark external ``text`` as inert data for model, log and report channels.

    The wrapped payload no longer begins with any directive marker, so it
    cannot change routing, tool authorization or verdicts, while the original
    content survives verbatim inside the marker.
    """
    return DATA_CHANNEL_MARKER + text
