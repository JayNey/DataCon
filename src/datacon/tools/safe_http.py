"""Shared safe HTTPS connection layer (security design delta 2.4 / 3.2, D44).

Implements the fixed anti-rebinding pipeline that T15 (intel fetching) and
T14 (model endpoints) reuse so it exists exactly once: resolve the hostname
through the injected ``resolver`` -> validate every answer against the
shared IPv4/IPv6 rejection set -> open a TCP/TLS connection directly to a
validated IP with TLS SNI and the HTTP ``Host`` header pinned to the
original hostname (no cross-hop connection reuse) -> recheck
``getpeername()`` before any HTTP byte leaves. Environment proxies are
never consulted: ``connect()`` only ever receives the validated
``(ip, port)`` tuple, so ``http_proxy`` and friends cannot bypass the
address checks.

The module resolves no names and opens no sockets on its own: the resolver
and the socket factory are injected per call, which keeps every path
offline by default and contract-testable. It is deliberately not a general
HTTP client: only origin-form, bodyless requests are sent. A response head
(the status line, the header block and the blank line, all inclusive) is
buffered only up to ``MAX_RESPONSE_HEAD_BYTES``: a head that accumulates
past the cap is refused even when its blank line never arrives, so a
runaway head cannot be buffered until the peer closes. Header keys are
lowercased, ``Content-Length`` framing is validated strictly (a missing,
non-integer or self-contradictory field leaves the response unframed), and
the body is handed out as a chunk-by-chunk stream that yields exactly the
declared ``Content-Length`` bytes and reports an early close as
``CONTENT_TRUNCATED``, so callers can count wire bytes while they stream.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import ipaddress
from typing import Iterator, Mapping, Protocol
from urllib.parse import urlsplit

CONNECT_TIMEOUT_SECONDS = 10.0
READ_TIMEOUT_SECONDS = 30.0
HTTPS_PORT = 443
# A response head (status line, header block and blank line, all inclusive)
# may never accumulate past this many bytes, whether or not its blank line
# ever arrives: a larger head is refused as RESPONSE_HEAD_TOO_LARGE instead
# of being buffered until the peer closes.
MAX_RESPONSE_HEAD_BYTES = 64 * 1024
_RECV_CHUNK_BYTES = 65536

# Shared IPv4/IPv6 rejection set (security design delta 2.4 / 3.2): private,
# loopback, link-local (which includes the cloud metadata endpoints), CGNAT,
# multicast, reserved, unspecified and documentation ranges. This is the
# single authoritative copy: ``intel_fetch`` delegates every address
# judgement to ``is_rejected_address`` instead of keeping a twin table.
_IPv4_NETWORKS: tuple[ipaddress.IPv4Network, ...] = tuple(
    ipaddress.IPv4Network(network)
    for network in (
        "0.0.0.0/8",
        "10.0.0.0/8",
        "100.64.0.0/10",
        "127.0.0.0/8",
        "169.254.0.0/16",
        "172.16.0.0/12",
        "192.0.0.0/24",
        "192.0.2.0/24",
        "192.168.0.0/16",
        "198.18.0.0/15",
        "198.51.100.0/24",
        "203.0.113.0/24",
        "224.0.0.0/4",
        "240.0.0.0/4",
    )
)
_IPv6_NETWORKS: tuple[ipaddress.IPv6Network, ...] = tuple(
    ipaddress.IPv6Network(network)
    for network in (
        "::/128",
        "::1/128",
        "::ffff:0:0/96",
        "64:ff9b::/96",
        "fc00::/7",
        "fe80::/10",
        "ff00::/8",
    )
)


class SafeHttpError(ValueError):
    """A guarded HTTPS step failed closed.

    Covers every failure path of this module: a non-HTTPS or hostless URL,
    an address answer inside the shared rejection set (the message names
    the offending ``address``), an empty resolution, a connect/TLS failure,
    a ``getpeername()`` peer that is not a validated address (no HTTP bytes
    were sent), and an unparseable, oversized or unframed response head.

    ``reason`` carries a stable token so callers can attribute the failure
    without parsing the message: ``ADDRESS_DENIED`` (an answer inside the
    rejection set, or not a literal IP at all), ``RESPONSE_HEAD_TOO_LARGE``
    (the head accumulated past ``MAX_RESPONSE_HEAD_BYTES``),
    ``RESPONSE_UNFRAMED`` (no trustworthy single ``Content-Length``), and
    ``CONTENT_TRUNCATED`` (the wire closed before the declared body
    arrived). Every other failure keeps the ``FETCH_FAILED`` default.
    """

    def __init__(self, message: str, *, reason: str = "FETCH_FAILED") -> None:
        super().__init__(message)
        self.message = message
        self.reason = reason


class Resolver(Protocol):
    """Resolves one hostname to literal IP answer strings.

    The production adapter owns real DNS and its budgets; this module only
    consumes the answers, so tests inject a recording fake and no lookup
    ever happens here.
    """

    def __call__(self, host: str) -> list[str]: ...


class GuardedSocket(Protocol):
    """The socket face ``connect_guarded`` drives (frozen by contract tests).

    ``connect`` takes the ``(ip, port)`` tuple, ``wrap_tls`` is the TLS
    mount point (the pinned SNI rides on its keyword), ``getpeername``
    reports the connected peer for the pre-send recheck, and
    ``sendall``/``recv``/``close`` carry the HTTP byte flow.
    """

    def connect(self, address: tuple[str, int]) -> None: ...

    def wrap_tls(
        self, sni: str | None = None, **options: object
    ) -> GuardedSocket: ...

    def getpeername(self) -> tuple[str, int]: ...

    def sendall(self, data: bytes) -> None: ...

    def recv(self, size: int) -> bytes: ...

    def close(self) -> None: ...


class SocketFactory(Protocol):
    """Creates one fresh, unconnected socket per hop.

    Cross-hop connection reuse is disabled by design: every guarded
    connection dials again through the factory, so a redirect target never
    inherits a previous hop's socket or answers.
    """

    def __call__(self) -> GuardedSocket: ...


def _unwrap_literal(
    address: str | ipaddress.IPv4Address | ipaddress.IPv6Address,
) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    """Return ``address`` as a literal IP, IPv4-mapped IPv6 unwrapped first.

    ``::ffff:127.0.0.1`` is judged as ``127.0.0.1``, matching the
    anti-rebinding rules in the security design delta. Only syntactically
    literal inputs are handled here; no DNS resolution happens.
    """
    parsed = ipaddress.ip_address(address) if isinstance(address, str) else address
    if isinstance(parsed, ipaddress.IPv6Address) and parsed.ipv4_mapped is not None:
        return parsed.ipv4_mapped
    return parsed


def is_rejected_address(
    address: str | ipaddress.IPv4Address | ipaddress.IPv6Address,
) -> bool:
    """Whether ``address`` falls into the shared IPv4/IPv6 rejection set.

    IPv4-mapped IPv6 addresses are unwrapped before judgement. A string
    that is not a literal IP address is rejected as well: the predicate is
    only ever asked about validated literal answers, so anything
    unparseable fails closed.
    """
    try:
        parsed = _unwrap_literal(address)
    except ValueError:
        return True
    networks: (
        tuple[ipaddress.IPv4Network, ...] | tuple[ipaddress.IPv6Network, ...]
    )
    if isinstance(parsed, ipaddress.IPv4Address):
        networks = _IPv4_NETWORKS
    else:
        networks = _IPv6_NETWORKS
    if any(parsed in network for network in networks):
        return True
    return bool(
        parsed.is_private
        or parsed.is_reserved
        or parsed.is_multicast
        or parsed.is_loopback
        or parsed.is_link_local
        or parsed.is_unspecified
    )


def resolve_validated(host: str, *, resolver: Resolver) -> list[str]:
    """Resolve ``host`` through ``resolver`` and validate every answer.

    Returns the validated answers as canonical IP strings in answer order.
    Fail-closed on any poison: an empty answer list, an answer that is not
    a literal IP address, or a single answer inside the shared rejection
    set raises ``SafeHttpError`` with the offending ``address`` named in
    the message, because one poisoned answer poisons the whole set and no
    socket may be opened against an unvalidated resolution.
    """
    answers = resolver(host)
    if not answers:
        raise SafeHttpError(
            f"address resolution for {host!r} returned no answers; failing"
            " closed instead of connecting anyway"
        )
    validated: list[str] = []
    for answer in answers:
        try:
            parsed = _unwrap_literal(answer)
        except ValueError:
            raise SafeHttpError(
                f"address answer {answer!r} for {host!r} is not a literal IP"
                " address",
                reason="ADDRESS_DENIED",
            ) from None
        if is_rejected_address(parsed):
            raise SafeHttpError(
                f"address answer {answer!r} for {host!r} falls into the"
                " shared rejection set (private, loopback, link-local,"
                " CGNAT, multicast, reserved, unspecified or cloud metadata)",
                reason="ADDRESS_DENIED",
            )
        validated.append(str(parsed))
    return validated


@dataclass(frozen=True)
class GuardedResponse:
    """One parsed response head plus its chunk-by-chunk body stream.

    ``content_length`` is the validated single integer ``Content-Length``
    value, or ``None`` when the head carried no ``Content-Length`` at all:
    nothing frames such a body, so ``body_chunks`` yields no bytes either.
    ``headers`` maps lowercased header names to their values (the canonical
    lookup form: wire ``Content-Encoding`` is stored as ``content-encoding``).
    ``body_chunks`` yields exactly the declared body bytes as the wire
    delivered them and raises ``CONTENT_TRUNCATED`` on an early close, so a
    caller can count wire bytes while streaming. The non-status fields stay
    out of equality: two responses compare by their status line alone,
    exactly as before.
    """

    status: int
    reason: str = ""
    content_length: int | None = None
    headers: Mapping[str, str] = field(
        default_factory=dict, compare=False, repr=False
    )
    body_chunks: Iterator[bytes] = field(
        default_factory=lambda: iter(()), compare=False, repr=False
    )


def _iter_body_chunks(
    socket: GuardedSocket, buffered: bytes, content_length: int | None
) -> Iterator[bytes]:
    """Yield exactly ``content_length`` body bytes, wire chunk by wire chunk.

    ``content_length is None`` means no ``Content-Length`` framed the
    response, so not one body byte is handed out -- not even bytes that
    already arrived together with the head. With a declared length, bytes
    that rode along with the head are served first, then one piece per
    ``recv`` return; an early orderly close (an empty ``recv``) with
    declared bytes still undelivered raises ``CONTENT_TRUNCATED`` instead
    of silently ending the stream short.
    """
    if content_length is None:
        return
    remaining = content_length
    if buffered and remaining:
        piece = buffered[:remaining]
        remaining -= len(piece)
        yield piece
    while remaining:
        chunk = socket.recv(_RECV_CHUNK_BYTES)
        if not chunk:
            raise SafeHttpError(
                f"connection closed with {remaining} of {content_length}"
                " declared body bytes undelivered",
                reason="CONTENT_TRUNCATED",
            )
        piece = chunk[:remaining]
        remaining -= len(piece)
        yield piece


class GuardedConnection:
    """One validated, hostname-pinned TLS connection for a single hop.

    The connection remembers the original hostname (TLS SNI and the HTTP
    ``Host`` header stay pinned to it, never the IP) and the set of
    addresses that passed validation. Every ``send_request`` rechecks
    ``getpeername()`` against that set before a single HTTP byte leaves,
    so a DNS rebind between connect and send aborts with zero bytes on the
    wire. Instances are never reused across hops.
    """

    def __init__(
        self,
        socket: GuardedSocket,
        hostname: str,
        validated_addresses: frozenset[str],
        port: int,
        connect_timeout: float,
        read_timeout: float,
    ) -> None:
        self._socket = socket
        self._hostname = hostname
        self._validated_addresses = validated_addresses
        self._port = port
        # Timeouts are carried for the transport adapter that owns the real
        # socket; the injected fakes have no clocks to apply them to.
        self._connect_timeout = connect_timeout
        self._read_timeout = read_timeout

    @property
    def hostname(self) -> str:
        """The pinned hostname: TLS SNI and HTTP Host never leave it."""
        return self._hostname

    @property
    def validated_addresses(self) -> frozenset[str]:
        """The address set a rechecked peer must belong to."""
        return self._validated_addresses

    def _recheck_peer(self) -> None:
        """TOCTOU recheck: abort before any HTTP byte if the peer drifted.

        The peer address must be one of the validated answers for this
        hop; a globally routable but never-validated peer is refused too,
        so answer-set drift cannot ride a public address.
        """
        try:
            peer = self._socket.getpeername()
        except OSError as error:
            raise SafeHttpError(
                f"getpeername() recheck on {self._hostname!r} failed: {error}"
            ) from error
        peer_address = peer[0]
        if peer_address not in self._validated_addresses:
            raise SafeHttpError(
                f"getpeername() recheck: peer {peer_address!r} is none of the"
                f" validated addresses {sorted(self._validated_addresses)}"
                f" for {self._hostname!r}; no HTTP bytes were sent"
            )

    @staticmethod
    def _reject_line_injection(text: str) -> None:
        if "\r" in text or "\n" in text:
            raise SafeHttpError(
                f"refusing to send CR/LF inside request metadata: {text!r}"
            )

    def send_request(
        self,
        method: str,
        path: str,
        headers: Mapping[str, str],
        body: bytes | None = None,
    ) -> None:
        """Send one origin-form request, bodyless or with exact bytes.

        The peer is rechecked first (a mismatch aborts with zero bytes
        sent), any caller-supplied ``Host`` header is dropped and replaced
        by the original hostname, and CR/LF inside the method, path or a
        header line is rejected so no string can inject extra headers or a
        second request. With a ``body``, the caller's ``Content-Length``
        is dropped too and replaced by the exact byte count, and the body
        leaves as its own write after the head so the wire carries
        byte-for-byte what was handed in - the canonical-JSON basis the
        outlet's ``request_digest`` is taken over.
        """
        self._recheck_peer()
        self._reject_line_injection(method)
        self._reject_line_injection(path)
        host_value = (
            self._hostname
            if self._port == HTTPS_PORT
            else f"{self._hostname}:{self._port}"
        )
        lines = [f"{method} {path} HTTP/1.1", f"Host: {host_value}"]
        for name, value in headers.items():
            if name.lower() == "host":
                # A forged Host header must not survive the pinning.
                continue
            if body is not None and name.lower() == "content-length":
                # The length is computed from the body, never trusted.
                continue
            self._reject_line_injection(name)
            self._reject_line_injection(value)
            lines.append(f"{name}: {value}")
        if body is not None:
            lines.append(f"Content-Length: {len(body)}")
        self._socket.sendall(("\r\n".join(lines) + "\r\n\r\n").encode("utf-8"))
        if body is not None:
            self._socket.sendall(body)

    @staticmethod
    def _parse_header_lines(raw_lines: list[bytes]) -> dict[str, str]:
        """Parse header lines into a lowercased-name dict; malformed fail."""
        headers: dict[str, str] = {}
        for raw_line in raw_lines:
            if not raw_line:
                continue
            try:
                line = raw_line.decode("ascii")
            except UnicodeDecodeError as error:
                raise SafeHttpError(
                    "header line from the connection is not ASCII:"
                    f" {raw_line!r}"
                ) from error
            name, separator, value = line.partition(":")
            if not separator or not name.strip():
                raise SafeHttpError(f"unparseable header line: {line!r}")
            headers[name.strip().lower()] = value.strip()
        return headers

    @staticmethod
    def _parse_content_length(
        hostname: str, raw_lines: list[bytes]
    ) -> int | None:
        """Resolve the response's ``Content-Length`` to one integer or None.

        Every ``Content-Length`` field is examined, however its name is
        cased, and comma-joined values are split into their tokens: the
        response is only framed when all of them agree on one ASCII
        decimal integer (consistent repetitions are accepted). Conflicting
        values leave the response unframed; a value that is not one
        decimal integer fails the same way, and no field at all means
        ``None`` -- nothing frames the body.
        """
        tokens: list[str] = []
        for raw_line in raw_lines:
            if not raw_line:
                continue
            line = raw_line.decode("ascii")
            name, separator, value = line.partition(":")
            if not separator or name.strip().lower() != "content-length":
                continue
            tokens.extend(token.strip() for token in value.split(","))
        if not tokens:
            return None
        declared: set[int] = set()
        for token in tokens:
            if not token or not token.isascii() or not token.isdigit():
                raise SafeHttpError(
                    f"content-length {token!r} from {hostname!r} is not a"
                    " decimal integer",
                    reason="RESPONSE_UNFRAMED",
                )
            declared.add(int(token))
        if len(declared) > 1:
            raise SafeHttpError(
                f"conflicting content-length fields {sorted(declared)!r}"
                f" from {hostname!r}: there is no single declared length",
                reason="RESPONSE_UNFRAMED",
            )
        return declared.pop()

    def read_response(self) -> GuardedResponse:
        """Read and parse one complete response head; the body streams after.

        The head (status line, header block and blank line, all inclusive)
        is buffered only up to ``MAX_RESPONSE_HEAD_BYTES``: a head that
        accumulates past the cap is refused with ``RESPONSE_HEAD_TOO_LARGE``
        even while its blank line has not arrived yet. Once the blank line
        lands, the status line and the header block (header keys
        lowercased) are parsed here. The returned response's
        ``content_length`` is the validated single integer length or
        ``None`` when the head carried none, and its ``body_chunks`` stream
        yields exactly the declared body bytes, one piece per ``recv``
        return, so the caller's wire counting sees the wire's own chunking.
        """
        buffer = bytearray()
        while b"\r\n\r\n" not in buffer:
            if len(buffer) > MAX_RESPONSE_HEAD_BYTES:
                raise SafeHttpError(
                    f"response head from {self._hostname!r} accumulated"
                    f" {len(buffer)} bytes without reaching its blank line,"
                    f" above the {MAX_RESPONSE_HEAD_BYTES} byte cap",
                    reason="RESPONSE_HEAD_TOO_LARGE",
                )
            chunk = self._socket.recv(_RECV_CHUNK_BYTES)
            if not chunk:
                break
            buffer += chunk
        head, separator, rest = bytes(buffer).partition(b"\r\n\r\n")
        if not separator:
            raise SafeHttpError(
                f"connection to {self._hostname!r} closed before the"
                " response head (status line, headers and blank line)"
                " arrived"
            )
        if len(head) + 4 > MAX_RESPONSE_HEAD_BYTES:
            raise SafeHttpError(
                f"response head from {self._hostname!r} is"
                f" {len(head) + 4} bytes (status line through blank line),"
                f" above the {MAX_RESPONSE_HEAD_BYTES} byte cap",
                reason="RESPONSE_HEAD_TOO_LARGE",
            )
        lines = head.split(b"\r\n")
        status_line = lines[0]
        if not status_line:
            raise SafeHttpError(
                f"connection to {self._hostname!r} closed before a status"
                " line arrived"
            )
        try:
            text = status_line.decode("ascii")
        except UnicodeDecodeError as error:
            raise SafeHttpError(
                f"status line from {self._hostname!r} is not ASCII:"
                f" {status_line!r}"
            ) from error
        parts = text.split(" ", 2)
        if len(parts) < 2 or not parts[0].startswith("HTTP/"):
            raise SafeHttpError(
                f"unparseable status line from {self._hostname!r}: {text!r}"
            )
        try:
            status = int(parts[1])
        except ValueError as error:
            raise SafeHttpError(
                f"status code in {text!r} from {self._hostname!r} is not an"
                " integer"
            ) from error
        headers = self._parse_header_lines(lines[1:])
        transfer_encoding = headers.get("transfer-encoding")
        if transfer_encoding is not None:
            raise SafeHttpError(
                f"transfer-encoding {transfer_encoding!r} from"
                f" {self._hostname!r} is not supported: only Content-Length"
                " framing is accepted for guarded responses",
                reason="RESPONSE_UNFRAMED",
            )
        content_length = self._parse_content_length(self._hostname, lines[1:])
        return GuardedResponse(
            status=status,
            reason=parts[2] if len(parts) > 2 else "",
            content_length=content_length,
            headers=headers,
            body_chunks=_iter_body_chunks(self._socket, rest, content_length),
        )

    def close(self) -> None:
        """Close the underlying socket; the connection is never reused."""
        self._socket.close()


def connect_guarded(
    url: str,
    *,
    resolver: Resolver,
    socket_factory: SocketFactory,
    connect_timeout: float = CONNECT_TIMEOUT_SECONDS,
    read_timeout: float = READ_TIMEOUT_SECONDS,
) -> GuardedConnection:
    """Open one guarded HTTPS connection to ``url``'s validated IP.

    Fail-closed order, frozen by the contract tests: the URL must be HTTPS
    with a host; every answer from ``resolver`` is validated before any
    socket object exists (a rejected answer aborts with an ``address``
    error and leaves the factory untouched); the first validated address is
    then dialed directly as ``(ip, port)`` — environment proxies are never
    consulted — and TLS is mounted with SNI pinned to the original
    hostname. The returned ``GuardedConnection`` rechecks ``getpeername()``
    before its first byte leaves. Each call resolves and dials again: no
    cross-hop connection reuse.
    """
    parts = urlsplit(url)
    if parts.scheme != "https":
        raise SafeHttpError(
            f"guarded connections are https-only, not"
            f" {parts.scheme or 'scheme-less'!r}: {url!r}"
        )
    hostname = parts.hostname
    if not hostname:
        raise SafeHttpError(f"URL has no host to validate: {url!r}")
    try:
        port = parts.port
    except ValueError as error:
        raise SafeHttpError(f"URL has no valid port: {url!r}") from error
    if port is None:
        port = HTTPS_PORT
    validated = resolve_validated(hostname, resolver=resolver)
    address = validated[0]
    raw_socket = socket_factory()
    try:
        raw_socket.connect((address, port))
        tls_socket = raw_socket.wrap_tls(sni=hostname)
    except OSError as error:
        raw_socket.close()
        raise SafeHttpError(
            f"guarded connection to {hostname!r} via {address} failed:"
            f" {error}"
        ) from error
    return GuardedConnection(
        socket=tls_socket,
        hostname=hostname,
        validated_addresses=frozenset(validated),
        port=port,
        connect_timeout=connect_timeout,
        read_timeout=read_timeout,
    )
