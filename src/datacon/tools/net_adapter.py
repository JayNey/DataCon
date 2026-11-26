"""Production transport adapter: real DNS, budgeted sockets, outlet POST.

``safe_http`` froze the guarded-connection pipeline around two injected
faces - the ``Resolver`` and the ``SocketFactory`` - and ``model_outlet``
froze the ``OutletTransport`` face. This module owns their production
halves (security design delta 2.4 / 3.2 / 3.4):

- ``ProductionResolver`` does the real DNS lookup inside its own budget
  and fails closed when the budget expires or the name does not resolve.
- ``ProductionSocketFactory`` hands out real sockets whose connect/read
  timeouts are pinned at construction (the fetch loop's per-call budgets
  carry the same configuration in production wiring), and whose TLS mount
  requires an SNI and wraps with a context derived from
  ``ssl.create_default_context()`` - the system trust chain, with no code
  path that could disable the verification.
- ``OutletHttpTransport`` posts one model request per call: the body is
  the canonical-JSON bytes the outlet's ``request_digest`` is taken over,
  redirects are refused (the endpoint is exact-match whitelisted upstream,
  so a 3xx is endpoint drift, not something to follow), and the response
  must be framed, within budget, and strictly a JSON object.

Nothing here is wired into a caller yet: the adapter is the seam the
workflow/execution integration will consume.
"""

from __future__ import annotations

import socket
import ssl
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as FutureTimeoutError
from typing import Callable
from urllib.parse import urlsplit

from datacon import jsonutil
from datacon.tools.intel_fetch import (
    CONNECT_TIMEOUT_SECONDS,
    READ_TIMEOUT_SECONDS,
    GuardedTransport,
)
from datacon.tools.safe_http import (
    GuardedSocket,
    Resolver,
    SafeHttpError,
    SocketFactory,
    connect_guarded,
)

__all__ = [
    "DNS_TIMEOUT_SECONDS",
    "MODEL_RESPONSE_MAX_BYTES",
    "OUTLET_USER_AGENT",
    "OutletHttpTransport",
    "ProductionResolver",
    "ProductionSocketFactory",
    "default_tls_context",
    "production_guarded_transport",
]

# The DNS budget belongs to this adapter (safe_http only consumes answers).
DNS_TIMEOUT_SECONDS = 5.0

# The model response ceiling borrows the intel path's decompressed-body
# total (security design delta 3.6): one analysis answer never deserves
# more room than one fetched advisory.
MODEL_RESPONSE_MAX_BYTES = 32 * 1024 * 1024

OUTLET_USER_AGENT = "datacon.model_outlet/0.1.0"


def default_tls_context() -> ssl.SSLContext:
    """The only context the production adapter ever wraps TLS with.

    ``ssl.create_default_context()`` verifies against the system trust
    chain with ``check_hostname`` on; there is deliberately no parameter
    to loosen either, and ``CertVerificationError``/handshake failures
    propagate to the caller as guarded-connection failures.
    """
    return ssl.create_default_context()


def _getaddrinfo_answers(host: str) -> list[str]:
    """Real DNS answers as literal IP strings, duplicates removed."""
    seen: list[str] = []
    for info in socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP):
        answer = info[4][0]
        if isinstance(answer, str) and answer not in seen:
            seen.append(answer)
    return seen


class ProductionResolver:
    """Real DNS inside a budget; both failure modes fail closed.

    The blocking ``getaddrinfo`` cannot be timed out in place, so it runs
    on a throwaway worker thread whose future is bounded by ``timeout``.
    A budget expiry raises ``SafeHttpError(reason="DNS_TIMEOUT")`` and an
    unresolvable name raises ``SafeHttpError(reason="DNS_FAILED")``; both
    abort the fetch before any socket exists, exactly like a rejected
    address answer would.
    """

    def __init__(
        self,
        *,
        timeout: float = DNS_TIMEOUT_SECONDS,
        lookup: Callable[[str], list[str]] | None = None,
    ) -> None:
        self.timeout = timeout
        self._lookup = lookup if lookup is not None else _getaddrinfo_answers

    def __call__(self, host: str) -> list[str]:
        # The blocking getaddrinfo cannot be interrupted, so a budget
        # expiry abandons the worker instead of joining it: shutdown
        # without waiting lets the caller fail closed immediately while
        # the stray worker finishes its lookup and exits on its own.
        executor = ThreadPoolExecutor(max_workers=1)
        future = executor.submit(self._lookup, host)
        try:
            answered = future.result(timeout=self.timeout)
        except FutureTimeoutError as error:
            raise SafeHttpError(
                f"DNS lookup for {host!r} exceeded its"
                f" {self.timeout}s budget",
                reason="DNS_TIMEOUT",
            ) from error
        except socket.gaierror as error:
            raise SafeHttpError(
                f"DNS lookup for {host!r} failed: {error}",
                reason="DNS_FAILED",
            ) from error
        finally:
            executor.shutdown(wait=False)
        answers: list[str] = []
        for answer in answered:
            if answer not in answers:
                answers.append(answer)
        return answers


class _RealGuardedSocket:
    """A real socket in the ``GuardedSocket`` shape the pipeline drives.

    The underlying OS socket is created lazily at ``connect`` time, with
    the address family taken from the validated literal IP, and the
    connect budget applied before dialing. ``wrap_tls`` mounts TLS through
    the injected context factory with the SNI mandatory - there is no
    call shape that disables certificate verification - and pins the read
    budget on the TLS socket it returns.
    """

    def __init__(
        self,
        *,
        connect_timeout: float,
        read_timeout: float,
        context_factory: Callable[[], ssl.SSLContext],
        wrapped: socket.socket | None = None,
    ) -> None:
        self._connect_timeout = connect_timeout
        self._read_timeout = read_timeout
        self._context_factory = context_factory
        self._socket = wrapped
        self.timeouts: list[float] = []

    def connect(self, address: tuple[str, int]) -> None:
        if self._socket is not None:
            raise SafeHttpError("guarded socket connects exactly once")
        ip, port = address
        family = socket.AF_INET6 if ":" in ip else socket.AF_INET
        raw = socket.socket(family, socket.SOCK_STREAM)
        self._socket = raw
        # The recorded settimeout is the budget the OS dial runs under;
        # a socket timeout is exactly what bounds connect().
        self.settimeout(self._connect_timeout)
        raw.connect((ip, port))

    def settimeout(self, value: float) -> None:
        """Apply one timeout to the underlying socket; recorded for tests."""
        self.timeouts.append(value)
        if self._socket is not None:
            self._socket.settimeout(value)

    def wrap_tls(
        self, sni: str | None = None, **options: object
    ) -> GuardedSocket:
        if not isinstance(sni, str) or not sni:
            raise SafeHttpError(
                "the production TLS mount requires the pinned SNI hostname"
            )
        if self._socket is None:
            # Unreachable through the guarded pipeline (connect always
            # precedes the mount); real misuse fails at the ssl layer.
            raise SafeHttpError("TLS mounts only on a connected socket")
        context = self._context_factory()
        tls = _RealGuardedSocket(
            connect_timeout=self._connect_timeout,
            read_timeout=self._read_timeout,
            context_factory=self._context_factory,
            wrapped=context.wrap_socket(self._socket, server_hostname=sni),
        )
        tls.settimeout(self._read_timeout)
        return tls

    def getpeername(self) -> tuple[str, int]:
        assert self._socket is not None
        return self._socket.getpeername()

    def sendall(self, data: bytes) -> None:
        assert self._socket is not None
        self._socket.sendall(data)

    def recv(self, size: int) -> bytes:
        assert self._socket is not None
        return self._socket.recv(size)

    def close(self) -> None:
        if self._socket is not None:
            self._socket.close()


class ProductionSocketFactory:
    """Creates one fresh, unconnected real socket per hop.

    The budgets are pinned here because the ``SocketFactory`` face has no
    per-call arguments: production wiring builds the factory from the same
    constants the fetch loop passes per call, so the socket the OS dials
    with and the budget the loop asked for cannot diverge (pinned by a
    contract test). Timeouts on a wrapped TLS socket are the read budget;
    the connect budget covers dialing and the TLS handshake.
    """

    def __init__(
        self,
        connect_timeout: float = CONNECT_TIMEOUT_SECONDS,
        read_timeout: float = READ_TIMEOUT_SECONDS,
        context_factory: Callable[[], ssl.SSLContext] = default_tls_context,
    ) -> None:
        self.connect_timeout = connect_timeout
        self.read_timeout = read_timeout
        self._context_factory = context_factory

    def __call__(self) -> GuardedSocket:
        return _RealGuardedSocket(
            connect_timeout=self.connect_timeout,
            read_timeout=self.read_timeout,
            context_factory=self._context_factory,
        )


def production_guarded_transport() -> GuardedTransport:
    """The intel fetch transport wired with the production faces."""
    return GuardedTransport(
        resolver=ProductionResolver(),
        socket_factory=ProductionSocketFactory(
            CONNECT_TIMEOUT_SECONDS, READ_TIMEOUT_SECONDS
        ),
    )


class OutletHttpTransport:
    """``OutletTransport`` face over one guarded connection per request.

    ``request`` posts the canonical-JSON encoding of ``body`` to the
    endpoint's origin-form path and returns the strictly parsed JSON
    object answer. Redirects are refused outright - the outlet validated
    an exact-match HTTPS endpoint upstream, so a 3xx is drift, never a
    hop to follow - and an unframed, oversized, truncated or non-object
    answer fails closed with a stable ``SafeHttpError`` reason.
    """

    def __init__(
        self,
        *,
        resolver: Resolver,
        socket_factory: SocketFactory,
        max_response_bytes: int = MODEL_RESPONSE_MAX_BYTES,
    ) -> None:
        self._resolver = resolver
        self._socket_factory = socket_factory
        self._max_response_bytes = max_response_bytes

    def request(self, endpoint: str, body: object) -> object:
        payload = jsonutil.canonical_bytes(body)
        connection = connect_guarded(
            endpoint,
            resolver=self._resolver,
            socket_factory=self._socket_factory,
        )
        parts = urlsplit(endpoint)
        path = parts.path or "/"
        if parts.query:
            path = f"{path}?{parts.query}"
        try:
            connection.send_request(
                "POST",
                path,
                {
                    "Content-Type": "application/json",
                    "Accept": "application/json",
                    "User-Agent": OUTLET_USER_AGENT,
                },
                body=payload,
            )
            response = connection.read_response()
            status = response.status
            if 300 <= status < 400:
                raise SafeHttpError(
                    f"model endpoint answered {status}; the outlet follows no"
                    " redirects because its endpoint is exact-match"
                    " whitelisted",
                    reason="OUTLET_REDIRECTED",
                )
            if not 200 <= status < 300:
                raise SafeHttpError(
                    f"model endpoint answered {status}",
                    reason="OUTLET_HTTP_STATUS",
                )
            length = response.content_length
            if length is None:
                raise SafeHttpError(
                    "model endpoint response carried no single"
                    " Content-Length; nothing frames the body, so not one"
                    " body byte is trusted",
                    reason="RESPONSE_UNFRAMED",
                )
            if length > self._max_response_bytes:
                raise SafeHttpError(
                    f"model endpoint response declares {length} bytes,"
                    f" over the {self._max_response_bytes}-byte ceiling",
                    reason="OUTLET_RESPONSE_TOO_LARGE",
                )
            received = bytearray()
            for chunk in response.body_chunks:
                received += chunk
        finally:
            connection.close()
        try:
            document = jsonutil.loads_strict(bytes(received))
        except ValueError as error:
            raise SafeHttpError(
                f"model endpoint response is not strict JSON: {error}",
                reason="OUTLET_BAD_JSON",
            ) from error
        if not isinstance(document, dict):
            raise SafeHttpError(
                "model endpoint response must be a JSON object",
                reason="OUTLET_BAD_JSON",
            )
        return document
