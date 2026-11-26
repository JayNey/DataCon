"""Production transport adapter: real DNS, budgeted sockets, outlet POST.

RED-phase contract tests for ``datacon.tools.net_adapter``, the production
half of the transport split frozen in ``safe_http`` and ``model_outlet``:
the guarded connection layer consumes injected ``Resolver`` and
``SocketFactory`` faces, so this module owns the real counterparts - a
DNS resolver with its own budget that fails closed, a socket factory that
pins the connect/read timeouts and mounts TLS with the SNI required and
the system trust chain never disabled (security design delta 2.4 / 3.2 /
3.4) - plus the ``OutletTransport`` face that posts one canonical-JSON
model request per call and never follows redirects.

The resolver's lookup and the TLS context stay injectable, and the socket
tests that need real timeout semantics drive a local stalling TCP server;
nothing here resolves production DNS or dials a third-party host.
"""

from __future__ import annotations

import socket as socket_module
import ssl
import threading
import time

import pytest

HOST = "advisory.example.com"
PUBLIC_V4 = "93.184.216.34"
PUBLIC_V6 = "2606:2800:220:1:248:1893:25c8:1946"


class FakeResolver:
    """Injected resolver double: serves ``answers[host]`` and records."""

    def __init__(self, answers):
        self._answers = dict(answers)
        self.calls = []

    def __call__(self, host):
        self.calls.append(host)
        return list(self._answers[host])


class FakeSocket:
    """Recording socket double in the ``GuardedSocket`` protocol shape."""

    def __init__(self, inbox=()):
        self.connect_calls = []
        self.sni = None
        self.sent = []
        self.closed = False
        self.recv_count = 0
        self._inbox = list(inbox)

    def connect(self, address):
        self.connect_calls.append(tuple(address))

    def wrap_tls(self, sni=None, **options):
        self.sni = sni
        return self

    def getpeername(self):
        if not self.connect_calls:
            raise AssertionError("getpeername() before connect()")
        return self.connect_calls[-1]

    def sendall(self, data):
        self.sent.append(bytes(data))

    def recv(self, size):
        self.recv_count += 1
        return self._inbox.pop(0) if self._inbox else b""

    def close(self):
        self.closed = True


class FakeSocketFactory:
    def __init__(self, inbox=()):
        self._inbox = list(inbox)
        self.sockets = []

    def __call__(self):
        sock = FakeSocket(self._inbox)
        self.sockets.append(sock)
        return sock


class RecordingContext:
    """TLS context double: records the wrap and hands the socket back.

    The production socket face carries its own ``settimeout`` (it records
    the applied budgets), so handing the same object back is enough: the
    SNI pin is asserted from the recorded wrap call and the read timeout
    from the socket's own ``timeouts`` ledger.
    """

    def __init__(self):
        self.wrap_calls = []

    def wrap_socket(self, sock, server_hostname=None):
        self.wrap_calls.append((sock, server_hostname))
        return sock


def _response(status_line, headers, body: bytes) -> list[bytes]:
    head = (status_line + "\r\n").encode("ascii")
    for name, value in headers:
        head += f"{name}: {value}\r\n".encode("ascii")
    # One wire chunk carrying head, blank line and the whole declared body.
    return [head + b"\r\n" + body]


# --- production resolver -------------------------------------------------


def test_production_resolver_dedups_answers_preserving_order():
    from datacon.tools.net_adapter import ProductionResolver

    seen = []

    def lookup(host):
        seen.append(host)
        return [PUBLIC_V4, PUBLIC_V6, PUBLIC_V4]

    resolver = ProductionResolver(lookup=lookup)
    assert resolver(HOST) == [PUBLIC_V4, PUBLIC_V6]
    assert seen == [HOST]


def test_production_resolver_fails_closed_when_the_dns_budget_expires():
    from datacon.tools.net_adapter import ProductionResolver
    from datacon.tools.safe_http import SafeHttpError

    def slow_lookup(host):
        time.sleep(1.0)
        return [PUBLIC_V4]

    resolver = ProductionResolver(lookup=slow_lookup, timeout=0.2)
    started = time.monotonic()
    with pytest.raises(SafeHttpError) as excinfo:
        resolver(HOST)
    elapsed = time.monotonic() - started
    assert excinfo.value.reason == "DNS_TIMEOUT"
    # The budget, not the lookup, ends the wait.
    assert elapsed < 0.9


def test_production_resolver_reports_unresolvable_hosts_fail_closed():
    from datacon.tools.net_adapter import ProductionResolver
    from datacon.tools.safe_http import SafeHttpError

    def failing_lookup(host):
        raise socket_module.gaierror(-2, "Name or service not known")

    resolver = ProductionResolver(lookup=failing_lookup)
    with pytest.raises(SafeHttpError) as excinfo:
        resolver(HOST)
    assert excinfo.value.reason == "DNS_FAILED"


# --- production socket factory -------------------------------------------


def test_default_tls_context_never_disables_verification():
    from datacon.tools.net_adapter import default_tls_context

    context = default_tls_context()
    assert context.check_hostname is True
    assert context.verify_mode == ssl.CERT_REQUIRED


def test_production_socket_pins_sni_and_applies_the_read_timeout():
    import socket as socket_module

    from datacon.tools.net_adapter import ProductionSocketFactory

    server = socket_module.socket(socket_module.AF_INET)
    server.bind(("127.0.0.1", 0))
    server.listen(1)
    port = server.getsockname()[1]
    try:
        context = RecordingContext()
        factory = ProductionSocketFactory(
            connect_timeout=1.0, read_timeout=7.5,
            context_factory=lambda: context,
        )
        raw = factory()
        raw.connect(("127.0.0.1", port))
        tls = raw.wrap_tls(sni=HOST)

        # The pin that matters is the SNI hostname; the wrapped object is
        # the raw OS socket, an internal detail of the face.
        assert [call[1] for call in context.wrap_calls] == [HOST]
        assert tls.timeouts == [7.5]
    finally:
        server.close()


def test_production_socket_refuses_to_mount_tls_without_sni():
    from datacon.tools.net_adapter import ProductionSocketFactory
    from datacon.tools.safe_http import SafeHttpError

    factory = ProductionSocketFactory(context_factory=RecordingContext)
    with pytest.raises(SafeHttpError):
        factory().wrap_tls(sni=None)


def test_production_socket_applies_the_connect_budget_before_dialing():
    import socket as socket_module

    from datacon.tools.net_adapter import ProductionSocketFactory

    # A local listener answers deterministically, so what the test pins is
    # the enforcement mechanism itself: the connect budget reaches the OS
    # socket as its timeout before the dial starts (a socket timeout is
    # exactly what bounds connect()), recorded on the face for the ledger.
    server = socket_module.socket(socket_module.AF_INET)
    server.bind(("127.0.0.1", 0))
    server.listen(1)
    port = server.getsockname()[1]
    try:
        factory = ProductionSocketFactory(
            connect_timeout=0.7, read_timeout=7.5,
            context_factory=RecordingContext,
        )
        raw = factory()
        raw.connect(("127.0.0.1", port))
        assert raw.timeouts == [0.7]
        assert raw.getpeername() == ("127.0.0.1", port)
    finally:
        server.close()


def test_production_socket_recv_enforces_the_read_timeout():
    from datacon.tools.net_adapter import ProductionSocketFactory

    server = socket_module.socket(socket_module.AF_INET)
    server.bind(("127.0.0.1", 0))
    server.listen(1)
    port = server.getsockname()[1]

    def stall():
        connection, _ = server.accept()
        time.sleep(5.0)
        connection.close()

    thread = threading.Thread(target=stall, daemon=True)
    thread.start()
    try:
        # A real TCP peer that never answers: the timeout applied by the
        # TLS mount (the recording context hands the real socket through)
        # is the only thing that ends the read.
        factory = ProductionSocketFactory(
            connect_timeout=2.0, read_timeout=0.3, context_factory=RecordingContext
        )
        raw = factory()
        raw.connect(("127.0.0.1", port))
        tls = raw.wrap_tls(sni=HOST)
        started = time.monotonic()
        with pytest.raises(OSError):
            tls.recv(4096)
        assert time.monotonic() - started < 3.0
    finally:
        server.close()
        thread.join(timeout=6.0)


# --- production wiring ----------------------------------------------------


def test_production_socket_factory_defaults_match_the_fetch_budgets():
    from datacon.tools import intel_fetch
    from datacon.tools.net_adapter import ProductionSocketFactory

    factory = ProductionSocketFactory()
    assert factory.connect_timeout == intel_fetch.CONNECT_TIMEOUT_SECONDS
    assert factory.read_timeout == intel_fetch.READ_TIMEOUT_SECONDS


def test_production_guarded_transport_wires_the_production_faces():
    from datacon.tools.intel_fetch import GuardedTransport
    from datacon.tools.net_adapter import (
        ProductionResolver,
        ProductionSocketFactory,
        production_guarded_transport,
    )

    transport = production_guarded_transport()
    assert isinstance(transport, GuardedTransport)
    assert isinstance(transport._resolver, ProductionResolver)
    assert isinstance(transport._socket_factory, ProductionSocketFactory)


# --- model outlet transport ------------------------------------------------


def test_outlet_transport_posts_canonical_bytes_and_parses_strictly():
    from datacon import jsonutil
    from datacon.tools.net_adapter import OutletHttpTransport

    body = {"fields": {"a": 1}, "notes": ["x", "y"]}
    payload = jsonutil.canonical_bytes(body)
    factory = FakeSocketFactory(
        inbox=_response(
            "HTTP/1.1 200 OK",
            [("Content-Type", "application/json"), ("Content-Length", "10")],
            b'{"x": "y"} not-parsed',
        )
    )
    transport = OutletHttpTransport(
        resolver=FakeResolver({HOST: [PUBLIC_V4]}), socket_factory=factory
    )

    result = transport.request(f"https://{HOST}/v1/analyze", body)

    assert result == {"x": "y"}
    sock = factory.sockets[0]
    assert sock.sni == HOST
    head = sock.sent[0]
    assert head.startswith(b"POST /v1/analyze HTTP/1.1\r\n")
    assert f"Host: {HOST}\r\n".encode("ascii") in head
    assert f"Content-Length: {len(payload)}\r\n".encode("ascii") in head
    assert b"Content-Length: 999" not in head
    # The wire carries exactly the canonical bytes the digest is taken over.
    assert sock.sent[-1] == payload
    assert sock.closed is True


def test_outlet_transport_refuses_redirects_without_a_second_dial():
    from datacon.tools.net_adapter import OutletHttpTransport
    from datacon.tools.safe_http import SafeHttpError

    factory = FakeSocketFactory(
        inbox=_response(
            "HTTP/1.1 302 Found",
            [("Location", "https://elsewhere.example.net/v1"), ("Content-Length", "0")],
            b"",
        )
    )
    transport = OutletHttpTransport(
        resolver=FakeResolver({HOST: [PUBLIC_V4]}), socket_factory=factory
    )

    with pytest.raises(SafeHttpError) as excinfo:
        transport.request(f"https://{HOST}/v1/analyze", {"a": 1})

    assert excinfo.value.reason == "OUTLET_REDIRECTED"
    assert len(factory.sockets) == 1


def test_outlet_transport_fails_closed_on_non_success_status():
    from datacon.tools.net_adapter import OutletHttpTransport
    from datacon.tools.safe_http import SafeHttpError

    factory = FakeSocketFactory(
        inbox=_response(
            "HTTP/1.1 503 Service Unavailable", [("Content-Length", "3")], b"boo"
        )
    )
    transport = OutletHttpTransport(
        resolver=FakeResolver({HOST: [PUBLIC_V4]}), socket_factory=factory
    )

    with pytest.raises(SafeHttpError) as excinfo:
        transport.request(f"https://{HOST}/v1/analyze", {"a": 1})

    assert excinfo.value.reason == "OUTLET_HTTP_STATUS"


def test_outlet_transport_fails_closed_on_unframed_or_oversized_bodies():
    from datacon.tools.net_adapter import OutletHttpTransport
    from datacon.tools.safe_http import SafeHttpError

    unframed = FakeSocketFactory(inbox=[b"HTTP/1.1 200 OK\r\n\r\n"])
    transport = OutletHttpTransport(
        resolver=FakeResolver({HOST: [PUBLIC_V4]}), socket_factory=unframed
    )
    with pytest.raises(SafeHttpError) as excinfo:
        transport.request(f"https://{HOST}/v1/analyze", {"a": 1})
    assert excinfo.value.reason == "RESPONSE_UNFRAMED"

    oversized = FakeSocketFactory(
        inbox=_response(
            "HTTP/1.1 200 OK", [("Content-Length", "9")], b"123456789"
        )
    )
    transport = OutletHttpTransport(
        resolver=FakeResolver({HOST: [PUBLIC_V4]}),
        socket_factory=oversized,
        max_response_bytes=8,
    )
    with pytest.raises(SafeHttpError) as excinfo:
        transport.request(f"https://{HOST}/v1/analyze", {"a": 1})
    assert excinfo.value.reason == "OUTLET_RESPONSE_TOO_LARGE"
    # The head was read (one recv carried the single scripted chunk); the
    # declared-oversized body stream never started.
    assert oversized.sockets[0].recv_count == 1


def test_outlet_transport_surfaces_truncated_and_non_json_bodies():
    from datacon.tools.net_adapter import OutletHttpTransport
    from datacon.tools.safe_http import SafeHttpError

    truncated = FakeSocketFactory(
        inbox=[b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nshort"]
    )
    transport = OutletHttpTransport(
        resolver=FakeResolver({HOST: [PUBLIC_V4]}), socket_factory=truncated
    )
    with pytest.raises(SafeHttpError) as excinfo:
        transport.request(f"https://{HOST}/v1/analyze", {"a": 1})
    assert excinfo.value.reason == "CONTENT_TRUNCATED"

    not_json = FakeSocketFactory(
        inbox=_response("HTTP/1.1 200 OK", [("Content-Length", "3")], b"abc")
    )
    transport = OutletHttpTransport(
        resolver=FakeResolver({HOST: [PUBLIC_V4]}), socket_factory=not_json
    )
    with pytest.raises(SafeHttpError) as excinfo:
        transport.request(f"https://{HOST}/v1/analyze", {"a": 1})
    assert excinfo.value.reason == "OUTLET_BAD_JSON"

    json_array = FakeSocketFactory(
        inbox=_response(
            "HTTP/1.1 200 OK", [("Content-Length", "7")], b'[1, 2] '
        )
    )
    transport = OutletHttpTransport(
        resolver=FakeResolver({HOST: [PUBLIC_V4]}), socket_factory=json_array
    )
    with pytest.raises(SafeHttpError) as excinfo:
        transport.request(f"https://{HOST}/v1/analyze", {"a": 1})
    assert excinfo.value.reason == "OUTLET_BAD_JSON"
