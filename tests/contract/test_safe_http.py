"""Shared safe HTTP connection layer (security design delta 2.4 / 3.2).

RED-phase contract tests for ``datacon.tools.safe_http``, the connection
layer both T15 (intel fetching) and T14 (model endpoints) reuse so the
anti-rebinding pipeline exists exactly once: DNS resolve -> address
validation against the shared rejection set -> direct TCP/TLS connection
to a validated IP with TLS SNI and the HTTP ``Host`` header pinned to the
original hostname (no cross-redirect connection reuse) -> a
``getpeername()`` recheck before any HTTP byte leaves, and environment
proxies ignored so they cannot bypass the address checks.

The module does not exist yet, so each coordinate imports the contract
face inside the test function and fails at its own missing entry point.
No test resolves DNS, opens a socket or sleeps: the resolver and the
socket factory are recording fakes injected per call, and a fixed
``peer`` on the fake socket is what simulates a DNS rebind.
"""

from __future__ import annotations

import ipaddress

import pytest

HOST = "advisory.example.com"
MIRROR_HOST = "mirror.example.org"
HTTPS_PORT = 443

# Globally routable fixture addresses (verified outside every rejected
# range: not private, reserved, CGNAT, benchmarking or documentation
# space). They play the "validated" DNS answers throughout.
PUBLIC_V4_PRIMARY = "93.184.216.34"
PUBLIC_V4_OTHER = "198.35.26.96"

# One rejected answer per category of the shared rejection set: private,
# loopback, cloud metadata, IPv4-mapped IPv6 (unwrapped first), IPv6
# metadata and CGNAT.
REJECTED_ANSWERS = (
    ("10.0.0.5", "private 10/8"),
    ("127.0.0.1", "IPv4 loopback"),
    ("169.254.169.254", "IPv4 cloud metadata"),
    ("::ffff:127.0.0.1", "IPv4-mapped IPv6 loopback"),
    ("fd00:ec2::254", "IPv6 cloud metadata"),
    ("100.64.0.9", "CGNAT 100.64.0.0/10"),
)

OK_RESPONSE = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"


class FakeResolver:
    """Injected resolver: serves ``answers[host]`` and records every call."""

    def __init__(self, answers):
        self._answers = dict(answers)
        self.calls = []

    def __call__(self, host):
        self.calls.append(host)
        answers = self._answers.get(host)
        if answers is None:
            raise AssertionError(f"unexpected DNS query for {host!r}")
        return list(answers)


class FakeSocket:
    """Recording socket double; no TCP, TLS or DNS ever happens.

    Protocol expected by ``connect_guarded`` (frozen by these tests):
    ``connect((ip, port))`` then ``wrap_tls(sni=...)`` (the TLS mount
    point; returns the still-observable recording object), then
    ``getpeername()`` / ``sendall(bytes)`` / ``recv(size)`` / ``close()``.

    ``peer`` fixes what ``getpeername()`` reports regardless of the
    address handed to ``connect()``: that is the DNS-rebinding simulator.
    Without it the socket answers like a real one, with the last
    connected address.
    """

    def __init__(self, peer=None, inbox=()):
        self.connect_calls = []
        self.sni = None
        self.tls_options = None
        self.sent = []
        self.closed = False
        self._peer = peer
        self._inbox = list(inbox)

    def connect(self, address):
        self.connect_calls.append(tuple(address))

    def wrap_tls(self, sni=None, **options):
        """TLS mount point: records the pinned SNI for the assertion."""
        self.sni = sni
        self.tls_options = dict(options)
        return self

    def getpeername(self):
        if self._peer is not None:
            return (self._peer, HTTPS_PORT)
        if not self.connect_calls:
            raise AssertionError("getpeername() before connect()")
        return self.connect_calls[-1]

    def sendall(self, data):
        self.sent.append(bytes(data))

    def recv(self, size):
        assert size > 0
        return self._inbox.pop(0) if self._inbox else b""

    def close(self):
        self.closed = True


class FakeSocketFactory:
    """Injected socket_factory(): hands out FakeSockets and records them."""

    def __init__(self, **socket_kwargs):
        self._socket_kwargs = socket_kwargs
        self.sockets = []

    def __call__(self):
        sock = FakeSocket(**self._socket_kwargs)
        self.sockets.append(sock)
        return sock


def test_dns_answers_are_validated_before_any_socket_opens():
    from datacon.tools.safe_http import (
        SafeHttpError,
        connect_guarded,
        is_rejected_address,
        resolve_validated,
    )

    # the shared rejection predicate itself: string and ipaddress inputs
    # agree, and IPv4-mapped IPv6 is judged after unwrapping
    for answer, _why in REJECTED_ANSWERS:
        assert is_rejected_address(answer) is True
        assert is_rejected_address(ipaddress.ip_address(answer)) is True
    assert is_rejected_address(PUBLIC_V4_PRIMARY) is False

    # one rejected answer poisons the whole answer set (fail closed on any)
    for answer, _why in REJECTED_ANSWERS:
        resolver = FakeResolver({HOST: [PUBLIC_V4_PRIMARY, answer]})
        with pytest.raises(SafeHttpError, match=r"(?i)address"):
            resolve_validated(HOST, resolver=resolver)

    # an empty resolution is a failure, never a "connect anyway"
    resolver = FakeResolver({HOST: []})
    with pytest.raises(SafeHttpError):
        resolve_validated(HOST, resolver=resolver)

    # all-public answers come back as the validated IP strings
    resolver = FakeResolver({HOST: [PUBLIC_V4_PRIMARY, PUBLIC_V4_OTHER]})
    assert resolve_validated(HOST, resolver=resolver) == [
        PUBLIC_V4_PRIMARY,
        PUBLIC_V4_OTHER,
    ]

    # validate-before-connect: the same poisoned answers abort
    # connect_guarded before any socket object is created
    for answer, _why in REJECTED_ANSWERS:
        resolver = FakeResolver({HOST: [answer]})
        factory = FakeSocketFactory()
        with pytest.raises(SafeHttpError, match=r"(?i)address"):
            connect_guarded(
                f"https://{HOST}/advisory.txt",
                resolver=resolver,
                socket_factory=factory,
            )
        assert factory.sockets == []


def test_rebind_to_metadata_ip_is_aborted_before_http_bytes():
    from datacon.tools.safe_http import SafeHttpError, connect_guarded

    # DNS answers a public IP and pass validation, but the socket's peer
    # turns out to be the cloud metadata endpoint: the TOCTOU recheck
    # must abort before a single HTTP byte is sent. The raise may happen
    # at either recheck point (post-connect or pre-send); what is frozen
    # here is that no HTTP bytes ever leave.
    resolver = FakeResolver({HOST: [PUBLIC_V4_PRIMARY]})
    factory = FakeSocketFactory(peer="169.254.169.254")
    with pytest.raises(SafeHttpError, match="getpeername"):
        connection = connect_guarded(
            f"https://{HOST}/advisory.txt",
            resolver=resolver,
            socket_factory=factory,
        )
        connection.send_request("GET", "/advisory.txt", {})

    sock = factory.sockets[0]
    assert sock.connect_calls == [(PUBLIC_V4_PRIMARY, HTTPS_PORT)]
    assert sock.sent == []


def test_connection_pins_sni_and_host_to_the_hostname():
    from datacon.tools.safe_http import connect_guarded

    resolver = FakeResolver({HOST: [PUBLIC_V4_PRIMARY]})
    factory = FakeSocketFactory(inbox=[OK_RESPONSE])
    connection = connect_guarded(
        f"https://{HOST}/advisory.txt",
        resolver=resolver,
        socket_factory=factory,
    )
    # a forged Host header from the caller must not survive the pinning
    connection.send_request(
        "GET",
        "/advisory.txt",
        {"Accept": "*/*", "Host": "evil.example.net"},
    )
    response = connection.read_response()
    connection.close()

    sock = factory.sockets[0]
    # the TCP/TLS connection goes to the validated IP...
    assert sock.connect_calls == [(PUBLIC_V4_PRIMARY, HTTPS_PORT)]
    # ...while TLS SNI and the HTTP Host header stay pinned to the
    # original hostname, never the IP and never the forged header
    assert sock.sni == HOST
    wire = b"".join(sock.sent).lower()
    assert b"get" in wire and b"/advisory.txt" in wire
    assert b"host: " + HOST.encode() in wire
    assert b"host: evil.example.net" not in wire
    assert b"host: " + PUBLIC_V4_PRIMARY.encode() not in wire
    # the response object exposes the status parsed from the wire
    assert getattr(response, "status", None) == 200
    assert sock.closed is True


def test_peer_must_match_a_validated_address():
    from datacon.tools.safe_http import SafeHttpError, connect_guarded

    # the peer drifted to a different public IP that validation never
    # saw: sending is refused even though the address is globally
    # routable (defends against answer-set drift, not just bad ranges)
    resolver = FakeResolver({HOST: [PUBLIC_V4_PRIMARY]})
    factory = FakeSocketFactory(peer=PUBLIC_V4_OTHER)
    with pytest.raises(SafeHttpError, match="getpeername"):
        connection = connect_guarded(
            f"https://{HOST}/advisory.txt",
            resolver=resolver,
            socket_factory=factory,
        )
        connection.send_request("GET", "/advisory.txt", {})
    assert factory.sockets[0].sent == []

    # the mirrored sanity case: a peer matching the validated answer
    # completes the request
    factory = FakeSocketFactory(inbox=[OK_RESPONSE])
    connection = connect_guarded(
        f"https://{HOST}/advisory.txt",
        resolver=FakeResolver({HOST: [PUBLIC_V4_PRIMARY]}),
        socket_factory=factory,
    )
    connection.send_request("GET", "/advisory.txt", {})
    assert factory.sockets[0].sent != []


def test_each_hop_opens_a_new_validated_connection():
    from datacon.tools.safe_http import SafeHttpError, connect_guarded

    url_first = f"https://{HOST}/advisory.txt"
    url_second = f"https://{MIRROR_HOST}/advisory.txt"

    # two hops as a redirect chain would drive them: each hop resolves
    # its own hostname (different answers) and gets its own socket
    resolver = FakeResolver(
        {HOST: [PUBLIC_V4_PRIMARY], MIRROR_HOST: [PUBLIC_V4_OTHER]}
    )
    factory = FakeSocketFactory(inbox=[OK_RESPONSE])
    connection_first = connect_guarded(
        url_first, resolver=resolver, socket_factory=factory
    )
    connection_first.send_request("GET", "/advisory.txt", {})
    connection_first.read_response()
    connection_first.close()
    connection_second = connect_guarded(
        url_second, resolver=resolver, socket_factory=factory
    )
    connection_second.send_request("GET", "/advisory.txt", {})
    connection_second.close()

    assert resolver.calls == [HOST, MIRROR_HOST]
    assert len(factory.sockets) == 2
    first, second = factory.sockets
    # no connection object is reused across the redirect
    assert first is not second
    assert first.closed is True
    assert first.connect_calls == [(PUBLIC_V4_PRIMARY, HTTPS_PORT)]
    assert second.connect_calls == [(PUBLIC_V4_OTHER, HTTPS_PORT)]
    assert first.sni == HOST
    assert second.sni == MIRROR_HOST
    assert b"host: " + HOST.encode() in b"".join(first.sent).lower()
    assert b"host: " + MIRROR_HOST.encode() in b"".join(second.sent).lower()

    # the second hop's answers are revalidated, not inherited from the
    # first hop: a rejected answer for the redirect target aborts before
    # its socket exists
    factory = FakeSocketFactory()
    resolver = FakeResolver(
        {HOST: [PUBLIC_V4_PRIMARY], MIRROR_HOST: ["169.254.169.254"]}
    )
    connection_first = connect_guarded(
        url_first, resolver=resolver, socket_factory=factory
    )
    connection_first.send_request("GET", "/advisory.txt", {})
    connection_first.close()
    with pytest.raises(SafeHttpError, match=r"(?i)address"):
        connect_guarded(url_second, resolver=resolver, socket_factory=factory)
    assert len(factory.sockets) == 1


def test_environment_proxies_are_not_honored(monkeypatch):
    from datacon.tools.safe_http import connect_guarded

    for name in (
        "http_proxy",
        "https_proxy",
        "all_proxy",
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
    ):
        monkeypatch.setenv(name, "http://proxy.corp.example:3128")

    # with every proxy variable set, the connection still goes directly
    # to the validated IP: connect() only ever receives the
    # (validated IP, port) tuple, never a proxy host, and the request
    # stays origin-form with the pinned Host header
    resolver = FakeResolver({HOST: [PUBLIC_V4_PRIMARY]})
    factory = FakeSocketFactory(inbox=[OK_RESPONSE])
    connection = connect_guarded(
        f"https://{HOST}/advisory.txt",
        resolver=resolver,
        socket_factory=factory,
    )
    connection.send_request("GET", "/advisory.txt", {})
    connection.read_response()
    connection.close()

    assert len(factory.sockets) == 1
    sock = factory.sockets[0]
    assert sock.connect_calls == [(PUBLIC_V4_PRIMARY, HTTPS_PORT)]
    wire = b"".join(sock.sent).lower()
    assert b"host: " + HOST.encode() in wire
    assert b"proxy.corp.example" not in wire
    assert b"connect " not in wire
