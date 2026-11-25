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


# Response framing coordinates added by the T15 self-review. The doubles
# below replay a scripted wire the way a real socket delivers it: ``recv``
# never hands out more bytes than the caller asked for, and the wire is cut
# into *segments* -- bursts that arrive separately, so a coordinate can say
# whether body bytes rode along with the head in one chunk or turned up
# later. Once every burst is spent ``recv`` answers ``b""``: the peer closed
# the connection (EOF). No TCP, TLS or DNS happens here either.


class FakeWireSocket(FakeSocket):
    """A ``FakeSocket`` whose ``recv`` serves a scripted wire.

    ``segments`` are the bursts of bytes the peer sends, in order. Each is
    handed out in pieces of at most ``size`` bytes -- never more than the
    caller asked for, as on a real socket -- and a burst is never merged
    into the one before it. Once every burst is spent ``recv`` answers
    ``b""`` for good: the peer closed the connection.
    """

    def __init__(self, segments):
        super().__init__()
        self._segments = [bytes(segment) for segment in segments]

    def recv(self, size):
        assert size > 0
        while self._segments and not self._segments[0]:
            self._segments.pop(0)
        if not self._segments:
            return b""
        piece = self._segments[0][:size]
        self._segments[0] = self._segments[0][len(piece) :]
        return piece


class FakeWireSocketFactory:
    """Injected socket_factory(): every socket replays the same wire."""

    def __init__(self, *segments):
        self.segments = [bytes(segment) for segment in segments]
        self.sockets = []

    def __call__(self):
        sock = FakeWireSocket(self.segments)
        self.sockets.append(sock)
        return sock


def _read_response_over(*segments):
    """Send the fixture request over a wire of ``segments``; read the response.

    The connection stays open, so a returned response can still stream its
    body.
    """
    from datacon.tools.safe_http import connect_guarded

    connection = connect_guarded(
        f"https://{HOST}/advisory.txt",
        resolver=FakeResolver({HOST: [PUBLIC_V4_PRIMARY]}),
        socket_factory=FakeWireSocketFactory(*segments),
    )
    connection.send_request("GET", "/advisory.txt", {})
    return connection.read_response()


# Size of one ``X-Pad-NNNNNN`` filler header line in a padded response head.
PAD_LINE_BYTES = 1024


def _pad_line(index, size):
    """One ``size``-byte header line whose name carries ``index``."""
    name = f"X-Pad-{index:06d}: "
    return name.encode("ascii") + b"a" * (size - len(name) - 2) + b"\r\n"


def _padded_head(total, *, blank_line=True):
    """A response head of exactly ``total`` bytes, padded with header lines.

    The head is every byte from the status line through the blank line,
    both inclusive -- what a reader must buffer before it can parse. It
    declares a 10-byte body and pads with ``X-Pad-NNNNNN`` lines of about
    ``PAD_LINE_BYTES`` each, none of them oversized. With ``blank_line``
    turned off the head is left unterminated: it just runs on.
    """
    prefix = b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n"
    budget = total - len(prefix) - (2 if blank_line else 0)
    count = (budget + PAD_LINE_BYTES - 1) // PAD_LINE_BYTES
    base, wider = divmod(budget, count)
    lines = [
        _pad_line(index, base + 1 if index < wider else base) for index in range(count)
    ]
    head = prefix + b"".join(lines) + (b"\r\n" if blank_line else b"")
    assert len(head) == total
    return head


def test_response_head_is_capped():
    import datacon.tools.safe_http as safe_http
    from datacon.tools.safe_http import SafeHttpError

    head_limit = safe_http.MAX_RESPONSE_HEAD_BYTES
    body = b"0123456789"

    # one byte over the cap, blank line included, is refused before any of
    # the head is parsed or its body streamed
    with pytest.raises(SafeHttpError) as excinfo:
        _read_response_over(_padded_head(head_limit + 1) + body)
    assert excinfo.value.reason == "RESPONSE_HEAD_TOO_LARGE"

    # a head that never reaches its blank line is cut off at the cap too:
    # the reader must not keep buffering a runaway head until the peer closes
    with pytest.raises(SafeHttpError) as excinfo:
        _read_response_over(_padded_head(2 * head_limit, blank_line=False))
    assert excinfo.value.reason == "RESPONSE_HEAD_TOO_LARGE"

    # exactly at the cap is still a legal head: every padded line parses
    # and the body behind it streams undisturbed
    head = _padded_head(head_limit)
    response = _read_response_over(head + body)
    assert response.status == 200
    padded = sum(name.startswith("x-pad-") for name in response.headers)
    assert padded == head.count(b"X-Pad-")
    assert b"".join(response.body_chunks) == body


def test_duplicate_or_conflicting_content_length_is_rejected():
    from datacon.tools.safe_http import SafeHttpError

    # two Content-Length fields that disagree, spelled alike or with
    # different case (field names are case-insensitive on the wire): there
    # is no single declared length, so the response has no trustworthy frame
    for header_block in (
        b"Content-Length: 5\r\nContent-Length: 10\r\n",
        b"Content-Length: 5\r\ncontent-length: 10\r\n",
    ):
        with pytest.raises(SafeHttpError) as excinfo:
            _read_response_over(
                b"HTTP/1.1 200 OK\r\n" + header_block + b"\r\n0123456789"
            )
        assert excinfo.value.reason == "RESPONSE_UNFRAMED"


def test_body_stream_reports_truncation_at_eof():
    from datacon.tools.safe_http import SafeHttpError

    head = b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n"
    body = b"0123456789" * 10
    short = body[:10]

    # the peer closes with 90 of the 100 declared bytes still undelivered:
    # after 10 bytes, whether they rode along with the head or arrived on
    # their own, or before a single one. The stream must report the
    # truncation instead of just ending.
    for segments in ((head + short,), (head, short), (head,)):
        response = _read_response_over(*segments)
        with pytest.raises(SafeHttpError) as excinfo:
            b"".join(response.body_chunks)
        assert excinfo.value.reason == "CONTENT_TRUNCATED"

    # the mirrored sanity case: exactly the declared 100 bytes, in one
    # burst or split across several, end the stream normally and are its
    # whole content
    for segments in ((head + body,), (head, body[:30], body[30:])):
        response = _read_response_over(*segments)
        assert response.content_length == 100
        assert b"".join(response.body_chunks) == body


def test_missing_content_length_leaves_body_unframed_and_empty():
    head = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\n"
    body = b"0123456789"

    # no Content-Length on the wire: nothing frames the body, so not one of
    # its bytes may be handed out as a body -- neither the bytes that
    # arrived together with the head in the very same chunk, nor the bytes
    # of a later burst. The head itself still parses.
    for segments in ((head + body,), (head, body)):
        response = _read_response_over(*segments)
        assert response.status == 200
        assert response.content_length is None
        assert list(response.body_chunks) == []


def test_safe_http_errors_carry_a_reason_code():
    from datacon.tools.safe_http import (
        SafeHttpError,
        connect_guarded,
        resolve_validated,
    )

    # the typed error stays a ValueError subclass, so existing handlers hold
    assert issubclass(SafeHttpError, ValueError)

    # a poisoned answer -- inside the shared rejection set, or not a
    # literal IP at all -- is reported as an address denial, from the
    # resolver step and from the public entry point alike
    poisoned = [answer for answer, _why in REJECTED_ANSWERS]
    poisoned += ["advisory.example.com", "93.184.216.34:443"]
    for answer in poisoned:
        resolver = FakeResolver({HOST: [PUBLIC_V4_PRIMARY, answer]})
        with pytest.raises(SafeHttpError) as excinfo:
            resolve_validated(HOST, resolver=resolver)
        assert excinfo.value.reason == "ADDRESS_DENIED", answer

        factory = FakeSocketFactory()
        with pytest.raises(SafeHttpError) as excinfo:
            connect_guarded(
                f"https://{HOST}/advisory.txt",
                resolver=resolver,
                socket_factory=factory,
            )
        assert excinfo.value.reason == "ADDRESS_DENIED", answer
        assert factory.sockets == []

    # the pre-existing failures carry the default code: a non-https URL is
    # refused before any lookup (the resolver here fails on any query)...
    with pytest.raises(SafeHttpError) as excinfo:
        connect_guarded(
            f"http://{HOST}/advisory.txt",
            resolver=FakeResolver({}),
            socket_factory=FakeSocketFactory(),
        )
    assert excinfo.value.reason == "FETCH_FAILED"

    # ...and so is an empty resolution
    with pytest.raises(SafeHttpError) as excinfo:
        resolve_validated(HOST, resolver=FakeResolver({HOST: []}))
    assert excinfo.value.reason == "FETCH_FAILED"
