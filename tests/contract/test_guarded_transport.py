"""GuardedTransport: fetch_intel running on safe_http (T15 R1a, D44).

RED-phase contract tests for the bridge between the intel fetch pure-logic
layer (``datacon.tools.intel_fetch.fetch_intel`` with its ``Transport`` /
``Hop`` protocol) and the shared safe connection layer
(``datacon.tools.safe_http``: injected resolver -> address validation ->
direct TLS dial -> ``getpeername`` recheck -> hostname-pinned request).
``datacon.tools.intel_fetch.GuardedTransport`` does not exist yet, so every
coordinate imports it inside the test function and fails at its own missing
entry point. The frozen construction face is
``GuardedTransport(*, resolver, socket_factory, clock=time.monotonic)``
implementing ``fetch(url, *, connect_timeout, read_timeout) -> Hop``; the
per-hop pipeline is ``connect_guarded`` -> ``send_request("GET", path,
headers)`` -> response parsed into a ``Hop`` (lowercased header keys, 3xx
``Location`` becoming ``Hop.location``, ``elapsed_seconds`` as the
difference of two injected-clock calls, body served as the wire's remaining
bytes chunk by chunk).

No test opens a socket, resolves DNS or sleeps: the resolver answers from a
dict, the socket factory hands out recording doubles, and time is an
injected step counter. Scripted wire convention for every hop (the
implementation round aligns the incremental ``safe_http.read_response``
extension to it): a socket's ``recv`` pops the ordered chunks of exactly one
complete HTTP/1.1 response -- status line, CRLF header lines, blank line,
then a body of exactly ``Content-Length`` bytes -- and returns ``b""`` once
the script is exhausted (orderly close). The head arrives as one chunk and
the body is split into fixed-size pieces, so head parsing may assume one
head chunk while body streaming must be chunk-by-chunk.
"""

from __future__ import annotations

import gzip

import pytest

HOST = "advisory.example.com"
MIRROR_HOST = "mirror.example.org"
ARCHIVE_HOST = "archive.example.net"
ALLOWLIST = (HOST, MIRROR_HOST)
HTTPS_PORT = 443

# Globally routable fixture addresses (the same role as in test_safe_http:
# they play the validated DNS answers and sit outside every rejected range).
PUBLIC_V4_PRIMARY = "93.184.216.34"
PUBLIC_V4_OTHER = "198.35.26.96"
PUBLIC_V4_THIRD = "140.82.121.4"


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


class StepClock:
    """Injected clock: returns the current value, then advances by ``step``.

    Consecutive calls differ by exactly ``step`` and no real time passes, so
    a hop's ``elapsed_seconds`` is a pure function of the injection; the
    non-zero ``start`` option exposes an implementation that reports the
    clock's absolute value instead of the difference of two calls.
    """

    def __init__(self, step, start=0.0):
        self._step = step
        self._now = start
        self.calls = 0

    def __call__(self):
        value = self._now
        self._now += self._step
        self.calls += 1
        return value


def _hop_script(status, reason, headers=(), body=b"", *, body_chunk_bytes=4096):
    """Serialize one HTTP/1.1 response into ordered wire chunks.

    The head (status line + headers + blank line, always carrying
    ``Content-Length``) forms the first chunk; the body follows split into
    ``body_chunk_bytes`` pieces so a hop body always streams chunk by chunk.
    """
    header_items = dict(headers)
    header_items.setdefault("Content-Length", str(len(body)))
    lines = [f"HTTP/1.1 {status} {reason}"]
    lines.extend(f"{name}: {value}" for name, value in header_items.items())
    head = ("\r\n".join(lines) + "\r\n\r\n").encode("ascii")
    body_chunks = [
        body[offset : offset + body_chunk_bytes]
        for offset in range(0, len(body), body_chunk_bytes)
    ]
    return [head, *body_chunks]


class ScriptedSocket:
    """Recording socket double for the safe_http GuardedSocket protocol.

    ``connect((ip, port))`` / ``wrap_tls(sni=...)`` / ``getpeername()`` /
    ``sendall`` / ``recv`` / ``close`` behave exactly as test_safe_http's
    doubles do. ``recv`` pops the next scripted wire chunk and returns
    ``b""`` once the script is exhausted; every non-empty recv and the first
    close append an event to the shared log so a leak test can prove each
    socket was closed exactly once, after its last wire byte was read.
    """

    def __init__(self, wire_chunks, index, events):
        self.index = index
        self.connect_calls = []
        self.sni = None
        self.sent = []
        self.closed = False
        self._inbox = list(wire_chunks)
        self._events = events

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
        assert size > 0
        chunk = self._inbox.pop(0) if self._inbox else b""
        if chunk:
            self._events.append(("recv", self.index))
        return chunk

    def close(self):
        if not self.closed:
            self.closed = True
            self._events.append(("close", self.index))


class ScriptedSocketFactory:
    """Injected socket_factory(): hands out one scripted socket per hop."""

    def __init__(self, hop_scripts):
        self._pending = [list(script) for script in hop_scripts]
        self.sockets = []
        self.events = []

    def __call__(self):
        if not self._pending:
            raise AssertionError(
                "socket factory asked for an unscripted extra connection"
            )
        sock = ScriptedSocket(
            self._pending.pop(0), index=len(self.sockets), events=self.events
        )
        self.sockets.append(sock)
        return sock


def test_guarded_transport_serves_fetch_intel_end_to_end():
    from datacon.tools.intel_fetch import GuardedTransport, fetch_intel

    url = f"https://{HOST}/cve-2099-0001.txt"
    body = b"advisory text\n"
    resolver = FakeResolver({HOST: [PUBLIC_V4_PRIMARY]})
    factory = ScriptedSocketFactory(
        [
            _hop_script(
                200,
                "OK",
                {"Content-Type": "text/plain"},
                body,
                body_chunk_bytes=7,
            )
        ]
    )
    transport = GuardedTransport(
        resolver=resolver,
        socket_factory=factory,
        clock=StepClock(step=0.25),
    )

    result = fetch_intel(url, allowlist=ALLOWLIST, transport=transport)

    # the pure-logic layer sees the wire truth through the adapter: body,
    # status and the visited-hop chain all come from the scripted response
    assert result.body == body
    assert result.status == 200
    assert result.hops == (url,)
    # and the hop really went through the guarded pipeline: one validated
    # DNS answer dialed directly, SNI and Host pinned to the hostname
    assert resolver.calls == [HOST]
    assert len(factory.sockets) == 1
    sock = factory.sockets[0]
    assert sock.connect_calls == [(PUBLIC_V4_PRIMARY, HTTPS_PORT)]
    assert sock.sni == HOST
    wire = b"".join(sock.sent).lower()
    assert b"get /cve-2099-0001.txt" in wire
    assert b"host: " + HOST.encode() in wire


def test_guarded_transport_propagates_redirect_location_per_hop():
    from datacon.tools.intel_fetch import GuardedTransport, fetch_intel

    first_url = f"https://{HOST}/cve-2099-0001.txt"
    final_url = f"https://{MIRROR_HOST}/cve-2099-0001.txt"
    body = b"mirrored advisory\n"
    resolver = FakeResolver(
        {HOST: [PUBLIC_V4_PRIMARY], MIRROR_HOST: [PUBLIC_V4_OTHER]}
    )
    factory = ScriptedSocketFactory(
        [
            _hop_script(302, "Found", {"Location": final_url}),
            _hop_script(200, "OK", {}, body),
        ]
    )
    transport = GuardedTransport(
        resolver=resolver,
        socket_factory=factory,
        clock=StepClock(step=0.5),
    )

    result = fetch_intel(first_url, allowlist=ALLOWLIST, transport=transport)

    # the 302's Location became hop two: the visited chain covers both URLs
    # and the final body arrived through the second guarded connection
    assert result.hops == (first_url, final_url)
    assert result.status == 200
    assert result.body == body
    # per-hop revalidation through safe_http: the redirect target resolves
    # to its own answer and dials on a fresh socket with its own pinned
    # SNI and Host header (cross-hop connection reuse stays impossible)
    assert resolver.calls == [HOST, MIRROR_HOST]
    assert len(factory.sockets) == 2
    first, second = factory.sockets
    assert first is not second
    assert first.connect_calls == [(PUBLIC_V4_PRIMARY, HTTPS_PORT)]
    assert second.connect_calls == [(PUBLIC_V4_OTHER, HTTPS_PORT)]
    assert first.sni == HOST
    assert second.sni == MIRROR_HOST
    first_wire = b"".join(first.sent).lower()
    second_wire = b"".join(second.sent).lower()
    assert b"host: " + HOST.encode() in first_wire
    assert b"host: " + MIRROR_HOST.encode() in second_wire


def test_guarded_transport_enforces_redirect_limit_through_safe_http():
    from datacon.tools.intel_fetch import (
        MAX_REDIRECT_HOPS,
        GuardedTransport,
        IntelFetchError,
        fetch_intel,
    )

    assert MAX_REDIRECT_HOPS == 5
    hosts = tuple(f"hop{index}.{HOST}" for index in range(7))
    urls = [f"https://{host}/advisory.txt" for host in hosts]
    resolver = FakeResolver({host: [PUBLIC_V4_PRIMARY] for host in hosts[:6]})
    factory = ScriptedSocketFactory(
        [
            _hop_script(302, "Found", {"Location": urls[index + 1]})
            for index in range(6)
        ]
    )
    transport = GuardedTransport(
        resolver=resolver,
        socket_factory=factory,
        clock=StepClock(step=0.1),
    )

    with pytest.raises(IntelFetchError, match="REDIRECT_LIMIT_EXCEEDED") as caught:
        fetch_intel(urls[0], allowlist=hosts, transport=transport)

    # the sixth redirect is refused with the hop count in the message, and
    # it was refused through real guarded hops: six distinct sockets were
    # dialed (one per hop, none reused) while the seventh URL never reached
    # the resolver or the socket factory
    assert "6" in str(caught.value)
    assert len(factory.sockets) == 6
    assert len({id(sock) for sock in factory.sockets}) == 6
    assert resolver.calls == list(hosts[:6])


def test_guarded_transport_streams_gzip_body_for_budget_counting():
    from datacon.tools.intel_fetch import (
        MAX_COMPRESSION_RATIO,
        GuardedTransport,
        IntelFetchError,
        fetch_intel,
    )

    url = f"https://{HOST}/advisory.txt"

    def build_transport(factory):
        return GuardedTransport(
            resolver=FakeResolver({HOST: [PUBLIC_V4_PRIMARY]}),
            socket_factory=factory,
            clock=StepClock(step=0.5),
        )

    # an ordinary gzip body crosses the wire in small chunks and comes back
    # decompressed: the head carries Content-Encoding in canonical case, so
    # the Hop must expose lowercased header keys for the encoding lookup
    plain = b"advisory content\n" * 64
    factory = ScriptedSocketFactory(
        [
            _hop_script(
                200,
                "OK",
                {"Content-Type": "text/plain", "Content-Encoding": "gzip"},
                gzip.compress(plain),
                body_chunk_bytes=64,
            )
        ]
    )
    result = fetch_intel(
        url, allowlist=ALLOWLIST, transport=build_transport(factory)
    )
    assert result.body == plain
    assert result.status == 200

    # the over-limit variant: ~2 KiB on the wire expanding to 2 MiB stays
    # under the wire cap and the 32 MiB absolute cap, so only counting while
    # the stream decompresses can cut it at the 100:1 ratio cap
    bomb = gzip.compress(b"\0" * (2 * 1024 * 1024))
    assert len(bomb) * MAX_COMPRESSION_RATIO < 2 * 1024 * 1024
    factory = ScriptedSocketFactory(
        [
            _hop_script(
                200,
                "OK",
                {"Content-Encoding": "gzip"},
                bomb,
                body_chunk_bytes=64,
            )
        ]
    )
    with pytest.raises(IntelFetchError, match="DECOMPRESSION_BOMB"):
        fetch_intel(
            url, allowlist=ALLOWLIST, transport=build_transport(factory)
        )


def test_guarded_transport_elapsed_comes_from_injected_clock():
    from datacon.tools.intel_fetch import (
        GuardedTransport,
        IntelFetchError,
        fetch_intel,
    )

    first_url = f"https://{HOST}/slow-redirect"
    final_url = f"https://{MIRROR_HOST}/slow-final"

    def build_transport(clock):
        resolver = FakeResolver(
            {HOST: [PUBLIC_V4_PRIMARY], MIRROR_HOST: [PUBLIC_V4_OTHER]}
        )
        factory = ScriptedSocketFactory(
            [
                _hop_script(302, "Found", {"Location": final_url}),
                _hop_script(200, "OK", {}, b"finally\n"),
            ]
        )
        return GuardedTransport(
            resolver=resolver, socket_factory=factory, clock=clock
        )

    # under the budget: two hops of one second each -- measured as the
    # difference of two clock calls, not the clock's absolute value, which
    # already sits at 1000 -- complete far inside the 60 second total
    fast = build_transport(StepClock(step=1.0, start=1000.0))
    result = fetch_intel(first_url, allowlist=ALLOWLIST, transport=fast)
    assert result.status == 200
    assert result.body == b"finally\n"
    assert result.hops == (first_url, final_url)

    # over the budget: two hops of forty seconds accumulate to eighty and
    # the fetch is cut with FETCH_TIMEOUT even though every socket answered
    slow = build_transport(StepClock(step=40.0))
    with pytest.raises(IntelFetchError, match="FETCH_TIMEOUT"):
        fetch_intel(first_url, allowlist=ALLOWLIST, transport=slow)


def test_guarded_transport_never_leaks_sockets_on_success():
    from datacon.tools.intel_fetch import GuardedTransport, fetch_intel

    first_url = f"https://{HOST}/one"
    second_url = f"https://{MIRROR_HOST}/two"
    final_url = f"https://{ARCHIVE_HOST}/three"
    body = b"final advisory\n"
    allowlist = (HOST, MIRROR_HOST, ARCHIVE_HOST)
    resolver = FakeResolver(
        {
            HOST: [PUBLIC_V4_PRIMARY],
            MIRROR_HOST: [PUBLIC_V4_OTHER],
            ARCHIVE_HOST: [PUBLIC_V4_THIRD],
        }
    )
    factory = ScriptedSocketFactory(
        [
            _hop_script(302, "Found", {"Location": second_url}),
            _hop_script(302, "Found", {"Location": final_url}),
            _hop_script(200, "OK", {}, body, body_chunk_bytes=8),
        ]
    )
    transport = GuardedTransport(
        resolver=resolver,
        socket_factory=factory,
        clock=StepClock(step=0.5),
    )

    result = fetch_intel(first_url, allowlist=allowlist, transport=transport)

    # the full chain succeeded, so every hop's connection is finished: each
    # of the three sockets closed exactly once, after its last wire byte
    # was read, and no extra socket was ever dialed (zero leaks)
    assert result.body == body
    assert result.hops == (first_url, second_url, final_url)
    assert len(factory.sockets) == 3
    assert all(sock.closed for sock in factory.sockets)
    close_events = [event for event in factory.events if event[0] == "close"]
    assert len(close_events) == 3
    for sock in factory.sockets:
        recv_positions = [
            position
            for position, event in enumerate(factory.events)
            if event == ("recv", sock.index)
        ]
        close_positions = [
            position
            for position, event in enumerate(factory.events)
            if event == ("close", sock.index)
        ]
        assert recv_positions, "a hop socket never read its scripted response"
        assert len(close_positions) == 1
        assert close_positions[0] > max(recv_positions)
