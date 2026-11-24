"""Offline intel snapshot provider for the T11 ``intel`` node (T15, REQ-02).

Implements the offline side of T15 behind the injectable ``IntelProvider``
port (``datacon.orchestration``). The v0.2 security design delta section 3.1
requires that an offline case reads already-pinned snapshots only and sends
no network request; section 3.5 requires that the ``intel`` node consume a
snapshot only when it is present, intact and licensed. The provider therefore
has no transport at all: it never calls ``intel_fetch.fetch_intel``,
``safe_http`` or the socket layer, and it is deterministic -- its answer
depends only on the request's case, the registry's order and the pinned
bytes, never on a clock or on the network.

Every source the case registry lists for the request's case is checked in
registry order, and the first failure decides the answer (v0.2 README
section 5, edges #5 and #6):

1. the request names no case at ``target.case_id``, so nothing can be
   looked up;
2. the case has no registered source: nothing is read, and a source that is
   not registered is never fetched;
3. a source is registered for another case: a factual mismatch, which v0.1
   files as ``SOURCE_CONFLICT``, so the snapshot is never even opened -- a
   conflict comes before content;
4. the registered digest is not a ``sha256:`` digest: nothing can be
   verified against such a pin;
5. the snapshot store answers ``None`` or raises;
6. the bytes do not hash to the registered digest: the material exists but
   cannot be verified, which v0.1 files under ``MATERIAL_MISSING``;
7. the license is missing or does not cover the system use.

Integrity (step 6) is decided before license (step 7) on purpose: altered
material is reported as unverifiable material, never as a policy matter.
Reason codes follow interface contract delta section 10, where T15 adds no
top-level reason code: snapshot failures are ``MATERIAL_MISSING``, a source
conflict is ``SOURCE_CONFLICT`` and a license failure is ``POLICY_DENIED``.
The fine reason rides in ``summary["sub_reason"]``.

``resolve_intel`` never raises. Every failure, down to a port that raises
unexpectedly, is an answer: a blocked ``IntelResult`` that offers no snapshot
digest. Neither ``message`` nor ``summary`` ever carries snapshot text. They
name the source, the reason and the fine reason only, and the text of a
raised exception is deliberately never repeated, because a snapshot store may
quote the bytes it failed on.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping, Protocol, Sequence, runtime_checkable

from datacon import jsonutil
from datacon.orchestration import IntelResult
from datacon.tools.intel_fetch import SYSTEM_USE


class _Blocked(Exception):
    """One refusal on its way to the single place that turns it into an answer."""

    def __init__(
        self,
        reason_code: str,
        sub_reason: str,
        message: str,
        source_id: str | None = None,
    ) -> None:
        super().__init__(message)
        self.reason_code = reason_code
        self.sub_reason = sub_reason
        self.message = message
        self.source_id = source_id

    def as_result(self) -> IntelResult:
        """Return the blocked ``IntelResult`` this refusal stands for."""
        summary: dict[str, Any] = {"sub_reason": self.sub_reason}
        if self.source_id is not None:
            summary["source_id"] = self.source_id
        return IntelResult(
            status="blocked",
            snapshot_digest=None,
            reason_code=self.reason_code,
            message=self.message,
            summary=summary,
        )


@dataclass(frozen=True)
class IntelSource:
    """One intel source a case registers: a pinned snapshot and its license.

    A registration is an immutable record; the license cannot be swapped
    after the fact. ``snapshot_digest`` pins the snapshot bytes as
    ``sha256:`` followed by 64 lower-case hex digits. The record itself is
    not validated here, because the provider, not the constructor, is the
    gate: a mis-registered source can be built, and is then refused by
    ``SnapshotIntelProvider`` with a reason instead of an exception.
    ``license`` is ``None`` when the source carries none, and
    ``permitted_uses`` lists the uses the license covers; it must name
    ``intel_fetch.SYSTEM_USE`` before the snapshot may enter the
    reproduction workflow.
    """

    source_id: str
    case_id: str
    snapshot_path: str
    snapshot_digest: str
    source_url: str
    license: str | None
    permitted_uses: tuple[str, ...]


@runtime_checkable
class SourceRegistry(Protocol):
    """Port listing the intel sources registered for a case, in check order."""

    def sources_for(self, case_id: str) -> Sequence[IntelSource]: ...


@runtime_checkable
class SnapshotLoader(Protocol):
    """Port reading one pinned snapshot; ``None`` when it cannot be read.

    The provider trusts this port no further than it verifies: whatever
    comes back must still hash to the source's registered digest.
    """

    def __call__(self, case_id: str, source: IntelSource) -> bytes | None: ...


def _case_id(request: Mapping[str, Any]) -> str | None:
    """Return ``request["target"]["case_id"]``, or ``None`` for an odd shape.

    Anything that is not a request mapping, or whose ``target`` is not a
    mapping, or whose case id is not non-blank text, is the same answer:
    the request names no case.
    """
    if not isinstance(request, Mapping):
        return None
    target = request.get("target")
    if not isinstance(target, Mapping):
        return None
    case_id = target.get("case_id")
    if not isinstance(case_id, str) or not case_id.strip():
        return None
    return case_id


def _source_id(source: IntelSource) -> str | None:
    """Return ``source.source_id`` when it is text, so summaries stay data."""
    return source.source_id if isinstance(source.source_id, str) else None


def _license_rejection(source: IntelSource) -> str | None:
    """Return why ``source``'s license is refused, or ``None`` when it passes.

    This is the offline twin of ``intel_fetch.check_license``: same verdict
    and same ``LICENSE_REJECTED`` fine reason. It is kept local because that
    gate compares the license a fetched snapshot claims with a registry entry
    keyed by source host. Here the registration itself is the license record
    -- there is no second claim to compare against -- and sources are keyed
    by case, not by host.
    """
    license_id = source.license
    if not isinstance(license_id, str) or not license_id.strip():
        return "no license is registered"
    uses = source.permitted_uses
    # ``in`` on a text value is a substring test, and a malformed record
    # grants nothing: only a sequence that names the system use passes.
    if isinstance(uses, str) or not isinstance(uses, Sequence):
        return "its permitted uses are not registered as a list"
    if SYSTEM_USE not in uses:
        return f"its license does not permit {SYSTEM_USE!r}"
    return None


def _ready(source: IntelSource) -> IntelResult:
    """Build the ready answer: a summary object that never holds the snapshot."""
    summary = {
        "snapshot_digest": source.snapshot_digest,
        "license": source.license,
        "source_url": source.source_url,
        # A pinned snapshot is read, not fetched: no redirect was followed.
        "redirect_chain_digest": None,
    }
    return IntelResult(
        status="ready",
        snapshot_digest=source.snapshot_digest,
        reason_code=None,
        message=None,
        summary=summary,
    )


class SnapshotIntelProvider:
    """``IntelProvider`` that verifies pinned snapshots; it has no transport.

    ``registry`` lists the intel sources registered for a case, in the order
    they are to be checked. ``snapshot_loader`` reads one pinned snapshot of
    that case and answers ``None`` when it cannot be read. Both ports are
    data, not authority: the provider does not filter or repair what the
    registry answers, it verifies every source in the given order and lets
    the first failure decide. When every source passes, the answer is
    ``ready`` and its summary is the first source's.
    """

    def __init__(
        self, *, registry: SourceRegistry, snapshot_loader: SnapshotLoader
    ) -> None:
        self._registry = registry
        self._snapshot_loader = snapshot_loader

    def resolve_intel(
        self, *, job_id: str, family_id: str, request: Mapping[str, Any]
    ) -> IntelResult:
        """Answer which pinned snapshot of ``request``'s case may go on.

        The result is ``ready`` with the summary of the first verified
        source, or ``blocked`` with the reason and its fine reason; it is
        never an exception. ``job_id`` and ``family_id`` belong to the port's
        signature only: the answer is a property of the case's registered
        material, so the same registration and bytes always answer the same.
        """
        del job_id, family_id
        try:
            return self._resolve(request)
        except _Blocked as blocked:
            return blocked.as_result()
        except Exception as error:  # noqa: BLE001 - the provider answers, never raises
            # The exception's own text is not repeated: a port may quote the
            # snapshot bytes it failed on. Its type names the failure.
            return _Blocked(
                "MATERIAL_MISSING",
                "SNAPSHOT_UNREADABLE",
                f"intel snapshot could not be resolved: {type(error).__name__} raised",
            ).as_result()

    def _resolve(self, request: Mapping[str, Any]) -> IntelResult:
        """Resolve the request; raises ``_Blocked`` for every refusal."""
        case_id = _case_id(request)
        if case_id is None:
            raise _Blocked(
                "MATERIAL_MISSING",
                "SNAPSHOT_MISSING",
                "intel request names no case at target.case_id",
            )
        sources = tuple(self._registry.sources_for(case_id))
        if not sources:
            raise _Blocked(
                "MATERIAL_MISSING",
                "SNAPSHOT_MISSING",
                f"case {case_id!r} has no registered intel source",
            )
        for source in sources:
            self._verify(case_id, source)
        # Every registered source passed: the first one names the snapshot.
        return _ready(sources[0])

    def _verify(self, case_id: str, source: IntelSource) -> None:
        """Raise ``_Blocked`` unless ``source`` may enter ``version``."""
        source_id = _source_id(source)
        # A conflict comes before content: a source filed for another case is
        # a factual mismatch, so its snapshot is never opened.
        if source.case_id != case_id:
            raise _Blocked(
                "SOURCE_CONFLICT",
                "SOURCE_CASE_MISMATCH",
                f"intel source {source_id!r} is registered for case"
                f" {source.case_id!r}, not {case_id!r}",
                source_id,
            )
        if not jsonutil.is_digest(source.snapshot_digest):
            raise _Blocked(
                "MATERIAL_MISSING",
                "SNAPSHOT_DIGEST_INVALID",
                f"intel source {source_id!r} is registered with a digest that"
                " is not a sha256 digest",
                source_id,
            )
        body = self._read(case_id, source, source_id)
        if jsonutil.digest_bytes(body) != source.snapshot_digest:
            raise _Blocked(
                "MATERIAL_MISSING",
                "DIGEST_MISMATCH",
                f"pinned snapshot of intel source {source_id!r} does not match"
                " its registered digest",
                source_id,
            )
        # Integrity first, license second: altered material is reported as
        # unverifiable material even when its license would be refused too.
        rejected = _license_rejection(source)
        if rejected is not None:
            raise _Blocked(
                "POLICY_DENIED",
                "LICENSE_REJECTED",
                f"intel source {source_id!r} is refused: {rejected}",
                source_id,
            )

    def _read(
        self, case_id: str, source: IntelSource, source_id: str | None
    ) -> bytes:
        """Read ``source``'s pinned snapshot; a failing store is an answer."""
        try:
            body = self._snapshot_loader(case_id, source)
        except Exception as error:  # noqa: BLE001 - a failing store is an answer
            raise _Blocked(
                "MATERIAL_MISSING",
                "SNAPSHOT_UNREADABLE",
                f"snapshot store raised {type(error).__name__} for intel source"
                f" {source_id!r}",
                source_id,
            ) from error
        if body is None:
            raise _Blocked(
                "MATERIAL_MISSING",
                "SNAPSHOT_MISSING",
                f"pinned snapshot of intel source {source_id!r} cannot be read",
                source_id,
            )
        if not isinstance(body, bytes):
            raise _Blocked(
                "MATERIAL_MISSING",
                "SNAPSHOT_UNREADABLE",
                f"snapshot store answered {type(body).__name__}, not bytes, for"
                f" intel source {source_id!r}",
                source_id,
            )
        return body
