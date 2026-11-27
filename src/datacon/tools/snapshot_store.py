"""Content-addressed immutable snapshot store (security design delta 3.5).

``intel_fetch.build_snapshot`` builds the seven-field record for one
completed fetch and explicitly leaves persistence to this adapter: the
record and its body land under a root in a content-addressed layout
(``by-digest/<xx>/<digest>`` for the bytes, a ``.record.json`` sibling in
canonical JSON), writes are immutable - write-once via an atomic
create-if-absent link, never an overwrite - and the digest in the record
must honestly describe the bytes it is stored next to. A later fetch of the
same body adds a new record beside the untouched bytes, exactly as the
spec's "new snapshot, no overwrite" rule requires.

``snapshot_loader`` is the production ``SnapshotLoader`` face: it reads one
pinned snapshot by its registered relative path, refuses paths that try to
leave the root, and answers ``None`` for anything it cannot read so the
provider's own digest verification stays the single authority.
"""

from __future__ import annotations

import hashlib
import os
import tempfile
from pathlib import Path
from typing import Any, Mapping, NamedTuple

from datacon import jsonutil
from datacon.tools.intel_provider import IntelSource

__all__ = [
    "SNAPSHOT_RECORD_FIELDS",
    "PersistedSnapshot",
    "SnapshotStore",
    "SnapshotStoreError",
    "snapshot_loader",
]


class SnapshotStoreError(ValueError):
    """A snapshot could not be persisted or the store itself is corrupt."""


# The closed record shape of security-design-delta 3.5: source URL,
# collection time, HTTP status, content digest, license, redirect chain
# digest and the collecting tool version. Nothing else may be stored.
SNAPSHOT_RECORD_FIELDS = frozenset(
    {
        "source_url",
        "http_status",
        "content_digest",
        "license",
        "redirect_chain_digest",
        "fetched_at",
        "tool_version",
    }
)


class PersistedSnapshot(NamedTuple):
    """Where one persisted snapshot and its record landed."""

    snapshot_digest: str
    snapshot_path: str
    record_path: str
    record_digest: str


def _digest(payload: bytes) -> str:
    return "sha256:" + hashlib.sha256(payload).hexdigest()


class SnapshotStore:
    """Persists fetch records and bodies immutably under one root."""

    def __init__(self, root: Path) -> None:
        self._root = Path(root)

    def persist(
        self, snapshot: Mapping[str, Any], body: bytes
    ) -> PersistedSnapshot:
        """Store ``snapshot`` and ``body``; returns where they landed.

        The record's key set is closed and its ``content_digest`` must equal
        the digest of ``body``: a record may not lie about the content it
        pins. Both files are written once (atomically, without overwrite)
        and made read-only; storing the exact same record and body again is
        an idempotent no-op.
        """
        if not isinstance(snapshot, Mapping):
            raise SnapshotStoreError("snapshot record must be a JSON object")
        keys = set(snapshot)
        missing = SNAPSHOT_RECORD_FIELDS - keys
        unknown = keys - SNAPSHOT_RECORD_FIELDS
        if missing:
            raise SnapshotStoreError(
                "snapshot record is missing field(s): "
                + ", ".join(sorted(missing))
            )
        if unknown:
            raise SnapshotStoreError(
                "snapshot record has unknown field(s): "
                + ", ".join(sorted(str(key) for key in unknown))
            )
        for field in ("source_url", "redirect_chain_digest", "tool_version"):
            try:
                jsonutil.require_text(snapshot[field], f"snapshot.{field}")
            except ValueError as error:
                raise SnapshotStoreError(str(error)) from error
        http_status = snapshot["http_status"]
        if type(http_status) is not int:
            raise SnapshotStoreError("snapshot.http_status must be an integer")
        try:
            jsonutil.require_rfc3339(
                snapshot["fetched_at"], "snapshot.fetched_at"
            )
        except (TypeError, ValueError) as error:
            raise SnapshotStoreError(str(error)) from error
        declared_digest = jsonutil.require_digest(
            snapshot["content_digest"], "snapshot.content_digest"
        )
        if not isinstance(body, bytes):
            raise SnapshotStoreError("snapshot body must be bytes")
        actual_digest = _digest(body)
        if declared_digest != actual_digest:
            raise SnapshotStoreError(
                "snapshot.content_digest does not match the body bytes:"
                f" record says {declared_digest}, body hashes to"
                f" {actual_digest}"
            )

        hex_digest = actual_digest.removeprefix("sha256:")
        body_path = (
            self._root / "by-digest" / hex_digest[:2] / hex_digest
        )
        record_bytes = jsonutil.canonical_bytes(dict(snapshot))
        # The record is addressed by its own digest, not the body's: a
        # later fetch of the same bytes writes a new record (new
        # fetched_at, new digest) beside the untouched body, and only an
        # identical record ever maps onto an existing record path.
        record_hex = _digest(record_bytes).removeprefix("sha256:")
        record_path = (
            self._root
            / "by-digest"
            / record_hex[:2]
            / f"{record_hex}.record.json"
        )

        self._write_immutable(body_path, body)
        self._write_immutable(record_path, record_bytes)
        return PersistedSnapshot(
            snapshot_digest=actual_digest,
            snapshot_path=body_path.relative_to(self._root).as_posix(),
            record_path=record_path.relative_to(self._root).as_posix(),
            record_digest=_digest(record_bytes),
        )

    def _write_immutable(self, target: Path, data: bytes) -> None:
        """Create ``target`` with ``data`` exactly once; never overwrite.

        The write goes to a temporary file that is fsynced and read-only,
        then atomically hard-linked into place: the link fails if the name
        already exists, so no path can ever be overwritten. An existing name
        must already carry these exact bytes - a divergent file at a
        content-addressed name is corruption and fails closed.
        """
        target.parent.mkdir(parents=True, exist_ok=True)
        if target.exists():
            if target.read_bytes() != data:
                raise SnapshotStoreError(
                    f"content-addressed path {target.name} holds different"
                    " bytes than the ones being stored: the store is corrupt"
                )
            return
        handle, temporary_name = tempfile.mkstemp(
            dir=target.parent, prefix=".incoming-"
        )
        try:
            with os.fdopen(handle, "wb") as stream:
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
            os.chmod(temporary_name, 0o444)
            try:
                os.link(temporary_name, target)
            except FileExistsError:
                if target.read_bytes() != data:
                    raise SnapshotStoreError(
                        f"content-addressed path {target.name} holds"
                        " different bytes than the ones being stored: the"
                        " store is corrupt"
                    ) from None
        finally:
            try:
                os.unlink(temporary_name)
            except FileNotFoundError:
                pass


def snapshot_loader(root: Path):
    """Return the production ``SnapshotLoader`` reading under ``root``.

    The registered ``snapshot_path`` must be a safe relative POSIX path; a
    path that is absolute, traversing or resolves outside the root answers
    ``None``, as does anything that cannot be read. Verifying the bytes
    against the registered digest stays the provider's job.
    """

    base = Path(root).resolve()

    def _load(case_id: str, source: IntelSource) -> bytes | None:
        del case_id
        try:
            relative = jsonutil.safe_relative_path(
                source.snapshot_path, "snapshot_path"
            )
        except ValueError:
            return None
        candidate = (base / relative).resolve()
        if base != candidate and base not in candidate.parents:
            return None
        try:
            return candidate.read_bytes()
        except OSError:
            return None

    return _load
