"""T15 snapshot store: content-addressed immutable snapshots and the reader.

RED-phase contract tests for ``datacon.tools.snapshot_store``, the adapter
``intel_fetch.build_snapshot``'s docstring delegates persistence to: the
seven-field record and its body land in a content-addressed layout under a
root, writes are immutable (write-once, never overwrite; a later fetch of
the same bytes adds a record, it never rewrites the body), and the
production ``SnapshotLoader`` reads a pinned snapshot by its registered
relative path without ever leaving the root. Everything runs offline against
a temporary root; no network is touched.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest


BODY = b"CVE-2099-0001 advisory text; pinned snapshot body."


def _record(**overrides: object) -> dict:
    record = {
        "source_url": "https://advisory.example.com/cve-2099-0001.txt",
        "http_status": 200,
        "content_digest": _digest(BODY),
        "license": "CC-BY-4.0",
        "redirect_chain_digest": _digest(b"https://advisory.example.com/a\nhttps://advisory.example.com/b"),
        "fetched_at": "2026-11-26T00:00:00+00:00",
        "tool_version": "datacon.intel_fetch/0.1.0",
    }
    return {**record, **overrides}


def _digest(payload: bytes) -> str:
    import hashlib

    return "sha256:" + hashlib.sha256(payload).hexdigest()


def test_snapshot_store_persists_body_and_record_content_addressed(tmp_path):
    from datacon.tools.snapshot_store import SnapshotStore

    store = SnapshotStore(tmp_path)
    persisted = store.persist(_record(), BODY)

    hex_digest = persisted.snapshot_digest.removeprefix("sha256:")
    assert persisted.snapshot_path == f"by-digest/{hex_digest[:2]}/{hex_digest}"
    body_file = tmp_path / persisted.snapshot_path
    assert body_file.read_bytes() == BODY

    record_file = tmp_path / Path(persisted.record_path)
    assert record_file.exists()
    on_disk = json.loads(record_file.read_bytes())
    assert on_disk == _record()
    # The record is written as canonical JSON: stable bytes, stable digest.
    assert persisted.record_digest == _digest(record_file.read_bytes())


def test_snapshot_store_is_write_once_and_idempotent(tmp_path):
    from datacon.tools.snapshot_store import SnapshotStore

    store = SnapshotStore(tmp_path)
    first = store.persist(_record(), BODY)
    again = store.persist(_record(), BODY)
    assert again.snapshot_path == first.snapshot_path
    assert again.record_path == first.record_path

    # A later fetch of the same bytes keeps the body and adds a new record.
    refetched = store.persist(
        _record(fetched_at="2026-11-27T00:00:00+00:00"), BODY
    )
    assert refetched.snapshot_path == first.snapshot_path
    assert refetched.record_path != first.record_path
    assert (tmp_path / first.snapshot_path).read_bytes() == BODY
    records = list((tmp_path / "by-digest").rglob("*.record.json"))
    assert len(records) == 2


def test_snapshot_store_refuses_a_corrupted_body_at_the_digest_path(tmp_path):
    from datacon.tools.snapshot_store import SnapshotStore

    store = SnapshotStore(tmp_path)
    persisted = store.persist(_record(), BODY)
    body_file = tmp_path / persisted.snapshot_path
    # Break immutability the only way a test can: rewrite the file in place.
    os.chmod(body_file, 0o644)
    body_file.write_bytes(b"tampered")
    with pytest.raises(Exception, match="(?i)corrupt|mismatch|digest"):
        store.persist(_record(), BODY)


def test_snapshot_store_validates_the_closed_record_shape(tmp_path):
    from datacon.tools.snapshot_store import SnapshotStore

    store = SnapshotStore(tmp_path)
    missing = _record()
    del missing["redirect_chain_digest"]
    with pytest.raises(Exception, match="redirect_chain_digest"):
        store.persist(missing, BODY)
    unknown = _record(extra="field")
    with pytest.raises(Exception, match="extra"):
        store.persist(unknown, BODY)
    # The record may not lie about the content it pins.
    lying = _record(content_digest=_digest(b"other bytes"))
    with pytest.raises(Exception, match="(?i)content_digest"):
        store.persist(lying, BODY)


def test_snapshot_files_are_read_only(tmp_path):
    from datacon.tools.snapshot_store import SnapshotStore

    store = SnapshotStore(tmp_path)
    persisted = store.persist(_record(), BODY)
    for path in (persisted.snapshot_path, persisted.record_path):
        mode = (tmp_path / path).stat().st_mode & 0o222
        assert mode == 0, path


def test_snapshot_loader_reads_pinned_snapshots(tmp_path):
    from datacon.tools.intel_provider import IntelSource
    from datacon.tools.snapshot_store import SnapshotStore, snapshot_loader

    store = SnapshotStore(tmp_path)
    persisted = store.persist(_record(), BODY)
    loader = snapshot_loader(tmp_path)
    source = IntelSource(
        source_id="advisory-primary",
        case_id="cve-2099-0001",
        snapshot_path=persisted.snapshot_path,
        snapshot_digest=persisted.snapshot_digest,
        source_url=_record()["source_url"],
        license="CC-BY-4.0",
        permitted_uses=("reproduction",),
    )

    assert loader("cve-2099-0001", source) == BODY

    # Missing snapshots read as None; unsafe paths never leave the root.
    missing = IntelSource(
        source_id="advisory-primary",
        case_id="cve-2099-0001",
        snapshot_path="by-digest/ff/" + "0" * 64,
        snapshot_digest=persisted.snapshot_digest,
        source_url=_record()["source_url"],
        license="CC-BY-4.0",
        permitted_uses=("reproduction",),
    )
    assert loader("cve-2099-0001", missing) is None

    for unsafe in ("../secrets", "/etc/passwd", "a/../..", "back\\slash"):
        escaping = IntelSource(
            source_id="advisory-primary",
            case_id="cve-2099-0001",
            snapshot_path=unsafe,
            snapshot_digest=persisted.snapshot_digest,
            source_url=_record()["source_url"],
            license="CC-BY-4.0",
            permitted_uses=("reproduction",),
        )
        assert loader("cve-2099-0001", escaping) is None, unsafe


def test_snapshot_store_composes_with_the_snapshot_provider(tmp_path):
    from datacon.tools.intel_provider import (
        IntelSource,
        SnapshotIntelProvider,
    )
    from datacon.tools.snapshot_store import SnapshotStore, snapshot_loader

    store = SnapshotStore(tmp_path)
    persisted = store.persist(_record(), BODY)
    source = IntelSource(
        source_id="advisory-primary",
        case_id="cve-2099-0001",
        snapshot_path=persisted.snapshot_path,
        snapshot_digest=persisted.snapshot_digest,
        source_url=_record()["source_url"],
        license="CC-BY-4.0",
        permitted_uses=("reproduction",),
    )

    class _Registry:
        def sources_for(self, case_id):
            return (source,)

    provider = SnapshotIntelProvider(
        registry=_Registry(), snapshot_loader=snapshot_loader(tmp_path)
    )
    result = provider.resolve_intel(
        job_id="0f8fad5b-d9cb-469f-a165-70867728950e",
        family_id="2f1c0f5e-3d7a-4b6c-9f10-2a4b6c8d0e11",
        request={"target": {"case_id": "cve-2099-0001"}},
    )
    assert result.status == "ready", result
    assert result.snapshot_digest == persisted.snapshot_digest
    assert result.summary["source_url"] == _record()["source_url"]

    # Tampering with the persisted body is caught by the composed verify.
    body_file = tmp_path / persisted.snapshot_path
    os.chmod(body_file, 0o644)
    body_file.write_bytes(b"tampered")
    tampered = provider.resolve_intel(
        job_id="0f8fad5b-d9cb-469f-a165-70867728950e",
        family_id="2f1c0f5e-3d7a-4b6c-9f10-2a4b6c8d0e11",
        request={"target": {"case_id": "cve-2099-0001"}},
    )
    assert tampered.status == "blocked"
    assert tampered.reason_code == "MATERIAL_MISSING"
    assert tampered.summary["sub_reason"] == "DIGEST_MISMATCH"
