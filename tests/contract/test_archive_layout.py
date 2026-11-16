"""B1: evidence bundles are published into generation-scoped directories.

These tests exercise ``_archive`` directly so they run without PostgreSQL. The
database-backed "finish_execution returned False" rollback lives in the
integration suite; here we prove the filesystem layout itself prevents an old
worker from replacing a newer generation.
"""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from uuid import uuid4

from datacon import execution


def _fake_write_bundle(root, **kwargs):
    root = Path(root)
    root.mkdir(parents=True)
    (root / "manifest.json").write_text(
        json.dumps(kwargs["report"]), encoding="utf-8"
    )
    return SimpleNamespace(manifest_digest="sha256:" + "c" * 64)


def _archive_context(job_id, generation, run_root):
    return SimpleNamespace(
        job_id=job_id,
        job_id_text=str(job_id),
        generation=generation,
        plan_digest="sha256:" + "b" * 64,
        run_root=run_root,
    )


def test_old_generation_cannot_replace_a_newer_generation_bundle(
    tmp_path, monkeypatch
):
    evidence_root = tmp_path / "evidence"
    monkeypatch.setenv("DATACON_EVIDENCE_ROOT", str(evidence_root))
    monkeypatch.setenv("DATACON_RUN_ROOT", str(tmp_path / "runs"))
    monkeypatch.delenv("DATACON_JOURNAL_SECRET_FILE", raising=False)
    job_id = uuid4()

    # Both generations pass the fence in this test: the point is to prove the
    # filesystem layout itself prevents cross-generation overwrites even when
    # an old worker resumes after the new one published.
    monkeypatch.setattr(execution.state, "mark_archiving", lambda *a, **k: True)
    monkeypatch.setattr(
        execution.state, "assert_archive_fence", lambda *a, **k: True
    )
    monkeypatch.setattr(execution, "write_bundle", _fake_write_bundle)

    def archive(generation):
        digest, path, error = execution._archive(
            "dsn",
            _archive_context(job_id, generation, tmp_path / "runs"),
            report={"generation": generation},
            report_markdown="",
            artifacts={},
            verdict="FAILED",
        )
        assert error is None, error
        assert digest == "sha256:" + "c" * 64
        return Path(path)

    first = archive(1)
    second = archive(2)
    assert first.name == "generation-1"
    assert second.name == "generation-2"
    assert first.parent == second.parent == evidence_root / str(job_id)
    assert json.loads((second / "manifest.json").read_text())["generation"] == 2

    # The old worker resumes after the new generation published. It may only
    # replace its own generation directory.
    replay = archive(1)
    assert replay == first
    assert json.loads((second / "manifest.json").read_text())["generation"] == 2
    assert json.loads((first / "manifest.json").read_text())["generation"] == 1
    # No flat evidence/<job_id> bundle exists next to the generation dirs.
    assert not (evidence_root / str(job_id) / "manifest.json").exists()


def test_discard_published_bundle_only_removes_one_generation(tmp_path):
    job_root = tmp_path / "evidence" / "job-1"
    first = job_root / "generation-1"
    second = job_root / "generation-2"
    first.mkdir(parents=True)
    second.mkdir(parents=True)
    (second / "manifest.json").write_text("{}", encoding="utf-8")

    execution._discard_published_bundle(str(first))

    assert not first.exists()
    assert (second / "manifest.json").is_file()
    assert job_root.is_dir()
