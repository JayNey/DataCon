"""S-6/S-7 T12: ``datacon export`` must route family identities explicitly.

``export <FAMILY_ID>`` without ``--family`` used to fall through to the
single-bundle path and report ``INVALID_MANIFEST`` from the family index. It is
a request error, not an integrity error. The ``--family`` route is exercised
against recording doubles; the real PostgreSQL status/export shapes live in
``tests/integration/test_family_status.py``.
"""

from __future__ import annotations

import json
from types import SimpleNamespace
from uuid import uuid4

from datacon import cli, evidence, state

FAMILY_ID = "2f1c0f5e-3d7a-4b6c-9f10-2a4b6c8d0e11"
ROUND_ID = "3b7e1f2a-5c6d-4e8f-9012-3456789abcde"
DIGEST = "sha256:" + "52" * 32


def _configure(monkeypatch):
    monkeypatch.setenv("DATACON_DATABASE_URL", "postgresql://unused")
    monkeypatch.setattr(
        state,
        "load_job",
        lambda dsn, job_id: {
            "job_kind": "family",
            "evidence_status": "archived",
            "evidence_path": f"/evidence/{FAMILY_ID}/family.json",
            "evidence_digest": DIGEST,
        },
    )


def _sources():
    return {
        "family_path": f"/evidence/{FAMILY_ID}/family.json",
        "family_digest": DIGEST,
        "campaign": None,
        "rounds": [{"round_no": 1, "source": f"/evidence/{ROUND_ID}", "digest": DIGEST}],
    }


def test_export_family_route_succeeds(monkeypatch, capsys, tmp_path):
    _configure(monkeypatch)
    monkeypatch.setattr(
        state, "family_export_sources", lambda dsn, family_id: _sources()
    )
    seen = {}

    def _export_family(family_index, destination, **kwargs):
        seen.update(
            {
                "family_index": family_index,
                "destination": destination,
                **kwargs,
            }
        )
        return SimpleNamespace(
            root=tmp_path / "out",
            family_digest=DIGEST,
            round_digests={1: DIGEST},
            campaign_digest=None,
        )

    monkeypatch.setattr(evidence, "export_family", _export_family)

    code = cli.main(
        ["export", "--family", FAMILY_ID, "--out", str(tmp_path / "out")]
    )

    assert code == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["family_id"] == FAMILY_ID
    assert payload["rounds"] == {"1": DIGEST}
    assert seen["rounds"] == [(1, f"/evidence/{ROUND_ID}")]


def test_export_positional_family_is_a_request_error(monkeypatch, capsys):
    _configure(monkeypatch)

    code = cli.main(["export", FAMILY_ID, "--out", "out"])

    assert code == 2
    payload = json.loads(capsys.readouterr().err)
    assert payload["reason_code"] == "INVALID_REQUEST"
    assert "--family" in payload["message"]


def test_export_rejects_job_id_and_family_together(monkeypatch, capsys):
    _configure(monkeypatch)

    code = cli.main(
        ["export", FAMILY_ID, "--family", FAMILY_ID, "--out", "out"]
    )

    assert code == 2
    payload = json.loads(capsys.readouterr().err)
    assert payload["reason_code"] == "INVALID_REQUEST"


def test_export_family_rejects_a_non_family_uuid(monkeypatch, capsys):
    _configure(monkeypatch)

    def _not_a_family(dsn, family_id):
        raise state.StateError("job is not a v2 family")

    monkeypatch.setattr(state, "family_export_sources", _not_a_family)

    code = cli.main(["export", "--family", str(uuid4()), "--out", "out"])

    assert code == 3
    payload = json.loads(capsys.readouterr().err)
    assert payload["reason_code"] == "EVIDENCE_NOT_AVAILABLE"


def test_export_family_rejects_unarchived_family(monkeypatch, capsys):
    _configure(monkeypatch)
    monkeypatch.setattr(
        state,
        "load_job",
        lambda dsn, job_id: {
            "job_kind": "family",
            "evidence_status": None,
            "evidence_path": None,
            "evidence_digest": None,
        },
    )

    code = cli.main(["export", "--family", FAMILY_ID, "--out", "out"])

    assert code == 3
    payload = json.loads(capsys.readouterr().err)
    assert payload["reason_code"] == "EVIDENCE_NOT_AVAILABLE"
