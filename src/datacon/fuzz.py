"""Frozen fuzz material, seed corpus and crash-seed provenance (T12 B, 改9).

This module owns the pure, container-free rules of the guided campaign:

* the repository's fixed libFuzzer shim and its reviewed digest;
* the guided ``harness_digest`` binding of the ``{harness, fuzz_shim}`` pair
  and the ``HARNESS_REJECTED`` checks the executor repeats right before any
  container starts;
* the registered initial seed corpus, its canonical ``seed_corpus_digest`` and
  the security-design §5 corpus ceilings (``POLICY_DENIED`` with a
  ``CORPUS_*`` sub-reason);
* the deterministic libFuzzer RNG seed and the crash-seed provenance record.

A crash seed is only an observation. Nothing here produces a verdict: a seed
becomes a conclusion only through a later six-replay validation round.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
from pathlib import Path, PurePosixPath
from typing import Any, Mapping, Sequence

from datacon import jsonutil


HARNESS_REJECTED = "HARNESS_REJECTED"
POLICY_DENIED = "POLICY_DENIED"

#: Read-only repository material: the only libFuzzer entry point DataCon links.
FUZZ_SHIM_PATH = Path(__file__).resolve().parent / "data" / "fuzz_shim.c"
#: Digest recorded when the shim was reviewed. Any other bytes are rejected.
FUZZ_SHIM_REVIEWED_DIGEST = (
    "sha256:adbf5fdec18be55aaece3c148264e61ebf83cd35e317068302a23323bc2de99f"
)
#: Name the shim is staged under next to the case materials (``/fixture``).
FUZZ_SHIM_STAGED_NAME = "fuzz_shim.c"
#: Default archive names of the two campaign build outputs (delta §5 改9).
PARSER_OUTPUT = "parser"
FUZZER_OUTPUT = "fuzzer"

MIB = 1024 * 1024
CORPUS_MAX_TOTAL_BYTES = 64 * MIB
CORPUS_MAX_FILE_BYTES = 8 * MIB
CORPUS_MAX_FILE_COUNT = 4096
CORPUS_TOTAL_BYTES_EXCEEDED = "CORPUS_TOTAL_BYTES_EXCEEDED"
CORPUS_FILE_BYTES_EXCEEDED = "CORPUS_FILE_BYTES_EXCEEDED"
CORPUS_FILE_COUNT_EXCEEDED = "CORPUS_FILE_COUNT_EXCEEDED"

#: At most this many distinct crash seeds are kept from one campaign.
MAX_CRASH_SEEDS = 8
#: Fixed evidence paths of the campaign fuzz roles.
FUZZ_LOG_PATH = "fuzz/fuzz.log"
FUZZ_PROVENANCE_PATH = "fuzz/provenance.json"
CRASH_SEED_DIRECTORY = "fuzz/crashes"

CRASH_SEED_PROVENANCE_FIELDS = (
    "path",
    "sha256",
    "size_bytes",
    "campaign_job_id",
    "fuzz_log_digest",
    "rng_seed",
)


class HarnessRejected(RuntimeError):
    """The frozen harness or the fixed shim cannot be proven unchanged."""

    reason_code = HARNESS_REJECTED

    def __init__(self, sub_reason: str, message: str) -> None:
        super().__init__(message)
        self.sub_reason = sub_reason
        self.message = message


class CorpusPolicyDenied(RuntimeError):
    """The seed corpus exceeds a security-design §5 ceiling."""

    reason_code = POLICY_DENIED

    def __init__(self, sub_reason: str, message: str) -> None:
        super().__init__(message)
        self.sub_reason = sub_reason
        self.message = message


def load_fuzz_shim(
    path: Path | str = FUZZ_SHIM_PATH,
    *,
    reviewed_digest: str = FUZZ_SHIM_REVIEWED_DIGEST,
) -> bytes:
    """Return the fixed shim bytes, or reject any unreviewed shim."""
    shim = Path(path)
    try:
        if shim.is_symlink() or not shim.is_file():
            raise HarnessRejected(
                "FUZZ_SHIM_MISSING", "the fixed fuzz shim is missing"
            )
        data = shim.read_bytes()
    except OSError as error:
        raise HarnessRejected(
            "FUZZ_SHIM_MISSING", f"the fixed fuzz shim is not readable: {error}"
        ) from error
    actual = jsonutil.digest_bytes(data)
    if actual != reviewed_digest:
        raise HarnessRejected(
            "FUZZ_SHIM_NOT_REVIEWED",
            "the fuzz shim bytes differ from the reviewed shim "
            f"(expected {reviewed_digest}, got {actual})",
        )
    return data


def guided_harness_digest(harness_digest: str, fuzz_shim_digest: str) -> str:
    """Return the guided envelope ``harness_digest`` of the normalized pair."""
    return jsonutil.digest_json(
        {
            "harness": jsonutil.require_digest(harness_digest, "harness"),
            "fuzz_shim": jsonutil.require_digest(fuzz_shim_digest, "fuzz_shim"),
        }
    )


def verify_frozen_harness(
    *,
    harness_bytes: bytes | None,
    registered_harness_digest: str,
    envelope_harness_digest: Any,
    shim_bytes: bytes | None,
    reviewed_shim_digest: str = FUZZ_SHIM_REVIEWED_DIGEST,
) -> dict[str, str]:
    """Prove the exact harness/shim pair the guided envelope approved.

    ``registered_harness_digest`` is the case registry's reviewed harness
    digest. Bytes that are missing, rewritten (for example model-generated) or
    paired with an unreviewed shim are ``HARNESS_REJECTED``; nothing that
    fails here may reach a container. Returns the verified pair.
    """
    if not isinstance(harness_bytes, (bytes, bytearray)):
        raise HarnessRejected("HARNESS_MISSING", "the frozen harness is missing")
    harness_digest = jsonutil.digest_bytes(bytes(harness_bytes))
    if harness_digest != registered_harness_digest:
        raise HarnessRejected(
            "HARNESS_NOT_REVIEWED",
            "the harness bytes differ from the reviewed case harness "
            f"(expected {registered_harness_digest}, got {harness_digest})",
        )
    if not isinstance(shim_bytes, (bytes, bytearray)):
        raise HarnessRejected("FUZZ_SHIM_MISSING", "the fixed fuzz shim is missing")
    shim_digest = jsonutil.digest_bytes(bytes(shim_bytes))
    if shim_digest != reviewed_shim_digest:
        raise HarnessRejected(
            "FUZZ_SHIM_NOT_REVIEWED",
            "the fuzz shim bytes differ from the reviewed shim",
        )
    expected = guided_harness_digest(harness_digest, shim_digest)
    if envelope_harness_digest != expected:
        raise HarnessRejected(
            "HARNESS_PAIR_MISMATCH",
            "the approved harness_digest does not bind this {harness, fuzz_shim} "
            f"pair (expected {expected}, got {envelope_harness_digest!r})",
        )
    return {"harness": harness_digest, "fuzz_shim": shim_digest}


@dataclass(frozen=True)
class SeedCorpusEntry:
    """One registered initial seed: unique file name, material path, digest."""

    name: str
    path: str
    digest: str


def registered_seed_corpus(
    ceilings: Mapping[str, Any] | None,
    *,
    manifest_case: Mapping[str, Any],
    materials: Mapping[str, Any],
) -> list[SeedCorpusEntry]:
    """Return the registry's ``seed_corpus`` (default: the normal+candidate inputs)."""
    declared = None if ceilings is None else ceilings.get("seed_corpus")
    if declared is None:
        inputs = manifest_case.get("inputs")
        if not isinstance(inputs, Mapping):
            raise ValueError("the case has no registered inputs")
        declared = []
        for key in ("normal", "candidate"):
            relative = inputs.get(key)
            if not isinstance(relative, str):
                raise ValueError(f"the case has no {key} input")
            declared.append(
                {
                    "name": PurePosixPath(relative).name,
                    "path": relative,
                    "digest": materials.get(relative),
                }
            )
    if not isinstance(declared, list) or not declared:
        raise ValueError("seed_corpus must be a non-empty array")
    entries: list[SeedCorpusEntry] = []
    names: set[str] = set()
    for index, item in enumerate(declared):
        if not isinstance(item, Mapping) or set(item) != {"name", "path", "digest"}:
            raise ValueError(
                f"seed_corpus[{index}] must have exactly name, path and digest"
            )
        name = item["name"]
        if (
            not isinstance(name, str)
            or not name
            or "/" in name
            or name in (".", "..")
            or name != name.strip()
            or any(ord(character) < 0x20 for character in name)
        ):
            raise ValueError(f"seed_corpus[{index}].name is not a plain file name")
        if name in names:
            raise ValueError(f"seed_corpus[{index}].name {name!r} is duplicated")
        names.add(name)
        path = jsonutil.safe_relative_path(item["path"], f"seed_corpus[{index}].path")
        digest = jsonutil.require_digest(item["digest"], f"seed_corpus[{index}].digest")
        if materials.get(path) != digest:
            raise ValueError(
                f"seed_corpus[{index}] is not a registered case material"
            )
        entries.append(SeedCorpusEntry(name=name, path=path, digest=digest))
    return entries


def seed_corpus_digest(entries: Sequence[SeedCorpusEntry]) -> str:
    """``digest_json(sorted([{name, sha256}], by name))``: names + bytes only."""
    return jsonutil.digest_json(
        sorted(
            ({"name": entry.name, "sha256": entry.digest} for entry in entries),
            key=lambda item: item["name"],
        )
    )


def check_corpus_limits(sizes: Sequence[int]) -> None:
    """Fail closed when a corpus exceeds the §5 count, per-file or total ceiling."""
    if len(sizes) > CORPUS_MAX_FILE_COUNT:
        raise CorpusPolicyDenied(
            CORPUS_FILE_COUNT_EXCEEDED,
            f"seed corpus has {len(sizes)} files; the ceiling is "
            f"{CORPUS_MAX_FILE_COUNT}",
        )
    for size in sizes:
        if size > CORPUS_MAX_FILE_BYTES:
            raise CorpusPolicyDenied(
                CORPUS_FILE_BYTES_EXCEEDED,
                f"a seed corpus file has {size} bytes; the ceiling is "
                f"{CORPUS_MAX_FILE_BYTES}",
            )
    total = sum(sizes)
    if total > CORPUS_MAX_TOTAL_BYTES:
        raise CorpusPolicyDenied(
            CORPUS_TOTAL_BYTES_EXCEEDED,
            f"seed corpus has {total} bytes; the ceiling is "
            f"{CORPUS_MAX_TOTAL_BYTES}",
        )


def campaign_rng_seed(job_id: str, plan_digest: str) -> int:
    """Deterministic libFuzzer ``-seed`` for one campaign plan (never 0)."""
    material = f"datacon-campaign-rng:{job_id}:{plan_digest}".encode("utf-8")
    value = int.from_bytes(hashlib.sha256(material).digest()[:4], "big")
    return value % 2_147_483_646 + 1


def crash_seed_path(index: int) -> str:
    return f"{CRASH_SEED_DIRECTORY}/seed-{index:03d}.bin"


def crash_seed_records(
    crashes: Sequence[bytes],
    *,
    campaign_job_id: str,
    fuzz_log_digest: str,
    rng_seed: int,
) -> list[dict[str, Any]]:
    """Freeze each distinct crash input with its provenance, discovery order."""
    jsonutil.require_digest(fuzz_log_digest, "fuzz_log_digest")
    records: list[dict[str, Any]] = []
    seen: set[str] = set()
    for data in crashes:
        if not isinstance(data, (bytes, bytearray)):
            raise ValueError("a crash seed must be bytes")
        digest = jsonutil.digest_bytes(bytes(data))
        if digest in seen:
            continue
        seen.add(digest)
        if len(records) >= MAX_CRASH_SEEDS:
            break
        records.append(
            {
                "path": crash_seed_path(len(records)),
                "sha256": digest,
                "size_bytes": len(data),
                "campaign_job_id": campaign_job_id,
                "fuzz_log_digest": fuzz_log_digest,
                "rng_seed": rng_seed,
            }
        )
    return records


def validate_crash_seed_record(
    record: Any, *, data: bytes | None = None, campaign_job_id: str | None = None
) -> dict[str, Any]:
    """Require every provenance field; optionally bind the record to its bytes."""
    if not isinstance(record, Mapping):
        raise ValueError("crash seed provenance must be an object")
    missing = [field for field in CRASH_SEED_PROVENANCE_FIELDS if field not in record]
    if missing:
        raise ValueError(
            "crash seed provenance is missing " + ", ".join(missing)
        )
    path = record["path"]
    if not isinstance(path, str) or not path.startswith(CRASH_SEED_DIRECTORY + "/"):
        raise ValueError("crash seed path must live under fuzz/crashes/")
    digest = jsonutil.require_digest(record["sha256"], "crash seed sha256")
    jsonutil.require_digest(record["fuzz_log_digest"], "crash seed fuzz_log_digest")
    if type(record["size_bytes"]) is not int or record["size_bytes"] < 0:
        raise ValueError("crash seed size_bytes must be a non-negative integer")
    if type(record["rng_seed"]) is not int or record["rng_seed"] < 1:
        raise ValueError("crash seed rng_seed must be a positive integer")
    if not isinstance(record["campaign_job_id"], str) or not record["campaign_job_id"]:
        raise ValueError("crash seed campaign_job_id is required")
    if campaign_job_id is not None and record["campaign_job_id"] != campaign_job_id:
        raise ValueError("crash seed belongs to another campaign")
    if data is not None:
        if jsonutil.digest_bytes(data) != digest or len(data) != record["size_bytes"]:
            raise ValueError("crash seed bytes do not match their provenance")
    return dict(record)


def fuzz_provenance_document(
    *,
    campaign_job_id: str,
    plan_digest: str,
    rng_seed: int,
    fuzz_log_digest: str,
    harness_pair: Mapping[str, str],
    seed_corpus_digest_value: str,
    fuzzer_digests: Mapping[str, str],
    max_total_time_seconds: int,
    status: str,
    exit_code: int | None,
    crash_seeds: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    """The ``fuzz_provenance`` document archived at ``fuzz/provenance.json``."""
    return {
        "schema_version": 1,
        "engine": "libfuzzer",
        "campaign_job_id": campaign_job_id,
        "plan_digest": plan_digest,
        "rng_seed": rng_seed,
        "fuzz_log_digest": fuzz_log_digest,
        "harness_digest": dict(harness_pair),
        "fuzz_shim_digest": harness_pair["fuzz_shim"],
        "seed_corpus_digest": seed_corpus_digest_value,
        "fuzzer_digests": dict(fuzzer_digests),
        "max_total_time_seconds": max_total_time_seconds,
        "status": status,
        "exit_code": exit_code,
        "crash_count": len(crash_seeds),
        "crash_seeds": [dict(item) for item in crash_seeds],
    }


__all__ = [
    "CORPUS_FILE_BYTES_EXCEEDED",
    "CORPUS_FILE_COUNT_EXCEEDED",
    "CORPUS_MAX_FILE_BYTES",
    "CORPUS_MAX_FILE_COUNT",
    "CORPUS_MAX_TOTAL_BYTES",
    "CORPUS_TOTAL_BYTES_EXCEEDED",
    "CRASH_SEED_DIRECTORY",
    "CorpusPolicyDenied",
    "FUZZER_OUTPUT",
    "FUZZ_LOG_PATH",
    "FUZZ_PROVENANCE_PATH",
    "FUZZ_SHIM_PATH",
    "FUZZ_SHIM_REVIEWED_DIGEST",
    "FUZZ_SHIM_STAGED_NAME",
    "HARNESS_REJECTED",
    "HarnessRejected",
    "MAX_CRASH_SEEDS",
    "PARSER_OUTPUT",
    "SeedCorpusEntry",
    "campaign_rng_seed",
    "check_corpus_limits",
    "crash_seed_path",
    "crash_seed_records",
    "fuzz_provenance_document",
    "guided_harness_digest",
    "load_fuzz_shim",
    "registered_seed_corpus",
    "seed_corpus_digest",
    "validate_crash_seed_record",
    "verify_frozen_harness",
]
