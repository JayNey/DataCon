"""CLI entry point for submitting, querying, reviewing and working DataCon jobs."""

from __future__ import annotations

import argparse
import getpass
import json
import os
import re
import sys
from pathlib import Path
from uuid import UUID

import psycopg

from datacon import evidence, state, store, workflow
from datacon.contracts import MAX_REQUEST_BYTES, InvalidRequest, parse_request

_DIGEST = re.compile(r"sha256:[0-9a-f]{64}")


def _error(exit_code: int, reason_code: str, message: str) -> int:
    print(
        json.dumps({"reason_code": reason_code, "message": message}, ensure_ascii=False),
        file=sys.stderr,
    )
    return exit_code


DATABASE_ERROR_MESSAGE = "database operation failed"


def _database_error_message(error: psycopg.Error) -> str:
    """Return a generic database failure message.

    ``psycopg`` error text can embed the full connection URI, including the
    user, password, and host, so it must never reach stderr. Only the SQLSTATE
    (a non-sensitive server-side code) may be appended as extra context.
    """
    sqlstate = getattr(error, "sqlstate", None)
    if sqlstate:
        return f"{DATABASE_ERROR_MESSAGE} (sqlstate: {sqlstate})"
    return DATABASE_ERROR_MESSAGE


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="datacon")
    commands = parser.add_subparsers(dest="command", required=True)

    submit = commands.add_parser("submit", help="validate and enqueue a request")
    submit.add_argument("--request", required=True, type=Path)

    status = commands.add_parser("status", help="look up one job")
    status.add_argument("job_id")

    review = commands.add_parser("review", help="record an operator review decision")
    review.add_argument("job_id")
    review.add_argument("--plan-digest", required=True)
    review.add_argument("--decision", required=True, choices=("approve", "reject"))

    worker = commands.add_parser("worker", help="claim and advance queued jobs")
    worker.add_argument(
        "--once",
        action="store_true",
        help="process at most one claim and exit (used by local acceptance runs)",
    )
    worker.add_argument("--poll-seconds", type=float, default=2.0)
    worker.add_argument(
        "--prepare-only",
        action="store_true",
        help="stop after workflow/review reconciliation (keeps READY jobs unexecuted)",
    )

    export = commands.add_parser("export", help="export the archived evidence bundle")
    export.add_argument("job_id")
    export.add_argument("--out", required=True, type=Path)

    verify = commands.add_parser(
        "verify-bundle", help="verify an evidence bundle offline"
    )
    verify.add_argument("directory", type=Path)
    verify.add_argument("--expected-digest", default=None)
    return parser


def _database_url() -> str | None:
    return os.getenv("DATACON_DATABASE_URL")


def _operator_id() -> str:
    value = os.getenv("DATACON_OPERATOR_ID")
    if value is None:
        try:
            value = getpass.getuser()
        except Exception:  # noqa: BLE001 - local identity fallback
            value = "local-operator"
    value = value.strip()
    if not value or len(value) > 128:
        raise ValueError("operator identity must be between 1 and 128 characters")
    if any(character in value for character in "\x00\r\n"):
        raise ValueError("operator identity contains control characters")
    return value


def _parse_job_id(value: str) -> UUID | None:
    try:
        return UUID(value)
    except (AttributeError, TypeError, ValueError):
        return None


def _submit(args) -> int:
    try:
        size = args.request.stat().st_size
        if size > MAX_REQUEST_BYTES:
            raise ValueError(
                f"request payload exceeds {MAX_REQUEST_BYTES} bytes"
            )
        request = parse_request(args.request.read_text(encoding="utf-8"))
        operator = _operator_id()
    except (InvalidRequest, UnicodeError, OSError, ValueError) as error:
        return _error(2, "INVALID_REQUEST", f"cannot read request: {error}")
    dsn = _database_url()
    if not dsn:
        return _error(1, "DATABASE_NOT_CONFIGURED", "set DATACON_DATABASE_URL")
    try:
        result = store.submit(dsn, request, operator_id=operator)
    except psycopg.Error as error:
        return _error(1, "DATABASE_ERROR", _database_error_message(error))
    except RuntimeError as error:
        return _error(1, "INVALID_CONFIGURATION", str(error))
    print(json.dumps(result, ensure_ascii=False))
    return 0


def _status(args) -> int:
    job_id = _parse_job_id(args.job_id)
    if job_id is None:
        return _error(2, "INVALID_REQUEST", "job_id must be a UUID")
    dsn = _database_url()
    if not dsn:
        return _error(1, "DATABASE_NOT_CONFIGURED", "set DATACON_DATABASE_URL")
    try:
        result = store.status(dsn, job_id)
    except psycopg.Error as error:
        return _error(1, "DATABASE_ERROR", _database_error_message(error))
    if result is None:
        return _error(3, "JOB_NOT_FOUND", "job does not exist")
    print(json.dumps(result, ensure_ascii=False))
    return 0


def _review(args) -> int:
    job_id = _parse_job_id(args.job_id)
    if job_id is None:
        return _error(2, "INVALID_REQUEST", "job_id must be a UUID")
    if not _DIGEST.fullmatch(args.plan_digest):
        return _error(2, "INVALID_REQUEST", "plan_digest must be a sha256 digest")
    try:
        operator = _operator_id()
    except ValueError as error:
        return _error(2, "INVALID_REQUEST", str(error))
    dsn = _database_url()
    if not dsn:
        return _error(1, "DATABASE_NOT_CONFIGURED", "set DATACON_DATABASE_URL")
    try:
        outcome = state.record_review(
            dsn,
            job_id,
            plan_digest=args.plan_digest,
            decision=args.decision,
            reviewer_id=operator,
        )
    except psycopg.Error as error:
        return _error(1, "DATABASE_ERROR", _database_error_message(error))
    except state.StateError as error:
        return _error(3, "REVIEW_ERROR", str(error))

    if outcome.status in ("applied", "idempotent"):
        payload = {
            "job_id": str(job_id),
            "state": outcome.state,
            "decision": outcome.review["decision"] if outcome.review else args.decision,
            "plan_digest": outcome.review["plan_digest"] if outcome.review else args.plan_digest,
            "reviewer_id": outcome.review["reviewer_id"] if outcome.review else operator,
            "idempotent": outcome.status == "idempotent",
        }
        print(json.dumps(payload, ensure_ascii=False))
        return 0
    return _error(3, outcome.reason_code, outcome.message or "review was not recorded")


def _worker(args) -> int:
    dsn = _database_url()
    if not dsn:
        return _error(1, "DATABASE_NOT_CONFIGURED", "set DATACON_DATABASE_URL")
    if not (args.poll_seconds > 0):
        return _error(2, "INVALID_REQUEST", "poll_seconds must be positive")
    try:
        result = workflow.run_worker(
            dsn,
            once=args.once,
            poll_seconds=args.poll_seconds,
            execute=not args.prepare_only,
        )
    except psycopg.Error as error:
        return _error(1, "DATABASE_ERROR", _database_error_message(error))
    except RuntimeError as error:
        return _error(1, "INVALID_CONFIGURATION", str(error))
    print(json.dumps(result, ensure_ascii=False))
    return 0


def _export(args) -> int:
    job_id = _parse_job_id(args.job_id)
    if job_id is None:
        return _error(2, "INVALID_REQUEST", "job_id must be a UUID")
    dsn = _database_url()
    if not dsn:
        return _error(1, "DATABASE_NOT_CONFIGURED", "set DATACON_DATABASE_URL")
    try:
        job = state.load_job(dsn, job_id)
    except psycopg.Error as error:
        return _error(1, "DATABASE_ERROR", _database_error_message(error))
    if job is None:
        return _error(3, "JOB_NOT_FOUND", "job does not exist")
    if (
        job.get("evidence_status") != "archived"
        or not job.get("evidence_path")
        or not job.get("evidence_digest")
    ):
        return _error(
            3,
            "EVIDENCE_NOT_AVAILABLE",
            "no archived evidence bundle is available for this job",
        )
    try:
        verified = evidence.verify_bundle(job["evidence_path"])
    except evidence.BundleError as error:
        return _error(3, error.reason_code, error.message)
    except OSError as error:
        return _error(3, "EVIDENCE_NOT_AVAILABLE", str(error))
    if verified.manifest_digest != job["evidence_digest"]:
        return _error(
            3,
            "EVIDENCE_INTEGRITY_ERROR",
            "the archived bundle digest does not match the trusted task record",
        )
    try:
        exported = evidence.export_bundle(
            verified.root,
            args.out,
            expected_manifest_digest=job["evidence_digest"],
        )
    except evidence.BundleError as error:
        return _error(3, error.reason_code, error.message)
    except OSError as error:
        return _error(3, "EVIDENCE_NOT_AVAILABLE", str(error))
    print(
        json.dumps(
            {
                "job_id": str(job_id),
                "out": str(exported.root),
                "manifest_digest": exported.manifest_digest,
                "files": len(exported.manifest["files"]),
                "verdict": exported.manifest.get("verdict"),
            },
            ensure_ascii=False,
        )
    )
    return 0


def _verify_bundle(args) -> int:
    expected = args.expected_digest
    if expected is not None and not _DIGEST.fullmatch(expected):
        return _error(2, "INVALID_REQUEST", "expected digest must be a sha256 digest")
    try:
        verified = evidence.verify_bundle(args.directory)
    except evidence.BundleError as error:
        return _error(3, error.reason_code, error.message)
    except OSError as error:
        return _error(3, "EVIDENCE_NOT_AVAILABLE", str(error))
    if expected is not None and verified.manifest_digest != expected:
        return _error(
            3,
            "EVIDENCE_INTEGRITY_ERROR",
            "the bundle manifest digest does not match the expected digest",
        )
    print(
        json.dumps(
            {
                "status": "valid",
                "job_id": verified.manifest["job_id"],
                "manifest_digest": verified.manifest_digest,
                "files": len(verified.manifest["files"]),
                "verdict": verified.manifest.get("verdict"),
            },
            ensure_ascii=False,
        )
    )
    return 0


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.command == "submit":
        return _submit(args)
    if args.command == "status":
        return _status(args)
    if args.command == "review":
        return _review(args)
    if args.command == "worker":
        return _worker(args)
    if args.command == "export":
        return _export(args)
    if args.command == "verify-bundle":
        return _verify_bundle(args)
    return _error(2, "INVALID_REQUEST", "unknown command")
