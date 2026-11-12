"""CLI entry point for submitting and querying DataCon jobs."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from uuid import UUID

import psycopg

from datacon import store
from datacon.contracts import InvalidRequest, parse_request


def _error(exit_code: int, reason_code: str, message: str) -> int:
    print(
        json.dumps({"reason_code": reason_code, "message": message}, ensure_ascii=False),
        file=sys.stderr,
    )
    return exit_code


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="datacon")
    commands = parser.add_subparsers(dest="command", required=True)

    submit = commands.add_parser("submit", help="validate and enqueue a request")
    submit.add_argument("--request", required=True, type=Path)

    status = commands.add_parser("status", help="look up one job")
    status.add_argument("job_id")
    return parser


def _database_url() -> str | None:
    return os.getenv("DATACON_DATABASE_URL")


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)

    if args.command == "submit":
        try:
            request = parse_request(args.request.read_text(encoding="utf-8"))
        except (InvalidRequest, UnicodeError, OSError) as error:
            return _error(2, "INVALID_REQUEST", f"cannot read request: {error}")
        dsn = _database_url()
        if not dsn:
            return _error(1, "DATABASE_NOT_CONFIGURED", "set DATACON_DATABASE_URL")
        try:
            result = store.submit(dsn, request)
        except psycopg.Error as error:
            return _error(1, "DATABASE_ERROR", f"database operation failed: {error}")
        print(json.dumps(result, ensure_ascii=False))
        return 0

    try:
        job_id = UUID(args.job_id)
    except (AttributeError, TypeError, ValueError):
        return _error(2, "INVALID_REQUEST", "job_id must be a UUID")

    dsn = _database_url()
    if not dsn:
        return _error(1, "DATABASE_NOT_CONFIGURED", "set DATACON_DATABASE_URL")
    try:
        result = store.status(dsn, job_id)
    except psycopg.Error as error:
        return _error(1, "DATABASE_ERROR", f"database operation failed: {error}")
    if result is None:
        return _error(3, "JOB_NOT_FOUND", "job does not exist")
    print(json.dumps(result, ensure_ascii=False))
    return 0
