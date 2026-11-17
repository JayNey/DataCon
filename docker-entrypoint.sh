#!/bin/sh
# DataCon container entry point.
#
# The worker requires the journal HMAC secret. Help output must stay usable
# without mounted secrets (image smoke tests and read-only diagnostics), but an
# actual worker/run start fails closed with an actionable message when the
# secret file is missing or unreadable.
set -eu

for arg in "$@"; do
    case "$arg" in
        --help|-h)
            exec datacon "$@"
            ;;
    esac
done

case "${1:-}" in
    worker|run)
        secret_file="${DATACON_JOURNAL_SECRET_FILE:-}"
        if [ -z "$secret_file" ]; then
            echo "datacon: DATACON_JOURNAL_SECRET_FILE is not set" >&2
            exit 2
        fi
        if [ ! -r "$secret_file" ]; then
            echo "datacon: journal secret file is missing or unreadable: $secret_file" >&2
            exit 2
        fi
        if [ ! -s "$secret_file" ]; then
            echo "datacon: journal secret file is empty: $secret_file" >&2
            exit 2
        fi
        ;;
esac

exec datacon "$@"
