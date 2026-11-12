#!/bin/sh
set -eu

# The replay container mounts /work as the only writable, executable tmpfs.
# clang needs a writable TMPDIR for its temporary files.
export TMPDIR="${TMPDIR:-/work}"

case "${1:-}" in
    vulnerable|fixed) version=$1 ;;
    *) exit 2 ;;
esac

exec clang -std=c11 -g -O0 -fno-omit-frame-pointer -fsanitize=address \
    "/fixture/$version/parser.c" /fixture/harness.c -o /work/parser
