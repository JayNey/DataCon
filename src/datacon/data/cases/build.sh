#!/bin/sh
set -eu

# The replay container mounts /work as the only writable, executable tmpfs.
# clang needs a writable TMPDIR for its temporary files.
export TMPDIR="${TMPDIR:-/work}"

case "${1:-}" in
    vulnerable|fixed) version=$1 ;;
    *) exit 2 ;;
esac

clang -std=c11 -g -O0 -fno-omit-frame-pointer -fsanitize=address \
    "/fixture/$version/parser.c" /fixture/harness.c -o /work/parser

# A guided campaign stages the repository's fixed libFuzzer shim next to the
# frozen materials. The same build then links the fuzzer from the unchanged
# harness (its main renamed for libFuzzer) and the reviewed shim.
if [ -f /fixture/fuzz_shim.c ]; then
    clang -std=c11 -g -O1 -fno-omit-frame-pointer -fsanitize=fuzzer,address \
        -Dmain=datacon_harness_main \
        "/fixture/$version/parser.c" /fixture/harness.c /fixture/fuzz_shim.c \
        -o /work/fuzzer
fi
