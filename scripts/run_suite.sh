#!/usr/bin/env bash
set -uo pipefail

if [ "$#" -ne 3 ]; then
  echo "usage: $0 <marker> <label> <report_path>" >&2
  exit 2
fi

marker="$1"
label="$2"
report="$3"

mkdir -p "$(dirname "$report")"

uv run --frozen pytest -q -m "$marker" -rs --junitxml="$report"
pytest_rc=$?

uv run --frozen python - "$report" "$label" <<'PY'
import pathlib
import sys
from datacon.ci_gates import check_junit_report

summary = check_junit_report(pathlib.Path(sys.argv[1]), label=sys.argv[2])
print(
    f"{summary['label']}: total={summary['total']} skipped={summary['skipped']} "
    f"failures={summary['failures']} errors={summary['errors']}"
)
PY
junit_rc=$?

if [ "$pytest_rc" -ne 0 ] || [ "$junit_rc" -ne 0 ]; then
  exit 1
fi
exit 0
