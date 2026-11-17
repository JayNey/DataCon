"""CI merge-gate validators for DataCon (REQ-10, TC-09, TC-10).

Provides deterministic, offline-testable checks for:
- Markdown relative links
- REQ-01..REQ-10 and TC-01..TC-10 reference consistency
- Contract examples (examples/request.json)
- Dependency lock consistency (uv.lock, pyproject.toml, requirements-ci.txt)
- GitHub Actions workflow pinning (40-char commit SHA) & least privilege
- JUnit XML zero-skip / zero-failure gates
- Secret scanning & structured vulnerability waiver validation
"""

from __future__ import annotations

from datetime import date
import json
from pathlib import Path
import re
from typing import Any, Iterable, Sequence
import xml.etree.ElementTree as ET

from datacon.contracts import InvalidRequest, parse_request

VALID_REQS = frozenset(f"REQ-{i:02d}" for i in range(1, 11))
VALID_TCS = frozenset(f"TC-{i:02d}" for i in range(1, 11))

_MD_LINK = re.compile(r"\[[^\]]*\]\(([^)]+)\)")
_REQ_REF = re.compile(r"\bREQ-[0-9]{2}\b")
_TC_REF = re.compile(r"\bTC-[0-9]{2}\b")
_ACTION_USES = re.compile(r"^\s*(?:-\s*)?uses:\s*([^\s#]+)")
_ACTION_SHA = re.compile(r"^[^@]+@[0-9a-f]{40}$")
_ISO_DATE = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}$")

_SECRET_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("private_key", re.compile(r"-----BEGIN (?:RSA |OPENSSH |EC |PGP )?PRIVATE KEY-----")),
    ("postgres_password_uri", re.compile(r"postgres(?:ql)?://[^:\s]+:[^@\s$\{]+@")),
    ("github_pat", re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{20,}\b")),
    ("aws_access_key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
)

_REQUIRED_WAIVER_FIELDS = frozenset({"id", "scope", "impact", "owner", "expires_at"})
_BLOCKING_SEVERITIES = frozenset({"CRITICAL", "HIGH"})


class GateError(RuntimeError):
    """A CI merge gate failed closed."""


def check_markdown_links(
    files: Iterable[Path], *, root: Path
) -> list[str]:
    """Return error strings for any broken relative Markdown link."""
    errors: list[str] = []
    resolved_root = root.resolve()
    for path in files:
        text = path.read_text(encoding="utf-8")
        in_fence = False
        for line_no, line in enumerate(text.splitlines(), start=1):
            stripped = line.strip()
            if stripped.startswith("```"):
                in_fence = not in_fence
                continue
            if in_fence:
                continue
            for match in _MD_LINK.finditer(line):
                raw_target = match.group(1).strip()
                if not raw_target or raw_target.startswith(("#", "http://", "https://", "mailto:")):
                    continue
                target_part = raw_target.split("#", 1)[0].strip()
                if not target_part:
                    continue
                candidate = (path.parent / target_part).resolve()
                if candidate != resolved_root and resolved_root not in candidate.parents:
                    errors.append(f"{path}:{line_no}: link escapes repository root: {raw_target}")
                    continue
                if not candidate.exists():
                    errors.append(f"{path}:{line_no}: broken relative link: {raw_target}")
    return errors


def check_req_tc_consistency(files: Iterable[Path]) -> list[str]:
    """Verify all REQ-XX and TC-XX references belong to REQ-01..10 / TC-01..10."""
    errors: list[str] = []
    for path in files:
        text = path.read_text(encoding="utf-8")
        for req in sorted(set(_REQ_REF.findall(text))):
            if req not in VALID_REQS:
                errors.append(f"{path}: unknown requirement reference {req}")
        for tc in sorted(set(_TC_REF.findall(text))):
            if tc not in VALID_TCS:
                errors.append(f"{path}: unknown test-case reference {tc}")
    return errors


def check_workflow_security(files: Iterable[Path]) -> list[str]:
    """Enforce 40-char SHA action pinning, least privilege, and no continue-on-error."""
    errors: list[str] = []
    for path in files:
        text = path.read_text(encoding="utf-8")
        has_contents_read = "contents: read" in text
        if "write-all" in text or "contents: write" in text:
            errors.append(f"{path}: excessive workflow permissions detected")
        if not has_contents_read:
            errors.append(f"{path}: workflow must declare 'contents: read' permissions")
        for line_no, line in enumerate(text.splitlines(), start=1):
            if "continue-on-error: true" in line.replace(" ", "").replace(":", ": "):
                if re.search(r"continue-on-error\s*:\s*true", line):
                    errors.append(f"{path}:{line_no}: continue-on-error: true is forbidden")
            uses_match = _ACTION_USES.match(line)
            if uses_match:
                ref = uses_match.group(1)
                if ref.startswith("./"):
                    continue
                if not _ACTION_SHA.fullmatch(ref):
                    errors.append(
                        f"{path}:{line_no}: action '{ref}' must be pinned to a 40-char commit SHA"
                    )
    return errors


def check_junit_report(path: Path, *, label: str) -> dict[str, Any]:
    """Fail closed if a JUnit report has 0 tests, any skipped, or any failure/error."""
    if not path.is_file():
        raise GateError(f"JUnit report missing for {label}: {path}")
    root = ET.parse(path).getroot()
    suites = [root] if root.tag == "testsuite" else root.findall("testsuite")
    total = sum(int(suite.get("tests", 0)) for suite in suites)
    skipped = sum(int(suite.get("skipped", 0)) for suite in suites)
    failures = sum(int(suite.get("failures", 0)) for suite in suites)
    errors = sum(int(suite.get("errors", 0)) for suite in suites)
    if total == 0:
        raise GateError(f"the {label} suite did not run any tests")
    if skipped or failures or errors:
        raise GateError(
            f"CI requires the {label} suite to pass with zero skips "
            f"(total={total} skipped={skipped} failures={failures} errors={errors})"
        )
    return {
        "label": label,
        "total": total,
        "skipped": skipped,
        "failures": failures,
        "errors": errors,
    }


def evaluate_scan_findings(
    findings: Sequence[dict[str, Any]],
    *,
    waivers: Sequence[dict[str, Any]] = (),
    today: str | None = None,
) -> dict[str, int]:
    """Block unwaived CRITICAL/HIGH findings; validate structured waivers."""
    current_day = date.fromisoformat(today) if today else date.today()
    waiver_map: dict[str, dict[str, Any]] = {}
    for entry in waivers:
        if not isinstance(entry, dict):
            raise GateError("waiver entry must be an object")
        missing = sorted(_REQUIRED_WAIVER_FIELDS - set(entry))
        if missing:
            raise GateError(
                f"waiver {entry.get('id', '<unknown>')} is missing required fields: {', '.join(missing)}"
            )
        for field in _REQUIRED_WAIVER_FIELDS:
            val = entry.get(field)
            if not isinstance(val, str) or not val.strip():
                raise GateError(f"waiver field {field} must be a non-empty string")
        expires_raw = entry["expires_at"].strip()
        if not _ISO_DATE.fullmatch(expires_raw):
            raise GateError(f"waiver {entry['id']} expires_at must be YYYY-MM-DD")
        expires = date.fromisoformat(expires_raw)
        if expires < current_day:
            raise GateError(f"waiver {entry['id']} is expired ({expires_raw})")
        waiver_map[entry["id"]] = entry

    blocked = 0
    waived = 0
    for finding in findings:
        severity = str(finding.get("severity", "")).upper()
        fid = str(finding.get("id", ""))
        if severity in _BLOCKING_SEVERITIES:
            if fid in waiver_map:
                waived += 1
            else:
                blocked += 1
                raise GateError(
                    f"unwaived {severity} vulnerability finding: {fid}"
                )
    return {"total": len(findings), "blocked": blocked, "waived": waived}


def scan_secrets(files: Iterable[Path]) -> list[str]:
    """Scan text files for leaked credentials or private keys."""
    hits: list[str] = []
    for path in files:
        if not path.is_file():
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        for line_no, line in enumerate(text.splitlines(), start=1):
            for name, pattern in _SECRET_PATTERNS:
                if pattern.search(line):
                    hits.append(f"{path}:{line_no}: potential secret ({name})")
    return hits


def check_dependency_lock(root: Path) -> list[str]:
    """Verify pyproject.toml, requirements-ci.txt, and uv.lock agree on uv==0.12.7."""
    errors: list[str] = []
    pyproject = (root / "pyproject.toml").read_text(encoding="utf-8")
    req_ci = (root / "requirements-ci.txt").read_text(encoding="utf-8")
    uv_lock = root / "uv.lock"
    if not uv_lock.is_file() or uv_lock.stat().st_size == 0:
        errors.append("uv.lock is missing or empty")
    if 'required-version = "==0.12.7"' not in pyproject:
        errors.append("pyproject.toml must pin tool.uv.required-version == 0.12.7")
    if 'uv_build==0.12.7' not in pyproject:
        errors.append("pyproject.toml must pin build-system uv_build==0.12.7")
    if "uv==0.12.7 --hash=sha256:" not in req_ci:
        errors.append("requirements-ci.txt must pin uv==0.12.7 with sha256 hash")
    return errors


def check_contract_examples(root: Path) -> list[str]:
    """Validate repository contract example payloads."""
    errors: list[str] = []
    example = root / "examples" / "request.json"
    if not example.is_file():
        return [f"missing contract example: {example}"]
    try:
        parse_request(example.read_text(encoding="utf-8"))
    except (InvalidRequest, OSError, UnicodeError) as error:
        errors.append(f"{example}: invalid contract example: {error}")
    return errors


def run_repo_static_gates(root: Path) -> dict[str, Any]:
    """Run all T07 repository static merge gates and return a structured report."""
    md_files = [
        path
        for path in [root / "README.md", *sorted((root / "tests").rglob("*.md"))]
        if path.is_file()
    ]
    workflow_files = sorted((root / ".github" / "workflows").glob("*.yml"))
    tracked_source = [
        *sorted((root / "src").rglob("*.py")),
        *sorted((root / "migrations").glob("*.sql")),
        *workflow_files,
        root / "README.md",
        root / "pyproject.toml",
        root / "requirements-ci.txt",
    ]
    errors: list[str] = []
    errors.extend(check_markdown_links(md_files, root=root))
    errors.extend(check_req_tc_consistency(md_files))
    errors.extend(check_workflow_security(workflow_files))
    errors.extend(check_dependency_lock(root))
    errors.extend(check_contract_examples(root))
    errors.extend(scan_secrets(tracked_source))
    return {
        "ok": not errors,
        "errors": errors,
        "checked_markdown": len(md_files),
        "checked_workflows": len(workflow_files),
    }


def main(argv: list[str] | None = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(prog="datacon-ci-gates")
    parser.add_argument("--root", type=Path, default=Path("."))
    args = parser.parse_args(argv)
    report = run_repo_static_gates(args.root.resolve())
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
