"""CI merge-gate validators for DataCon (REQ-10, TC-09, TC-10).

All workflow checks parse YAML instead of searching text, so a commented
``contents: read`` cannot satisfy least privilege. Secret scanning walks the
whole tracked tree (including tests, examples, Dockerfile and uv.lock). The
vulnerability scan gate consumes a real scanner JSON report; when the report
is absent in a path that requires it the gate fails closed.
"""

from __future__ import annotations

from datetime import date
import json
import os
from pathlib import Path
import re
from typing import Any, Iterable, Mapping, Sequence
import tomllib
import xml.etree.ElementTree as ET

import yaml

from datacon import jsonutil
from datacon.contracts import InvalidRequest, parse_request

VALID_REQS = frozenset(f"REQ-{i:02d}" for i in range(1, 11))
VALID_TCS = frozenset(f"TC-{i:02d}" for i in range(1, 11))

_MD_LINK = re.compile(r"\[[^\]]*\]\(([^)]+)\)")
_REQ_REF = re.compile(r"\bREQ-[0-9]{2}\b")
_TC_REF = re.compile(r"\bTC-[0-9]{2}\b")
_ACTION_SHA = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+@[0-9a-f]{40}")
_REUSABLE_WORKFLOW_SHA = re.compile(
    r"[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)+@[0-9a-f]{40}"
)
_UNTRUSTED_RUN_EXPR_TOKENS = (
    "github.event",
    "inputs.",
    "github.head_ref",
    "github.ref_name",
    "github.base_ref",
    "steps.",
    "steps[",
    "needs.",
    "needs[",
)
_DOCKER_DIGEST = re.compile(r"docker://[^\s@]+@sha256:[0-9a-f]{64}")
_RUN_EXPRESSION = re.compile(r"\$\{\{(.*?)\}\}", re.S)
_ISO_DATE = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}$")
_UV_REQUIREMENT = re.compile(r"uv==0\.12\.7 --hash=sha256:[0-9a-f]{64}")
_SHA256 = re.compile(r"sha256:[0-9a-f]{64}")

_ALLOWED_PERMISSIONS = {
    "contents": "read",
    "actions": "read",
}
_FORBIDDEN_PERMISSION_KEYS = frozenset(
    {
        "id-token",
        "packages",
        "security-events",
        "pull-requests",
        "issues",
        "deployments",
        "checks",
        "statuses",
        "attestations",
        "artifact-metadata",
    }
)
_WORKFLOW_EXCLUDED_DIRS = frozenset(
    {
        ".git",
        ".venv",
        "node_modules",
        "dist",
        "build",
        "__pycache__",
        ".review",
        ".pytest_cache",
        ".mypy_cache",
        ".ruff_cache",
    }
)

_SECRET_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("private_key", re.compile(r"-----BEGIN (?:RSA |OPENSSH |EC |PGP )?PRIVATE KEY-----")),
    ("postgres_password_uri", re.compile(r"postgres(?:ql)?://[^:\s]+:[^@\s$\{]+@")),
    ("github_pat", re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{20,}\b")),
    ("aws_access_key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    (
        "aws_secret_access_key",
        re.compile(
            r"(?i)aws_secret_access_key\s*[=:]\s*['\"]?[A-Za-z0-9/+=]{32,}"
        ),
    ),
    ("password_assignment", re.compile(r"(?i)\bpassword\s*[=:]\s*['\"][^'\"]{4,}['\"]")),
    ("token_assignment", re.compile(r"(?i)\btoken\s*[=:]\s*['\"][^'\"]{8,}['\"]")),
)

_REQUIRED_WAIVER_FIELDS = frozenset({"id", "scope", "impact", "owner", "expires_at"})
_BLOCKING_SEVERITIES = frozenset({"CRITICAL", "HIGH"})


class GateError(RuntimeError):
    """A CI merge gate failed closed."""


def check_markdown_links(files: Iterable[Path], *, root: Path) -> list[str]:
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


def _load_workflow(path: Path) -> Any:
    try:
        document = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as error:
        raise GateError(f"{path}: workflow is not valid YAML: {error}") from error
    if not isinstance(document, Mapping):
        raise GateError(f"{path}: workflow must be a YAML mapping")
    return document


def _workflow_trigger(document: Mapping[str, Any]) -> Any:
    # PyYAML resolves the unquoted key ``on`` as the boolean True (YAML 1.1).
    return document.get("on", document.get(True))


def _check_permissions(
    value: Any,
    *,
    path: Path,
    label: str,
    errors: list[str],
    require_contents: bool = False,
) -> None:
    if not isinstance(value, Mapping):
        errors.append(f"{path}: {label} permissions must be a mapping")
        return
    if require_contents and "contents" not in value:
        errors.append(f"{path}: {label} permissions must declare contents: read")
    for key, level in value.items():
        if not isinstance(key, str):
            errors.append(f"{path}: {label} permission key must be a string")
            continue
        if key in _FORBIDDEN_PERMISSION_KEYS:
            errors.append(f"{path}: {label} permission '{key}' is not allowed (write permissions are forbidden)")
            continue
        if key not in _ALLOWED_PERMISSIONS:
            errors.append(f"{path}: {label} permission '{key}' is not allowed")
            continue
        allowed = _ALLOWED_PERMISSIONS[key]
        if not isinstance(level, str) or level.strip().lower() != allowed:
            errors.append(
                f"{path}: {label} permission '{key}' must be '{allowed}', got {level!r}"
            )


def _walk_yaml(
    value: Any, _seen: set[int] | None = None
) -> Iterable[tuple[str, Any]]:
    """Walk a parsed YAML value, converting anchor cycles into GateError.

    PyYAML can build a self-referential list/mapping from an anchor such as
    ``x: &a [*a]``. Recursing into it raises ``RecursionError`` and aborts the
    gate; detecting the container identity first turns it into a deterministic
    failure instead.
    """
    seen = _seen if _seen is not None else set()
    if isinstance(value, Mapping):
        marker = id(value)
        if marker in seen:
            raise GateError("workflow contains a circular YAML reference")
        seen.add(marker)
        try:
            for key, item in value.items():
                yield str(key), item
                yield from _walk_yaml(item, seen)
        finally:
            seen.discard(marker)
    elif isinstance(value, list):
        marker = id(value)
        if marker in seen:
            raise GateError("workflow contains a circular YAML reference")
        seen.add(marker)
        try:
            for item in value:
                yield from _walk_yaml(item, seen)
        finally:
            seen.discard(marker)


def _continue_on_error_is_true(value: Any) -> bool:
    if value is False:
        return False
    if isinstance(value, str) and value.strip().lower() == "false":
        return False
    return True


def _untrusted_expressions(text: str) -> list[str]:
    found: list[str] = []
    for match in _RUN_EXPRESSION.finditer(text):
        expression = match.group(1).lower()
        if any(token in expression for token in _UNTRUSTED_RUN_EXPR_TOKENS):
            found.append(expression.strip())
    return found


def _check_run_expressions(text: str) -> list[str]:
    errors: list[str] = []
    for expression in _untrusted_expressions(text):
        errors.append(
            "run: contains an untrusted '${{ ... }}' expression "
            f"({expression}); pass it through env: instead"
        )
    return errors


def _check_with_expressions(with_block: Any) -> list[str]:
    """Reject attacker-controlled expressions interpolated into action inputs.

    ``env:`` is the supported boundary for untrusted values: the workflow may
    put ``${{ github.event... }}`` in ``env`` and reference the variable from
    ``run``. Passing the same expression straight into an action's ``with:``
    (for example ``actions/github-script``'s ``script:``) is injection, so it
    is rejected while constant and safe references stay valid.
    """
    errors: list[str] = []
    for key, value in _walk_yaml(with_block):
        if not isinstance(value, str):
            continue
        for expression in _untrusted_expressions(value):
            errors.append(
                f"with.{key} contains an untrusted '${{{{ ... }}}}' expression "
                f"({expression}); pass it through env: instead"
            )
    return errors


def check_workflow_security(files: Iterable[Path]) -> list[str]:
    """Parse each workflow and enforce secure permissions, pins and triggers."""
    errors: list[str] = []
    for path in files:
        document = _load_workflow(path)
        trigger = _workflow_trigger(document)
        trigger_text = json.dumps(trigger, default=str) if not isinstance(trigger, str) else trigger
        if "pull_request_target" in trigger_text:
            errors.append(f"{path}: pull_request_target is forbidden")
        if "permissions" not in document:
            errors.append(f"{path}: workflow must declare 'contents: read' permissions")
        else:
            _check_permissions(
                document["permissions"],
                path=path,
                label="workflow",
                errors=errors,
                require_contents=True,
            )

        jobs = document.get("jobs")
        if not isinstance(jobs, Mapping):
            errors.append(f"{path}: workflow must declare a jobs mapping")
            jobs = {}
        for job_name, job in jobs.items():
            if not isinstance(job, Mapping):
                errors.append(f"{path}: job {job_name} must be a mapping")
                continue
            if "permissions" in job:
                _check_permissions(
                    job["permissions"],
                    path=path,
                    label=f"job {job_name}",
                    errors=errors,
                )
            try:
                for key, value in _walk_yaml(job):
                    if key == "continue-on-error" and _continue_on_error_is_true(value):
                        errors.append(
                            f"{path}: job {job_name} uses continue-on-error: {value!r}"
                        )
            except GateError as error:
                errors.append(f"{path}: job {job_name}: {error}")
                continue
            job_with = job.get("with")
            if job_with is not None:
                try:
                    for problem in _check_with_expressions(job_with):
                        errors.append(f"{path}: job {job_name}: {problem}")
                except GateError as error:
                    errors.append(f"{path}: job {job_name}: {error}")
            job_uses = job.get("uses")
            if job_uses is not None:
                if not isinstance(job_uses, str):
                    errors.append(f"{path}: job {job_name} uses must be a string")
                elif job_uses.startswith("./"):
                    if ".." in Path(job_uses).parts:
                        errors.append(
                            f"{path}: job {job_name} local reusable workflow '{job_uses}' "
                            "must not traverse parent directories"
                        )
                elif not _REUSABLE_WORKFLOW_SHA.fullmatch(job_uses):
                    errors.append(
                        f"{path}: job {job_name} reusable workflow '{job_uses}' "
                        "must be pinned to a 40-char commit SHA"
                    )
            steps = job.get("steps")
            if not isinstance(steps, list):
                continue
            for index, step in enumerate(steps):
                if not isinstance(step, Mapping):
                    errors.append(f"{path}: job {job_name} step {index} must be a mapping")
                    continue
                with_block = step.get("with")
                uses = step.get("uses")
                if uses is not None:
                    if not isinstance(uses, str):
                        errors.append(f"{path}: job {job_name} step {index} uses must be a string")
                    elif uses.startswith("./"):
                        pass
                    elif uses.startswith("docker://"):
                        if not _DOCKER_DIGEST.fullmatch(uses):
                            errors.append(
                                f"{path}: job {job_name} step {index} docker action "
                                f"'{uses}' must be pinned to a sha256 digest"
                            )
                    elif not _ACTION_SHA.fullmatch(uses):
                        errors.append(
                            f"{path}: job {job_name} step {index} action '{uses}' "
                            "must be pinned to a 40-char commit SHA"
                        )
                    if isinstance(uses, str) and uses.startswith("actions/checkout"):
                        if isinstance(with_block, Mapping):
                            ref = with_block.get("ref")
                            if isinstance(ref, str):
                                lowered = ref.lower()
                                if (
                                    "${{" in lowered
                                    or "github.event" in lowered
                                    or "inputs." in lowered
                                ):
                                    errors.append(
                                        f"{path}: job {job_name} step {index} "
                                        "checkout ref comes from an expression; "
                                        "pin a literal ref instead"
                                    )
                if with_block is not None:
                    try:
                        for problem in _check_with_expressions(with_block):
                            errors.append(
                                f"{path}: job {job_name} step {index}: {problem}"
                            )
                    except GateError as error:
                        errors.append(f"{path}: job {job_name} step {index}: {error}")
                run_text = step.get("run")
                if isinstance(run_text, str):
                    for problem in _check_run_expressions(run_text):
                        errors.append(f"{path}: job {job_name} step {index}: {problem}")
    return errors


def _junit_count(element: Any, attribute: str, label: str) -> int:
    raw = element.get(attribute)
    if raw is None or raw.strip() == "":
        return 0
    try:
        value = int(raw)
    except (TypeError, ValueError) as error:
        raise GateError(
            f"JUnit report {label} has a non-integer {attribute} attribute: {raw!r}"
        ) from error
    if value < 0:
        raise GateError(
            f"JUnit report {label} has a negative {attribute} attribute: {raw!r}"
        )
    return value


def check_junit_report(path: Path, *, label: str) -> dict[str, Any]:
    """Fail closed if a JUnit report is empty, skipped, failed, or contradictory.

    The check walks every ``testsuite`` (including nested ``testsuites``),
    counts the real ``<testcase>`` elements, and requires the element-level
    ``<failure>``/``<error>``/``<skipped>`` nodes to agree with the suite
    attributes. A report whose attributes claim zero failures while a testcase
    carries a ``<failure>`` child is rejected.
    """
    if not path.is_file():
        raise GateError(f"JUnit report missing for {label}: {path}")
    try:
        root = ET.parse(path).getroot()
    except (ET.ParseError, OSError) as error:
        raise GateError(f"JUnit report cannot be parsed for {label}: {error}") from error
    suites = list(root.iter("testsuite"))
    if not suites:
        raise GateError(f"the {label} suite did not run any tests")
    total = sum(_junit_count(suite, "tests", label) for suite in suites)
    skipped = sum(_junit_count(suite, "skipped", label) for suite in suites)
    failures = sum(_junit_count(suite, "failures", label) for suite in suites)
    errors = sum(_junit_count(suite, "errors", label) for suite in suites)
    testcases = list(root.iter("testcase"))
    # Count the element-level result nodes across the whole document, including
    # nested testsuites and failure/error children placed directly on a suite.
    child_skipped = sum(1 for _ in root.iter("skipped"))
    child_failures = sum(1 for _ in root.iter("failure"))
    child_errors = sum(1 for _ in root.iter("error"))
    if total == 0 or not testcases:
        raise GateError(f"the {label} suite did not run any tests")
    if len(testcases) != total:
        raise GateError(
            f"JUnit report {label} is contradictory: tests={total} but "
            f"testcase elements={len(testcases)}"
        )
    if (child_skipped, child_failures, child_errors) != (skipped, failures, errors):
        raise GateError(
            f"JUnit report {label} attributes disagree with testcase children "
            f"(attributes: skipped={skipped} failures={failures} errors={errors}; "
            f"children: skipped={child_skipped} failures={child_failures} "
            f"errors={child_errors})"
        )
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


def _waiver_scope_matches(scope: str, finding: dict[str, str]) -> bool:
    """Match a waiver scope against a finding's package or scan target.

    Supported forms are ``package:<name>``, the bare package name, ``target:``
    plus the scan target, and the bare target string. Any other human-readable
    scope is documentation only and never waives a finding.
    """
    normalized = scope.strip()
    lowered = normalized.lower()
    package = str(finding.get("package", "")).strip()
    target = str(finding.get("target", "")).strip()
    if lowered.startswith("package:"):
        return package.strip().lower() == normalized.split(":", 1)[1].strip().lower()
    if lowered.startswith("target:"):
        return target == normalized.split(":", 1)[1].strip()
    if not normalized:
        return False
    return normalized == package or normalized == target


def evaluate_scan_findings(
    findings: Sequence[dict[str, Any]],
    *,
    waivers: Sequence[dict[str, Any]] = (),
    today: str | None = None,
) -> dict[str, int]:
    """Block unwaived CRITICAL/HIGH findings; validate structured waivers.

    A waiver is bound to ``(id, scope)``. A waiver for ``pkg-a`` therefore
    cannot silence the same CVE on ``openssl``. Duplicate ``(id, scope)``
    entries are rejected as a conflicting waiver set.
    """
    try:
        current_day = date.fromisoformat(today) if today else date.today()
    except ValueError as error:
        raise GateError(f"invalid evaluation date {today!r}") from error
    waiver_scopes: dict[str, list[dict[str, Any]]] = {}
    seen_scopes: set[tuple[str, str]] = set()
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
        try:
            expires = date.fromisoformat(expires_raw)
        except ValueError as error:
            raise GateError(
                f"waiver {entry['id']} expires_at is not a valid date: {expires_raw}"
            ) from error
        if expires < current_day:
            raise GateError(f"waiver {entry['id']} is expired ({expires_raw})")
        key = (entry["id"].strip(), entry["scope"].strip())
        if key in seen_scopes:
            raise GateError(
                f"duplicate/conflicting waiver for id={key[0]!r} scope={key[1]!r}"
            )
        seen_scopes.add(key)
        waiver_scopes.setdefault(key[0], []).append(entry)

    blocked = 0
    waived = 0
    for finding in findings:
        severity = str(finding.get("severity", "")).upper()
        fid = str(finding.get("id", "")).strip()
        if severity not in _BLOCKING_SEVERITIES:
            continue
        matching = [
            entry
            for entry in waiver_scopes.get(fid, ())
            if _waiver_scope_matches(entry["scope"], finding)
        ]
        if matching:
            waived += 1
        else:
            blocked += 1
            scope = str(finding.get("package") or finding.get("target") or "<unknown>")
            raise GateError(
                f"unwaived {severity} vulnerability finding: {fid} (scope={scope})"
            )
    return {"total": len(findings), "blocked": blocked, "waived": waived}


def parse_trivy_findings(report: Any) -> list[dict[str, str]]:
    """Convert a Trivy JSON report into the flat finding shape the gate uses.

    An empty ``{"Results": []}`` or a report that lacks the schema/scan target
    metadata is rejected: an unreadable, truncated, or zero-target scanner
    output must never look like a clean scan.
    """
    if not isinstance(report, Mapping):
        raise GateError("scanner report must be a JSON object")
    schema_version = report.get("SchemaVersion")
    if type(schema_version) is not int or schema_version <= 0:
        raise GateError("scanner report is missing a valid SchemaVersion")
    results = report.get("Results")
    if not isinstance(results, list) or not results:
        raise GateError(
            "scanner report has no scan targets (Results must be a non-empty list)"
        )
    artifact_name = report.get("ArtifactName")
    if not isinstance(artifact_name, str) or not artifact_name.strip():
        # A filesystem/config scan may omit ArtifactName, but every result must
        # then carry an explicit target.
        for result in results:
            if not isinstance(result, Mapping):
                raise GateError("scanner result entry must be an object")
            target = result.get("Target")
            if not isinstance(target, str) or not target.strip():
                raise GateError(
                    "scanner report is missing scan metadata "
                    "(ArtifactName or a non-empty result Target)"
                )
    findings: list[dict[str, str]] = []
    for result in results:
        if not isinstance(result, Mapping):
            raise GateError("scanner result entry must be an object")
        target = result.get("Target")
        vulnerabilities = result.get("Vulnerabilities", [])
        if vulnerabilities is None:
            vulnerabilities = []
        if not isinstance(vulnerabilities, list):
            raise GateError("scanner Vulnerabilities must be a list")
        for vulnerability in vulnerabilities:
            if not isinstance(vulnerability, Mapping):
                raise GateError("scanner vulnerability entry must be an object")
            finding_id = vulnerability.get("VulnerabilityID")
            severity = vulnerability.get("Severity")
            if not isinstance(finding_id, str) or not finding_id:
                raise GateError("scanner vulnerability is missing VulnerabilityID")
            if not isinstance(severity, str) or not severity:
                raise GateError(f"scanner vulnerability {finding_id} is missing Severity")
            findings.append(
                {
                    "id": finding_id,
                    "severity": severity.upper(),
                    "package": str(vulnerability.get("PkgName", "")),
                    "target": str(target) if isinstance(target, str) else "",
                }
            )
    return findings


def evaluate_scan_report(
    report_path: Path,
    *,
    waivers_path: Path | None = None,
    today: str | None = None,
) -> dict[str, int]:
    """Load a real scanner JSON report and block unwaived HIGH/CRITICAL issues."""
    if not report_path.is_file():
        raise GateError(f"scanner report is missing: {report_path}")
    try:
        report = jsonutil.loads_strict(report_path.read_bytes())
    except (OSError, jsonutil.StrictJsonError) as error:
        raise GateError(f"scanner report cannot be read strictly: {error}") from error
    waivers: list[dict[str, Any]] = []
    if waivers_path is not None:
        if not waivers_path.is_file():
            raise GateError(f"waiver file is missing: {waivers_path}")
        try:
            waiver_document = jsonutil.loads_strict(waivers_path.read_bytes())
        except (OSError, jsonutil.StrictJsonError) as error:
            raise GateError(f"waiver file cannot be read strictly: {error}") from error
        if not isinstance(waiver_document, list):
            raise GateError("waiver file must contain a JSON list")
        waivers = waiver_document
    return evaluate_scan_findings(
        parse_trivy_findings(report), waivers=waivers, today=today
    )


def iter_repo_files(root: Path) -> list[Path]:
    """Return every regular file under root, excluding generated directories."""
    files: list[Path] = []
    for current, directories, names in os.walk(root):
        directories[:] = sorted(
            directory
            for directory in directories
            if directory not in _WORKFLOW_EXCLUDED_DIRS
        )
        for name in sorted(names):
            path = Path(current) / name
            if path.is_file() and not path.is_symlink():
                files.append(path)
    return files


def scan_secrets(files: Iterable[Path]) -> list[str]:
    """Scan text files for leaked credentials or private keys."""
    hits: list[str] = []
    for path in files:
        if not path.is_file() or path.is_symlink():
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        for line_no, line in enumerate(text.splitlines(), start=1):
            for name, pattern in _SECRET_PATTERNS:
                if pattern.search(line):
                    hits.append(f"{path}:{line_no}: potential secret ({name})")
    return hits


_REQUIREMENT = re.compile(r"^([A-Za-z0-9_.-]+)(?:\[[^\]]*\])?\s*(.*)$")


def _requirement_parts(requirement: Any) -> tuple[str, str]:
    if not isinstance(requirement, str):
        raise GateError(f"dependency requirement must be a string: {requirement!r}")
    match = _REQUIREMENT.match(requirement.strip())
    if match is None:
        raise GateError(f"dependency requirement is malformed: {requirement!r}")
    return match.group(1), match.group(2).strip()


def check_dependency_lock(root: Path) -> list[str]:
    """Parse pyproject.toml, requirements-ci.txt and uv.lock structurally.

    Comment lines never satisfy a pin: the requirement file is tokenized and
    only a real ``uv==0.12.7 --hash=sha256:<64hex>`` line is accepted.
    """
    errors: list[str] = []
    try:
        pyproject = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError) as error:
        return [f"pyproject.toml cannot be parsed: {error}"]
    try:
        uv_lock = tomllib.loads((root / "uv.lock").read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError) as error:
        return [f"uv.lock cannot be parsed: {error}"]

    required_version = (
        pyproject.get("tool", {}).get("uv", {}).get("required-version")
    )
    if required_version != "==0.12.7":
        errors.append("pyproject.toml must pin tool.uv.required-version == 0.12.7")
    build_requires = pyproject.get("build-system", {}).get("requires", [])
    if "uv_build==0.12.7" not in build_requires:
        errors.append("pyproject.toml must pin build-system uv_build==0.12.7")

    try:
        requirement_lines = [
            line.split("#", 1)[0].strip()
            for line in (root / "requirements-ci.txt")
            .read_text(encoding="utf-8")
            .splitlines()
        ]
    except OSError as error:
        requirement_lines = []
        errors.append(f"requirements-ci.txt cannot be read: {error}")
    non_empty_lines = [line for line in requirement_lines if line]
    if len(non_empty_lines) != 1 or not _UV_REQUIREMENT.fullmatch(non_empty_lines[0]):
        errors.append(
            "requirements-ci.txt must contain only an uncommented "
            "uv==0.12.7 --hash=sha256:<64hex> requirement"
        )

    project = pyproject.get("project", {})
    project_name = project.get("name")
    project_version = project.get("version")
    packages = {
        package.get("name"): package
        for package in uv_lock.get("package", [])
        if isinstance(package, Mapping)
    }
    datacon = packages.get(project_name)
    if datacon is None:
        errors.append(f"uv.lock is missing the {project_name} package")
        return errors
    if datacon.get("version") != project_version:
        errors.append(
            f"uv.lock {project_name} version {datacon.get('version')!r} does not "
            f"match pyproject {project_version!r}"
        )
    locked_dependencies = {
        dependency.get("name")
        for dependency in datacon.get("dependencies", [])
        if isinstance(dependency, Mapping)
    }
    try:
        project_dependencies = {
            name: specifier
            for name, specifier in (
                _requirement_parts(requirement)
                for requirement in project.get("dependencies", [])
            )
        }
    except GateError as error:
        errors.append(str(error))
        project_dependencies = {}
    missing = sorted(set(project_dependencies) - locked_dependencies)
    if missing:
        errors.append(f"uv.lock datacon dependencies are missing: {', '.join(missing)}")
    requires_dist = {
        entry.get("name"): str(entry.get("specifier", "")).strip()
        for entry in datacon.get("metadata", {}).get("requires-dist", [])
        if isinstance(entry, Mapping)
    }
    for name, specifier in sorted(project_dependencies.items()):
        if name not in requires_dist:
            errors.append(
                f"uv.lock metadata.requires-dist is missing {name} from pyproject"
            )
            continue
        if requires_dist[name] != specifier:
            errors.append(
                f"uv.lock version constraint for {name} {requires_dist[name]!r} "
                f"does not match pyproject {specifier!r}"
            )
    dev_dependencies = {
        dependency.get("name")
        for dependency in datacon.get("dev-dependencies", {}).get("dev", [])
        if isinstance(dependency, Mapping)
    }
    if "pyyaml" not in dev_dependencies:
        errors.append("uv.lock dev group must include pyyaml for workflow parsing")
    if "pyyaml" not in packages:
        errors.append("uv.lock must contain the pyyaml package")
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


def check_test_partition_counts(
    total: int, group_counts: Mapping[str, int], *, expected_groups: Sequence[str]
) -> list[str]:
    """Fail when marker groups overlap (sum > total) or leave tests uncovered."""
    errors: list[str] = []
    missing_groups = sorted(set(expected_groups) - set(group_counts))
    if missing_groups:
        errors.append(f"partition is missing groups: {', '.join(missing_groups)}")
    if any(type(count) is not int or count < 0 for count in group_counts.values()):
        errors.append("partition counts must be non-negative integers")
    summed = sum(group_counts.values())
    if summed != total:
        errors.append(
            f"marker groups are not a partition: sum={summed} collected={total} "
            "(overlap or uncovered tests)"
        )
    return errors


def run_repo_static_gates(
    root: Path,
    *,
    findings_path: Path | None = None,
    waivers_path: Path | None = None,
    require_scan: bool = False,
) -> dict[str, Any]:
    """Run all T07 repository static merge gates and return a structured report."""
    md_files = [
        path
        for path in [root / "README.md", *sorted((root / "tests").rglob("*.md"))]
        if path.is_file()
    ]
    workflow_dir = root / ".github" / "workflows"
    workflow_files = sorted(
        [*workflow_dir.glob("*.yml"), *workflow_dir.glob("*.yaml")]
    )
    errors: list[str] = []
    if workflow_dir.is_dir():
        for path in sorted(workflow_dir.iterdir()):
            if path.is_file() and path.suffix.lower() not in (".yml", ".yaml"):
                errors.append(
                    f"{path}: unexpected non-YAML file in .github/workflows"
                )
    errors.extend(check_markdown_links(md_files, root=root))
    errors.extend(check_req_tc_consistency(md_files))
    errors.extend(check_workflow_security(workflow_files))
    errors.extend(check_dependency_lock(root))
    errors.extend(check_contract_examples(root))
    errors.extend(scan_secrets(iter_repo_files(root)))

    scan_summary: dict[str, Any] = {"status": "not_run", "findings": 0}
    if findings_path is not None:
        try:
            scan_summary = {
                "status": "evaluated",
                "findings": 0,
                **evaluate_scan_report(
                    findings_path, waivers_path=waivers_path
                ),
            }
        except GateError as error:
            errors.append(str(error))
            scan_summary = {"status": "failed", "error": str(error)}
    elif require_scan:
        errors.append(
            "a scanner report is required (--findings) but none was provided"
        )
        scan_summary = {"status": "missing_report"}
    return {
        "ok": not errors,
        "errors": errors,
        "checked_markdown": len(md_files),
        "checked_workflows": len(workflow_files),
        "scanned_files": len(iter_repo_files(root)),
        "scan": scan_summary,
    }


def main(argv: list[str] | None = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(prog="datacon-ci-gates")
    parser.add_argument("--root", type=Path, default=Path("."))
    parser.add_argument(
        "--findings",
        type=Path,
        default=None,
        help="Trivy JSON report; required when --require-scan is set",
    )
    parser.add_argument(
        "--waivers",
        type=Path,
        default=None,
        help="JSON list of structured vulnerability waivers",
    )
    parser.add_argument(
        "--require-scan",
        action="store_true",
        help="fail closed when no scanner report is supplied",
    )
    args = parser.parse_args(argv)
    report = run_repo_static_gates(
        args.root.resolve(),
        findings_path=args.findings,
        waivers_path=args.waivers,
        require_scan=args.require_scan,
    )
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
