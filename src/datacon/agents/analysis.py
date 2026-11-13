"""Offline intelligence, revision, patch and source analysis.

The analyser only reads pinned local material. External advisory text, source
comments and tool output are treated as data; no text is ever executed and no
model can add a tool call or change the deterministic findings.
"""

from __future__ import annotations

from dataclasses import dataclass
import re
import tempfile
from typing import Any, Callable

from datacon import jsonutil
from datacon.agent_contracts import (
    AnalysisModel,
    ContractError,
    Finding,
    ModelContext,
    ModelSuggestion,
    validate_findings,
)
from datacon.cases import (
    CaseConfigurationError,
    CaseDefinition,
    TransientCaseError,
    load_registry,
)
from datacon.contracts import (
    analysis_digest,
    canonical_analysis_bytes,
    plan_digest,
    plan_summary,
)
from datacon.tools.source import (
    GitRepository,
    SourceToolError,
    TransientSourceToolError,
    extract_symbols,
)


class AnalysisBlocked(Exception):
    """Analysis cannot produce a contract-compliant plan."""

    def __init__(
        self, reason_code: str, message: str, details: dict[str, Any] | None = None
    ):
        super().__init__(message)
        self.reason_code = reason_code
        self.message = message
        self.details = details or {}


class RetryableAnalysisError(Exception):
    """A recoverable infrastructure failure during analysis.

    The Supervisor may retry this error once. Missing material, digest
    mismatches, source conflicts and contract failures must use
    ``AnalysisBlocked`` instead.
    """

    def __init__(self, message: str):
        super().__init__(message)
        self.message = message


MAX_ADVISORY_BYTES = 1024 * 1024


def _analysis_contract_reason(error: ValueError) -> str:
    """Classify a canonical-analysis contract failure.

    Finding/evidence field violations are evidence errors. Paths and other
    material-derived fields are repairable material errors. Both are blocked;
    neither may escape to the workflow's generic ``FAILED`` handler.
    """
    message = str(error)
    if message.startswith(
        ("finding.", "evidence_ref", "a finding requires")
    ):
        return "EVIDENCE_INVALID"
    return "MATERIAL_MISSING"


@dataclass(frozen=True)
class AnalyzedCase:
    plan: dict[str, Any]
    plan_digest: str
    summary: dict[str, Any]
    findings: tuple[Finding, ...]
    evidence_refs: frozenset[str]
    tool_calls: tuple[dict[str, Any], ...]


ToolRecorder = Callable[[str, str, dict[str, Any], str], None]


def _material(
    case: CaseDefinition, materials: dict[str, str], relative: str, label: str
) -> tuple[bytes, str]:
    expected = materials.get(relative)
    if expected is None:
        raise AnalysisBlocked(
            "MATERIAL_MISSING", f"{label} is not pinned by the case manifest"
        )
    try:
        return case.read_material(relative, expected)
    except TransientCaseError as error:
        raise RetryableAnalysisError(error.message) from error
    except CaseConfigurationError as error:
        raise AnalysisBlocked(error.reason_code, error.message) from error


def _read_pinned(
    case: CaseDefinition, relative: str, expected: str | None, label: str
) -> tuple[bytes, str]:
    try:
        return case.read_material(relative, expected)
    except TransientCaseError as error:
        raise RetryableAnalysisError(error.message) from error
    except CaseConfigurationError as error:
        raise AnalysisBlocked(error.reason_code, error.message) from error


def _advisory(
    case: CaseDefinition,
    advisory_bytes: bytes,
    *,
    registry_commits: dict[str, str],
    resolved_commits: dict[str, str],
) -> dict[str, Any]:
    if len(advisory_bytes) > MAX_ADVISORY_BYTES:
        raise AnalysisBlocked(
            "MATERIAL_MISSING",
            f"advisory snapshot exceeds the {MAX_ADVISORY_BYTES} byte cap",
        )
    try:
        advisory = jsonutil.loads_strict(advisory_bytes)
    except jsonutil.StrictJsonError as error:
        raise AnalysisBlocked("MATERIAL_MISSING", f"advisory snapshot is invalid: {error}")
    if not isinstance(advisory, dict):
        raise AnalysisBlocked("MATERIAL_MISSING", "advisory snapshot must be an object")
    advisory_version = advisory.get("schema_version")
    if type(advisory_version) is not int or advisory_version != 1:
        raise AnalysisBlocked(
            "MATERIAL_MISSING", "advisory schema_version must be 1"
        )
    if advisory.get("cve_id") != case.cve_id:
        raise AnalysisBlocked(
            "SOURCE_CONFLICT", "advisory snapshot names a different CVE"
        )
    try:
        collected_at = jsonutil.require_rfc3339(
            advisory.get("collected_at"), "advisory.collected_at"
        )
    except ValueError as error:
        raise AnalysisBlocked("MATERIAL_MISSING", str(error)) from error

    advisory_commits = {}
    for role in ("vulnerable", "fixed"):
        value = advisory.get(f"{role}_commit")
        if not isinstance(value, str) or not re.fullmatch(
            r"(?:[0-9a-f]{40}|[0-9a-f]{64})", value
        ):
            raise AnalysisBlocked(
                "MATERIAL_MISSING", f"advisory {role} commit is invalid"
            )
        advisory_commits[role] = value

    sources = advisory.get("sources")
    if not isinstance(sources, list) or not sources:
        raise AnalysisBlocked("MATERIAL_MISSING", "advisory has no sources")
    normalized_sources = []
    for source in sources:
        if not isinstance(source, dict):
            raise AnalysisBlocked("SOURCE_CONFLICT", "advisory source is not an object")
        try:
            name = jsonutil.require_text(source.get("name"), "advisory source name")
            url = jsonutil.require_text(source.get("url"), "advisory source url")
            published = jsonutil.require_text(
                source.get("published_at"), "advisory source published_at"
            )
        except ValueError as error:
            raise AnalysisBlocked("MATERIAL_MISSING", str(error)) from error
        if not url.startswith("https://"):
            raise AnalysisBlocked(
                "SOURCE_CONFLICT", f"advisory source {name} is not an https URL"
            )
        for role in ("vulnerable", "fixed"):
            commit = source.get(f"{role}_commit")
            if commit != advisory_commits[role]:
                raise AnalysisBlocked(
                    "SOURCE_CONFLICT",
                    f"advisory sources disagree on the {role} commit",
                )
        for role in ("vulnerable", "fixed"):
            if advisory_commits[role] != registry_commits[role]:
                raise AnalysisBlocked(
                    "SOURCE_CONFLICT",
                    f"advisory and case registry disagree on the {role} commit",
                )
            if advisory_commits[role] != resolved_commits[role]:
                raise AnalysisBlocked(
                    "SOURCE_CONFLICT",
                    f"advisory and Git repository disagree on the {role} commit",
                )
        normalized_sources.append({"name": name, "url": url, "published_at": published})
    return {
        "collected_at": collected_at,
        "sources": normalized_sources,
        "vulnerable_commit": advisory_commits["vulnerable"],
        "fixed_commit": advisory_commits["fixed"],
    }


def _diff_counts(patch: bytes) -> tuple[int, int]:
    added = 0
    removed = 0
    for line in patch.decode("utf-8", "replace").splitlines():
        if line.startswith("+") and not line.startswith("+++"):
            added += 1
        elif line.startswith("-") and not line.startswith("---"):
            removed += 1
    return added, removed


_PATCH_HEADER_PREFIXES = (
    b"diff --git ",
    b"index ",
    b"new file mode ",
    b"deleted file mode ",
    b"old mode ",
    b"new mode ",
    b"similarity index ",
    b"rename from ",
    b"rename to ",
)


def _patch_body(patch: bytes) -> bytes:
    """Return a patch body without transport headers for byte comparison."""
    return b"".join(
        line
        for line in patch.splitlines(keepends=True)
        if not line.startswith(_PATCH_HEADER_PREFIXES)
    )


def _deterministic_findings(
    *,
    cve_id: str,
    vulnerable: str,
    fixed: str,
    source_path: str,
    harness_path: str,
    function: str,
    asan_error: str,
    added: int,
    removed: int,
    definitions: dict[str, list[dict[str, Any]]],
    call_sites: list[dict[str, Any]],
    candidate_digest: str,
    intel_ref: str,
) -> tuple[list[Finding], set[str]]:
    diff_ref = f"git:diff/{vulnerable}..{fixed}/{source_path}"
    vulnerable_ref = f"git:blob/{vulnerable}/{source_path}"
    fixed_ref = f"git:blob/{fixed}/{source_path}"
    call_line = call_sites[0]["start_line"] if call_sites else 0
    harness_ref = (
        f"source/{harness_path}#L{call_line}" if call_line else "material/harness"
    )
    refs = {
        diff_ref,
        vulnerable_ref,
        fixed_ref,
        harness_ref,
        f"git:commit/{vulnerable}",
        f"git:commit/{fixed}",
        intel_ref,
        "material/harness",
        "material/build_recipe",
        "material/dependencies",
        "material/patch",
        "material/input/normal",
        f"material/input/candidate/{candidate_digest}",
    }
    for role, symbols in definitions.items():
        for symbol in symbols:
            refs.add(f"git:blob/{vulnerable if role == 'vulnerable' else fixed}/{symbol['path']}")
    findings = [
        Finding(
            "fact",
            f"The fixed commit changes {source_path} (+{added}/-{removed} lines).",
            "high",
            (diff_ref,),
        ),
        Finding(
            "fact",
            f"The function {definitions['fixed'][0]['name']} is defined in "
            f"{source_path} lines {definitions['fixed'][0]['start_line']}-"
            f"{definitions['fixed'][0]['end_line']} in the fixed revision and "
            f"lines {definitions['vulnerable'][0]['start_line']}-"
            f"{definitions['vulnerable'][0]['end_line']} in the vulnerable revision.",
            "high",
            (vulnerable_ref, fixed_ref),
        ),
        Finding(
            "fact",
            f"The harness calls {call_sites[0]['name']} at line {call_line}."
            if call_sites
            else "The harness contains no call to the analysed function.",
            "high",
            (harness_ref,),
        ),
        Finding(
            "fact",
            f"The offline advisory snapshot for {cve_id} records fixed commit {fixed}.",
            "high",
            (intel_ref,),
        ),
        Finding(
            "hypothesis",
            f"The change to {source_path} may be related to the reported "
            f"{asan_error} in {function}.",
            "medium",
            (diff_ref, vulnerable_ref),
        ),
        Finding(
            "hypothesis",
            "The fixed candidate input reaches the same call path without a "
            "sanitizer diagnostic.",
            "low",
            (harness_ref, f"material/input/candidate/{candidate_digest}"),
        ),
    ]
    return findings, refs


def _evidence_ref_is_resolvable(
    reference: str,
    *,
    case: CaseDefinition,
    vulnerable: str,
    fixed: str,
    changed_paths: tuple[str, ...],
    git_paths: dict[str, frozenset[str]],
    material_refs: dict[str, tuple[str, str]],
    candidate_digest: str,
    advisory_digest: str,
) -> bool:
    """Resolve an evidence reference against the artifact it names.

    Membership in ``evidence_refs`` is not enough: each reference must name an
    object that the deterministic tools can actually resolve.
    """
    if reference.startswith("git:commit/"):
        return reference.removeprefix("git:commit/") in (vulnerable, fixed)
    if reference.startswith("git:blob/"):
        oid, separator, path = reference.removeprefix("git:blob/").partition("/")
        if not separator or not path:
            return False
        if oid == vulnerable:
            return path in git_paths["vulnerable"]
        if oid == fixed:
            return path in git_paths["fixed"]
        return False
    if reference.startswith("git:diff/"):
        rest = reference.removeprefix("git:diff/")
        pair, separator, path = rest.partition("/")
        return (
            bool(separator)
            and bool(path)
            and pair == f"{vulnerable}..{fixed}"
            and path in changed_paths
        )
    if reference.startswith("intel/"):
        return reference == f"intel/{advisory_digest}"
    if reference.startswith("material/input/candidate/"):
        return reference == f"material/input/candidate/{candidate_digest}"
    if reference.startswith("material/"):
        pinned = material_refs.get(reference)
        return pinned is not None and jsonutil.is_digest(pinned[1])
    if reference.startswith("source/"):
        path, separator, line_text = reference.removeprefix("source/").rpartition(
            "#L"
        )
        if not separator or not path or not line_text.isdigit():
            return False
        line = int(line_text)
        if line < 1:
            return False
        try:
            safe_path = jsonutil.safe_relative_path(path, "evidence source path")
        except ValueError:
            return False
        try:
            data, _ = case.read_material(safe_path, None)
        except TransientCaseError as error:
            raise RetryableAnalysisError(error.message) from error
        except CaseConfigurationError:
            return False
        return line <= len(data.splitlines())
    return False


def analyze_case(
    request: dict[str, Any],
    *,
    case_root: str | None = None,
    model: AnalysisModel | None = None,
    recorder: ToolRecorder | None = None,
) -> AnalyzedCase:
    if request["target"]["kind"] == "binary":
        raise AnalysisBlocked(
            "UNSUPPORTED_TARGET",
            "binary targets are outside the MVP source-analysis scope",
        )

    try:
        registry = load_registry(case_root)
        case = registry.case(request["target"]["case_id"])
    except TransientCaseError as error:
        raise RetryableAnalysisError(error.message) from error
    except CaseConfigurationError as error:
        raise AnalysisBlocked(error.reason_code, error.message) from error
    if case.cve_id != request["cve_id"]:
        raise AnalysisBlocked(
            "INVALID_REQUEST", "request cve_id does not match the registered case"
        )

    isolation = registry.document.get("isolation") or {}
    if not isinstance(isolation, dict):
        raise AnalysisBlocked(
            "MATERIAL_MISSING", "case registry isolation must be an object"
        )

    manifest = case.manifest
    manifest_case = case.manifest_case
    materials = manifest.get("materials")
    if not isinstance(materials, dict):
        raise AnalysisBlocked("MATERIAL_MISSING", "case manifest has no materials")

    repository = case.repository
    advisory_entry = case.advisory
    source_rel_vulnerable = manifest["versions"]["vulnerable"]
    source_rel_fixed = manifest["versions"]["fixed"]
    source_path = jsonutil.safe_relative_path(
        repository["source_path"], "repository.source_path"
    )
    try:
        harness_rel = jsonutil.safe_relative_path(manifest["harness"], "harness")
    except ValueError as error:
        raise AnalysisBlocked("MATERIAL_MISSING", str(error)) from error

    harness, harness_digest = _material(
        case, materials, manifest["harness"], "harness"
    )
    vulnerable_material, _ = _material(
        case, materials, source_rel_vulnerable, "vulnerable source"
    )
    fixed_material, _ = _material(
        case, materials, source_rel_fixed, "fixed source"
    )
    build_recipe, build_recipe_digest = _material(
        case, materials, manifest["build_recipe"], "build recipe"
    )
    dependencies, dependencies_digest = _material(
        case, materials, manifest["dependencies"], "dependency lock"
    )
    patch, patch_digest = _material(
        case, materials, repository["patch"], "fix patch"
    )
    candidate_rel = manifest_case["inputs"]["candidate"]
    normal_rel = manifest_case["inputs"]["normal"]
    candidate, candidate_digest = _material(
        case, materials, candidate_rel, "candidate input"
    )
    _, normal_digest = _material(case, materials, normal_rel, "normal input")

    try:
        bundle_path = case.material(repository["bundle"])
    except CaseConfigurationError as error:
        raise AnalysisBlocked(error.reason_code, error.message) from error
    _, bundle_digest = _read_pinned(
        case, repository["bundle"], repository["bundle_digest"], "repository bundle"
    )

    tool_calls: list[dict[str, Any]] = []

    def record(tool_id: str, step_key: str, params: dict[str, Any], digest: str):
        item = {
            "tool_id": tool_id,
            "step_key": step_key,
            "params": params,
            "result_digest": digest,
        }
        tool_calls.append(item)
        if recorder is not None:
            recorder(tool_id, step_key, params, digest)

    vulnerable = fixed = ""
    git_paths: dict[str, frozenset[str]] = {}
    definitions: dict[str, list[dict[str, Any]]] = {}
    call_sites: list[dict[str, Any]] = []
    diff_digest = ""
    changed_paths: tuple[str, ...] = ()
    try:
        with tempfile.TemporaryDirectory(prefix="datacon-git-") as temporary:
            from pathlib import Path

            git = GitRepository.from_bundle(
                bundle_path,
                Path(temporary) / "repo",
                refs=tuple(repository["refs"].values()),
            )
            vulnerable = git.resolve_commit(
                repository["refs"]["vulnerable"], repository["commits"]["vulnerable"]
            )
            record(
                "git.resolve",
                "git.resolve:vulnerable",
                {"ref": repository["refs"]["vulnerable"]},
                jsonutil.digest_json({"commit": vulnerable}),
            )
            fixed = git.resolve_commit(
                repository["refs"]["fixed"], repository["commits"]["fixed"]
            )
            record(
                "git.resolve",
                "git.resolve:fixed",
                {"ref": repository["refs"]["fixed"]},
                jsonutil.digest_json({"commit": fixed}),
            )
            git_paths = {
                "vulnerable": git.list_paths(vulnerable),
                "fixed": git.list_paths(fixed),
            }
            record(
                "git.resolve",
                "git.resolve:trees",
                {"vulnerable": vulnerable, "fixed": fixed},
                jsonutil.digest_json(
                    {
                        role: sorted(paths)
                        for role, paths in git_paths.items()
                    }
                ),
            )
            vulnerable_source = git.read_blob(vulnerable, source_path)
            fixed_source = git.read_blob(fixed, source_path)
            if vulnerable_source != vulnerable_material:
                raise AnalysisBlocked(
                    "MATERIAL_MISSING",
                    "the vulnerable source material does not match the Git object",
                )
            if fixed_source != fixed_material:
                raise AnalysisBlocked(
                    "MATERIAL_MISSING",
                    "the fixed source material does not match the Git object",
                )
            if jsonutil.digest_bytes(vulnerable_source) != materials[source_rel_vulnerable]:
                raise AnalysisBlocked(
                    "MATERIAL_MISSING",
                    "the vulnerable Git object does not match the pinned source material",
                )
            if jsonutil.digest_bytes(fixed_source) != materials[source_rel_fixed]:
                raise AnalysisBlocked(
                    "MATERIAL_MISSING",
                    "the fixed Git object does not match the pinned source material",
                )
            diff = git.diff(vulnerable, fixed)
            diff_digest = diff.digest
            changed_paths = diff.changed_paths
            record(
                "git.diff",
                "git.diff:source",
                {"vulnerable": vulnerable, "fixed": fixed},
                diff_digest,
            )
            definitions = {
                "vulnerable": extract_symbols(
                    vulnerable_source,
                    path=source_path,
                    revision="vulnerable",
                    function_name=manifest["asan_signature"]["function"],
                    role="definition",
                ),
                "fixed": extract_symbols(
                    fixed_source,
                    path=source_path,
                    revision="fixed",
                    function_name=manifest["asan_signature"]["function"],
                    role="definition",
                ),
            }
            call_sites = extract_symbols(
                harness,
                path=manifest["harness"],
                revision="harness",
                function_name=manifest["asan_signature"]["function"],
                role="call_site",
            )
            record(
                "tree_sitter.extract",
                "tree_sitter.extract:source",
                {"function": manifest["asan_signature"]["function"]},
                jsonutil.digest_json(
                    {
                        "definitions": definitions,
                        "call_sites": call_sites,
                    }
                ),
            )
    except TransientSourceToolError as error:
        raise RetryableAnalysisError(error.message) from error
    except SourceToolError as error:
        raise AnalysisBlocked("MATERIAL_MISSING", error.message) from error
    except TransientCaseError as error:
        raise RetryableAnalysisError(error.message) from error
    except CaseConfigurationError as error:
        raise AnalysisBlocked(error.reason_code, error.message) from error

    if not definitions["vulnerable"] or not definitions["fixed"]:
        raise AnalysisBlocked(
            "MATERIAL_MISSING",
            f"target function {manifest['asan_signature']['function']} is missing from a revision",
        )
    if not call_sites:
        raise AnalysisBlocked(
            "MATERIAL_MISSING", "the harness does not call the target function"
        )
    if source_path not in changed_paths:
        raise AnalysisBlocked(
            "SOURCE_CONFLICT", "the patch does not change the analysed source path"
        )

    advisory_bytes, advisory_digest = _read_pinned(
        case,
        advisory_entry["path"],
        advisory_entry["digest"],
        "advisory snapshot",
    )
    advisory = _advisory(
        case,
        advisory_bytes,
        registry_commits=repository["commits"],
        resolved_commits={"vulnerable": vulnerable, "fixed": fixed},
    )
    if advisory_digest != advisory_entry["digest"]:
        raise AnalysisBlocked(
            "MATERIAL_MISSING", "advisory snapshot digest does not match the registry"
        )

    added, removed = _diff_counts(patch)
    git_added, git_removed = _diff_counts(diff.patch)
    if (added, removed) != (git_added, git_removed):
        raise AnalysisBlocked(
            "SOURCE_CONFLICT",
            "the pinned fix patch does not match the Git diff line counts",
        )
    if _patch_body(patch) != _patch_body(diff.patch):
        raise AnalysisBlocked(
            "SOURCE_CONFLICT",
            "the pinned fix patch does not match the Git diff content",
        )
    findings, evidence_refs = _deterministic_findings(
        cve_id=case.cve_id,
        vulnerable=vulnerable,
        fixed=fixed,
        source_path=source_path,
        harness_path=harness_rel,
        function=manifest["asan_signature"]["function"],
        asan_error=manifest["asan_signature"]["error"],
        added=added,
        removed=removed,
        definitions=definitions,
        call_sites=call_sites,
        candidate_digest=candidate_digest,
        intel_ref=f"intel/{advisory_digest}",
    )
    material_refs = {
        "material/harness": (manifest["harness"], harness_digest),
        "material/build_recipe": (manifest["build_recipe"], build_recipe_digest),
        "material/dependencies": (
            manifest["dependencies"],
            dependencies_digest,
        ),
        "material/patch": (repository["patch"], patch_digest),
        "material/input/normal": (normal_rel, normal_digest),
        f"material/input/candidate/{candidate_digest}": (
            candidate_rel,
            candidate_digest,
        ),
    }

    def resolve_all(candidates: list[Finding]) -> None:
        for finding in candidates:
            for reference in finding.evidence_refs:
                if not _evidence_ref_is_resolvable(
                    reference,
                    case=case,
                    vulnerable=vulnerable,
                    fixed=fixed,
                    changed_paths=changed_paths,
                    git_paths=git_paths,
                    material_refs=material_refs,
                    candidate_digest=candidate_digest,
                    advisory_digest=advisory_digest,
                ):
                    raise AnalysisBlocked(
                        "EVIDENCE_INVALID",
                        f"evidence reference is not resolvable: {reference}",
                    )

    resolve_all(findings)

    context = ModelContext(
        cve_id=case.cve_id,
        advisory={
            "collected_at": advisory["collected_at"],
            "sources": advisory["sources"],
        },
        diff={
            "digest": diff_digest,
            "changed_paths": list(changed_paths),
        },
        symbols=tuple(
            [
                *definitions["vulnerable"],
                *definitions["fixed"],
                *call_sites,
            ]
        ),
        evidence_refs=frozenset(evidence_refs),
    )
    suggestion = (model or AnalysisModel()).propose(context)
    if not isinstance(suggestion, ModelSuggestion):
        raise AnalysisBlocked("EVIDENCE_INVALID", "model returned an invalid suggestion")
    try:
        model_findings = validate_findings(suggestion.findings, evidence_refs)
    except ContractError as error:
        raise AnalysisBlocked("EVIDENCE_INVALID", str(error)) from error
    resolve_all(list(model_findings))
    findings.extend(model_findings)

    analysis = {
        "diff_digest": diff_digest,
        "changed_paths": list(changed_paths),
        "symbols": [*definitions["vulnerable"], *definitions["fixed"], *call_sites],
        "findings": [finding.as_dict() for finding in findings],
    }
    try:
        normalized_analysis = jsonutil.loads_strict(
            canonical_analysis_bytes(analysis)
        )
        normalized_analysis_digest = analysis_digest(normalized_analysis)
    except ValueError as error:
        raise AnalysisBlocked(
            _analysis_contract_reason(error), str(error)
        ) from error

    image = manifest.get("image")
    if not isinstance(image, str) or "@" not in image:
        raise AnalysisBlocked("MATERIAL_MISSING", "case image is not pinned by digest")
    image_digest = image.split("@", 1)[1]
    try:
        jsonutil.require_digest(image_digest, "image digest")
        asan_options = jsonutil.require_text(
            manifest.get("asan_options"), "case asan_options"
        )
        platform = jsonutil.require_text(manifest.get("platform"), "case platform")
    except ValueError as error:
        raise AnalysisBlocked("MATERIAL_MISSING", str(error)) from error
    toolchain = manifest.get("toolchain")
    if not isinstance(toolchain, dict) or not toolchain:
        raise AnalysisBlocked(
            "MATERIAL_MISSING", "case toolchain must be a non-empty object"
        )

    used_materials = {
        key: materials[key]
        for key in {
            manifest["harness"],
            manifest["build_recipe"],
            manifest["dependencies"],
            repository["patch"],
            source_rel_vulnerable,
            source_rel_fixed,
            candidate_rel,
            normal_rel,
        }
    }
    case_config = {
        "case_id": case.case_id,
        "cve_id": case.cve_id,
        "benchmark_id": case.benchmark_id,
        "registry_entry": case.entry,
        "manifest_case": manifest_case,
        "materials": used_materials,
        "image": image,
        "platform": platform,
        "toolchain": toolchain,
        "asan_options": asan_options,
        "asan_signature": manifest["asan_signature"],
    }
    try:
        case_config_digest = jsonutil.digest_json(case_config)
    except (ValueError, UnicodeError, RecursionError) as error:
        # Case validation normally rejects these values first. This is the
        # defense in depth that keeps any remaining non-canonical case config
        # (for example from a substituted registry entry) a repairable
        # block instead of an uncaught analysis failure.
        raise AnalysisBlocked(
            "MATERIAL_MISSING",
            f"case configuration is not canonical JSON: {error}",
        ) from error

    plan = {
        "case_id": case.case_id,
        "cve_id": case.cve_id,
        "case_config_digest": case_config_digest,
        "repository": {
            "origin": repository["origin"],
            "bundle_digest": bundle_digest,
            "patch_digest": patch_digest,
        },
        "revisions": {"vulnerable": vulnerable, "fixed": fixed},
        "dependencies_digest": dependencies_digest,
        "image_digest": image_digest,
        "platform": platform,
        "toolchain": dict(toolchain),
        "asan_options": asan_options,
        "build_recipe_digest": build_recipe_digest,
        "harness_digest": harness_digest,
        "inputs": {"candidate": candidate_digest, "normal": normal_digest},
        "expected_exit": manifest_case["expected_exit"],
        "asan_signature": {
            "error": manifest["asan_signature"]["error"],
            "function": manifest["asan_signature"]["function"],
            "source": manifest["asan_signature"]["source"],
        },
        "limits": dict(request["limits"]),
        "isolation": dict(isolation),
        "intel": {
            "snapshot": advisory_entry["path"],
            "collected_at": advisory["collected_at"],
            "content_digest": advisory_digest,
            "sources": [source["url"] for source in advisory["sources"]],
        },
        "analysis": normalized_analysis,
        "analysis_digest": normalized_analysis_digest,
        "policy_version": registry.document.get("policy_version", "1"),
    }
    try:
        digest = plan_digest(plan)
        summary = plan_summary(plan)
    except ValueError as error:
        raise AnalysisBlocked("MATERIAL_MISSING", f"plan is invalid: {error}") from error

    return AnalyzedCase(
        plan=plan,
        plan_digest=digest,
        summary=summary,
        findings=tuple(findings),
        evidence_refs=frozenset(evidence_refs),
        tool_calls=tuple(tool_calls),
    )
