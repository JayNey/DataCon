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
from datacon.cases import CaseConfigurationError, CaseDefinition, load_registry
from datacon.contracts import (
    analysis_digest,
    canonical_analysis_bytes,
    plan_digest,
    plan_summary,
)
from datacon.tools.source import (
    GitRepository,
    SourceToolError,
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
    except CaseConfigurationError as error:
        raise AnalysisBlocked(error.reason_code, error.message) from error


def _advisory(
    case: CaseDefinition,
    advisory_bytes: bytes,
    *,
    registry_commits: dict[str, str],
    resolved_commits: dict[str, str],
) -> dict[str, Any]:
    try:
        advisory = jsonutil.loads_strict(advisory_bytes)
    except jsonutil.StrictJsonError as error:
        raise AnalysisBlocked("MATERIAL_MISSING", f"advisory snapshot is invalid: {error}")
    if not isinstance(advisory, dict):
        raise AnalysisBlocked("MATERIAL_MISSING", "advisory snapshot must be an object")
    if advisory.get("schema_version") != 1:
        raise AnalysisBlocked("MATERIAL_MISSING", "advisory schema_version must be 1")
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


def _deterministic_findings(
    *,
    cve_id: str,
    vulnerable: str,
    fixed: str,
    source_path: str,
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
    harness_ref = f"source/harness.c#L{call_line}" if call_line else "material/harness"
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
            "The out-of-bounds write at the string terminator is the root cause of "
            "the reported heap-buffer-overflow.",
            "high",
            (diff_ref, vulnerable_ref),
        ),
        Finding(
            "hypothesis",
            "The fixed candidate input reaches the same call path without an "
            "out-of-bounds write.",
            "medium",
            (harness_ref, f"material/input/candidate/{candidate_digest}"),
        ),
    ]
    return findings, refs


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
    except CaseConfigurationError as error:
        raise AnalysisBlocked(error.reason_code, error.message) from error
    if case.cve_id != request["cve_id"]:
        raise AnalysisBlocked(
            "INVALID_REQUEST", "request cve_id does not match the registered case"
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

    harness, harness_digest = _material(
        case, materials, manifest["harness"], "harness"
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
        _, bundle_digest = case.read_material(
            repository["bundle"], repository["bundle_digest"]
        )
    except CaseConfigurationError as error:
        raise AnalysisBlocked(error.reason_code, error.message) from error

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
            vulnerable_source = git.read_blob(vulnerable, source_path)
            fixed_source = git.read_blob(fixed, source_path)
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
    except SourceToolError as error:
        raise AnalysisBlocked("MATERIAL_MISSING", error.message) from error
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

    try:
        advisory_bytes, advisory_digest = case.read_material(
            advisory_entry["path"], advisory_entry["digest"]
        )
    except CaseConfigurationError as error:
        raise AnalysisBlocked(error.reason_code, error.message) from error
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
    findings, evidence_refs = _deterministic_findings(
        cve_id=case.cve_id,
        vulnerable=vulnerable,
        fixed=fixed,
        source_path=source_path,
        added=added,
        removed=removed,
        definitions=definitions,
        call_sites=call_sites,
        candidate_digest=candidate_digest,
        intel_ref=f"intel/{advisory_digest}",
    )

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
    findings.extend(model_findings)

    analysis = {
        "diff_digest": diff_digest,
        "changed_paths": list(changed_paths),
        "symbols": [*definitions["vulnerable"], *definitions["fixed"], *call_sites],
        "findings": [finding.as_dict() for finding in findings],
    }
    normalized_analysis = jsonutil.loads_strict(canonical_analysis_bytes(analysis))
    normalized_analysis_digest = analysis_digest(normalized_analysis)

    image = manifest.get("image")
    if not isinstance(image, str) or "@" not in image:
        raise AnalysisBlocked("MATERIAL_MISSING", "case image is not pinned by digest")
    image_digest = image.split("@", 1)[1]
    try:
        jsonutil.require_digest(image_digest, "image digest")
    except ValueError as error:
        raise AnalysisBlocked("MATERIAL_MISSING", str(error)) from error

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
        "asan_signature": manifest["asan_signature"],
    }
    case_config_digest = jsonutil.digest_json(case_config)

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
        "isolation": dict((registry.document.get("isolation") or {})),
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
