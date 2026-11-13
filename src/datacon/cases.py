"""Registered cases for offline planning.

A deployment points ``DATACON_CASE_ROOT`` at a directory containing
``registry.json`` and the materials it references. The default synthetic case
is shipped as package data, so an installed wheel works without a source
checkout. ``tests/fixtures/cases`` mirrors that directory for the test baseline.
"""

from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path
from typing import Any

from datacon import jsonutil

PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_CASE_ROOT = Path(__file__).resolve().parent / "data" / "cases"

_CASE_FIELDS = frozenset(
    {"cve_id", "benchmark_id", "repository", "advisory"}
)
_REPOSITORY_FIELDS = frozenset(
    {"origin", "bundle", "bundle_digest", "source_path", "refs", "commits", "patch"}
)
_SIGNATURE_FIELDS = frozenset({"error", "function", "source"})


class CaseConfigurationError(ValueError):
    """The local case registry or one of its materials is unusable."""

    def __init__(self, reason_code: str, message: str):
        super().__init__(message)
        self.reason_code = reason_code
        self.message = message


class TransientCaseError(CaseConfigurationError):
    """A recoverable I/O error while reading pinned case material.

    Missing files and digest mismatches stay ``CaseConfigurationError``; only
    failures that may succeed on a second attempt use this subclass.
    """


@dataclass(frozen=True)
class CaseDefinition:
    case_id: str
    cve_id: str
    benchmark_id: str
    entry: dict[str, Any]
    manifest: dict[str, Any]
    manifest_case: dict[str, Any]
    material_root: Path
    repository: dict[str, Any]
    advisory: dict[str, Any]

    def material(self, relative: str) -> Path:
        return self._resolve(relative)

    def _resolve(self, relative: str) -> Path:
        try:
            return jsonutil.resolve_inside(self.material_root, relative)
        except ValueError as error:
            raise CaseConfigurationError("MATERIAL_MISSING", str(error)) from error

    def read_material(self, relative: str, expected_digest: str | None) -> tuple[bytes, str]:
        """Read a material after checking containment, presence and digest."""
        path = self._resolve(relative)
        if not path.is_file():
            raise CaseConfigurationError(
                "MATERIAL_MISSING", f"material {relative} is missing"
            )
        try:
            data = path.read_bytes()
        except (FileNotFoundError, PermissionError) as error:
            raise CaseConfigurationError(
                "MATERIAL_MISSING", f"material {relative} is not readable"
            ) from error
        except OSError as error:
            raise TransientCaseError(
                "MATERIAL_IO_ERROR", f"material {relative} cannot be read: {error}"
            ) from error
        digest = jsonutil.digest_bytes(data)
        if expected_digest is not None and digest != expected_digest:
            raise CaseConfigurationError(
                "MATERIAL_MISSING",
                f"material {relative} digest does not match the case registry",
            )
        return data, digest


def _validate_manifest_for_case(
    manifest: dict[str, Any],
    manifest_case: dict[str, Any],
    benchmark_id: str,
) -> None:
    """Validate the manifest fields a plan is built from.

    A broken manifest is a repairable case configuration problem, not an
    analysis crash. Every structural error is classified as
    ``MATERIAL_MISSING`` with the offending field in the message before any
    field is indexed directly by the analyzer.
    """
    label = f"case manifest cases.{benchmark_id}"
    try:
        versions = jsonutil.require_object(
            manifest.get("versions"),
            required={"vulnerable", "fixed"},
            label="case manifest versions",
        )
        for role in ("vulnerable", "fixed"):
            jsonutil.safe_relative_path(
                versions[role], f"case manifest versions.{role}"
            )
        for field in ("harness", "build_recipe", "dependencies"):
            jsonutil.require_text(
                manifest.get(field), f"case manifest {field}"
            )
        signature = jsonutil.require_object(
            manifest.get("asan_signature"),
            required=set(_SIGNATURE_FIELDS),
            optional={"operation", "access_size"},
            label="case manifest asan_signature",
        )
        for field in sorted(_SIGNATURE_FIELDS):
            jsonutil.require_text(
                signature[field], f"case manifest asan_signature.{field}"
            )
        image = jsonutil.require_text(
            manifest.get("image"), "case manifest image"
        )
        tag, separator, image_digest = image.partition("@")
        if not separator or not tag or not image_digest.startswith("sha256:"):
            raise ValueError(
                "case manifest image must be pinned by an @sha256 digest"
            )
        jsonutil.require_digest(image_digest, "case manifest image digest")
        jsonutil.require_text(
            manifest.get("platform"), "case manifest platform"
        )
        jsonutil.require_text(
            manifest.get("asan_options"), "case manifest asan_options"
        )
        toolchain = manifest.get("toolchain")
        if not isinstance(toolchain, dict) or not toolchain:
            raise ValueError(
                "case manifest toolchain must be a non-empty object"
            )
        materials = manifest.get("materials")
        if not isinstance(materials, dict) or not materials:
            raise ValueError(
                "case manifest materials must be a non-empty object"
            )
        for relative, digest in materials.items():
            jsonutil.safe_relative_path(
                relative, f"case manifest materials path {relative}"
            )
            jsonutil.require_digest(
                digest, f"case manifest materials[{relative}]"
            )
        inputs = jsonutil.require_object(
            manifest_case.get("inputs"),
            required={"candidate", "normal"},
            label=f"{label}.inputs",
        )
        for role in ("candidate", "normal"):
            jsonutil.safe_relative_path(
                inputs[role], f"{label}.inputs.{role}"
            )
        expected_exit = jsonutil.require_object(
            manifest_case.get("expected_exit"),
            required={"normal", "candidate_clean"},
            optional={"candidate_asan"},
            label=f"{label}.expected_exit",
        )
        for key, value in expected_exit.items():
            if type(value) is not int or not 0 <= value <= 255:
                raise ValueError(
                    f"{label}.expected_exit.{key} must be an exit code"
                )
    except ValueError as error:
        raise CaseConfigurationError(
            "MATERIAL_MISSING",
            f"case manifest for benchmark {benchmark_id} is invalid: {error}",
        ) from error


@dataclass(frozen=True)
class CaseRegistry:
    root: Path
    document: dict[str, Any]
    manifest: dict[str, Any]
    material_root: Path

    def case(self, case_id: str) -> CaseDefinition:
        entry = self.document["cases"].get(case_id)
        if entry is None:
            raise CaseConfigurationError(
                "INVALID_REQUEST", "case_id is not registered"
            )
        benchmark_id = entry["benchmark_id"]
        manifest_cases = self.manifest.get("cases")
        if not isinstance(manifest_cases, dict):
            raise CaseConfigurationError(
                "MATERIAL_MISSING",
                "case manifest cases must be an object",
            )
        manifest_case = manifest_cases.get(benchmark_id)
        if manifest_case is None:
            raise CaseConfigurationError(
                "MATERIAL_MISSING",
                f"benchmark {benchmark_id} is missing from the case manifest",
            )
        if not isinstance(manifest_case, dict):
            raise CaseConfigurationError(
                "MATERIAL_MISSING",
                f"manifest case {benchmark_id} must be an object",
            )
        if manifest_case.get("case_id") != case_id:
            raise CaseConfigurationError(
                "SOURCE_CONFLICT",
                f"manifest case {benchmark_id} is registered for a different case",
            )
        _validate_manifest_for_case(self.manifest, manifest_case, benchmark_id)
        return CaseDefinition(
            case_id=case_id,
            cve_id=entry["cve_id"],
            benchmark_id=benchmark_id,
            entry=entry,
            manifest=self.manifest,
            manifest_case=manifest_case,
            material_root=self.material_root,
            repository=entry["repository"],
            advisory=entry["advisory"],
        )

    def cves(self) -> dict[str, str]:
        return {
            case_id: entry["cve_id"]
            for case_id, entry in self.document["cases"].items()
        }


def case_root(path: str | os.PathLike[str] | None = None) -> Path:
    configured = path or os.getenv("DATACON_CASE_ROOT") or DEFAULT_CASE_ROOT
    root = Path(configured).expanduser()
    if not root.is_absolute():
        root = Path.cwd() / root
    return root.resolve()


def _load_json(path: Path, label: str) -> dict[str, Any]:
    try:
        text = path.read_text(encoding="utf-8")
    except (FileNotFoundError, PermissionError) as error:
        raise CaseConfigurationError(
            "MATERIAL_MISSING", f"{label} is not readable: {error}"
        ) from error
    except OSError as error:
        raise TransientCaseError(
            "MATERIAL_IO_ERROR", f"{label} cannot be read: {error}"
        ) from error
    try:
        document = jsonutil.loads_strict(text)
    except jsonutil.StrictJsonError as error:
        raise CaseConfigurationError(
            "MATERIAL_MISSING", f"{label} is not valid JSON: {error}"
        ) from error
    if not isinstance(document, dict):
        raise CaseConfigurationError(
            "MATERIAL_MISSING", f"{label} must be a JSON object"
        )
    return document


def load_registry(
    path: str | os.PathLike[str] | None = None,
    *,
    root: str | os.PathLike[str] | None = None,
) -> CaseRegistry:
    """Load and validate the local case registry.

    ``root`` overrides the directory that contains ``registry.json``; it is the
    only knob tests need to exercise broken or substituted material.
    """
    base = case_root(path if path is not None else root)
    document = _load_json(base / "registry.json", "case registry")
    if document.get("schema_version") != 1:
        raise CaseConfigurationError(
            "MATERIAL_MISSING", "case registry schema_version must be 1"
        )
    try:
        material_root = jsonutil.resolve_inside(
            base,
            jsonutil.safe_relative_path(
                document.get("material_root", "."), "material_root", allow_dot=True
            ),
            allow_dot=True,
        )
        manifest_path = jsonutil.safe_relative_path(
            document.get("manifest", "manifest.json"), "manifest"
        )
    except ValueError as error:
        raise CaseConfigurationError("MATERIAL_MISSING", str(error)) from error
    manifest = _load_json(base / manifest_path, "case manifest")
    if manifest.get("schema_version") != 1:
        raise CaseConfigurationError(
            "MATERIAL_MISSING", "case manifest schema_version must be 1"
        )
    cases = document.get("cases")
    if not isinstance(cases, dict) or not cases:
        raise CaseConfigurationError(
            "MATERIAL_MISSING", "case registry must declare at least one case"
        )

    for case_id, entry in cases.items():
        if not isinstance(case_id, str) or not case_id.strip():
            raise CaseConfigurationError("INVALID_REQUEST", "invalid case_id")
        try:
            jsonutil.require_object(
                entry, required=set(_CASE_FIELDS), label=f"case {case_id}"
            )
            jsonutil.require_text(entry["cve_id"], f"{case_id}.cve_id")
            jsonutil.require_text(entry["benchmark_id"], f"{case_id}.benchmark_id")
            repository = jsonutil.require_object(
                entry["repository"],
                required=set(_REPOSITORY_FIELDS),
                label=f"{case_id}.repository",
            )
            jsonutil.require_text(repository["origin"], f"{case_id}.origin")
            jsonutil.safe_relative_path(
                repository["bundle"], f"{case_id}.bundle"
            )
            jsonutil.require_digest(
                repository["bundle_digest"], f"{case_id}.bundle_digest"
            )
            jsonutil.safe_relative_path(
                repository["source_path"], f"{case_id}.source_path"
            )
            refs = jsonutil.require_object(
                repository["refs"],
                required={"vulnerable", "fixed"},
                label=f"{case_id}.refs",
            )
            commits = jsonutil.require_object(
                repository["commits"],
                required={"vulnerable", "fixed"},
                label=f"{case_id}.commits",
            )
            for role in ("vulnerable", "fixed"):
                jsonutil.require_text(refs[role], f"{case_id}.refs.{role}")
                jsonutil.require_text(commits[role], f"{case_id}.commits.{role}")
            jsonutil.safe_relative_path(
                repository["patch"], f"{case_id}.patch"
            )
            advisory = jsonutil.require_object(
                entry["advisory"],
                required={"path", "digest"},
                label=f"{case_id}.advisory",
            )
            jsonutil.safe_relative_path(advisory["path"], f"{case_id}.advisory.path")
            jsonutil.require_digest(
                advisory["digest"], f"{case_id}.advisory.digest"
            )
        except ValueError as error:
            raise CaseConfigurationError(
                "MATERIAL_MISSING", f"case {case_id} is invalid: {error}"
            ) from error

        if entry["benchmark_id"] not in manifest.get("cases", {}):
            raise CaseConfigurationError(
                "MATERIAL_MISSING",
                f"case {case_id} references unknown benchmark {entry['benchmark_id']}",
            )

    return CaseRegistry(
        root=base,
        document=document,
        manifest=manifest,
        material_root=material_root,
    )


def registered_cves() -> dict[str, str]:
    return load_registry().cves()
