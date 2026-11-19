"""Static contract tests for `.github/dependabot.yml` (dependency-noise guards).

`dependabot.yml` deliberately lives outside `.github/workflows/`, so
`datacon.ci_gates` never sees it: a typo or a dropped `ignore` rule fails
silently in GitHub's UI instead of failing CI. These tests pin the rules that
keep Dependabot from opening PRs this repo cannot merge:

* `python` minor/major bumps change the runtime version and must be done by
  hand (requires-python, every workflow's setup-python, uv.lock).
* `uv` / `uv-build` are pinned in three places and cross-checked by
  `ci_gates.check_dependency_lock`, so Dependabot can never produce a
  mergeable upgrade for them.
* Root `pip` (`directory: "/"`) is removed and forbidden: `requirements-ci.txt`
  only pins `uv` (which is upgraded manually), while a root `pip` entry still
  scans `pyproject.toml` and opens PRs that omit `uv.lock` updates, breaking
  `uv sync --frozen`. If CI requirements ever need automated updates, move
  `requirements-ci.txt` into a dedicated subdirectory without `pyproject.toml`
  before adding a `pip` entry for that subdirectory.
"""

from __future__ import annotations

from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parents[2]
DEPENDABOT = REPO_ROOT / ".github" / "dependabot.yml"


def _load() -> dict:
    return yaml.safe_load(DEPENDABOT.read_text(encoding="utf-8"))


def _entry(document: dict, ecosystem: str) -> dict:
    entries = [
        update
        for update in document["updates"]
        if update.get("package-ecosystem") == ecosystem
    ]
    assert len(entries) == 1, f"expected exactly one {ecosystem!r} ecosystem entry"
    return entries[0]


def _ignore_rule(entry: dict, dependency: str) -> dict:
    rules = [
        rule
        for rule in entry.get("ignore") or ()
        if isinstance(rule, dict) and rule.get("dependency-name") == dependency
    ]
    assert len(rules) == 1, f"expected exactly one ignore rule for {dependency!r}"
    return rules[0]


def test_dependabot_keeps_expected_ecosystems_without_root_pip():
    document = _load()
    assert document["version"] == 2
    ecosystems = {update["package-ecosystem"] for update in document["updates"]}
    assert {"docker", "uv"} <= ecosystems
    root_pip_entries = [
        update
        for update in document["updates"]
        if update.get("package-ecosystem") == "pip"
        and (
            update.get("directory") == "/"
            or "/" in (update.get("directories") or ())
        )
    ]
    assert not root_pip_entries, (
        "pip ecosystem must not target '/': it also scans pyproject.toml "
        "without updating uv.lock"
    )


def test_docker_allows_only_python_patch_and_digest_refreshes():
    ignore = _ignore_rule(_entry(_load(), "docker"), "python")
    update_types = set(ignore.get("update-types") or ())
    # minor/major change the runtime interpreter version; patch stays open so
    # 3.12.x rebuilds and same-tag digest rotations can still be reviewed.
    assert "version-update:semver-minor" in update_types
    assert "version-update:semver-major" in update_types
    assert "version-update:semver-patch" not in update_types


def test_uv_ignores_uv_and_uv_build_completely():
    entry = _entry(_load(), "uv")
    # No `update-types` filter: the three-place pin makes even a patch bump
    # unmergeable, so every uv/uv-build PR must be suppressed.
    for dependency in ("uv", "uv-build"):
        ignore = _ignore_rule(entry, dependency)
        assert "update-types" not in ignore, (
            f"uv must ignore {dependency} for all update types"
        )
