import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import sysconfig
import zipfile

from datacon import cases as case_registry

ROOT = Path(__file__).resolve().parents[2]
FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "cases"


def build_wheel(destination):
    result = subprocess.run(
        ["uv", "build", "--wheel", "--out-dir", str(destination)],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=180,
        env=os.environ.copy(),
    )
    assert result.returncode == 0, result.stdout + result.stderr
    wheels = sorted(destination.glob("*.whl"))
    assert len(wheels) == 1, wheels
    return wheels[0]


def extract_wheel(wheel, destination):
    destination.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(wheel) as archive:
        archive.extractall(destination)


def custom_case_root(package_cases, destination):
    shutil.copytree(package_cases, destination)
    registry = json.loads((destination / "registry.json").read_text(encoding="utf-8"))
    manifest = json.loads((destination / "manifest.json").read_text(encoding="utf-8"))
    registry["cases"]["custom-parser"] = {
        **registry["cases"]["fixture-c-parser"],
        "benchmark_id": "B99",
    }
    manifest["cases"]["B99"] = {
        **manifest["cases"]["B01"],
        "case_id": "custom-parser",
    }
    (destination / "registry.json").write_text(
        json.dumps(registry, indent=2) + "\n", encoding="utf-8"
    )
    (destination / "manifest.json").write_text(
        json.dumps(manifest, indent=2) + "\n", encoding="utf-8"
    )


def request_body(case_id):
    return {
        "schema_version": 1,
        "cve_id": "CVE-2099-0001",
        "target": {
            "kind": "source",
            "case_id": case_id,
            "goal": "validate a request against the packaged case registry",
        },
    }


SMOKE = """
import json
import os
import sys

import datacon

package_dir = os.path.dirname(os.path.realpath(datacon.__file__))
assert package_dir == os.path.join(sys.argv[1], "datacon"), package_dir

from datacon.contracts import parse_request

base = json.loads(sys.argv[3])
assert parse_request(json.dumps(base))["target"]["case_id"] == "fixture-c-parser"

os.environ["DATACON_CASE_ROOT"] = sys.argv[2]
custom = json.loads(sys.argv[4])
assert parse_request(json.dumps(custom))["target"]["case_id"] == "custom-parser"
print("wheel-smoke-ok")
"""


ANALYZE = """
import json
import os
import sys

import datacon

package_dir = os.path.dirname(os.path.realpath(datacon.__file__))
assert package_dir == os.path.join(sys.argv[1], "datacon"), package_dir
assert "DATACON_CASE_ROOT" not in os.environ

from datacon.agents.analysis import analyze_case
from datacon.contracts import DEFAULT_LIMITS, parse_request

body = json.loads(sys.argv[2])
body["limits"] = dict(DEFAULT_LIMITS)
request = parse_request(json.dumps(body))
result = analyze_case(request)
assert result.plan_digest.startswith("sha256:"), result.plan_digest
assert result.plan["case_id"] == "fixture-c-parser", result.plan["case_id"]
assert result.findings, "the packaged case must produce findings"
assert result.plan["repository"]["bundle_digest"].startswith("sha256:")
print("wheel-analyze-ok")
"""


def test_packaged_default_case_data_matches_test_fixtures():
    package = Path(case_registry.DEFAULT_CASE_ROOT)
    assert package.is_dir()
    for path in sorted(package.rglob("*")):
        if path.is_file():
            relative = path.relative_to(package)
            assert (FIXTURES / relative).read_bytes() == path.read_bytes(), relative


def test_wheel_install_has_default_case_registry(tmp_path):
    wheel = build_wheel(tmp_path / "wheel")
    site = tmp_path / "site"
    extract_wheel(wheel, site)

    names = set(zipfile.ZipFile(wheel).namelist())
    for relative in (
        "datacon/data/cases/registry.json",
        "datacon/data/cases/manifest.json",
        "datacon/data/cases/advisory.json",
        "datacon/data/cases/vulnerable/parser.c",
        "datacon/data/cases/fixed/parser.c",
        "datacon/data/cases/harness.c",
        "datacon/data/cases/fixture-repo.bundle",
        "datacon/data/cases/fix.patch",
        "datacon/data/cases/build.sh",
        "datacon/data/cases/dependencies.lock",
        "datacon/data/cases/inputs/candidate.txt",
        "datacon/data/cases/inputs/clean.txt",
        "datacon/data/cases/inputs/normal.txt",
    ):
        assert relative in names, relative

    package_cases = site / "datacon" / "data" / "cases"
    custom = tmp_path / "custom-cases"
    custom_case_root(package_cases, custom)

    env = os.environ.copy()
    env.pop("DATACON_CASE_ROOT", None)
    env["PYTHONPATH"] = str(site)
    result = subprocess.run(
        [
            sys.executable,
            "-S",
            "-c",
            SMOKE,
            str(site),
            str(custom),
            json.dumps(request_body("fixture-c-parser")),
            json.dumps(request_body("custom-parser")),
        ],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        timeout=60,
        env=env,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "wheel-smoke-ok" in result.stdout


def test_wheel_install_can_analyze_the_default_case(tmp_path):
    wheel = build_wheel(tmp_path / "wheel")
    site = tmp_path / "site"
    extract_wheel(wheel, site)

    env = os.environ.copy()
    env.pop("DATACON_CASE_ROOT", None)
    env["PYTHONPATH"] = str(site)
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            ANALYZE,
            str(site),
            json.dumps(request_body("fixture-c-parser")),
        ],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        timeout=120,
        env=env,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "wheel-analyze-ok" in result.stdout


INSTALLED_SMOKE = """
import importlib.metadata as metadata
import json
import os
import sys

import datacon

site = os.path.realpath(sys.argv[1])
package_file = os.path.realpath(datacon.__file__)
assert package_file.startswith(site + os.sep), package_file

version = metadata.version("datacon")
assert version == "0.1.0", version
requires = metadata.requires("datacon") or []
assert any(requirement.lower().startswith("psycopg") for requirement in requires), requires
entries = {
    entry.name: entry.value
    for entry in metadata.entry_points(group="console_scripts")
}
assert entries.get("datacon") == "datacon.cli:main", entries

from datacon.agents.analysis import analyze_case
from datacon.contracts import DEFAULT_LIMITS, parse_request

body = json.loads(sys.argv[2])
body["limits"] = dict(DEFAULT_LIMITS)
request = parse_request(json.dumps(body))
assert request["target"]["case_id"] == "fixture-c-parser"
result = analyze_case(request)
assert result.plan["case_id"] == "fixture-c-parser", result.plan["case_id"]
assert result.plan_digest.startswith("sha256:"), result.plan_digest
print("wheel-installed-ok")
"""


def test_installed_wheel_exposes_entry_point_metadata_and_default_case(tmp_path):
    """Install the wheel in a real venv instead of only extracting its zip.

    Dependencies stay in the locked project environment and are exposed via
    PYTHONPATH; the datacon package itself must come from the installed wheel,
    and the console script must be the wheel's real entry point.
    """
    if shutil.which("uv") is None:
        import pytest

        pytest.skip("uv is required to build the wheel for the installation test")

    wheel = build_wheel(tmp_path / "wheel")
    venv = tmp_path / "venv"
    subprocess.run(
        [sys.executable, "-m", "venv", str(venv)],
        check=True,
        capture_output=True,
        text=True,
        timeout=120,
        env=os.environ.copy(),
    )
    if os.name == "nt":
        python = venv / "Scripts" / "python.exe"
        console = venv / "Scripts" / "datacon.exe"
    else:
        python = venv / "bin" / "python"
        console = venv / "bin" / "datacon"

    installed = subprocess.run(
        [
            str(python),
            "-m",
            "pip",
            "install",
            "--no-index",
            "--no-deps",
            "--disable-pip-version-check",
            str(wheel),
        ],
        capture_output=True,
        text=True,
        timeout=120,
        env=os.environ.copy(),
    )
    assert installed.returncode == 0, installed.stdout + installed.stderr

    deps_site = sysconfig.get_paths()["purelib"]
    env = os.environ.copy()
    env.pop("DATACON_CASE_ROOT", None)
    env["PYTHONPATH"] = deps_site

    help_result = subprocess.run(
        [str(console), "--help"],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        timeout=60,
        env=env,
    )
    assert help_result.returncode == 0, help_result.stdout + help_result.stderr
    assert "usage: datacon" in help_result.stdout

    site = subprocess.run(
        [
            str(python),
            "-c",
            "import sysconfig; print(sysconfig.get_paths()['purelib'])",
        ],
        capture_output=True,
        text=True,
        timeout=60,
        env=os.environ.copy(),
    )
    assert site.returncode == 0, site.stdout + site.stderr
    smoke = subprocess.run(
        [
            str(python),
            "-c",
            INSTALLED_SMOKE,
            site.stdout.strip(),
            json.dumps(request_body("fixture-c-parser")),
        ],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        timeout=120,
        env=env,
    )
    assert smoke.returncode == 0, smoke.stdout + smoke.stderr
    assert "wheel-installed-ok" in smoke.stdout
