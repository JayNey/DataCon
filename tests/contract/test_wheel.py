import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
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
