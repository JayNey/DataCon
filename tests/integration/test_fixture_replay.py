import json
import os
from pathlib import Path
import shutil
import subprocess

import pytest

pytestmark = pytest.mark.asan

CASES = Path(__file__).resolve().parents[1] / "fixtures" / "cases"


@pytest.fixture(scope="module")
def manifest():
    return json.loads((CASES / "manifest.json").read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def compiler():
    executable = shutil.which(os.getenv("CC", "clang"))
    if executable is None:
        pytest.skip("clang is required for the synthetic ASan fixture replay")
    return executable


@pytest.fixture(scope="module")
def binaries(tmp_path_factory, manifest, compiler):
    build_dir = tmp_path_factory.mktemp("asan-fixtures")
    result = {}
    for version, source in manifest["versions"].items():
        binary = build_dir / f"parser-{version}"
        subprocess.run(
            [
                compiler,
                "-std=c11",
                "-g",
                "-O0",
                "-fno-omit-frame-pointer",
                "-fsanitize=address",
                str(CASES / source),
                str(CASES / manifest["harness"]),
                "-o",
                str(binary),
            ],
            check=True,
            capture_output=True,
            text=True,
        )
        result[version] = binary
    return result


def replay(manifest, binary, input_path, tmp_path):
    env = os.environ.copy()
    env["ASAN_OPTIONS"] = manifest["asan_options"]
    env["TMPDIR"] = str(tmp_path)
    symbolizer = shutil.which("llvm-symbolizer")
    if symbolizer is not None:
        env["ASAN_SYMBOLIZER_PATH"] = symbolizer
    with input_path.open("rb") as stdin:
        return subprocess.run(
            [str(binary)],
            stdin=stdin,
            capture_output=True,
            text=True,
            timeout=30,
            env=env,
        )


@pytest.mark.parametrize("version", ["vulnerable", "fixed"])
def test_normal_input_passes_on_both_versions(manifest, binaries, tmp_path, version):
    case = manifest["cases"]["B01"]
    result = replay(
        manifest,
        binaries[version],
        CASES / case["inputs"]["normal"],
        tmp_path,
    )
    assert result.returncode == case["expected_exit"]["normal"], result.stderr
    assert result.stdout == case["expected_stdout"]["normal"]
    assert "AddressSanitizer" not in result.stderr


def test_b01_candidate_hits_the_expected_asan_signature(manifest, binaries, tmp_path):
    case = manifest["cases"]["B01"]
    signature = manifest["asan_signature"]
    result = replay(
        manifest,
        binaries["vulnerable"],
        CASES / case["inputs"]["candidate"],
        tmp_path,
    )
    assert result.returncode == case["expected_exit"]["candidate_asan"], result.stderr
    assert f'ERROR: AddressSanitizer: {signature["error"]}' in result.stderr
    assert (
        f'{signature["operation"]} of size {signature["access_size"]}'
        in result.stderr
    )

    symbolized = (
        signature["function"] in result.stderr
        and f'{signature["source"]}:' in result.stderr
    )
    if not symbolized:
        if shutil.which("llvm-symbolizer") is None:
            pytest.skip(
                "ASan frames are not symbolized; install llvm-symbolizer to assert "
                f"{signature['function']} at {signature['source']} (CI installs llvm)"
            )
        pytest.fail(
            "llvm-symbolizer is installed but the ASan report lacks the expected "
            f"{signature['function']} frame from {signature['source']}"
        )


def test_b01_candidate_is_clean_on_the_fixed_version(manifest, binaries, tmp_path):
    case = manifest["cases"]["B01"]
    result = replay(
        manifest,
        binaries["fixed"],
        CASES / case["inputs"]["candidate"],
        tmp_path,
    )
    assert result.returncode == case["expected_exit"]["candidate_clean"], result.stderr
    assert result.stdout == case["expected_stdout"]["candidate_clean"]
    assert "AddressSanitizer" not in result.stderr


@pytest.mark.parametrize("version", ["vulnerable", "fixed"])
def test_b02_candidate_is_clean_on_both_versions(manifest, binaries, tmp_path, version):
    case = manifest["cases"]["B02"]
    result = replay(
        manifest,
        binaries[version],
        CASES / case["inputs"]["candidate"],
        tmp_path,
    )
    assert result.returncode == case["expected_exit"]["candidate_clean"], result.stderr
    assert result.stdout == case["expected_stdout"]["candidate_clean"]
    assert "AddressSanitizer" not in result.stderr
