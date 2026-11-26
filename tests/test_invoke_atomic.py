"""invoke-atomic engine tests.

The local tests drive the real, unmodified Invoke-AtomicRedTeam module through
pwsh with `sh` atomics, so they need `python tools/fetch_vendor.py` and pwsh
(on PATH or PWSH_PATH). They are skipped otherwise. The remote tests replace
WinRM with fakes and check staging and parameter passing only.
"""
import asyncio
import base64
import json
import sys
import textwrap
import zipfile
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from config import settings  # noqa: E402
from core import invoke_atomic as ia  # noqa: E402
from core import outcome as oc  # noqa: E402
from core.atomic_engine import AtomicEngine  # noqa: E402
from core.executor import DeterministicExecutor, ExecutionJob, Target, TestSelection  # noqa: E402
from core.winrm_runner import RemoteConnection  # noqa: E402

_status = ia.vendor_status()
needs_pwsh = pytest.mark.skipif(
    sys.platform == "win32" or not _status["available"] or not _status["local_powershell"],
    reason="needs vendor modules (tools/fetch_vendor.py) and pwsh on a POSIX host",
)

GUID = "11111111-1111-1111-1111-11111111{:04d}"


def _atomic(root: Path, tid: str, body: str) -> None:
    d = root / tid
    d.mkdir(parents=True)
    (d / f"{tid}.yaml").write_text(textwrap.dedent(body), encoding="utf-8")


@pytest.fixture
def atomics(tmp_path):
    marker = tmp_path / "marker"
    _atomic(tmp_path, "T9101", f"""
        attack_technique: T9101
        display_name: marker with cleanup and input arg
        atomic_tests:
        - name: marker
          auto_generated_guid: {GUID.format(1)}
          description: d
          supported_platforms: [linux]
          input_arguments:
            word:
              description: w
              type: string
              default: default-word
          executor:
            name: sh
            command: |
              echo #{{word}} > {marker}
              cat {marker}
            cleanup_command: |
              rm -f {marker}
        """)
    _atomic(tmp_path, "T9102", f"""
        attack_technique: T9102
        display_name: unmet prereq
        atomic_tests:
        - name: needs-tool
          auto_generated_guid: {GUID.format(2)}
          description: d
          supported_platforms: [linux]
          dependency_executor_name: sh
          dependencies:
          - description: protonred-fake-tool must be installed
            prereq_command: |
              test -f /nonexistent/protonred-fake-tool
            get_prereq_command: |
              true
          executor:
            name: sh
            command: |
              echo should-not-run
        """)
    _atomic(tmp_path, "T9103", f"""
        attack_technique: T9103
        display_name: av block
        atomic_tests:
        - name: amsi
          auto_generated_guid: {GUID.format(3)}
          description: d
          supported_platforms: [linux]
          executor:
            name: sh
            command: |
              echo "This script contains malicious content and has been blocked by your antivirus software." 1>&2
              exit 1
        """)
    _atomic(tmp_path, "T9104", f"""
        attack_technique: T9104
        display_name: slow
        atomic_tests:
        - name: sleeper
          auto_generated_guid: {GUID.format(4)}
          description: d
          supported_platforms: [linux]
          executor:
            name: sh
            command: |
              sleep 30
        """)
    engine = AtomicEngine(atomics_path=str(tmp_path))
    assert engine.load_all() == 4
    engine.marker = marker
    return engine


def _run(engine, tid, arg_overrides=None, **job_kw):
    job = ExecutionJob(
        job_id="job-ia",
        targets=[Target(target_id="t1", name="local", os_platform="linux", privilege="admin")],
        selections=[TestSelection(technique_id=tid, test_index=0, arg_overrides=arg_overrides or {})],
        engine="invoke-atomic",
        **job_kw,
    )
    asyncio.run(DeterministicExecutor(engine).run(job))
    return job.results[0]


@needs_pwsh
def test_success_runs_test_and_cleanup(atomics):
    r = _run(atomics, "T9101")
    assert r.outcome == oc.SUCCESS, (r.stdout, r.stderr)
    assert r.stdout.strip() == "default-word"
    assert "echo default-word" in r.command_executed
    assert r.test_guid == GUID.format(1)
    assert r.cleanup_status == "ran"
    assert not atomics.marker.exists(), "Invoke-AtomicTest -Cleanup should have removed the marker"


@needs_pwsh
def test_input_args_are_passed(atomics):
    r = _run(atomics, "T9101", arg_overrides={"word": "custom-word"})
    assert r.stdout.strip() == "custom-word"


@needs_pwsh
def test_cleanup_disabled(atomics):
    r = _run(atomics, "T9101", run_cleanup=False)
    assert r.cleanup_status == "disabled"
    assert atomics.marker.exists()


@needs_pwsh
def test_unmet_prereq(atomics):
    r = _run(atomics, "T9102")
    assert r.outcome == oc.PREREQ_MISSING and r.skipped
    assert "protonred-fake-tool must be installed" in r.skip_reason


@needs_pwsh
def test_av_block_classified(atomics):
    r = _run(atomics, "T9103")
    assert r.outcome == oc.BLOCKED, (r.exit_code, r.stderr)


@needs_pwsh
def test_timeout(atomics, monkeypatch):
    monkeypatch.setattr(settings, "AGENT_TIMEOUT_SECONDS", 3)
    r = _run(atomics, "T9104")
    assert r.outcome == oc.TIMEOUT, (r.exit_code, r.stderr)


# ── no PowerShell needed below ────────────────────────────────────────────────

def _encode(obj) -> str:
    return ia.RESULT_MARKER + base64.b64encode(json.dumps(obj).encode()).decode()


def test_parse_result_full():
    out = "noise\n" + _encode({
        "prereq": {"met": True, "reasons": [], "output": ""},
        "test": {"exit_code": 5, "is_timeout": False, "stdout": "o", "stderr": "e", "command": "c"},
        "cleanup": {"ran": True, "output": "done"},
        "output": "console", "error": None,
    })
    r = ia.parse_result(out)
    assert (r.test_ran, r.exit_code, r.stdout, r.stderr, r.command) == (True, 5, "o", "e", "c")
    assert r.cleanup_ran and r.cleanup_output == "done" and not r.error


def test_parse_result_missing_marker():
    r = ia.parse_result("Import-Module : file not found", "boom")
    assert not r.test_ran and "boom" in r.error


def test_unavailable_vendor_is_an_error(tmp_path, monkeypatch, atomics):
    monkeypatch.setattr(settings, "VENDOR_DIR", str(tmp_path / "empty"))
    r = _run(atomics, "T9101")
    assert r.outcome == oc.ERROR and "fetch_vendor" in r.stderr


def test_remote_staging_and_params(tmp_path, monkeypatch, atomics):
    """Modules + only the needed technique are staged once; the script gets remote paths."""
    if not _status["available"]:
        pytest.skip("needs vendor modules")
    calls = {"copies": [], "scripts": []}
    staged = set()

    async def fake_ps(conn, script, timeout):
        calls["scripts"].append(script)
        if "'CURRENT'" in script:
            return ("CURRENT" if any(d in script for d in staged) else "STALE"), ""
        if "Expand-Archive" in script:
            for d in ("ProtonRed\\modules", "ProtonRed\\atomics\\T9101"):
                if d in script:
                    staged.add(d)
            return "STAGED", ""
        params = json.loads(base64.b64decode(script.split("'")[1]))
        calls["params"] = params
        return _encode({"test": {"exit_code": 0, "stdout": "ok", "stderr": "", "command": "x"},
                        "cleanup": {"ran": True, "output": ""}}), ""

    async def fake_copy(conn, src, dest, timeout):
        with zipfile.ZipFile(src) as zf:
            calls["copies"].append((dest, sorted(zf.namelist())))

    monkeypatch.setattr(ia, "run_remote_ps", fake_ps)
    monkeypatch.setattr(ia, "copy_to_remote", fake_copy)

    backend = ia.InvokeAtomicBackend(atomics_path=str(atomics.atomics_path))
    conn = RemoteConnection(host="dc01", username="u", password="p", pool="job-x")
    test = atomics.get_technique("T9101").atomic_tests[0]

    for _ in range(2):
        r = asyncio.run(backend.run("T9101", test.guid, 0, {"word": "w"}, 60, conn))
        assert r.test_ran and r.exit_code == 0

    # Staged once each, even though the test ran twice.
    assert len(calls["copies"]) == 2
    mod_dest, mod_files = calls["copies"][0]
    assert mod_dest.endswith("\\.protonred-modules.zip")
    assert "modules/Invoke-AtomicRedTeam/Invoke-AtomicRedTeam.psd1" in mod_files
    assert "modules/powershell-yaml/powershell-yaml.psd1" in mod_files
    assert "modules/ProtonRed-ExecutionLogger.psm1" in mod_files
    tech_dest, tech_files = calls["copies"][1]
    assert tech_files == ["T9101/T9101.yaml"], "only the selected technique is copied"

    p = calls["params"]
    assert p["atomics_dir"] == "C:\\ProgramData\\ProtonRed\\atomics"
    assert p["modules_dir"] == "C:\\ProgramData\\ProtonRed\\modules"
    assert p["test_guid"] == test.guid and p["input_args"] == {"word": "w"}

    # A new job re-checks the target but finds it current: no new uploads.
    backend.forget("job-x")
    asyncio.run(backend.run("T9101", test.guid, 0, {}, 60, conn))
    assert len(calls["copies"]) == 2
