"""Execution-pipeline tests. Run on any OS: command_prompt atomics fall back to
`sh -c` off Windows, so the fake atomics below use commands valid in both."""
import asyncio
import sys
import textwrap
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core import outcome as oc  # noqa: E402
from core.atomic_engine import AtomicEngine  # noqa: E402
from core.executor import DeterministicExecutor, ExecutionJob, Target, TestSelection, serialize_job_results  # noqa: E402
from core.winrm_runner import _prepare_cmd  # noqa: E402

pytestmark = pytest.mark.skipif(sys.platform == "win32", reason="fake atomics use POSIX sh")


def _write_atomic(root: Path, tid: str, body: str) -> None:
    d = root / tid
    d.mkdir(parents=True)
    (d / f"{tid}.yaml").write_text(textwrap.dedent(body), encoding="utf-8")


@pytest.fixture
def engine(tmp_path):
    marker = tmp_path / "marker"
    _write_atomic(tmp_path, "T9001", f"""
        attack_technique: T9001
        display_name: Writes a marker and cleans it up
        atomic_tests:
        - name: marker
          auto_generated_guid: g-1
          description: d
          supported_platforms: [windows, linux]
          input_arguments:
            path:
              description: p
              type: path
              default: {marker}
          executor:
            name: command_prompt
            command: |
              echo hi > #{{path}}
            cleanup_command: |
              rm -f #{{path}}
        """)
    _write_atomic(tmp_path, "T9002", """
        attack_technique: T9002
        display_name: Missing prerequisite
        atomic_tests:
        - name: needs-file
          auto_generated_guid: g-2
          description: d
          supported_platforms: [windows, linux]
          dependency_executor_name: command_prompt
          dependencies:
          - description: tool must exist
            prereq_command: test -f /nonexistent/tool
            get_prereq_command: "true"
          executor:
            name: command_prompt
            command: echo should-not-run
        """)
    _write_atomic(tmp_path, "T9003", """
        attack_technique: T9003
        display_name: Blocked by AV
        atomic_tests:
        - name: amsi
          auto_generated_guid: g-3
          description: d
          supported_platforms: [windows, linux]
          executor:
            name: command_prompt
            command: echo 'This script contains malicious content' 1>&2; exit 1
        """)
    _write_atomic(tmp_path, "T9004", """
        attack_technique: T9004
        display_name: Uses PathToAtomicsFolder
        atomic_tests:
        - name: atomics-path
          auto_generated_guid: g-4
          description: d
          supported_platforms: [windows, linux]
          input_arguments:
            f:
              description: f
              type: path
              default: PathToAtomicsFolder/T9004/T9004.yaml
          executor:
            name: command_prompt
            command: |
              test -f #{f}
        """)
    e = AtomicEngine(atomics_path=str(tmp_path))
    assert e.load_all() == 4
    e.marker = marker
    return e


def _run(engine, selections, **job_kw):
    job = ExecutionJob(
        job_id="job-1",
        targets=[Target(target_id="t1", name="local", os_platform="linux", privilege="admin")],
        selections=[TestSelection(technique_id=t, test_index=0) for t in selections],
        **job_kw,
    )
    asyncio.run(DeterministicExecutor(engine).run(job))
    return job


def test_cleanup_runs_after_test(engine):
    job = _run(engine, ["T9001"])
    r = job.results[0]
    assert r.outcome == oc.SUCCESS and r.success, (r.exit_code, r.stderr, r.command_executed)
    assert r.cleanup_status == "ok"
    assert not engine.marker.exists(), "cleanup_command should have removed the marker"


def test_cleanup_can_be_disabled(engine):
    job = _run(engine, ["T9001"], run_cleanup=False)
    assert job.results[0].cleanup_status == "disabled"
    assert engine.marker.exists()


def test_unmet_prereq_skips_test(engine):
    r = _run(engine, ["T9002"]).results[0]
    assert r.outcome == oc.PREREQ_MISSING and r.skipped
    assert "tool must exist" in r.skip_reason


def test_prereq_check_can_be_disabled(engine):
    r = _run(engine, ["T9002"], check_prereqs=False).results[0]
    assert r.outcome == oc.SUCCESS and "should-not-run" in r.stdout


def test_amsi_block_classified(engine):
    r = _run(engine, ["T9003"]).results[0]
    assert r.outcome == oc.BLOCKED and not r.success


def test_atomics_folder_placeholder_resolved(engine):
    r = _run(engine, ["T9004"]).results[0]
    assert r.outcome == oc.SUCCESS, r.command_executed


def test_serialized_results_keep_identity_fields(engine):
    data = serialize_job_results(_run(engine, ["T9001", "T9003"]))
    res = data["by_target"][0]["results"]
    assert {"test_index", "test_guid", "target_id", "outcome", "cleanup_status"} <= set(res[0])
    assert data["summary"]["outcomes"]["blocked"] == 1


@pytest.mark.parametrize("exit_code,stdout,stderr,timed_out,expected", [
    (0, "ok", "", False, oc.SUCCESS),
    (1, "Alice\nBob", "", False, oc.PARTIAL),
    (1, "", "", False, oc.FAILED),
    (5, "", "Access denied (security control): x", False, oc.BLOCKED),
    (0, "", "This script contains malicious content and has been blocked", False, oc.BLOCKED),
    (1, "", "'mimikatz' is not recognized as an internal or external command", False, oc.ERROR),
    (-1, "", "WinRM connect failed: refused", False, oc.ERROR),
    (-1, "", "Execution timed out after 60s", True, oc.TIMEOUT),
    (0, "C:\\notes.txt: access denied to vault", "", False, oc.SUCCESS),  # stdout is not scanned
])
def test_classify(exit_code, stdout, stderr, timed_out, expected):
    assert oc.classify(exit_code, stdout, stderr, timed_out) == expected


def test_prepare_cmd_chains_lines():
    assert _prepare_cmd("@echo off\r\nwhoami\n\n  hostname  \n") == "whoami & hostname"


def test_cancel_mid_test_still_runs_cleanup(tmp_path):
    flag = tmp_path / "cleaned"
    _write_atomic(tmp_path, "T9005", f"""
        attack_technique: T9005
        display_name: slow
        atomic_tests:
        - name: slow
          auto_generated_guid: g-5
          description: d
          supported_platforms: [windows, linux]
          executor:
            name: command_prompt
            command: |
              sleep 30
            cleanup_command: |
              touch {flag}
        """)
    e = AtomicEngine(atomics_path=str(tmp_path))
    e.load_all()
    job = ExecutionJob(
        job_id="job-c",
        targets=[Target(target_id="t1", name="local", os_platform="linux", privilege="admin")],
        selections=[TestSelection(technique_id="T9005", test_index=0)],
    )

    async def main():
        task = asyncio.create_task(DeterministicExecutor(e).run(job))
        await asyncio.sleep(0.5)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

    asyncio.run(main())
    assert flag.exists(), "cleanup must run when a job is cancelled mid-test"
