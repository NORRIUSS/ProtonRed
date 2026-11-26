"""
Deterministic executor — runs selected TTPs without AI involvement.
Collects structured results for later AI analysis.

A job runs the selected TTPs against one or more TARGETS (fan-out). Each target
is either:
  - local  : run on this machine via subprocess (tool deployed on the box), or
  - remote : run on another host via WinRM — the TTP executes as-if-local there.

Each target carries its own OS, privilege (admin/standard user), and
domain-join state, which drive per-target skip decisions.
"""
import asyncio
import inspect
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from typing import AsyncGenerator, Callable, Optional

from core.atomic_engine import AtomicEngine, ExecutionResult
from core.tactic_map import get_tactic_for_technique, DOMAIN_REQUIRED_TECHNIQUES
from core.winrm_runner import RemoteConnection, clear_client_cache
from core import outcome as oc
from config import settings


@dataclass
class TestSelection:
    technique_id: str
    test_index: int
    arg_overrides: dict = field(default_factory=dict)


@dataclass
class Target:
    target_id: str
    name: str                          # display label, e.g. "DC01" or "localhost"
    os_platform: str = "windows"       # windows | linux | macos
    privilege: str = "standard_user"   # admin | standard_user
    connection: str = "local"          # local | remote
    domain_joined: bool = False
    # Remote (WinRM) — only used when connection == "remote"
    host: str = "localhost"
    winrm_username: str = ""
    winrm_password: str = ""
    winrm_transport: str = "ntlm"      # ntlm | kerberos | credssp | negotiate | basic
    winrm_port: int = 5985
    winrm_ssl: bool = False
    notes: str = ""

    @property
    def elevation_available(self) -> bool:
        return self.privilege == "admin"

    @property
    def is_remote(self) -> bool:
        return self.connection == "remote"

    def remote_connection(self, pool: str = "") -> Optional[RemoteConnection]:
        if not self.is_remote:
            return None
        return RemoteConnection(
            host=self.host,
            username=self.winrm_username,
            password=self.winrm_password,
            transport=self.winrm_transport,
            port=self.winrm_port,
            ssl=self.winrm_ssl,
            pool=pool,
        )


# Backward-compat alias — older callers may still import ScopeConfig.
@dataclass
class ScopeConfig:
    user_context: str
    target: str
    os_platform: str
    elevation_available: bool
    hostname: str = ""
    notes: str = ""


@dataclass
class JobResult:
    technique_id: str
    test_index: int
    test_name: str
    test_guid: str
    tactic: str
    success: bool
    exit_code: int
    stdout: str
    stderr: str
    command_executed: str
    duration_ms: int
    target_id: str = ""
    target_name: str = ""
    skipped: bool = False
    skip_reason: str = ""
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    # See core/outcome.py. Empty only for results loaded from pre-outcome files.
    outcome: str = ""
    # ok | failed | none (test has no cleanup) | disabled (job opted out) | "" (test not run)
    cleanup_status: str = ""
    cleanup_output: str = ""


@dataclass
class ExecutionJob:
    job_id: str
    targets: list[Target]
    selections: list[TestSelection]
    status: str = "pending"    # pending | running | done | error
    results: list[JobResult] = field(default_factory=list)
    start_time: Optional[str] = None
    end_time: Optional[str] = None
    total: int = 0
    completed: int = 0
    error: Optional[str] = None
    # Run each test's cleanup_command after it, on the same target. ART tests
    # in persistence/defense-evasion leave real changes behind otherwise.
    run_cleanup: bool = True
    # Evaluate ART `dependencies` before running a test.
    check_prereqs: bool = True
    # Run `get_prereq_command` for unmet dependencies (usually downloads tools).
    get_prereqs: bool = False


@dataclass
class ExecutorEvent:
    type: str   # started | test_start | test_done | skipped | job_done | error
    data: dict
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat())


class DeterministicExecutor:
    def __init__(self, engine: AtomicEngine, on_event: Optional[Callable[[ExecutorEvent], None]] = None):
        self.engine = engine
        self.on_event = on_event

    async def _emit(self, event: ExecutorEvent):
        """Deliver an event and wait for it, so consumers see events in order
        and the last test_done arrives before the caller's completion message."""
        if self.on_event:
            res = self.on_event(event)
            if inspect.isawaitable(res):
                await res

    # Download cradle patterns — commands with these fetch from internet at runtime.
    _DOWNLOAD_PATTERNS = (
        "new-object net.webclient",
        "invoke-webrequest",
        "start-bitstransfer",
        "iwr http",
        "iwr https",
        "(new-object system.net.webclient)",
        "downloadfile(",
        "downloadstring(",
        "invoke-expression (new-object",
        "iex (new-object",
        "iex(new-object",
    )

    def _truncate_middle(self, text: str, max_len: int) -> str:
        if not text or len(text) <= max_len:
            return text or ""
        half = max_len // 2 - 10
        return text[:half] + "\n\n[... OUTPUT TRUNCATED TO PRESERVE MEMORY ...]\n\n" + text[-half:]

    def _command_needs_download(self, command: str) -> bool:
        low = (command or "").lower()
        return any(pat in low for pat in self._DOWNLOAD_PATTERNS)

    def _should_skip(self, technique_id: str, test_index: int, target: Target) -> tuple[bool, str]:
        technique = self.engine.get_technique(technique_id)
        if not technique:
            return True, f"Technique {technique_id} not found in loaded atomics"
        if test_index >= len(technique.atomic_tests):
            return True, f"Test index {test_index} out of range"

        test = technique.atomic_tests[test_index]

        # Platform check
        plat = target.os_platform.lower()
        if plat not in test.supported_platforms and "all" not in test.supported_platforms:
            return True, f"Not supported on {target.os_platform}"

        # Elevation check
        if test.executor.elevation_required and not target.elevation_available:
            return True, "Elevation required — target has standard-user privileges only"

        # Domain-membership check — AD-dependent techniques produce no signal off-domain
        if technique_id.upper() in DOMAIN_REQUIRED_TECHNIQUES and not target.domain_joined:
            return True, "Requires domain membership — target is not domain-joined"

        # Remote WinRM can only drive Windows shells (powershell/cmd)
        if target.is_remote and test.executor.name in ("bash", "sh"):
            return True, f"Executor '{test.executor.name}' not runnable remotely over WinRM"

        # Skip tests that download external tools at runtime — they hang or fail in isolated envs.
        if self._command_needs_download(test.executor.command):
            return True, "Requires external tool download — skipped in isolated environment"

        # wmic removed from Windows 11 — skip instead of returning misleading exit:-1.
        if (target.os_platform.lower() == "windows"
                and "wmic " in test.executor.command.lower()
                and not target.is_remote):
            return True, "wmic.exe removed from Windows 11 — not available on this host"

        return False, ""

    async def _cleanup(self, sel: TestSelection, remote: Optional[RemoteConnection]) -> tuple[str, str]:
        try:
            res = await self.engine.cleanup_atomic(
                sel.technique_id, sel.test_index, sel.arg_overrides, remote,
                timeout=settings.AGENT_TIMEOUT_SECONDS,
            )
        except Exception as exc:
            return "failed", f"Cleanup raised: {exc!r}"
        detail = "\n".join(x for x in (res.get("output", ""), res.get("error", "")) if x)
        return res["status"], self._truncate_middle(detail, 2000)

    async def _record_not_run(self, job: ExecutionJob, sel: TestSelection, target: Target,
                        test_name: str, outcome: str, reason: str) -> None:
        """Record a test that was never executed (filtered or prereqs unmet)."""
        job.results.append(JobResult(
            technique_id=sel.technique_id,
            test_index=sel.test_index,
            test_name=test_name,
            test_guid="",
            tactic=get_tactic_for_technique(sel.technique_id),
            success=False,
            exit_code=-1,
            stdout="",
            stderr="",
            command_executed="",
            duration_ms=0,
            target_id=target.target_id,
            target_name=target.name,
            skipped=True,
            skip_reason=reason,
            outcome=outcome,
        ))
        job.completed += 1
        await self._emit(ExecutorEvent(type="skipped", data={
            "technique_id": sel.technique_id,
            "target_id": target.target_id,
            "target_name": target.name,
            "reason": reason,
            "outcome": outcome,
            "progress": f"{job.completed}/{job.total}",
        }))

    async def run(self, job: ExecutionJob) -> ExecutionJob:
        job.status = "running"
        job.start_time = datetime.utcnow().isoformat()
        job.total = len(job.targets) * len(job.selections)

        await self._emit(ExecutorEvent(type="started", data={
            "job_id": job.job_id,
            "total": job.total,
            "targets": [
                {"target_id": t.target_id, "name": t.name, "connection": t.connection,
                 "os_platform": t.os_platform, "privilege": t.privilege, "domain_joined": t.domain_joined}
                for t in job.targets
            ],
        }))

        for target in job.targets:
            await self._emit(ExecutorEvent(type="target_start", data={
                "target_id": target.target_id,
                "name": target.name,
                "connection": target.connection,
                "host": target.host if target.is_remote else "local",
            }))
            remote = target.remote_connection(pool=job.job_id)

            for sel in job.selections:
                skip, reason = self._should_skip(sel.technique_id, sel.test_index, target)

                technique = self.engine.get_technique(sel.technique_id)
                test_name = ""
                if technique and sel.test_index < len(technique.atomic_tests):
                    test_name = technique.atomic_tests[sel.test_index].name

                await self._emit(ExecutorEvent(type="test_start", data={
                    "technique_id": sel.technique_id,
                    "test_index": sel.test_index,
                    "test_name": test_name,
                    "target_id": target.target_id,
                    "target_name": target.name,
                    "skipped": skip,
                    "skip_reason": reason,
                }))

                if skip:
                    await self._record_not_run(job, sel, target, test_name, oc.SKIPPED, reason)
                    continue

                technique_test = technique.atomic_tests[sel.test_index]
                if job.check_prereqs and technique_test.dependencies:
                    met, detail = await self.engine.check_prereqs(
                        technique_test, sel.arg_overrides, remote,
                        get_prereqs=job.get_prereqs, timeout=settings.AGENT_TIMEOUT_SECONDS,
                    )
                    if not met:
                        await self._record_not_run(job, sel, target, test_name, oc.PREREQ_MISSING,
                                             f"Prerequisites not met: {detail}")
                        continue

                t_start = asyncio.get_running_loop().time()

                try:
                    exec_result = await self.engine.execute_atomic(
                        technique_id=sel.technique_id,
                        test_index=sel.test_index,
                        arg_overrides=sel.arg_overrides,
                        timeout=settings.AGENT_TIMEOUT_SECONDS,
                        remote=remote,
                    )
                except asyncio.CancelledError:
                    # Cancelled mid-test: the test may have half-applied its
                    # changes, so still try to undo them before stopping.
                    if job.run_cleanup:
                        try:
                            await asyncio.wait_for(self._cleanup(sel, remote), timeout=60)
                        except BaseException:
                            pass
                    raise
                except Exception as exc:
                    exec_result = ExecutionResult(
                        technique_id=sel.technique_id,
                        test_name=test_name,
                        test_guid="",
                        success=False,
                        stdout="",
                        stderr=f"Executor raised: {exc!r}",
                        exit_code=-1,
                        platform=target.os_platform,
                        command_executed="",
                        outcome=oc.ERROR,
                    )

                duration_ms = int((asyncio.get_running_loop().time() - t_start) * 1000)

                cleanup_status, cleanup_output = "disabled", ""
                if job.run_cleanup:
                    cleanup_status, cleanup_output = await self._cleanup(sel, remote)

                result = JobResult(
                    technique_id=sel.technique_id,
                    test_index=sel.test_index,
                    test_name=exec_result.test_name,
                    test_guid=exec_result.test_guid,
                    tactic=get_tactic_for_technique(sel.technique_id),
                    success=exec_result.success,
                    exit_code=exec_result.exit_code,
                    stdout=self._truncate_middle(exec_result.stdout, 20000),
                    stderr=self._truncate_middle(exec_result.stderr, 8000),
                    command_executed=exec_result.command_executed[:2000],
                    duration_ms=duration_ms,
                    target_id=target.target_id,
                    target_name=target.name,
                    outcome=exec_result.outcome,
                    cleanup_status=cleanup_status,
                    cleanup_output=cleanup_output,
                )
                job.results.append(result)
                job.completed += 1

                await self._emit(ExecutorEvent(type="test_done", data={
                    "technique_id": sel.technique_id,
                    "test_name": result.test_name,
                    "target_id": target.target_id,
                    "target_name": target.name,
                    "success": result.success,
                    "outcome": result.outcome,
                    "exit_code": result.exit_code,
                    "duration_ms": duration_ms,
                    "cleanup_status": cleanup_status,
                    "progress": f"{job.completed}/{job.total}",
                    "stdout_preview": result.stdout[:300],
                }))

        clear_client_cache(job.job_id)
        job.status = "done"
        job.end_time = datetime.utcnow().isoformat()
        await self._emit(ExecutorEvent(type="job_done", data={
            "job_id": job.job_id,
            "total": job.total,
            "succeeded": sum(1 for r in job.results if r.success),
            "failed": sum(1 for r in job.results if not r.success and not r.skipped),
            "skipped": sum(1 for r in job.results if r.skipped),
        }))
        return job


def _target_to_dict(t: Target) -> dict:
    return {
        "target_id": t.target_id,
        "name": t.name,
        "os_platform": t.os_platform,
        "privilege": t.privilege,
        "connection": t.connection,
        "domain_joined": t.domain_joined,
        "host": t.host if t.is_remote else "local",
        "notes": t.notes,
    }


def _outcome_counts(results: list[JobResult]) -> dict:
    counts = {o: 0 for o in oc.ALL_OUTCOMES}
    for r in results:
        if r.outcome in counts:
            counts[r.outcome] += 1
    return counts


def serialize_job_results(job: ExecutionJob) -> dict:
    """Serialize raw TTP execution results — no AI, pure subprocess output."""
    per_target = []
    for t in job.targets:
        t_results = [r for r in job.results if r.target_id == t.target_id]
        per_target.append({
            "target": _target_to_dict(t),
            "summary": {
                "total_tests": len(t_results),
                "succeeded": sum(1 for r in t_results if r.success),
                "failed": sum(1 for r in t_results if not r.success and not r.skipped),
                "skipped": sum(1 for r in t_results if r.skipped),
                "tactics_tested": sorted(set(r.tactic for r in t_results if not r.skipped)),
                "outcomes": _outcome_counts(t_results),
            },
            "results": [
                {
                    "technique_id": r.technique_id,
                    "test_index": r.test_index,
                    "test_guid": r.test_guid,
                    "test_name": r.test_name,
                    "tactic": r.tactic,
                    "target_id": r.target_id,
                    "target_name": r.target_name,
                    "outcome": r.outcome,
                    "success": r.success,
                    "exit_code": r.exit_code,
                    "skipped": r.skipped,
                    "skip_reason": r.skip_reason,
                    "cleanup_status": r.cleanup_status,
                    "cleanup_output": r.cleanup_output,
                    "stdout": r.stdout,
                    "stderr": r.stderr,
                    "command_executed": r.command_executed,
                    "duration_ms": r.duration_ms,
                    "timestamp": r.timestamp,
                }
                for r in t_results
            ],
        })

    return {
        "job_id": job.job_id,
        "targets": [_target_to_dict(t) for t in job.targets],
        "summary": {
            "target_count": len(job.targets),
            "total_tests": job.total,
            "succeeded": sum(1 for r in job.results if r.success),
            "failed": sum(1 for r in job.results if not r.success and not r.skipped),
            "skipped": sum(1 for r in job.results if r.skipped),
            "outcomes": _outcome_counts(job.results),
            "cleanup_failed": sum(1 for r in job.results if r.cleanup_status == "failed"),
        },
        "by_target": per_target,
    }
