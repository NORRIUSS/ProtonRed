"""
`invoke-atomic` engine: runs tests through Red Canary's Invoke-AtomicRedTeam
module (unmodified) instead of ProtonRed's own executor.

Per test, one PowerShell script (ps/run_atomic.ps1) runs ON THE TARGET and
calls Invoke-AtomicTest up to three times: -CheckPrereqs, the test itself
(logged by ps/ProtonRed-ExecutionLogger.psm1), and -Cleanup. It returns one
base64 JSON line that this module parses.

  local target  : powershell.exe (Windows) or pwsh (elsewhere) on this machine,
                  using vendor/modules and the local atomics folder directly.
  remote target : over WinRM. Modules and the needed technique folder are
                  copied to the target on first use (no internet needed there),
                  then the script runs in a remote runspace.

Run `python tools/fetch_vendor.py` once to populate vendor/modules.
"""
import asyncio
import base64
import hashlib
import json
import os
import platform
import shutil
import tempfile
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from config import settings
from core.winrm_runner import RemoteConnection, copy_to_remote, run_remote_ps

BASE_DIR = Path(__file__).resolve().parent.parent
PS_DIR = BASE_DIR / "ps"
WRAPPER = PS_DIR / "run_atomic.ps1"
LOGGER = PS_DIR / "ProtonRed-ExecutionLogger.psm1"
RESULT_MARKER = "PROTONRED_RESULT:"
REQUIRED_MODULES = ("Invoke-AtomicRedTeam", "powershell-yaml")


def modules_dir() -> Path:
    return Path(settings.VENDOR_DIR) / "modules"


def vendor_status() -> dict:
    """What the invoke-atomic engine needs on the ProtonRed host."""
    missing = [m for m in REQUIRED_MODULES if not (modules_dir() / m).is_dir()]
    return {
        "available": not missing,
        "missing_modules": missing,
        "local_powershell": _local_powershell(),
        "hint": "run: python tools/fetch_vendor.py" if missing else "",
    }


def _local_powershell() -> Optional[str]:
    if platform.system().lower() == "windows":
        sysroot = os.environ.get("SystemRoot", "C:\\Windows")
        return os.path.join(sysroot, "System32", "WindowsPowerShell", "v1.0", "powershell.exe")
    return settings.PWSH_PATH or shutil.which("pwsh")


@dataclass
class InvokeResult:
    """Parsed outcome of one run_atomic.ps1 call."""
    prereq_checked: bool = False
    prereq_met: bool = True
    prereq_reasons: list = field(default_factory=list)
    test_ran: bool = False
    exit_code: int = -1
    timed_out: bool = False
    stdout: str = ""
    stderr: str = ""
    command: str = ""
    cleanup_ran: bool = False
    cleanup_output: str = ""
    console: str = ""        # Invoke-AtomicTest console text for the test run
    error: str = ""          # harness-level failure (module import, WinRM, parse)


def parse_result(output: str, errors: str = "") -> InvokeResult:
    """Find the PROTONRED_RESULT line in the script output and decode it."""
    line = next((ln for ln in reversed(output.splitlines()) if ln.startswith(RESULT_MARKER)), None)
    if line is None:
        detail = (errors or output or "no output").strip()
        return InvokeResult(error=f"Invoke-AtomicTest wrapper returned no result: {detail[:2000]}")
    try:
        data = json.loads(base64.b64decode(line[len(RESULT_MARKER):]).decode("utf-8-sig"))
    except Exception as exc:
        return InvokeResult(error=f"Could not decode wrapper result: {exc!r}")

    r = InvokeResult(console=data.get("output") or "", error=data.get("error") or "")
    pre = data.get("prereq")
    if pre:
        r.prereq_checked = True
        r.prereq_met = bool(pre.get("met"))
        r.prereq_reasons = [x for x in (pre.get("reasons") or []) if x]
    test = data.get("test")
    if test:
        r.test_ran = True
        code = test.get("exit_code")
        r.timed_out = bool(test.get("is_timeout"))
        r.exit_code = -1 if code is None else int(code)
        r.stdout = test.get("stdout") or ""
        r.stderr = test.get("stderr") or ""
        r.command = test.get("command") or ""
    cleanup = data.get("cleanup")
    if cleanup:
        r.cleanup_ran = bool(cleanup.get("ran"))
        r.cleanup_output = cleanup.get("output") or ""
    return r


def _zip_dir(entries: list[tuple[Path, str]]) -> tuple[str, str]:
    """Zip (source_dir_or_file, archive_prefix) pairs. Returns (zip_path, content_hash)."""
    h = hashlib.sha256()
    files: list[tuple[Path, str]] = []
    for src, prefix in entries:
        if src.is_file():
            files.append((src, prefix))
            continue
        for p in sorted(src.rglob("*")):
            if p.is_file():
                files.append((p, f"{prefix}/{p.relative_to(src).as_posix()}"))
    fd, zip_path = tempfile.mkstemp(suffix=".zip", prefix="protonred-")
    os.close(fd)
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
        for path, arc in files:
            data = path.read_bytes()
            h.update(arc.encode())
            h.update(hashlib.sha256(data).digest())
            zf.writestr(arc, data)
    return zip_path, h.hexdigest()[:16]


def _ps_quote(s: str) -> str:
    return "'" + s.replace("'", "''") + "'"


class InvokeAtomicBackend:
    def __init__(self, atomics_path: Optional[str] = None):
        self.atomics_path = Path(atomics_path or settings.ART_ATOMICS_PATH)
        self.remote_root = settings.INVOKE_ATOMIC_REMOTE_ROOT.rstrip("\\")
        # (pool, host) → set of staged item names, so each job checks a target once per item.
        self._staged: dict[tuple, set] = {}

    # ── public ────────────────────────────────────────────────────────────

    async def run(
        self,
        technique_id: str,
        test_guid: str,
        test_index: int,
        input_args: Optional[dict],
        timeout: int,
        remote: Optional[RemoteConnection] = None,
        check_prereqs: bool = True,
        get_prereqs: bool = False,
        run_test: bool = True,
        run_cleanup: bool = True,
    ) -> InvokeResult:
        status = vendor_status()
        if not status["available"]:
            return InvokeResult(error=f"invoke-atomic engine unavailable: missing {status['missing_modules']} ({status['hint']})")

        params = {
            "technique": technique_id.upper(),
            "test_guid": test_guid or "",
            "test_number": test_index + 1,     # Invoke-AtomicTest numbers tests from 1
            "input_args": {k: "" if v is None else str(v) for k, v in (input_args or {}).items()},
            "timeout": int(timeout),
            "check_prereqs": check_prereqs,
            "get_prereqs": get_prereqs,
            "run_test": run_test,
            "run_cleanup": run_cleanup,
        }
        # Budget: prereq check + optional fetch + test + cleanup, each bounded
        # by Invoke-AtomicTest's own -TimeoutSeconds, plus module import time.
        phases = (2 if check_prereqs else 0) + (2 if get_prereqs else 0) + int(run_test) + int(run_cleanup)
        budget = timeout * max(phases, 1) + 120

        try:
            if remote is None:
                return await self._run_local(params, budget)
            return await self._run_remote(remote, params, budget)
        except asyncio.TimeoutError:
            return InvokeResult(error=f"invoke-atomic run exceeded {budget}s", timed_out=True)
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            return InvokeResult(error=f"invoke-atomic run failed: {exc}")

    # ── local ─────────────────────────────────────────────────────────────

    async def _run_local(self, params: dict, budget: int) -> InvokeResult:
        ps = _local_powershell()
        if not ps:
            return InvokeResult(error="No local PowerShell found (install pwsh or set PWSH_PATH)")
        params = dict(params,
                      modules_dir=str(modules_dir().resolve()),
                      logger_path=str(LOGGER.resolve()),
                      atomics_dir=str(self.atomics_path.resolve()))
        fd, script = tempfile.mkstemp(suffix=".ps1", prefix="protonred-")
        with os.fdopen(fd, "w", encoding="utf-8-sig") as f:
            f.write(self._script(params))
        proc = None
        try:
            proc = await asyncio.create_subprocess_exec(
                ps, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", script,
                stdin=asyncio.subprocess.DEVNULL,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            out, err = await asyncio.wait_for(proc.communicate(), timeout=budget)
            return parse_result(out.decode("utf-8", "replace"), err.decode("utf-8", "replace"))
        except (asyncio.TimeoutError, asyncio.CancelledError):
            if proc is not None and proc.returncode is None:
                _kill_tree(proc.pid)
            raise
        finally:
            try:
                os.unlink(script)
            except OSError:
                pass

    # ── remote ────────────────────────────────────────────────────────────

    async def _run_remote(self, conn: RemoteConnection, params: dict, budget: int) -> InvokeResult:
        root = self.remote_root
        await self._stage(conn, "modules", [(modules_dir(), "modules"), (LOGGER, f"modules/{LOGGER.name}")], f"{root}\\modules")
        tech = params["technique"]
        tech_dir = self.atomics_path / tech
        if not tech_dir.is_dir():
            return InvokeResult(error=f"Technique folder {tech} not found in local atomics ({self.atomics_path})")
        await self._stage(conn, tech, [(tech_dir, tech)], f"{root}\\atomics\\{tech}")

        params = dict(params,
                      modules_dir=f"{root}\\modules",
                      logger_path=f"{root}\\modules\\{LOGGER.name}",
                      atomics_dir=f"{root}\\atomics")
        output, errors = await run_remote_ps(conn, self._script(params), timeout=budget)
        return parse_result(output, errors)

    async def _stage(self, conn: RemoteConnection, name: str, entries: list, dest_dir: str) -> None:
        """Make sure `dest_dir` on the target holds exactly `entries`, using a
        content hash marker to skip the upload when it is already current."""
        key = (conn.pool, conn.host)
        if name in self._staged.get(key, set()):
            return
        zip_path, digest = await asyncio.to_thread(_zip_dir, entries)
        try:
            # Archive paths are prefixed with the last path component of dest_dir.
            parent = dest_dir.rsplit("\\", 1)[0]
            marker = f"{dest_dir}\\.protonred-hash"
            check = (
                f"$m = {_ps_quote(marker)}; "
                f"if ((Test-Path -LiteralPath $m) -and ((Get-Content -LiteralPath $m -Raw).Trim() -eq {_ps_quote(digest)})) {{ 'CURRENT' }} "
                f"else {{ New-Item -ItemType Directory -Force -Path {_ps_quote(parent)} | Out-Null; 'STALE' }}"
            )
            out, _ = await run_remote_ps(conn, check, timeout=120)
            if "CURRENT" not in out:
                remote_zip = f"{parent}\\.protonred-{name}.zip"
                await copy_to_remote(conn, zip_path, remote_zip, timeout=600)
                expand = (
                    f"$ErrorActionPreference = 'Stop'; "
                    f"if (Test-Path -LiteralPath {_ps_quote(dest_dir)}) {{ Remove-Item -LiteralPath {_ps_quote(dest_dir)} -Recurse -Force }}; "
                    f"Expand-Archive -LiteralPath {_ps_quote(remote_zip)} -DestinationPath {_ps_quote(parent)} -Force; "
                    f"Remove-Item -LiteralPath {_ps_quote(remote_zip)} -Force; "
                    f"Set-Content -LiteralPath {_ps_quote(marker)} -Value {_ps_quote(digest)}; 'STAGED'"
                )
                out, errors = await run_remote_ps(conn, expand, timeout=600)
                if "STAGED" not in out:
                    raise RuntimeError(f"staging {name} to {dest_dir} failed: {errors or out}")
            self._staged.setdefault(key, set()).add(name)
        finally:
            try:
                os.unlink(zip_path)
            except OSError:
                pass

    def forget(self, pool: str) -> None:
        """Drop the per-job staging memo (files stay on the target for reuse)."""
        for key in [k for k in self._staged if k[0] == pool]:
            self._staged.pop(key, None)

    # ── shared ────────────────────────────────────────────────────────────

    @staticmethod
    def _script(params: dict) -> str:
        b64 = base64.b64encode(json.dumps(params).encode("utf-8")).decode("ascii")
        return f"$ParamsB64 = '{b64}'\n" + WRAPPER.read_text(encoding="utf-8")


def _kill_tree(pid: int) -> None:
    try:
        import psutil
        parent = psutil.Process(pid)
        for child in parent.children(recursive=True):
            try:
                child.kill()
            except Exception:
                pass
        parent.kill()
    except Exception:
        pass
