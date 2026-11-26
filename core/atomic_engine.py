"""
Atomic Red Team YAML loader and executor.
Parses ART atomics directory and executes tests via subprocess.
"""
import asyncio
import os
import platform
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import yaml

from config import settings
from core.outcome import classify, SUCCESS


@dataclass
class InputArgument:
    name: str
    description: str
    type: str
    default: str = ""


@dataclass
class Executor:
    name: str  # powershell | cmd | bash | sh | manual
    command: str
    cleanup_command: Optional[str] = None
    elevation_required: bool = False


@dataclass
class AtomicTest:
    name: str
    guid: str
    description: str
    supported_platforms: list[str]
    executor: Executor
    input_arguments: dict[str, InputArgument] = field(default_factory=dict)
    dependencies: list[dict] = field(default_factory=list)
    dependency_executor_name: str = "powershell"


@dataclass
class Technique:
    technique_id: str
    display_name: str
    atomic_tests: list[AtomicTest]
    tactic: str = ""


@dataclass
class ExecutionResult:
    technique_id: str
    test_name: str
    test_guid: str
    success: bool
    stdout: str
    stderr: str
    exit_code: int
    platform: str
    command_executed: str
    outcome: str = ""


class AtomicEngine:
    def __init__(self, atomics_path: Optional[str] = None):
        self.atomics_path = Path(atomics_path or settings.ART_ATOMICS_PATH)
        self._cache: dict[str, Technique] = {}
        self._tactic_map: dict[str, list[str]] = {}
        self._loaded = False

    def is_available(self) -> bool:
        return self.atomics_path.exists() and any(self.atomics_path.iterdir())

    def load_all(self) -> int:
        if not self.is_available():
            return 0
        count = 0
        for yaml_file in self.atomics_path.rglob("T*.yaml"):
            try:
                technique = self._parse_yaml(yaml_file)
                if technique:
                    self._cache[technique.technique_id] = technique
                    count += 1
            except Exception:
                continue
        self._loaded = True
        return count

    def _parse_yaml(self, path: Path) -> Optional[Technique]:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            data = yaml.safe_load(f)
        if not data or "attack_technique" not in data:
            return None

        tests = []
        for t in data.get("atomic_tests", []):
            executor_data = t.get("executor", {})
            executor = Executor(
                name=executor_data.get("name", "manual"),
                command=executor_data.get("command", ""),
                cleanup_command=executor_data.get("cleanup_command"),
                elevation_required=executor_data.get("elevation_required", False),
            )

            input_args = {}
            for arg_name, arg_data in t.get("input_arguments", {}).items():
                if isinstance(arg_data, dict):
                    input_args[arg_name] = InputArgument(
                        name=arg_name,
                        description=arg_data.get("description", ""),
                        type=arg_data.get("type", "string"),
                        default=str(arg_data.get("default", "")),
                    )

            test = AtomicTest(
                name=t.get("name", ""),
                guid=t.get("auto_generated_guid", ""),
                description=t.get("description", ""),
                supported_platforms=t.get("supported_platforms", []),
                executor=executor,
                input_arguments=input_args,
                dependencies=t.get("dependencies", []),
                dependency_executor_name=t.get("dependency_executor_name", "powershell"),
            )
            tests.append(test)

        return Technique(
            technique_id=data["attack_technique"],
            display_name=data.get("display_name", ""),
            atomic_tests=tests,
        )

    def get_technique(self, technique_id: str) -> Optional[Technique]:
        if not self._loaded:
            self.load_all()
        return self._cache.get(technique_id.upper())

    def list_techniques(self, platform_filter: Optional[str] = None) -> list[dict]:
        if not self._loaded:
            self.load_all()
        result = []
        for tid, tech in self._cache.items():
            tests = tech.atomic_tests
            if platform_filter:
                tests = [t for t in tests if platform_filter.lower() in t.supported_platforms]
            if tests:
                result.append({
                    "technique_id": tid,
                    "display_name": tech.display_name,
                    "test_count": len(tests),
                    "tactic": tech.tactic,
                })
        return sorted(result, key=lambda x: x["technique_id"])

    def search_techniques(self, query: str) -> list[dict]:
        if not self._loaded:
            self.load_all()
        query_lower = query.lower()
        results = []
        for tid, tech in self._cache.items():
            if query_lower in tid.lower() or query_lower in tech.display_name.lower():
                results.append({
                    "technique_id": tid,
                    "display_name": tech.display_name,
                    "test_count": len(tech.atomic_tests),
                })
                continue
            for test in tech.atomic_tests:
                if query_lower in test.name.lower() or query_lower in test.description.lower():
                    results.append({
                        "technique_id": tid,
                        "display_name": tech.display_name,
                        "test_count": len(tech.atomic_tests),
                    })
                    break
        return results

    def _substitute_args(
        self,
        command: str,
        input_args: dict[str, InputArgument],
        overrides: dict[str, str],
        remote: bool = False,
    ) -> str:
        """Fill #{arg} placeholders the way Invoke-AtomicTest does.

        ART defaults reference files shipped with the atomics as
        `PathToAtomicsFolder\\T1234\\bin\\...`. Locally that resolves to our
        atomics checkout. On a remote target those files do not exist, so the
        placeholder is left as-is and the test will fail visibly instead of
        pointing at a path on this machine.
        """
        if not command:
            return ""
        for arg_name, arg in input_args.items():
            value = overrides.get(arg_name, arg.default)
            value = "" if value is None else str(value)
            if not remote:
                value = self._resolve_atomics_folder(value)
            command = command.replace(f"#{{{arg_name}}}", value)
        if not remote:
            command = self._resolve_atomics_folder(command)
        return command

    def _resolve_atomics_folder(self, text: str) -> str:
        if "PathToAtomicsFolder" not in text:
            return text
        root = str(self.atomics_path.resolve())
        return text.replace("$PathToAtomicsFolder", root).replace("PathToAtomicsFolder", root)

    async def run_on_target(
        self,
        command: str,
        executor_name: str,
        timeout: int,
        remote: Optional["object"] = None,
    ) -> dict:
        """Run one command on the job's target, local subprocess or WinRM.

        Returns {"stdout", "stderr", "exit_code", "timed_out"}.
        """
        if remote is not None:
            from core.winrm_runner import run_remote
            result = await run_remote(conn=remote, command=command, executor_name=executor_name, timeout=timeout)
        else:
            result = await self._run_command(command=command, executor_name=executor_name, timeout=timeout)
        result.setdefault("timed_out", False)
        return result

    async def check_prereqs(
        self,
        test: "AtomicTest",
        arg_overrides: Optional[dict] = None,
        remote: Optional["object"] = None,
        get_prereqs: bool = False,
        timeout: int = 60,
    ) -> tuple[bool, str]:
        """Evaluate ART `dependencies` on the target.

        Each dependency has a `prereq_command` (exit 0 = met) and a
        `get_prereq_command` that installs it. Fetching is opt-in because it
        usually downloads tooling from the internet onto the target.

        Returns (all_met, human-readable detail of the first unmet dependency).
        """
        if not test.dependencies:
            return True, ""
        overrides = arg_overrides or {}
        is_remote = remote is not None
        dep_exec = test.dependency_executor_name or test.executor.name

        for dep in test.dependencies:
            if not isinstance(dep, dict):
                continue
            desc = (dep.get("description") or "").strip()
            check_cmd = self._substitute_args(dep.get("prereq_command", ""), test.input_arguments, overrides, is_remote)
            if not check_cmd.strip():
                continue

            res = await self.run_on_target(check_cmd, dep_exec, timeout, remote)
            if res["exit_code"] == 0 and not res["timed_out"]:
                continue

            if get_prereqs:
                get_cmd = self._substitute_args(dep.get("get_prereq_command", ""), test.input_arguments, overrides, is_remote)
                if get_cmd.strip():
                    await self.run_on_target(get_cmd, dep_exec, timeout, remote)
                    res = await self.run_on_target(check_cmd, dep_exec, timeout, remote)
                    if res["exit_code"] == 0 and not res["timed_out"]:
                        continue

            reason = "timed out" if res["timed_out"] else f"exit {res['exit_code']}"
            return False, f"{desc or 'Prerequisite'} ({reason})"

        return True, ""

    async def execute_atomic(
        self,
        technique_id: str,
        test_index: int = 0,
        arg_overrides: Optional[dict[str, str]] = None,
        timeout: int = 60,
        remote: Optional["object"] = None,
    ) -> ExecutionResult:
        technique = self.get_technique(technique_id)
        if not technique:
            return ExecutionResult(
                technique_id=technique_id,
                test_name="",
                test_guid="",
                success=False,
                stdout="",
                stderr=f"Technique {technique_id} not found in atomics",
                exit_code=-1,
                platform=platform.system().lower(),
                command_executed="",
            )

        if test_index >= len(technique.atomic_tests):
            return ExecutionResult(
                technique_id=technique_id,
                test_name="",
                test_guid="",
                success=False,
                stdout="",
                stderr=f"Test index {test_index} out of range (max {len(technique.atomic_tests)-1})",
                exit_code=-1,
                platform=platform.system().lower(),
                command_executed="",
            )

        test = technique.atomic_tests[test_index]
        overrides = arg_overrides or {}
        command = self._substitute_args(test.executor.command, test.input_arguments, overrides, remote is not None)

        current_platform = platform.system().lower()
        if current_platform == "darwin":
            current_platform = "macos"
        if remote is not None:
            current_platform = f"windows (remote {remote.host})"

        result = await self.run_on_target(command, test.executor.name, timeout, remote)
        outcome = classify(result["exit_code"], result["stdout"], result["stderr"], result["timed_out"])

        return ExecutionResult(
            technique_id=technique_id,
            test_name=test.name,
            test_guid=test.guid,
            success=outcome == SUCCESS,
            stdout=result["stdout"],
            stderr=result["stderr"],
            exit_code=result["exit_code"],
            platform=current_platform,
            command_executed=command,
            outcome=outcome,
        )

    async def cleanup_atomic(
        self,
        technique_id: str,
        test_index: int = 0,
        arg_overrides: Optional[dict] = None,
        remote: Optional["object"] = None,
        timeout: int = 60,
    ) -> dict:
        """Run the test's cleanup_command on the same target the test ran on.

        Returns {"status": "ok"|"failed"|"none", "exit_code", "output", "error"}.
        """
        technique = self.get_technique(technique_id)
        if not technique or test_index >= len(technique.atomic_tests):
            return {"status": "failed", "exit_code": -1, "output": "", "error": "Technique/test not found"}

        test = technique.atomic_tests[test_index]
        if not (test.executor.cleanup_command or "").strip():
            return {"status": "none", "exit_code": 0, "output": "", "error": ""}

        command = self._substitute_args(
            test.executor.cleanup_command, test.input_arguments, arg_overrides or {}, remote is not None
        )
        result = await self.run_on_target(command, test.executor.name, timeout, remote)
        ok = result["exit_code"] == 0 and not result["timed_out"]
        return {
            "status": "ok" if ok else "failed",
            "exit_code": result["exit_code"],
            "output": result["stdout"],
            "error": result["stderr"],
        }
    async def _run_command(self, command: str, executor_name: str, timeout: int) -> dict:
        if executor_name == "manual":
            return {"stdout": "[Manual execution required]", "stderr": "", "exit_code": 0}

        system = platform.system().lower()
        sysroot = os.environ.get("SystemRoot", "C:\\Windows")
        command = command.strip()
        tmp_path = None

        proc = None
        try:
            args = self._build_args(command, executor_name, system, sysroot)
            if args is None:
                return {"stdout": "", "stderr": "bash/sh not available on Windows", "exit_code": -1}

            # On Windows for powershell/cmd: write to a temp file to avoid argv quoting issues.
            if system == "windows" and executor_name in ("powershell", "pwsh", "cmd", "command_prompt"):
                suffix = ".ps1" if executor_name in ("powershell", "pwsh") else ".bat"
                with tempfile.NamedTemporaryFile(mode="w", suffix=suffix, delete=False,
                                                 encoding="utf-8", errors="replace") as f:
                    if suffix == ".bat":
                        f.write("@echo off\n")
                    f.write(command)
                    tmp_path = f.name
                if executor_name in ("powershell", "pwsh"):
                    ps_exe = os.path.join(sysroot, "System32", "WindowsPowerShell", "v1.0", "powershell.exe")
                    args = [ps_exe, "-NonInteractive", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", tmp_path]
                else:
                    cmd_exe = os.path.join(sysroot, "System32", "cmd.exe")
                    args = [cmd_exe, "/c", tmp_path]

            proc = await asyncio.create_subprocess_exec(
                *args,
                stdin=asyncio.subprocess.DEVNULL,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
            return {
                "stdout": stdout.decode("utf-8", errors="replace"),
                "stderr": stderr.decode("utf-8", errors="replace"),
                "exit_code": proc.returncode or 0,
            }
        except asyncio.TimeoutError:
            if proc is not None:
                try:
                    import psutil
                    parent = psutil.Process(proc.pid)
                    for child in parent.children(recursive=True):
                        try:
                            child.kill()
                        except Exception:
                            pass
                    parent.kill()
                except Exception:
                    try:
                        proc.kill()
                    except Exception:
                        pass
                try:
                    await proc.wait()
                except Exception:
                    pass
            return {"stdout": "", "stderr": f"Execution timed out after {timeout}s", "exit_code": -1, "timed_out": True}
        except asyncio.CancelledError:
            if proc is not None:
                try:
                    import psutil
                    parent = psutil.Process(proc.pid)
                    for child in parent.children(recursive=True):
                        try:
                            child.kill()
                        except Exception:
                            pass
                    parent.kill()
                except Exception:
                    try:
                        proc.kill()
                    except Exception:
                        pass
                try:
                    await proc.wait()
                except Exception:
                    pass
            raise
        except FileNotFoundError as e:
            return {"stdout": "", "stderr": f"Executor not found: {e}", "exit_code": -1}
        except Exception as e:
            return {"stdout": "", "stderr": str(e), "exit_code": -1}
        finally:
            if tmp_path:
                try:
                    os.unlink(tmp_path)
                except Exception:
                    pass

    def _build_args(self, command: str, executor_name: str, system: str, sysroot: str):
        """Return subprocess args list. Returns None if executor unavailable."""
        if executor_name in ("powershell", "pwsh"):
            if system == "windows":
                ps_exe = os.path.join(sysroot, "System32", "WindowsPowerShell", "v1.0", "powershell.exe")
                return [ps_exe, "-NonInteractive", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", command]
            return ["pwsh", "-NonInteractive", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", command]
        if executor_name in ("cmd", "command_prompt"):
            if system == "windows":
                cmd_exe = os.path.join(sysroot, "System32", "cmd.exe")
                return [cmd_exe, "/c", command]
            return ["sh", "-c", command]
        if executor_name in ("bash", "sh"):
            if system == "windows":
                import shutil as _shutil
                shell = _shutil.which("bash") or _shutil.which("sh")
                return [shell, "-c", command] if shell else None
            return [executor_name, "-c", command]
        # Unknown executor fallback.
        if system == "windows":
            cmd_exe = os.path.join(sysroot, "System32", "cmd.exe")
            return [cmd_exe, "/c", command]
        return ["sh", "-c", command]
