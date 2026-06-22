"""
Remote execution over WinRM (pypsrp).

A "remote" target is reached via WinRM and the atomic test runs *locally on that
host* — WinRM just gives us a shell on the box. Output comes back to us for
analysis. This is NOT lateral movement: the TTP executes as-if-local on the
remote machine, exactly like the local subprocess path, only the shell lives
on another host.

Used for non-domain (NTLM) or domain (kerberos/credssp) targets alike.
"""
import asyncio
import threading
from dataclasses import dataclass
from typing import Optional


@dataclass
class RemoteConnection:
    host: str
    username: str
    password: str
    transport: str = "ntlm"   # ntlm | kerberos | credssp | negotiate | basic
    port: int = 5985
    ssl: bool = False

    def cache_key(self) -> tuple:
        return (self.host, self.username, self.transport, self.port, self.ssl)


# Per-job WinRM client cache: cache_key → Client.
# Avoids re-authenticating for every test in a job.
_client_cache: dict = {}
_cache_lock = threading.Lock()

# Per-connection execution lock to prevent concurrent commands on the same WinRM Client
_client_locks: dict = {}
_locks_lock = threading.Lock()

# WinRM error codes that are transient (connection/session issues, not security controls).
# These warrant one automatic retry with a fresh connection.
_TRANSIENT_CODES = ("400", "2147944122", "2150858843", "2150859174")
# WSManFault code for access denied — this IS a pentest finding, not infra failure.
_ACCESS_DENIED_CODES = ("2147942405", "2147943455")


def _classify_winrm_error(err: str) -> str:
    """Return 'transient', 'access_denied', or 'fatal'."""
    low = err.lower()
    for code in _ACCESS_DENIED_CODES:
        if code in err:
            return "access_denied"
    if "access is denied" in low or "access denied" in low:
        return "access_denied"
    for code in _TRANSIENT_CODES:
        if code in err:
            return "transient"
    if "bad http response" in low or "rpc server" in low or "remote shell" in low:
        return "transient"
    return "fatal"


def _get_or_create_client(conn: RemoteConnection, timeout: int):
    from pypsrp.client import Client
    key = conn.cache_key()
    with _cache_lock:
        if key in _client_cache:
            return _client_cache[key], None
    try:
        client = Client(
            conn.host,
            username=conn.username,
            password=conn.password,
            ssl=conn.ssl,
            port=conn.port,
            auth=conn.transport,
            cert_validation=False,
            connection_timeout=timeout,
        )
    except Exception as e:
        return None, f"WinRM connect failed: {e}"
    with _cache_lock:
        _client_cache[key] = client
    return client, None


def _evict(conn: RemoteConnection):
    with _cache_lock:
        _client_cache.pop(conn.cache_key(), None)


def clear_client_cache():
    """Call after a job finishes to release WinRM sessions."""
    with _cache_lock:
        _client_cache.clear()
    with _locks_lock:
        _client_locks.clear()


def _execute_with_client(client, command: str, executor_name: str) -> dict:
    """Run command on an already-connected WinRM client. Raises on error."""
    if executor_name in ("powershell", "pwsh"):
        stdout, streams, had_errors = client.execute_ps(command)
        stderr = ""
        if had_errors:
            stderr = "\n".join(str(e) for e in (streams.error or []))
        return {
            "stdout": stdout or "",
            "stderr": stderr,
            "exit_code": 1 if had_errors else 0,
        }
    else:  # command_prompt, cmd, anything else → cmd shell
        stdout, stderr, rc = client.execute_cmd(command)
        return {"stdout": stdout or "", "stderr": stderr or "", "exit_code": rc}


async def run_remote(conn: RemoteConnection, command: str, executor_name: str, timeout: int) -> dict:
    """Async wrapper — pypsrp is blocking, so run it in a thread."""
    key = conn.cache_key()
    with _locks_lock:
        if key not in _client_locks:
            _client_locks[key] = threading.Lock()
        lock = _client_locks[key]
        
    def _locked_run():
        with lock:
            return _run_remote_sync(conn, command, executor_name, timeout)
            
    return await asyncio.to_thread(_locked_run)


def _run_remote_sync(conn: RemoteConnection, command: str, executor_name: str, timeout: int) -> dict:
    try:
        from pypsrp.client import Client  # noqa: F401 — ensure installed
    except ImportError:
        return {
            "stdout": "",
            "stderr": "pypsrp not installed — run start.ps1 -Reinstall",
            "exit_code": -1,
        }

    # WinRM reaches a Windows shell; bash/sh atomics cannot run remotely this way.
    if executor_name in ("bash", "sh"):
        return {
            "stdout": "",
            "stderr": f"Executor '{executor_name}' not runnable over WinRM (Windows shell only)",
            "exit_code": -1,
        }

    client, err = _get_or_create_client(conn, timeout)
    if err:
        return {"stdout": "", "stderr": err, "exit_code": -1}

    try:
        return _execute_with_client(client, command, executor_name)

    except Exception as e:
        err_str = str(e)
        _evict(conn)
        kind = _classify_winrm_error(err_str)

        if kind == "access_denied":
            # Real security control — access denied IS a pentest finding.
            # Return exit_code=5 (Windows access denied) so AI treats it as FAIL, not infra error.
            return {
                "stdout": "",
                "stderr": f"Access denied (security control): {e}",
                "exit_code": 5,
            }

        if kind == "transient":
            # Session evicted or RPC hiccup — retry once with fresh connection.
            client2, err2 = _get_or_create_client(conn, timeout)
            if err2:
                return {"stdout": "", "stderr": f"WinRM reconnect failed: {err2}", "exit_code": -1}
            try:
                return _execute_with_client(client2, command, executor_name)
            except Exception as e2:
                _evict(conn)
                return {
                    "stdout": "",
                    "stderr": f"WinRM execution error (retry failed): {e2}",
                    "exit_code": -1,
                }

        # Fatal / unknown — no retry
        return {"stdout": "", "stderr": f"WinRM execution error: {e}", "exit_code": -1}
