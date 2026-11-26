"""
Outcome classification for executed atomic tests.

Exit code alone cannot tell apart "the technique worked", "a security control
stopped it", "the tool is broken here" and "it ran out of time". The AI analyst
and the report need that distinction, otherwise an infra failure reads as a
defensive win and an AMSI block reads as a generic error.

Outcomes:
  success         exit 0, no sign of a block
  partial         non-zero exit but the command produced output worth reading
                  (e.g. `net user /domain` on a DC exits 1 with a full user list)
  failed          non-zero exit, no useful output, no block detected
  blocked         a security control (AV/AMSI/EDR, ACL, AppLocker/WDAC) stopped it
  error           the tool could not run the test (missing binary, WinRM failure)
  timeout         the test exceeded its time budget and was killed
  prereq_missing  prerequisites were not met, the test was not run
  skipped         filtered out before execution (platform, privilege, domain...)
"""

SUCCESS = "success"
PARTIAL = "partial"
FAILED = "failed"
BLOCKED = "blocked"
ERROR = "error"
TIMEOUT = "timeout"
PREREQ_MISSING = "prereq_missing"
SKIPPED = "skipped"

ALL_OUTCOMES = (SUCCESS, PARTIAL, FAILED, BLOCKED, ERROR, TIMEOUT, PREREQ_MISSING, SKIPPED)

# Matched case-insensitively against stderr only. stdout is deliberately not
# scanned: discovery tests (findstr, dir, reg query) can legitimately print
# text such as "access denied" that came from files on the target.
_BLOCKED_PATTERNS = (
    # AMSI
    "this script contains malicious content",
    "scriptcontainedmaliciouscontent",
    # Defender / AV
    "has been blocked by your antivirus",
    "operation did not complete successfully because the file contains a virus",
    "contains a virus or potentially unwanted software",
    # ACL / privilege enforcement
    "access is denied",
    "access denied",
    "unauthorizedaccessexception",
    "system error 5 has occurred",
    "0x80070005",
    "0xc0000022",
    # AppLocker / WDAC / SRP
    "blocked by group policy",
    "has been blocked by your system administrator",
    "an administrator has blocked",
    "applocker",
)

# Matched against stderr: the harness itself could not run the test.
_ERROR_PATTERNS = (
    "is not recognized as an internal or external command",
    "is not recognized as the name of a cmdlet",
    "executor not found",
    "executor raised",
    "winrm connect failed",
    "winrm reconnect failed",
    "winrm execution error",
    "not runnable over winrm",
    "bash/sh not available",
    "pypsrp not installed",
)


def classify(exit_code: int, stdout: str, stderr: str, timed_out: bool = False) -> str:
    if timed_out:
        return TIMEOUT
    err = (stderr or "").lower()
    if any(p in err for p in _ERROR_PATTERNS):
        return ERROR
    if any(p in err for p in _BLOCKED_PATTERNS):
        return BLOCKED
    if exit_code == 0:
        return SUCCESS
    if exit_code == -1:
        # -1 is the harness's own "could not run" code (see atomic_engine / winrm_runner).
        return ERROR
    if (stdout or "").strip():
        return PARTIAL
    return FAILED
