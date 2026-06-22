# AD Pentest Show — Runbook

Live demo script for `ad_pentest_show.py`.  
4-phase attack story against a real Windows AD environment.

---

## Prerequisites

| Requirement | Check |
|-------------|-------|
| Server running at `http://127.0.0.1:8000` | `curl http://127.0.0.1:8000/health` |
| DC reachable via WinRM | `Test-NetConnection 192.168.50.162 -Port 5985` |
| Python deps installed | `.runtime\python\python.exe -c "import httpx, websockets"` |
| ANSI colors work in terminal | Use Windows Terminal or VSCode terminal (not cmd.exe) |

### Start the server (if not running)

```powershell
cd C:\Users\Student\Desktop\agi-pentest
.\start.ps1
```

---

## Running the Show

### Full show (LOCAL + DC, no AI analysis):
```powershell
cd C:\Users\Student\Desktop\agi-pentest\client
.\..\..\.runtime\python\python.exe ad_pentest_show.py
```

### DC only:
```powershell
.\..\..\.runtime\python\python.exe ad_pentest_show.py --dc-only
```

### Local machine only:
```powershell
.\..\..\.runtime\python\python.exe ad_pentest_show.py --local-only
```

### With AI analysis after execution:
```powershell
.\..\..\.runtime\python\python.exe ad_pentest_show.py --analyze --api-key sk-ant-...
```

### Analyze an existing job (skip execution):
```powershell
.\..\..\.runtime\python\python.exe ad_pentest_show.py --job-id <uuid> --analyze --api-key sk-ant-...
```

---

## Target Configuration

Hardcoded in `ad_pentest_show.py` — edit `SHOW_CONFIG` section if needed:

| Field | Value |
|-------|-------|
| DC IP | 192.168.50.162 |
| Username | Administrator |
| Password | Aliilaali1 |
| Transport | NTLM |
| WinRM Port | 5985 |
| Local target | This machine (admin, local execution) |

---

## What Each Phase Does

### Phase 1 — Identity & Host Recon
*Purpose: Establish who we are and what machine we're on.*

| Technique | Index | Command | Expected |
|-----------|-------|---------|----------|
| T1033 | 0 | `whoami` | exit=0, username + groups |
| T1082 | 0 | `systeminfo` | exit=0, OS/hostname/domain info |
| T1016 | 0 | `ipconfig /all` | exit=0, network interfaces, DNS |

**All 3 succeed on both LOCAL and DC.**

---

### Phase 2 — Domain & Network Enumeration
*Purpose: Map the AD environment — users, groups, shares, connections.*

| Technique | Index | Command | Expected |
|-----------|-------|---------|----------|
| T1087.002 | 0 | `net user /domain` | exit=1 (DC normal), stdout has users |
| T1069.002 | 0 | domain groups | exit=1 (DC normal), stdout has groups |
| T1087.001 | 7 | `net user` | exit=1 (DC normal), local accounts |
| T1069.001 | 1 | `net localgroup` | exit=0, local groups |
| T1201 | 5 | `net accounts` | exit=0, password policy |
| T1135 | 3 | `net view \\<DC>` | exit=0, network shares |
| T1049 | 0 | `netstat -ano` | exit=0, active connections |
| T1057 | 1 | `tasklist` | exit=0, running processes |

**Note on exit=1 for T1087.001/002 and T1069.002 on DC:** This is normal Windows DC behavior. `net user` returns exit 1 on a DC but stdout still contains user data. The show script and AI analyzer both handle this correctly — stdout is captured regardless of exit code.

---

### Phase 3 — Configuration & Persistence Discovery
*Purpose: Find credentials in files, registry autoruns, installed software.*

| Technique | Index | Command | Expected |
|-----------|-------|---------|----------|
| T1012 | 0 | `reg query HKLM\...\Run` | exit=0, autorun entries (needs admin) |
| T1518 | 0 | `reg query` IE/software | exit=0, software versions |
| T1552.001 | 3 | `findstr /si password` | exit=0 or 1 (PS), may find creds in files |

**T1552.001 note:** PowerShell's `findstr` equivalent may return exit=1 with results or exit=0 with no results depending on DC config. Either way output is captured. AI interprets stdout correctly.

---

### Phase 4 — Credential Access (Drama)
*Purpose: Show AV detection — makes a compelling pentest story.*

| Technique | Index | Command | Expected |
|-----------|-------|---------|----------|
| T1558.003 | 0 | Invoke-Kerberoast | **FAIL — AMSI/Defender blocks** |
| T1003.001 | 0 | LSASS dump via ProcDump | **FAIL — access denied or AV** |

**These are EXPECTED failures.** They demonstrate:
- T1558.003: Windows Defender AMSI is active → AV detection finding in report
- T1003.001: Credential protection working (or AV blocked the tool)

**After T1558.003 fails:** WinRM connection re-authenticates for T1003.001 (+1-2 seconds). Normal behavior.

---

## Expected Show Output Summary

### 2-target run (LOCAL + DC), 16 techniques, 32 total executions:

```
Execution: ~20 OK, ~9 FAIL (expected), ~3 SKIP (domain skip on LOCAL)
```

Breakdown:
- Domain-required techniques (T1087.002, T1069.002, T1558.003) → **SKIP on LOCAL** (not domain-joined)
- T1558.003, T1003.001 → **FAIL on DC** (AV/access control — expected)
- T1087.001/002, T1069.002 (DC) → **FAIL exit=1** but stdout captured (net user DC behavior)
- Everything else → **OK**

---

## AI Analysis (Optional)

After execution, AI produces:
- **Risk level**: expected `high` (successful enumeration, blocked AV = AV present)
- **Findings**: 8-12 findings covering discovery, domain enumeration, AV detection
- **Attack path**: enumeration chain from whoami → domain users → shares → blocked cred access
- **Key observations**: AD user list, password policy, running processes, AV active

### Model recommendations for analysis:
| Speed | Model |
|-------|-------|
| Fast + cheap | `claude-haiku-4-5` |
| Best quality | `claude-sonnet-4-6` |
| Free / local | `ollama-llama3` (local Ollama required) |

---

## Troubleshooting

### Server not reachable
```powershell
# Check if server is running
Get-NetTCPConnection -LocalPort 8000 -ErrorAction SilentlyContinue
# Start if not
.\start.ps1
```

### DC WinRM refused / timeout
```powershell
# Test connectivity
Test-NetConnection 192.168.50.162 -Port 5985
# On DC: ensure WinRM enabled
# (on DC, run as admin): Enable-PSRemoting -Force
```

### NTLM auth failure (401)
- Verify password: `Aliilaali1`
- Verify username: `Administrator`
- Ensure DC WinRM allows NTLM: check DC WinRM config

### Port 8000 already in use
```powershell
$p = (Get-NetTCPConnection -LocalPort 8000).OwningProcess
Stop-Process -Id $p -Force
.\start.ps1
```

### Unicode/display issues
- Use **Windows Terminal** or **VSCode integrated terminal**
- Old `cmd.exe` console does not support ANSI colors → output looks broken

### Phase 4 takes longer than expected
Normal — T1558.003 AMSI block causes WinRM session to be evicted and re-created for T1003.001. Adds ~2-5 seconds.

---

## Files

| File | Purpose |
|------|---------|
| `client/ad_pentest_show.py` | Show runner script |
| `client/pentest_client.py` | Python SDK (used by show script) |
| `client/INTEGRATION.md` | Full API reference |
| `client/SHOW_RUNBOOK.md` | This file |
| `start.ps1` | Server launcher |

---

## Quick Reference Card

```
# Full show:
python ad_pentest_show.py

# DC only:
python ad_pentest_show.py --dc-only

# With AI analysis (Anthropic):
python ad_pentest_show.py --analyze --api-key sk-ant-YOUR_KEY

# Analyze saved job:
python ad_pentest_show.py --job-id abc123 --analyze --api-key sk-ant-YOUR_KEY

# Custom API URL:
python ad_pentest_show.py --api http://192.168.1.50:8000
```

(Run from `client/` directory, or adjust Python path.)
