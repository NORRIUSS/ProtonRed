# ProtonRed Pentest Tool — Project Brief for Claude

## What This Is

Windows-native penetration testing tool that integrates **Atomic Red Team (ART)** with **AI analysis**.

**Core flow:**
1. User selects targets (local or remote WinRM) + TTPs via tactic/technique checkboxes
2. Tool runs selected tests **deterministically** (no AI) via subprocess or WinRM → collects JSON results
3. AI receives JSON results → produces structured findings report (PDF export)

**AI does NOT select or run tests. AI only analyzes results after execution.**

---

## Integration Context — CRITICAL

This tool is **a module inside a larger web platform** (not yet built). Integration plan:
- This tool exposes a **REST API** (`FastAPI`, port 8000)
- The parent platform will call this API to start jobs, stream execution, retrieve results
- The current web UI (`ui/index.html`) is **temporary** — a single HTML file for standalone testing
- When integrated: parent platform provides its own frontend, calls `/api/*` and `/ws/*` endpoints directly
- Keep API clean and stateless-friendly; do not couple logic to the UI
- `client/` directory contains Python SDK, JS SDK, and integration reference for external consumers

---

## Architecture

```
proton-red/
├── api/
│   ├── main.py              # FastAPI app — all REST + WebSocket endpoints
│   └── models.py            # Pydantic request/response models
├── core/
│   ├── atomic_engine.py     # Parses ART YAML files, executes via subprocess (local)
│   ├── executor.py          # DeterministicExecutor — runs jobs, multi-target fan-out
│   ├── analyzer.py          # AIAnalyzer — single-call streaming + parse_analysis_response()
│   ├── tactic_map.py        # TACTIC_GROUPS, SCOPE_PROFILES, DOMAIN_REQUIRED_TECHNIQUES
│   ├── winrm_runner.py      # WinRM remote execution via pypsrp; NTLM auth; connection cache
│   └── reporter.py          # HTML/JSON report generation (if present)
├── providers/
│   ├── __init__.py          # PROVIDER_CATALOG (19+ models), get_provider()
│   ├── base.py              # AIProvider ABC, ProviderConfig dataclass
│   └── litellm_provider.py  # LiteLLM unified wrapper for all providers
├── config/
│   └── settings.py          # Settings class — reads env vars, ART path, etc.
├── ui/
│   └── index.html           # TEMPORARY standalone UI (single HTML file, ~1300 lines)
├── client/
│   ├── pentest_client.py    # Python async SDK (httpx + websockets)
│   ├── pentest_client.js    # JavaScript SDK (browser + Node.js)
│   ├── INTEGRATION.md       # Full API reference + confirmed technique index
│   └── ad_pentest_show.py   # Live AD demo script — 4-phase, 16 confirmed techniques
├── atomics/                 # Atomic Red Team YAML files (335 techniques, git-cloned)
├── .runtime/                # Portable Python 3.11.9 (bootstrapped by start.ps1)
├── start.ps1                # Self-bootstrapping launcher — sets up .runtime/ if missing
├── requirements.txt
└── CLAUDE.md                # This file
```

---

## Key Technical Decisions

### Multi-Target Model
Jobs accept an array of `Target` objects. Each target executed independently. Fan-out: `total_tests = len(targets) × len(selections)`.

```python
Target(
    target_id="dc01",
    name="DC01",
    os_platform="windows",       # windows | linux | macos
    privilege="admin",           # admin | standard_user
    connection="local",          # local | remote
    domain_joined=True,
    host="192.168.50.162",
    winrm_username="Administrator",
    winrm_password="...",
    winrm_transport="ntlm",      # ntlm | kerberos | credssp | negotiate | basic
    winrm_port=5985,
    winrm_ssl=False,
)
```

### Execution — Local + Remote WinRM
- **Local:** subprocess via full path `%SystemRoot%\System32\cmd.exe` and `...\WindowsPowerShell\v1.0\powershell.exe`
- **Remote:** `core/winrm_runner.py` using `pypsrp` — NTLM auth, `execute_ps` / `execute_cmd`
- WinRM connection cache: one NTLM handshake per `(host, username, transport, port, ssl)` per job; `clear_client_cache()` called after job done

### ART Executor Names — CRITICAL
ART YAML `executor.type` values (exact strings):
- `command_prompt` — 557 tests — maps to `cmd.exe /c`
- `powershell` — 699 tests — maps to `powershell.exe -NonInteractive -NoProfile -ExecutionPolicy Bypass -Command`
- `sh` / `bash` — 533 tests — not runnable on Windows without WSL; graceful skip
- `manual` — 15 tests — always skipped

`command_prompt` and `cmd` both handled as aliases → `cmd.exe`. Critical fix: previously bare `"cmd"` did not match `"command_prompt"`, causing 557 tests to fall through to `sh -c` → `[WinError 2]`.

### Privilege / Scope Mapping
```python
SCOPE_PROFILES = {
    "admin":         elevation_required_ok=True,
    "standard_user": elevation_required_ok=False,
}
```
`Target.privilege` maps to these. `elevation_required=True` test + `standard_user` target → skip.

### TTP Blocking Rules (executor `_should_skip()`)
1. **Platform** — `supported_platforms` must include target `os_platform`
2. **Elevation** — `elevation_required=True` + target is `standard_user` → skip
3. **Domain** — `DOMAIN_REQUIRED_TECHNIQUES` + `target.domain_joined=False` → skip

### DOMAIN_REQUIRED_TECHNIQUES
8 techniques need AD — skip if target not domain-joined:
`T1558.001, T1558.003, T1558.004, T1087.002, T1069.002, T1003.003, T1003.005, T1110.003`

Appear with `🏢 AD` badge in UI.

### Tactic Groups — 10
`discovery, credential-access, persistence, privilege-escalation, defense-evasion, execution, collection, exfiltration, impact, command-and-control`

Removed: `lateral-movement` (remote host required), `T1003.006` DCSync (remote DC).

### AI Analysis — Single Call
`ws_analyze` streams tokens → accumulates `full_response` → calls `parse_analysis_response(full_response)` to produce `AnalysisReport`. No second API call. `AnalysisFinding` includes `target_id` for multi-target attribution.

### AI Provider — LiteLLM
Single interface for 19+ models: Anthropic, OpenAI, Gemini, Mistral, Cohere, Groq, Together, Perplexity, Azure, Ollama, OpenRouter, custom.

API keys in browser `localStorage` (temp UI). In production, parent platform passes `ProviderConfig` per request.

---

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/` | Serves temporary UI HTML |
| GET | `/health` | Status + technique count |
| GET | `/api/tactics` | All tactic groups + techniques + tests |
| GET | `/api/scope-profiles` | Returns scope profiles |
| GET | `/api/techniques` | List techniques, optional `?platform=windows` filter |
| GET | `/api/techniques/{id}` | Full technique detail with tests |
| POST | `/api/jobs` | Create execution job → returns `job_id` |
| GET | `/api/jobs/{id}` | Job status |
| GET | `/api/jobs/{id}/results` | Full execution JSON (grouped by target) |
| GET | `/api/jobs/{id}/analysis` | AI analysis report |
| GET | `/api/jobs/{id}/report/html` | Printable HTML report (PDF via browser print) |
| WS | `/ws/execute/{job_id}` | Stream execution events live |
| WS | `/ws/analyze/{job_id}` | Stream AI analysis tokens live |

### Job Creation Payload
```json
{
  "targets": [
    {
      "target_id": "local-admin",
      "name": "LocalMachine",
      "os_platform": "windows",
      "privilege": "admin",
      "connection": "local",
      "domain_joined": false,
      "host": "localhost",
      "winrm_username": "",
      "winrm_password": "",
      "winrm_transport": "ntlm",
      "winrm_port": 5985,
      "winrm_ssl": false
    }
  ],
  "selections": [
    {"technique_id": "T1082", "test_index": 0, "arg_overrides": {}}
  ]
}
```

`total = len(targets) × len(selections)` (fan-out).

### Analyze WebSocket Protocol
1. Connect to `ws://.../ws/analyze/{job_id}`
2. Send: `{"job_id": "...", "provider": {"model_id": "claude-sonnet-4-6", "api_key": "sk-..."}}`
3. Receive: `analysis_start` → `token` (stream) → `analysis_complete`
4. After `analysis_complete`: fetch `GET /api/jobs/{id}/analysis` for parsed report

---

## Running Locally

```powershell
# Windows — portable launcher (bootstraps .runtime/python/ if missing)
.\start.ps1

# Manual:
.\.runtime\python\python.exe -m uvicorn api.main:app --host 127.0.0.1 --port 8000
# UI at http://localhost:8000
```

If atomics missing:
```bash
git clone https://github.com/redcanaryco/atomic-red-team atomics-repo
mv atomics-repo/atomics ./atomics
```

---

## Test DC

| Field | Value |
|-------|-------|
| IP | 192.168.50.162 |
| Username | Administrator |
| Password | Aliilaali1 |
| Hostname | WIN-G4RJOIM66GC |
| Domain | local.corp |
| OS | Windows Server 2019 DC Evaluation |
| WinRM | port 5985, NTLM, no SSL |
| Users | Administrator, Alice.Smith, Bob.Jones, Charlie.Brown |

---

## Confirmed-Working Techniques (Windows)

Tested local + DC WinRM. Use for demos and regression.

| Technique | Index | Executor | Description | Targets |
|-----------|-------|----------|-------------|---------|
| T1033 | 0 | command_prompt | whoami | LOCAL + DC |
| T1082 | 0 | command_prompt | systeminfo | LOCAL + DC |
| T1016 | 0 | command_prompt | ipconfig /all | LOCAL + DC |
| T1057 | 1 | command_prompt | tasklist | LOCAL + DC |
| T1049 | 0 | command_prompt | netstat -ano + net use | LOCAL + DC |
| T1087.001 | 7 | command_prompt | net user (local accounts) | LOCAL + DC |
| T1087.002 | 0 | command_prompt | net user /domain | DC (domain_joined=true) |
| T1069.001 | 1 | command_prompt | net localgroup | LOCAL + DC |
| T1069.002 | 0 | command_prompt | domain groups | DC (domain_joined=true) |
| T1201 | 5 | command_prompt | net accounts (password policy) | LOCAL + DC |
| T1135 | 3 | command_prompt | net view; arg: `computer_name` | DC |
| T1012 | 0 | command_prompt | reg query autorun (admin required) | LOCAL + DC |
| T1518 | 0 | command_prompt | reg query IE / software discovery | LOCAL + DC |
| T1552.001 | 3 | powershell | findstr passwords in files | LOCAL + DC |
| T1558.003 | 0 | powershell | Kerberoasting — AV-blocked on patched DC | DC (expected FAIL) |
| T1003.001 | 0 | command_prompt | LSASS dump via ProcDump — access denied | DC (expected FAIL) |

> T1087.001 / T1087.002: exit_code=1 on DC is normal — stdout still has user data. AI handles correctly.
> T1135 arg_overrides: `{ "computer_name": "192.168.50.162" }`

---

## Current State

- [x] ART engine — 335 techniques loaded, YAML parsing, subprocess execution
- [x] `command_prompt` executor — critical bug fixed; maps to full `cmd.exe` path
- [x] Full-path executors — PATH-independent via `%SystemRoot%`
- [x] Scope-based filtering — elevation + platform + domain-join blocking
- [x] Multi-target model — `Target[]` replaces single `ScopeConfig`; fan-out execution
- [x] WinRM remote execution — `core/winrm_runner.py` via pypsrp, NTLM
- [x] WinRM connection cache — one handshake per target per job
- [x] TTP selection UI — tactic sidebar, technique checkboxes, blocked state badges
- [x] Execution WebSocket — live log, progress bar, per-target events
- [x] AI analysis WebSocket — streaming tokens, single-call parse (no double API call)
- [x] Multi-target analysis — `target_id` per finding
- [x] LiteLLM multi-provider — 19+ models, API key per provider
- [x] PDF report — HTML report with @media print, "Save as PDF" button
- [x] Settings drawer — model + API key in localStorage
- [x] Python SDK — `client/pentest_client.py`
- [x] JavaScript SDK — `client/pentest_client.js`
- [x] Integration reference — `client/INTEGRATION.md`
- [x] Live demo script — `client/ad_pentest_show.py`
- [x] Portable launcher — `start.ps1` bootstraps `.runtime/python/`
- [x] Nmap port scanner — `core/nmap_scanner.py`; 4 profiles; XML → structured JSON
- [x] AI vulnerability analyzer — `core/vuln_analyzer.py`; candidate CVEs from service banners; advisory only
- [x] Scan REST endpoints — `POST /api/scans`, `GET /api/scans/{scan_id}`, `POST /api/scans/analyze`
- [x] Scan WebSockets — `WS /ws/scan` (live progress), `WS /ws/scan-analyze` (streaming AI vuln report)
- [ ] Parent platform REST integration — pending
- [ ] Auth/API key for the API itself — not needed until integration

---

## Atomic Red Team Notes

- YAML at `./atomics/T*/T*.yaml`
- Each technique has N `atomic_tests`, each with an `executor.type` (see executor names above)
- `executor.elevation_required` — boolean per test
- `input_arguments` — have defaults, overridable via `arg_overrides`
- 466 Windows tests require elevation, 752 do not
- Windows Defender / AMSI blocks credential-access techniques on patched systems — expected finding

---

## Windows-Specific Notes

- Multiple Python installs on system — always use `.runtime\python\python.exe`
- PowerShell execution policy: `-ExecutionPolicy Bypass` passed for all PS tests
- WinRM must be enabled on target: `Enable-PSRemoting -Force` + firewall port 5985
- `net user` on DC: exit_code=1 is normal; stdout has user list; AI handles correctly
- AMSI: T1558.003 blocked on patched DC — appears as FAIL with AMSI in stderr — this IS the pentest finding
