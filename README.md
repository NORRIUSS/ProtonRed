# ProtonRed Pentest Tool

<div align="center">

**Windows-native penetration testing tool integrating Atomic Red Team with AI analysis**

[![Python](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.110+-009688.svg)](https://fastapi.tiangolo.com/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

</div>

---

## Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [Quick Start](#quick-start)
- [Two Modes of Operation](#two-modes-of-operation)
  - [Job Mode (API)](#job-mode-api)
  - [Agent Mode (ReAct)](#agent-mode-react)
- [API Reference](#api-reference)
  - [REST Endpoints](#rest-endpoints)
  - [WebSocket Endpoints](#websocket-endpoints)
  - [Nmap Scanning](#nmap-scanning)
  - [Autonomous Agent Sessions](#autonomous-agent-sessions)
- [Client SDKs](#client-sdks)
  - [Python SDK](#python-sdk)
  - [JavaScript SDK](#javascript-sdk)
- [AI Providers](#ai-providers)
- [Data Models](#data-models)
- [Execution Rules](#execution-rules)
- [Test DC Configuration](#test-dc-configuration)
- [Confirmed-Working Techniques](#confirmed-working-techniques)
- [Configuration](#configuration)
- [Demo Script](#demo-script)
- [Integration Guide](#integration-guide)
- [Project Structure](#project-structure)
- [Requirements](#requirements)
- [Security Notes](#security-notes)
- [Windows-Specific Notes](#windows-specific-notes)

---

## Overview

ProtonRed is a **deterministic-first, AI-second** penetration testing tool that runs [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team) (ART) tests against Windows targets (local or remote via WinRM) and then uses AI to analyze the structured JSON results and produce comprehensive findings reports.

**Core Principle:** AI does NOT select or execute tests. AI only analyzes collected results after deterministic execution. This keeps the tool predictable, auditable, and safe.

### Core Flow

```
┌──────────────┐     ┌──────────────────┐     ┌─────────────────┐
│  User selects │────▶│  Deterministic   │────▶│  AI analyzes     │
│  targets+TTPs │     │  execution       │     │  results → report│
│  (via API/UI) │     │  (subprocess or  │     │  (streaming WS)  │
│               │     │   WinRM)         │     │                  │
└──────────────┘     └──────────────────┘     └─────────────────┘
```

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
│   ├── agent.py             # Autonomous ReAct-loop pentest agent
│   ├── tactic_map.py        # TACTIC_GROUPS, SCOPE_PROFILES, DOMAIN_REQUIRED_TECHNIQUES
│   ├── attack_mapper.py     # Objective → MITRE tactic/technique mapping
│   ├── winrm_runner.py      # WinRM remote execution via pypsrp; NTLM auth; connection cache
│   ├── nmap_scanner.py      # Nmap port scanner; 4 profiles; XML → structured JSON
│   ├── vuln_analyzer.py     # AI vulnerability analyzer; candidate CVEs from service banners
│   └── reporter.py          # HTML/JSON report generation
├── providers/
│   ├── __init__.py          # PROVIDER_CATALOG (25+ models), get_provider()
│   ├── base.py              # AIProvider ABC, ProviderConfig, Message dataclass
│   └── litellm_provider.py  # LiteLLM unified wrapper for all providers
├── config/
│   └── settings.py          # Settings class — reads env vars, ART path, etc.
├── ui/
│   └── index.html           # Standalone web UI (single HTML file)
├── client/
│   ├── pentest_client.py    # Python async SDK (httpx + websockets)
│   ├── pentest_client.js    # JavaScript SDK (browser + Node.js)
│   ├── INTEGRATION.md       # Full API reference + confirmed technique index
│   ├── SHOW_RUNBOOK.md      # Live AD demo runbook
│   └── ad_pentest_show.py   # Live AD demo script — 4-phase, 16 confirmed techniques
├── atomics/                 # Atomic Red Team YAML files (335 techniques, bootstrapped)
├── results/                 # Persisted execution + analysis JSON (survives restarts)
├── start.ps1                # Self-bootstrapping Windows launcher
├── main.py                  # CLI entry point (server, setup, run)
├── setup.py                 # pip install packaging
├── requirements.txt
└── README.md
```

---

## Quick Start

### Prerequisites

- Windows 10/11 or Windows Server 2016+
- Git (for cloning Atomic Red Team atomics)
- PowerShell 5.1+

### One-Command Launch

```powershell
.\start.ps1
```

This script automatically:
1. Bootstraps a **portable Python 3.11.9** runtime into `.runtime\python\` (no system install needed)
2. Installs all dependencies from `requirements.txt` (cached by hash)
3. Clones Atomic Red Team atomics into `.\atomics\` if missing (shallow clone)
4. Starts the FastAPI server at `http://localhost:8000`
5. Opens the web UI in your browser

### Manual Launch

```powershell
# Using portable Python
.\.runtime\python\python.exe -m uvicorn api.main:app --host 127.0.0.1 --port 8000

# Using system Python (if available)
python main.py server
```

### CLI Mode (Agent)

```powershell
python main.py run --target localhost --objective "Enumerate domain users and find credentials" --model claude-sonnet-4-6 --api-key sk-ant-...
```

---

## Two Modes of Operation

### Job Mode (API)

**User-directed, deterministic.** You select exactly which MITRE ATT&CK techniques to run against which targets. The tool executes them via subprocess (local) or WinRM (remote), collects structured JSON results, and then AI analyzes the output.

```
POST /api/jobs           → Create job with targets + selections
WS   /ws/execute/{id}    → Stream execution events (live log, per-test results)
GET  /api/jobs/{id}/results → Full results JSON (grouped by target)
WS   /ws/analyze/{id}    → Stream AI analysis tokens (optional)
GET  /api/jobs/{id}/analysis → Parsed findings report (optional)
GET  /api/jobs/{id}/report/html → Printable HTML report (optional)
```

### Agent Mode (ReAct)

**Autonomous AI-driven.** The AI agent follows a ReAct (Reasoning + Acting) loop:

```
Think → Select Tool → Execute → Observe → Think → ...
```

Available tools: `system_info`, `list_techniques`, `search_techniques`, `get_atomics`, `execute_atomic`, `cleanup_atomic`, `note`, `done`

The agent starts with environment discovery and works through MITRE ATT&CK phases relevant to the objective. It avoids repeating tests and adapts its plan based on execution results.

```
POST /api/sessions       → Start agent session with objective
WS   /ws/sessions/{id}   → Stream thought/tool_call/result/finding events
GET  /api/sessions/{id}  → Full session status, findings, event log
POST /api/sessions/{id}/cancel → Cancel running session
```

---

## API Reference

### REST Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/` | Serves web UI |
| `GET` | `/health` | Status + technique count + saved results |
| `GET` | `/docs` | OpenAPI/Swagger documentation |
| `GET` | `/api/providers` | List all available AI models |
| `GET` | `/api/tactics` | All tactic groups + techniques + tests |
| `GET` | `/api/scope-profiles` | Available scope profiles |
| `GET` | `/api/techniques?platform=windows` | List all techniques |
| `GET` | `/api/techniques/search?q={query}` | Search techniques |
| `GET` | `/api/techniques/{id}` | Full technique detail with tests |
| `POST` | `/api/jobs` | Create execution job → returns `job_id` |
| `POST` | `/api/jobs/{id}/cancel` | Cancel a running job |
| `GET` | `/api/jobs/{id}` | Job status |
| `GET` | `/api/jobs/{id}/results` | Full execution results (grouped by target) |
| `GET` | `/api/jobs/{id}/analysis` | AI analysis report (survives server restart) |
| `GET` | `/api/jobs/{id}/report/html` | Printable HTML report (PDF via browser print) |
| `GET` | `/api/results` | List all saved result files |
| `GET` | `/api/results/{id}` | Raw execution JSON for a completed job |
| `POST` | `/api/terminal/execute` | Execute a shell command locally on server |
| `GET` | `/api/nmap-scan-profiles` | Available nmap scan profiles |
| `POST` | `/api/scans` | Run nmap scan → returns `scan_id` |
| `GET` | `/api/scans` | List all saved scans |
| `GET` | `/api/scans/{id}` | Structured scan result (hosts, ports, banners) |
| `GET` | `/api/scans/{id}/raw` | Raw JSON scan result from disk |
| `GET` | `/api/scans/{id}/vulns` | Parsed vulnerability analysis report |
| `POST` | `/api/sessions` | Start autonomous agent session |
| `GET` | `/api/sessions/{id}` | Agent session status + findings + events |
| `POST` | `/api/sessions/{id}/cancel` | Cancel agent session |

### WebSocket Endpoints

| Path | Description | Protocol |
|------|-------------|----------|
| `/ws/execute/{job_id}` | Stream execution events live | Connect → auto-starts stream |
| `/ws/analyze/{job_id}` | Stream AI analysis tokens live | Connect → send provider config → receive tokens |
| `/ws/scan-analyze/{scan_id}` | Stream AI vuln analysis tokens | Connect → send provider config → receive tokens |
| `/ws/sessions/{session_id}` | Stream agent ReAct events live | Connect → receives thought/tool_call/result/finding/done |

#### Execution WebSocket Events

| Event Type | Data Fields | Description |
|-----------|-------------|-------------|
| `started` | `job_id`, `total`, `targets[]` | Job initiation |
| `target_start` | `target_id`, `name`, `connection`, `host` | Moving to next target |
| `test_start` | `technique_id`, `test_index`, `test_name`, `target_id`, `skipped`, `skip_reason` | About to run/skip |
| `test_done` | `technique_id`, `test_name`, `target_id`, `success`, `exit_code`, `duration_ms`, `progress`, `stdout_preview` | Test completed |
| `skipped` | `technique_id`, `target_id`, `target_name`, `reason`, `progress` | Test skipped with reason |
| `job_done` | `job_id`, `total`, `succeeded`, `failed`, `skipped` | All tests finished |
| `execution_complete` | `job_id`, `total`, `succeeded`, `failed`, `skipped`, `result_file` | Final event — close WS here |
| `error` | `message` | Fatal error |

#### Analysis WebSocket Protocol

1. Connect to `ws://host:8000/ws/analyze/{job_id}`
2. Send provider config:
```json
{
  "job_id": "uuid",
  "provider": {
    "model_id": "claude-sonnet-4-6",
    "api_key": "sk-ant-...",
    "base_url": "",
    "azure_api_base": "",
    "azure_api_version": ""
  }
}
```
3. Receive events: `analysis_start` → `token` (streamed) → `analysis_complete`
4. After `analysis_complete`, fetch `GET /api/jobs/{id}/analysis` for the parsed report

### Nmap Scanning

#### Scan Profiles

| Profile | Description |
|---------|-------------|
| `top-1000` | Nmap default top 1000 TCP ports with service detection |
| `active-directory` | Common AD/Windows domain service ports (53,88,135,389,445,3389,5985...) |
| `ad-top-1000` | Top 1000 ports + explicit AD ports **(default)** |
| `full` | All 65535 TCP ports with service detection (slow) |

#### Scan Flow

```
POST /api/scans                  → scan_id
GET  /api/scans/{id}            → structured scan JSON (hosts, ports, banners, CPEs)
WS   /ws/scan-analyze/{id}      → stream AI vulnerability analysis tokens
GET  /api/scans/{id}/vulns       → parsed VulnReport (CVE candidates, observations)
```

> **Advisory only** — all vulnerability findings are candidate hypotheses based on version banners. Validate against the real host before treating as confirmed.

### Autonomous Agent Sessions

#### ReAct Loop Tools

| Tool | Args | Description |
|------|------|-------------|
| `system_info` | none | Get hostname, IP, platform, atomics loaded |
| `list_techniques` | `platform` | List techniques for a platform (e.g., `windows`) |
| `search_techniques` | `query` | Search techniques by name/description |
| `get_atomics` | `technique_id` | Get full technique detail with all tests |
| `execute_atomic` | `technique_id`, `test_index`, `args` | Run an ART test, returns stdout/stderr/exit_code |
| `cleanup_atomic` | `technique_id`, `test_index` | Run test cleanup command |
| `note` | `finding`, `severity`, `technique_id`, `detail` | Record a finding |
| `done` | `summary` | Mark session complete with summary |

---

## Client SDKs

### Python SDK

```python
from pentest_client import PentestClient, Target, TestSelection

async with PentestClient("http://localhost:8000") as client:
    # Build targets
    dc = Target(
        name="DC01",
        target_id="dc01",
        os_platform="windows",
        privilege="admin",
        connection="remote",
        domain_joined=True,
        host="192.168.50.162",
        winrm_username="Administrator",
        winrm_password="...",
        winrm_transport="ntlm",
    )

    local = Target(
        name="LocalMachine",
        target_id="local",
        connection="local",
        privilege="admin",
        domain_joined=False,
    )

    # Select techniques
    selections = [
        TestSelection("T1033", 0),
        TestSelection("T1082", 0),
        TestSelection("T1069.002", 0),
        TestSelection("T1087.002", 0),
        TestSelection("T1201", 5),
    ]

    # Create and execute job
    job_id = await client.create_job([dc, local], selections)

    async for event in client.stream_execute(job_id):
        t, d = event.type, event.data
        if t == "test_done":
            print(f"  {'OK' if d['success'] else 'FAIL'} {d['technique_id']} exit={d['exit_code']}")
        elif t == "execution_complete":
            print(f"Done: {d['succeeded']} ok / {d['failed']} fail / {d['skipped']} skip")

    # Get full results
    results = await client.get_results(job_id)

    # Run AI analysis (streaming)
    async for token in client.stream_analyze(
        job_id,
        model_id="claude-sonnet-4-6",
        api_key="sk-ant-...",
    ):
        print(token, end="", flush=True)

    report = await client.get_analysis(job_id)
    print(f"Risk Level: {report.risk_level.upper()}")
    for f in report.findings:
        print(f"  [{f.severity.upper()}] {f.technique_id} — {f.title}")
```

### JavaScript SDK

```javascript
const { PentestClient, makeTarget, makeSelection } = require("./pentest_client");

const client = new PentestClient("http://localhost:8000");

const dc = makeTarget({
  name: "DC01",
  target_id: "dc01",
  privilege: "admin",
  connection: "remote",
  domain_joined: true,
  host: "192.168.50.162",
  winrm_username: "Administrator",
  winrm_password: "...",
});

const selections = [
  makeSelection("T1033", 0),
  makeSelection("T1082", 0),
  makeSelection("T1069.002", 0),
  makeSelection("T1087.002", 0),
];

(async () => {
  const jobId = await client.createJob([dc], selections);
  console.log("Job:", jobId);

  for await (const ev of client.streamExecute(jobId)) {
    if (ev.type === "test_done") {
      console.log(`${ev.data.success ? "OK" : "FAIL"} ${ev.data.technique_id}`);
    }
  }

  const results = await client.getResults(jobId);

  // AI analysis
  for await (const token of client.streamAnalyze(jobId, "claude-sonnet-4-6", "sk-ant-...")) {
    process.stdout.write(token);
  }

  const report = await client.getAnalysis(jobId);
  console.log("\nRisk:", report.risk_level);
})();
```

---

## AI Providers

ProtonRed uses **LiteLLM** as a unified provider interface, supporting 25+ models:

### Provider Catalog

| model_id | Provider | Notes |
|----------|----------|-------|
| `claude-sonnet-4-6` | Anthropic | Recommended — best analysis quality |
| `claude-opus-4-8` | Anthropic | Highest quality, slower |
| `claude-haiku-4-5` | Anthropic | Fast, cheaper |
| `gpt-4o` | OpenAI | |
| `gpt-4o-mini` | OpenAI | Fast, cheap |
| `o1` | OpenAI | Reasoning model |
| `gemini-1.5-pro` | Google | |
| `gemini-2.0-flash` | Google | Fast |
| `mistral-large` | Mistral | |
| `mistral-medium` | Mistral | |
| `command-r-plus` | Cohere | |
| `groq-llama-70b` | Groq | Very fast inference |
| `groq-mixtral` | Groq | |
| `together-llama-70b` | Together AI | |
| `perplexity-sonar` | Perplexity | |
| `azure-gpt-4o` | Azure OpenAI | Requires `azure_api_base` + `azure_api_version` |
| `ollama-llama3` | Ollama (local) | Requires local Ollama running |
| `ollama-mistral` | Ollama (local) | |
| `ollama-deepseek` | Ollama (local) | |
| `openrouter-claude-sonnet` | OpenRouter | Single key → 300+ models |
| `openrouter-gpt-4o` | OpenRouter | |
| `openrouter-gemini-pro` | OpenRouter | |
| `openrouter-llama-70b` | OpenRouter | |
| `openrouter-deepseek-r1` | OpenRouter | |
| `openrouter-qwen-72b` | OpenRouter | |
| `openrouter-custom` | OpenRouter | Custom model string |
| `custom` | Custom OpenAI-compatible | Set `base_url` in provider config |

API keys can be provided:
- **Per request** via the provider config object in API calls
- **Via environment** in `.env` file (`ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, etc.)
- **Via browser** localStorage (temporary UI only)

---

## Data Models

### Target

```json
{
  "target_id": "dc01",
  "name": "DC01",
  "os_platform": "windows",
  "privilege": "admin",
  "connection": "remote",
  "domain_joined": true,
  "host": "192.168.50.162",
  "winrm_username": "Administrator",
  "winrm_password": "...",
  "winrm_transport": "ntlm",
  "winrm_port": 5985,
  "winrm_ssl": false,
  "notes": ""
}
```

| Field | Values | Notes |
|-------|--------|-------|
| `target_id` | string | Unique identifier per target |
| `name` | string | Display label, e.g. "DC01" or "localhost" |
| `os_platform` | `windows` `linux` `macos` | Controls platform-based test skipping |
| `privilege` | `admin` `standard_user` | Controls elevation-based test skipping |
| `connection` | `local` `remote` | `remote` uses WinRM |
| `domain_joined` | bool | AD-required techniques skip if false |
| `winrm_transport` | `ntlm` `kerberos` `credssp` `negotiate` `basic` | WinRM auth method |

### TestSelection

```json
{
  "technique_id": "T1082",
  "test_index": 0,
  "arg_overrides": {}
}
```

### Job Creation Payload

```json
{
  "targets": [<Target>, ...],
  "selections": [<TestSelection>, ...]
}
```

`total = len(targets) × len(selections)` (fan-out per target).

### Analysis Report Response

```json
{
  "executive_summary": "Direct statement of what was compromised...",
  "risk_level": "high",
  "findings": [
    {
      "severity": "high",
      "technique_id": "T1069.002",
      "tactic": "discovery",
      "target_id": "tgt-1",
      "title": "Domain Group Membership Enumerated",
      "detail": "Exact statement of what happened...",
      "evidence": "Exact output lines from stdout that prove this finding...",
      "recommendation": "Specific, actionable remediation..."
    }
  ],
  "succeeded_techniques": ["T1082", "T1033"],
  "failed_techniques": ["T1558.003"],
  "key_observations": ["Concrete observation derived from output data"],
  "attack_path": "Step-by-step attack chain based on succeeded tests...",
  "timestamp": "2026-06-13T10:01:30Z",
  "error": null
}
```

### Exit Code Semantics

| exit_code | Meaning | AI Treatment |
|-----------|---------|--------------|
| `0` | Success — technique worked | Finding: technique executed successfully |
| `1` | Command ran but OS returned error (e.g., `net user` on DC) | Finding: technique attempted, assess stdout context |
| `5` | Access denied — security control blocked | Finding: defensive control working |
| `>0` (other) | OS/app error | Finding: assess context |
| `-1` | Infrastructure failure (timeout, WinRM unreachable, executor missing) | **Not a pentest finding** — exclude from analysis |

> WinRM `access denied` errors (WSManFault code `2147942405`) are mapped to `exit_code=5`, not `-1`, so AI correctly identifies them as security controls.

---

## Execution Rules

### TTP Blocking Rules (per-target skip decisions)

Tests are automatically skipped when:

1. **Platform mismatch** — `supported_platforms` does not include target `os_platform`
2. **Elevation required** — test requires elevation but target has `standard_user` privilege
3. **Domain required** — technique is AD-dependent but target is not domain-joined
4. **Remote executor** — `bash`/`sh` executor cannot run over WinRM (Windows shell only)
5. **Download required** — command fetches external tools from internet at runtime
6. **wmic removed** — `wmic.exe` removed from Windows 11, test not executable

### Skip Reason Reference

| Skip Reason | Cause |
|-------------|-------|
| `"Not supported on {platform}"` | Test targets different OS platform |
| `"Elevation required — target has standard-user privileges only"` | Test needs admin, target lacks it |
| `"Requires domain membership — target is not domain-joined"` | AD-only technique, non-domain target |
| `"Executor 'bash' not runnable remotely over WinRM"` | Linux executor on Windows remote target |
| `"Requires external tool download — skipped in isolated environment"` | Command uses runtime GitHub downloads |
| `"wmic.exe removed from Windows 11 — not available on this host"` | WMIC deprecated on Windows 11 |

### DOMAIN_REQUIRED_TECHNIQUES

8 techniques require Active Directory — skipped if target not domain-joined:

`T1558.001` (Golden Ticket), `T1558.003` (Kerberoasting), `T1558.004` (AS-REP Roasting),
`T1087.002` (Domain Account Discovery), `T1069.002` (Domain Groups),
`T1003.003` (NTDS.dit), `T1003.005` (Cached Domain Credentials), `T1110.003` (AD Password Spray)

### Tactic Groups (10)

| Tactic | Icon | Category |
|--------|------|----------|
| Discovery | 🔍 | Reconnaissance |
| Credential Access | 🔑 | Theft |
| Persistence | 🪝 | Maintain |
| Privilege Escalation | ⬆️ | Elevate |
| Defense Evasion | 🛡️ | Hide |
| Execution | ⚡ | Run |
| Collection | 📦 | Gather |
| Exfiltration | 📤 | Steal |
| Impact | 💥 | Destroy |
| Command & Control | 📡 | Communicate |

### ART Executor Types

| Executor | Count | Target |
|----------|-------|--------|
| `command_prompt` | 557 tests | `cmd.exe /c` |
| `powershell` | 699 tests | `powershell.exe -NonInteractive -NoProfile -ExecutionPolicy Bypass` |
| `sh` / `bash` | 533 tests | Not runnable on Windows without WSL — gracefully skipped |
| `manual` | 15 tests | Always skipped |

$> Note: `command_prompt` and `cmd` are handled as aliases → both map to `cmd.exe`. All executors use full system paths (`%SystemRoot%\System32\cmd.exe`) to be PATH-independent.

---

## Test DC Configuration

Built-in reference Domain Controller for development/testing:

| Field | Value |
|-------|-------|
| IP | 192.168.50.162 |
| Username | Administrator |
| Hostname | WIN-G4RJOIM66GC |
| Domain | local.corp |
| OS | Windows Server 2019 DC Evaluation |
| WinRM | port 5985, NTLM, no SSL |
| Users | Administrator, Alice.Smith, Bob.Jones, Charlie.Brown |

---

## Confirmed-Working Techniques

Tested on local Windows + remote DC via WinRM. Use for demos and regression testing.

| Technique | Index | Executor | Description | Targets |
|-----------|-------|----------|-------------|---------|
| T1033 | 0 | `command_prompt` | `whoami` | LOCAL + DC |
| T1082 | 0 | `command_prompt` | `systeminfo` | LOCAL + DC |
| T1016 | 0 | `command_prompt` | `ipconfig /all` | LOCAL + DC |
| T1057 | 1 | `command_prompt` | `tasklist` | LOCAL + DC |
| T1049 | 0 | `command_prompt` | `netstat -ano` + `net use` | LOCAL + DC |
| T1087.001 | 7 | `command_prompt` | `net user` (local accounts) | LOCAL + DC |
| T1087.002 | 0 | `command_prompt` | `net user /domain` | DC (domain_joined=true) |
| T1069.001 | 1 | `command_prompt` | `net localgroup` | LOCAL + DC |
| T1069.002 | 0 | `command_prompt` | Domain groups | DC (domain_joined=true) |
| T1201 | 5 | `command_prompt` | `net accounts` (password policy) | LOCAL + DC |
| T1135 | 3 | `command_prompt` | `net view` | DC (needs `computer_name` arg) |
| T1012 | 0 | `command_prompt` | `reg query` autorun (admin required) | LOCAL + DC |
| T1518 | 0 | `command_prompt` | `reg query` IE / software discovery | LOCAL + DC |
| T1552.001 | 3 | `powershell` | `findstr` passwords in files | LOCAL + DC |
| T1558.003 | 0 | `powershell` | Kerberoasting — AV-blocked on patched DC | DC (expected FAIL) |
| T1003.001 | 0 | `command_prompt` | LSASS dump via ProcDump | DC (expected FAIL) |

> T1087.001 / T1087.002: `exit_code=1` on DC is normal — stdout still has user data. AI handles correctly.
> T1135 `arg_overrides`: `{ "computer_name": "YOUR-DC-HOSTNAME" }`

---

## Configuration

Copy `.env.example` to `.env` and configure:

```env
# AI Providers
ANTHROPIC_API_KEY=sk-ant-...
OPENAI_API_KEY=sk-...
GEMINI_API_KEY=...
MISTRAL_API_KEY=...
COHERE_API_KEY=...
GROQ_API_KEY=...
TOGETHER_API_KEY=...
PERPLEXITY_API_KEY=...

# Azure OpenAI
AZURE_API_KEY=...
AZURE_API_BASE=https://your-resource.openai.azure.com
AZURE_API_VERSION=2024-02-01

# Ollama (local)
OLLAMA_BASE_URL=http://localhost:11434

# OpenRouter (single key → 300+ models)
OPENROUTER_API_KEY=sk-or-v1-...

# Custom Provider
CUSTOM_PROVIDER_BASE_URL=
CUSTOM_PROVIDER_API_KEY=

# App Config
ART_ATOMICS_PATH=./atomics
RESULTS_DIR=./results
MAX_AGENT_ITERATIONS=30
AGENT_TIMEOUT_SECONDS=300
API_HOST=0.0.0.0
API_PORT=8000
LOG_LEVEL=INFO

# API Security (optional — set to enable API key auth)
PROTONRED_API_KEY=

# Nmap
NMAP_PATH=
SCAN_TIMEOUT_SECONDS=600
```

---

## Demo Script

`client/ad_pentest_show.py` — a live 4-phase AD pentest demonstration:

```powershell
# Full show (LOCAL + DC execution):
python client/ad_pentest_show.py

# DC only:
python client/ad_pentest_show.py --dc-only

# Local machine only:
python client/ad_pentest_show.py --local-only

# With AI analysis after execution:
python client/ad_pentest_show.py --analyze --api-key sk-ant-...

# Analyze a previously saved job:
python client/ad_pentest_show.py --job-id <uuid> --analyze --api-key sk-ant-...

# Custom API URL:
python client/ad_pentest_show.py --api http://192.168.1.50:8000
```

### Demo Phases

| Phase | Description | Techniques |
|-------|-------------|------------|
| **Phase 1** | Identity & Host Recon | T1033 (whoami), T1082 (systeminfo), T1016 (ipconfig) |
| **Phase 2** | Domain & Network Enumeration | T1087.002, T1069.002, T1087.001, T1069.001, T1201, T1135, T1049, T1057 |
| **Phase 3** | Configuration & Persistence Discovery | T1012 (autorun), T1518 (software), T1552.001 (credential files) |
| **Phase 4** | Credential Access (AV drama) | T1558.003 (Kerberoasting — AMSI block), T1003.001 (LSASS dump — access denied) |

---

## Integration Guide

ProtonRed is designed as **a module inside a larger web platform**. The web UI (`ui/index.html`) is temporary — the real integration path is via the REST API and client SDKs.

### Integration Flow

```
Your Platform → REST API (port 8000) → ProtonRed Core
                                    → WebSocket (streaming events)
                                    → Results persisted to disk
```

### Key Integration Points

1. **REST API** is stateless-friendly — jobs survive server restarts via disk persistence
2. **Client SDKs** (`client/pentest_client.py`, `client/pentest_client.js`) are the recommended integration layer
3. **Raw results** (`results/{job_id}.json`) are pure subprocess output — no AI coupling
4. **Analysis** (`results/{job_id}.analysis.json`) is optional and independent of execution
5. **Cross-session workflow** — execute in one session, analyze in another after a restart

### Persistence Guarantees

| File | Endpoint | Survives Restart |
|------|----------|-----------------|
| `results/{id}.json` | `GET /api/results/{id}` | Yes |
| `results/{id}.analysis.json` | `GET /api/jobs/{id}/analysis` | Yes |
| `results/scans/{id}.json` | `GET /api/scans/{id}` | Yes |
| `results/scans/{id}.vulns.json` | `GET /api/scans/{id}/vulns` | Yes |

---

## Project Structure

```
├── api/                    FastAPI application layer
│   ├── main.py             All REST + WebSocket endpoints (~1230 lines)
│   └── models.py           Pydantic request/response models
├── core/                   Business logic
│   ├── atomic_engine.py    ART YAML parser + subprocess executor (~400 lines)
│   ├── executor.py         Deterministic job executor + multi-target fan-out (~390 lines)
│   ├── analyzer.py         AI analysis engine + structured report (~190 lines)
│   ├── agent.py            Autonomous ReAct-loop pentest agent (~340 lines)
│   ├── tactic_map.py       MITRE tactic/technique mapping (~190 lines)
│   ├── attack_mapper.py    Objective → attack phase mapping (~215 lines)
│   ├── winrm_runner.py     Remote execution via pypsrp/NTLM (~190 lines)
│   ├── nmap_scanner.py     Nmap port scanner (4 profiles) (~270 lines)
│   ├── vuln_analyzer.py    AI vulnerability analyzer (CVE candidates) (~190 lines)
│   └── reporter.py         HTML/JSON report generation (~170 lines)
├── providers/              AI provider layer
│   ├── base.py             Abstract provider + Message/ProviderConfig
│   ├── litellm_provider.py LiteLLM wrapper (25+ models)
│   └── __init__.py         Provider catalog + get_provider()
├── config/
│   └── settings.py         Environment-based configuration
├── client/                 Integration SDKs
│   ├── pentest_client.py   Python async SDK (~340 lines)
│   ├── pentest_client.js   JavaScript SDK (browser + Node.js)
│   ├── INTEGRATION.md      Full API reference (~1187 lines)
│   ├── SHOW_RUNBOOK.md     Demo script runbook (~236 lines)
│   └── ad_pentest_show.py  Live AD pentest demo (~360 lines)
├── ui/
│   └── index.html          Standalone web UI (~1784 lines)
├── atomics/                Atomic Red Team YAML files (335 techniques)
├── results/                Persisted execution + analysis JSON
├── start.ps1               Portable Windows launcher (~230 lines)
├── main.py                 CLI entry point (~135 lines)
├── setup.py                Package setup
├── requirements.txt        Python dependencies
├── .env.example            Environment template
└── CLAUDE.md               Project brief for Claude
```

---

## Requirements

### Python Dependencies

```
litellm>=1.40.0      # Unified AI provider interface
fastapi>=0.110.0      # REST + WebSocket server
uvicorn[standard]>=0.27.0  # ASGI server
websockets>=12.0      # WebSocket support
pydantic>=2.6.0       # Data validation
pyyaml>=6.0.1         # ART YAML parsing
python-dotenv>=1.0.0  # Environment loading
httpx>=0.27.0         # HTTP client (SDK)
aiofiles>=23.2.1      # Async file operations
rich>=13.7.0          # CLI formatting
typer>=0.12.0         # CLI framework
psutil>=5.9.0         # Process management
pypsrp>=0.8.1         # WinRM/PowerShell Remoting
```

### System Requirements

- Windows 10/11 or Windows Server 2016+
- PowerShell 5.1+
- Nmap (optional — for port scanning; install separately or set `NMAP_PATH`)
- Git (for cloning Atomic Red Team atomics)

---

## Security Notes

- **Credentials in memory**: WinRM passwords are held in memory during job execution. They are erased when the job cache is cleared.
- **No persistent auth**: API does not require authentication by default. Set `PROTONRED_API_KEY` in `.env` to enable API key auth via `X-API-Key` header.
- **Local execution only**: Tests run as the user running the server. For remote execution, WinRM credentials are needed.
- **Penetration testing tool**: Only use against systems you own or are authorized to test.
- **AI analysis caveat**: Nmap vulnerability analysis provides advisory CVE candidates only — every finding must be validated against the real host.

---

## Windows-Specific Notes

- **Portable runtime**: The `.runtime/` directory contains a self-contained Python 3.11.9. No system Python needed. Always use `.runtime\python\python.exe` to avoid conflicts with other Python installations.
- **PowerShell execution policy**: `-ExecutionPolicy Bypass` is passed for all PowerShell tests.
- **WinRM must be enabled on target**: Run `Enable-PSRemoting -Force` and open firewall port 5985.
- **`net user` on DC**: `exit_code=1` is normal — stdout still has user data. The AI analyzer handles this correctly.
- **AMSI/Defender**: T1558.003 (Kerberoasting) and similar credential-access techniques are blocked on patched DCs — this is expected behavior and is reported as a finding (AV/defensive control present).
- **Multiple Python installs**: The system may have multiple Python versions. The `start.ps1` launcher always uses the portable `.runtime\python\python.exe`.
- **Firewall**: The launcher automatically adds a Windows Firewall rule for the configured port. Run as admin if needed.

---

## License

MIT License — see LICENSE file for details.

---

## Maintainers

Built for integration into a larger web platform. The current UI is temporary — internal consumers should use the REST API and client SDKs directly.

---

<div align="center">
  <sub>ProtonRed Pentest Tool — Deterministic execution, intelligent analysis</sub>
</div>
