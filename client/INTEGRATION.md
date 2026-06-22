# ProtonRed — Integration Reference

## Overview

REST + WebSocket API. No auth (add API key middleware before exposing externally).

```
Base URL:  http://<host>:8000
WS Base:   ws://<host>:8000
```

---

## Core Flow

```
1. POST /api/jobs                  → job_id
2. WS   /ws/execute/{id}           → stream execution events
                                     ↳ raw JSON auto-saved → results/{id}.json
3. GET  /api/results/{id}          → raw TTP JSON (no AI, pure subprocess output)
4. WS   /ws/analyze/{id}           → stream AI analysis tokens          [OPTIONAL]
                                     ↳ analysis auto-saved → results/{id}.analysis.json
5. GET  /api/jobs/{id}/analysis    → parsed findings report              [OPTIONAL]
6. GET  /api/jobs/{id}/report/html → print-to-PDF report                 [OPTIONAL]
```

Steps 4–6 are optional. Both raw results and AI analysis are persisted to disk and survive server restarts.

**Persistence guarantees:**

| File | Endpoint | Survives restart |
|------|----------|-----------------|
| `results/{id}.json` | `GET /api/results/{id}` | ✓ |
| `results/{id}.analysis.json` | `GET /api/jobs/{id}/analysis` | ✓ |

**Cross-session workflow** — parent platform can execute and analyze in separate sessions:
```
Session 1:  POST /api/jobs → WS /ws/execute → results/{id}.json saved
[server restart]
Session 2:  WS /ws/analyze/{id}  → loads results/{id}.json from disk automatically
            GET /api/jobs/{id}/analysis → loads {id}.analysis.json from disk
```

---

## Data Models

### Target

```json
{
  "target_id":       "tgt-1",
  "name":            "DC01",
  "os_platform":     "windows",
  "privilege":       "admin",
  "connection":      "local",
  "domain_joined":   false,
  "host":            "localhost",
  "winrm_username":  "",
  "winrm_password":  "",
  "winrm_transport": "ntlm",
  "winrm_port":      5985,
  "winrm_ssl":       false,
  "notes":           ""
}
```

| Field | Values | Notes |
|-------|--------|-------|
| `os_platform` | `windows` `linux` `macos` | Controls platform-skip |
| `privilege` | `admin` `standard_user` | Controls elevation-skip |
| `connection` | `local` `remote` | `remote` uses WinRM |
| `domain_joined` | bool | AD-required techniques skip if false |
| `winrm_transport` | `ntlm` `kerberos` `credssp` `negotiate` `basic` | Auth method for WinRM |

### TestSelection

```json
{
  "technique_id": "T1082",
  "test_index":   0,
  "arg_overrides": {}
}
```

`test_index` is the 0-based index within the technique's `atomic_tests` array.
Different indices may target different platforms — check `/api/tactics` for `platforms` per test.

---

## Endpoints

### GET /api/scope-profiles

Returns available scope profiles used for technique filtering.

```json
{
  "profiles": [
    { "id": "workstation", "name": "Workstation", "description": "..." },
    { "id": "server", "name": "Server", "description": "..." }
  ]
}
```

---

### GET /api/techniques?platform=windows

List all techniques for a given platform (default: `windows`).

```json
{
  "techniques": [
    {
      "technique_id": "T1082",
      "display_name": "System Information Discovery",
      "test_count": 4
    }
  ]
}
```

---

### GET /api/techniques/{technique_id}

Get full detail for a single technique including all tests.

```json
{
  "technique_id": "T1082",
  "display_name": "System Information Discovery",
  "test_count": 4,
  "domain_required": false,
  "tests": [
    {
      "index": 0,
      "name": "System Information Discovery",
      "platforms": ["windows"],
      "elevation_required": false,
      "domain_required": false,
      "executor": "command_prompt",
      "needs_download": false
    }
  ]
}
```

404 if technique not found.

---

### GET /api/jobs/{job_id}

Get job status and counters.

```json
{
  "job_id": "<uuid>",
  "status": "done",
  "total": 10,
  "completed": 10,
  "succeeded": 8,
  "failed": 1,
  "skipped": 1,
  "start_time": "2026-06-13T10:00:00Z",
  "end_time": "2026-06-13T10:01:00Z",
  "error": null
}
```

---

### GET /api/jobs/{job_id}/results

Get full execution results for a job (same as `GET /api/results/{job_id}`).

---

### GET /api/jobs/{job_id}/report/html

Returns an HTML report suitable for printing to PDF. No JSON — returns `text/html`.

---

### GET /api/results

List all saved result files on disk.

```json
{
  "results": [
    { "job_id": "<uuid>", "file": "results/<uuid>.json", "size": 14823 }
  ]
}
```

---

### GET /api/results/{job_id}

Get raw execution results JSON for a job (loads from disk if not in memory).

---

### GET /api/nmap-scan-profiles

Returns available nmap scan profiles.

```json
{
  "profiles": [
    { "id": "top-1000",        "description": "Nmap default top 1000 TCP ports with service detection" },
    { "id": "active-directory","description": "Common Active Directory / Windows domain service ports" },
    { "id": "ad-top-1000",     "description": "Top 1000 ports plus explicit AD service ports" },
    { "id": "full",            "description": "All 65535 TCP ports with service detection (slow)" }
  ],
  "default": "ad-top-1000"
}
```

---

### GET /api/scans/{scan_id}/vulns

Returns parsed `VulnReport` for a completed scan analysis (same shape as documented in the Nmap section above). Note: endpoint is `/vulns`, not `/analysis`.

---

### GET /health



```json
{
  "status": "ok",
  "techniques_loaded": 335,
  "atomics_available": true,
  "jobs": 2,
  "analyses": 1,
  "saved_results": 7,
  "results_dir": "C:\\...\\results"
}
```

---

### GET /api/providers

Returns the full model catalog. Use returned `model_id` values in analyze requests.

```json
{
  "providers": [
    { "model_id": "claude-sonnet-4-6", "provider": "anthropic" },
    { "model_id": "gpt-4o",            "provider": "openai" }
  ]
}
```

---

### GET /api/techniques/search?q={query}

Search techniques by name or description.

```
GET /api/techniques/search?q=registry
```

```json
{
  "results": [
    { "technique_id": "T1012", "display_name": "Query Registry", "test_count": 6 },
    { "technique_id": "T1552.002", "display_name": "Credentials in Registry", "test_count": 3 }
  ]
}
```

---

### GET /api/tactics

Returns all tactic groups with techniques and tests.

```json
{
  "tactics": [
    {
      "id": "discovery",
      "name": "Discovery",
      "icon": "🔍",
      "technique_count": 21,
      "techniques": [
        {
          "technique_id": "T1082",
          "display_name": "System Information Discovery",
          "test_count": 6,
          "domain_required": false,
          "tests": [
            {
              "index": 0,
              "name": "System Information Discovery",
              "platforms": ["windows"],
              "elevation_required": false,
              "domain_required": false,
              "executor": "command_prompt"
            }
          ]
        }
      ]
    }
  ]
}
```

---

### POST /api/jobs

Create a job. Returns immediately with `job_id`. Execution happens over WebSocket.

**Request:**
```json
{
  "targets": [<Target>, ...],
  "selections": [<TestSelection>, ...]
}
```

**Response:**
```json
{
  "job_id": "uuid",
  "total": 6,
  "target_count": 2
}
```

`total = len(targets) × len(selections)` (fan-out).

---

### POST /api/jobs/{job_id}/cancel

Cancel an active or pending job execution. If the job is currently running, its task is aborted, active subprocesses are terminated, any remaining/non-executed tests are flagged as skipped (with reason `"Job cancelled"`), and cancellation events are broadcasted over the job's WebSocket connection.

**Request:**
No payload.

**Response:**
```json
{
  "status": "cancelled",
  "job_id": "uuid"
}
```

---

### GET /api/jobs/{job_id}

Job status.

```json
{
  "job_id": "uuid",
  "status": "pending|running|done|error",
  "total": 6,
  "completed": 4,
  "succeeded": 3,
  "failed": 1,
  "skipped": 0,
  "start_time": "2026-06-13T10:00:00",
  "end_time": null,
  "error": null
}
```

---

### GET /api/jobs/{job_id}/results

Full results grouped by target.

```json
{
  "job_id": "uuid",
  "targets": [<target dict>, ...],
  "summary": {
    "target_count": 2,
    "total_tests": 6,
    "succeeded": 4,
    "failed": 1,
    "skipped": 1
  },
  "by_target": [
    {
      "target": { "target_id": "tgt-1", "name": "DC01", ... },
      "summary": { "total_tests": 3, "succeeded": 2, "failed": 1, "skipped": 0, "tactics_tested": ["discovery"] },
      "results": [
        {
          "technique_id": "T1082",
          "test_name": "System Information Discovery",
          "tactic": "discovery",
          "success": true,
          "exit_code": 0,
          "skipped": false,
          "skip_reason": "",
          "stdout": "Host Name: DC01\nOS: Windows Server 2019...",
          "stderr": "",
          "command_executed": "systeminfo",
          "duration_ms": 3200,
          "timestamp": "2026-06-13T10:00:05"
        }
      ]
    }
  ]
}
```

**Skip reasons** (when `skipped=true`):

| skip_reason | Cause | Action |
|-------------|-------|--------|
| `"Not supported on windows"` | Test targets different OS platform | Choose correct platform test index |
| `"Elevation required — target has standard-user privileges only"` | Test needs admin, target is standard_user | Set `privilege: "admin"` on target |
| `"Requires domain membership — target is not domain-joined"` | AD-only technique, target not domain-joined | Set `domain_joined: true` or remove technique |
| `"Executor 'bash' not runnable remotely over WinRM"` | bash/sh test selected for WinRM remote target | Select a powershell/cmd variant |
| `"Requires external tool download — skipped in isolated environment"` | Command fetches tools from GitHub/internet at runtime | Not supported in offline/air-gapped environments |
| `"wmic.exe removed from Windows 11 — not available on this host"` | Test uses wmic, which was removed in Windows 11 | Use a different test index for this technique |

> **Note:** `skipped=true` results are not pentest findings and should be excluded from AI analysis scope. The executor automatically skips download-dependent tests (52 ART tests use runtime GitHub downloads) and wmic-based tests on Windows 11 hosts. These skips are expected and normal.

---

### GET /api/jobs/{job_id}/analysis

Parsed AI analysis. Available after `/ws/analyze` completes. **Persists across server restarts** — loaded from `results/{id}.analysis.json` if not in memory.

```json
{
  "executive_summary": "...",
  "risk_level": "high",
  "findings": [
    {
      "severity": "high",
      "technique_id": "T1069.002",
      "tactic": "discovery",
      "target_id": "tgt-1",
      "title": "Domain Group Membership Enumerated",
      "detail": "...",
      "evidence": "...",
      "recommendation": "..."
    }
  ],
  "succeeded_techniques": ["T1082", "T1033"],
  "failed_techniques": ["T1558.003"],
  "key_observations": ["..."],
  "attack_path": "...",
  "timestamp": "2026-06-13T10:01:30",
  "error": null
}
```

---

### GET /api/jobs/{job_id}/report/html

Full printable HTML report. Open in browser → Ctrl+P → Save as PDF.

---

### POST /api/terminal/execute

Run a system shell command locally on the server host machine. This is used by the frontend interactive web terminal to execute diagnostic or verification commands. Executes commands asynchronously with a timeout of 30 seconds.

**Request:**
```json
{
  "command": "whoami"
}
```

**Response:**
```json
{
  "stdout": "username\n",
  "stderr": "",
  "exit_code": 0
}
```

---

## Autonomous Agent (ReAct) Sessions

ProtonRed hosts a server-side autonomous agent loop that executes TTPs dynamically based on a target and objective using a ReAct (Reasoning and Acting) framework.

### POST /api/sessions

Start an autonomous agent session. Returns immediately with a `session_id` while running the agent loop in the background.

**Request:**
```json
{
  "target": "localhost",
  "objective": "Retrieve domain information and discover sensitive files.",
  "provider": {
    "model_id": "claude-sonnet-4-6",
    "api_key": "sk-ant-...",
    "base_url": "",
    "azure_api_base": "",
    "azure_api_version": ""
  },
  "max_iterations": 20,
  "atomics_path": "./atomics"
}
```

**Response:**
```json
{
  "session_id": "uuid",
  "status": "running"
}
```

---

### GET /api/sessions/{session_id}

Retrieve the status, findings, and complete event logs of an autonomous agent session.

**Response:**
```json
{
  "session_id": "uuid",
  "target": "localhost",
  "objective": "...",
  "provider_model": "claude-sonnet-4-6",
  "status": "running|done|cancelled|error",
  "iterations": 3,
  "findings": [
    {
      "severity": "high",
      "technique_id": "T1003",
      "title": "Credential Dumping",
      "detail": "...",
      "timestamp": "ISO8601"
    }
  ],
  "events": [
    {
      "type": "thought|tool_call|tool_result|finding|done|error",
      "data": {},
      "timestamp": "ISO8601"
    }
  ],
  "start_time": "ISO8601",
  "end_time": null,
  "error": null
}
```

---

### POST /api/sessions/{session_id}/cancel

Cancel a running autonomous agent session.

**Response:**
```json
{
  "status": "cancelled",
  "session_id": "uuid"
}
```

---

### WebSocket: /ws/sessions/{session_id}

Connect to stream agent session events live. Replays past events for late-joining clients automatically.

**Events:**
* `thought`: Contains the agent's current reasoning thought process (`{"thought": "..."}`).
* `tool_call`: Contains details about the technique/test selected to execute (`{"tool": "execute_atomic", "args": {}}`).
* `tool_result`: Contains the stdout, stderr, exit code, and success flag of the executed TTP.
* `finding`: Signals that a security vulnerability or finding was discovered.
* `done`: Sent when the agent finishes execution successfully (`{"summary": "..."}`).
* `error`: Sent if a fatal error occurs or if the session is cancelled.

---

## Raw TTP Results (No AI)

After every execution, the tool **automatically** saves a raw JSON file to `results/{job_id}.json` on disk. This file contains only subprocess output — no AI analysis, no transformation. Use it to feed downstream pipeline components.

### GET /api/results

List all saved raw execution result files. Analysis sidecar files (`*.analysis.json`) are excluded from this listing.

```json
{
  "results_dir": "C:\\...\\results",
  "count": 3,
  "files": [
    {
      "job_id": "uuid",
      "filename": "uuid.json",
      "size_bytes": 37588,
      "path": "C:\\...\\results\\uuid.json",
      "url": "/api/results/uuid",
      "analysis_url": "/api/jobs/uuid/analysis"
    }
  ]
}
```

`analysis_url` is always included. Returns 404 if analysis hasn't been run yet for that job.

### GET /api/results/{job_id}

Returns the raw execution JSON — identical structure to `GET /api/jobs/{id}/results`.

```json
{
  "job_id": "uuid",
  "targets": [...],
  "summary": {
    "target_count": 1,
    "total_tests": 10,
    "succeeded": 7,
    "failed": 2,
    "skipped": 1
  },
  "by_target": [
    {
      "target": { "target_id": "dc01", "name": "DC01", ... },
      "summary": { "total_tests": 10, "succeeded": 7, ... },
      "results": [
        {
          "technique_id": "T1082",
          "test_name": "System Information Discovery",
          "tactic": "discovery",
          "success": true,
          "exit_code": 0,
          "skipped": false,
          "skip_reason": "",
          "stdout": "Host Name: DC01\nOS Name: Windows Server 2019...",
          "stderr": "",
          "command_executed": "systeminfo\nreg query ...",
          "duration_ms": 3200,
          "timestamp": "2026-06-13T10:00:05"
        }
      ]
    }
  ]
}
```

**Key fields per result:**

| Field | Type | Notes |
|-------|------|-------|
| `success` | bool | `exit_code == 0` |
| `exit_code` | int | `0` = success, `>0` = OS/app error, `-1` = infrastructure error (timeout, WinRM fail) |
| `skipped` | bool | True if blocked by platform/elevation/domain rules |
| `skip_reason` | string | Human-readable skip reason |
| `stdout` | string | Raw subprocess stdout (max 3000 chars) |
| `stderr` | string | Raw subprocess stderr (max 1000 chars) |
| `command_executed` | string | Exact command that ran |
| `duration_ms` | int | Wall-clock execution time |

**Exit code semantics:**

| exit_code | Meaning | AI treatment |
|-----------|---------|--------------|
| `0` | Technique succeeded — attack worked | Finding: technique executed successfully |
| `1` | Command ran, OS returned error (key not found, tool unavailable, etc.) | Finding: technique attempted but blocked/failed |
| `5` | Access denied — security control blocked the technique | Finding: defensive control working (e.g., LSASS protection, NTDS access denied) |
| `>0` (other) | OS/app error — command ran but failed | Finding: technique attempted, assess context |
| `-1` | Infrastructure failure — WinRM unreachable, timeout, executor missing | **Not a pentest finding** — exclude from analysis |

> WinRM `access denied` errors (WSManFault code 2147942405) are mapped to `exit_code=5`, not `-1`, so the AI correctly identifies them as security controls rather than infrastructure failures.

> The executor retries once on transient WinRM errors (HTTP 400, RPC unavailable, shell creation failed) before returning `exit_code=-1`.

**Python: access raw results after execution**

```python
async for event in client.stream_execute(job_id):
    if event.type == "execution_complete":
        result_file = event.data["result_file"]  # disk path
        print(f"Raw JSON saved: {result_file}")

# Or fetch via API (no disk access needed):
import httpx
async with httpx.AsyncClient(base_url="http://localhost:8000") as hc:
    r = await hc.get(f"/api/results/{job_id}")
    raw = r.json()  # pure TTP data, no AI
```

---

## WebSocket: Execute

### Connect

```
ws://host:8000/ws/execute/{job_id}
```

No message to send — server starts streaming immediately on connect.

### Events

All events: `{ "type": "...", "data": {...}, "timestamp": "ISO8601" }`

| type | data fields | notes |
|------|-------------|-------|
| `started` | `job_id`, `total`, `targets[]` | Job kicked off |
| `target_start` | `target_id`, `name`, `connection`, `host` | Moving to next target |
| `test_start` | `technique_id`, `test_index`, `test_name`, `target_id`, `target_name`, `skipped`, `skip_reason` | About to run/skip |
| `test_done` | `technique_id`, `test_name`, `target_id`, `target_name`, `success`, `exit_code`, `duration_ms`, `progress`, `stdout_preview` | Completed |
| `skipped` | `technique_id`, `target_id`, `target_name`, `reason`, `progress` | Skipped with reason |
| `job_done` | `job_id`, `total`, `succeeded`, `failed`, `skipped` | All tests done |
| `execution_complete` | `job_id`, `total`, `succeeded`, `failed`, `skipped`, `result_file` | **Final event — close WS here.** `result_file` = absolute disk path to saved JSON (null if disk save failed) |
| `error` | `message` | Fatal error — includes `"already running"` / `"already done"` if same job connected twice |

`progress` format: `"4/10"` (completed/total).

---

## WebSocket: Analyze

### Connect

```
ws://host:8000/ws/analyze/{job_id}
```

The job does **not** need to be in server memory. If the server was restarted after execution, `ws/analyze` automatically loads the raw results from `results/{job_id}.json` on disk.

### Protocol

**Step 1 — Send provider config immediately after connect:**

```json
{
  "job_id": "uuid",
  "provider": {
    "model_id":          "claude-sonnet-4-6",
    "api_key":           "sk-ant-...",
    "base_url":          "",
    "azure_api_base":    "",
    "azure_api_version": ""
  }
}
```

`model_id` must be a key from `GET /api/providers` or a raw LiteLLM model string.

| Scenario | model_id | extra fields |
|----------|----------|--------------|
| Anthropic | `claude-sonnet-4-6` | `api_key: "sk-ant-..."` |
| OpenAI | `gpt-4o` | `api_key: "sk-..."` |
| Azure | `azure-gpt-4o` | `api_key`, `azure_api_base: "https://res.openai.azure.com"`, `azure_api_version: "2024-02-01"` |
| Ollama (local) | `ollama-llama3` | no api_key needed |
| OpenRouter | `openrouter-claude-sonnet` | `api_key: "sk-or-..."` |
| Custom endpoint | `custom` | `base_url: "http://host/v1"`, `api_key: "..."` |

**Step 2 — Receive events:**

| type | data | notes |
|------|------|-------|
| `analysis_start` | `model` | LLM call started |
| `token` | `token` (string) | Stream text chunk |
| `analysis_complete` | `job_id`, `risk_level`, `findings_count`, `report_url`, `error` | **Final — close WS** |
| `error` | `message` | Fatal |

Concatenate all `token` values to get raw JSON response. After `analysis_complete`, call `GET /api/jobs/{id}/analysis` for the parsed report.

---

## Supported Models (model_id values)

Pass the `model_id` key exactly as listed. Use `GET /api/providers` to fetch the live list.

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
| `openrouter-claude-sonnet` | OpenRouter | |
| `openrouter-gpt-4o` | OpenRouter | |
| `openrouter-gemini-pro` | OpenRouter | |
| `openrouter-llama-70b` | OpenRouter | |
| `openrouter-deepseek-r1` | OpenRouter | |
| `openrouter-qwen-72b` | OpenRouter | |
| `custom` | Custom OpenAI-compatible | Set `base_url` in provider config |

---

## Python SDK Quick Start

```python
import asyncio
from pentest_client import PentestClient, Target, TestSelection

async def run():
    async with PentestClient("http://localhost:8000") as c:
        # Define targets
        dc = Target(
            name="DC01",
            target_id="dc01",
            os_platform="windows",
            privilege="admin",
            connection="remote",
            domain_joined=True,
            host="192.168.1.10",
            winrm_username="Administrator",
            winrm_password="Password123!",
            winrm_transport="ntlm",
        )

        # Select techniques (confirmed working, Windows-native)
        selections = [
            TestSelection("T1033", 0),     # whoami (command_prompt)
            TestSelection("T1082", 0),     # systeminfo (command_prompt)
            TestSelection("T1069.002", 0), # domain groups (command_prompt)
            TestSelection("T1087.002", 0), # domain users (command_prompt)
            TestSelection("T1201", 5),     # password policy (command_prompt)
            TestSelection("T1135", 3, {"computer_name": "DC01"}),  # network shares
        ]

        # Create + execute job
        job_id = await c.create_job([dc], selections)
        print(f"Job: {job_id}")

        async for event in c.stream_execute(job_id):
            t, d = event.type, event.data
            if t == "target_start":
                print(f"\n>>> {d['name']}")
            elif t == "test_done":
                print(f"  {'OK' if d['success'] else 'FAIL'} {d['technique_id']} exit={d['exit_code']}")
            elif t == "skipped":
                print(f"  SKIP {d['technique_id']}: {d['reason']}")
            elif t == "execution_complete":
                print(f"\nDone: {d['succeeded']} ok / {d['failed']} fail / {d['skipped']} skip")

        # Get full results
        results = await c.get_results(job_id)
        for tgt_group in results.by_target:
            for r in tgt_group["results"]:
                if r["success"] and r["stdout"]:
                    print(f"\n--- {r['technique_id']} stdout ---")
                    print(r["stdout"][:200])

        # Run AI analysis (streaming)
        print("\n=== AI Analysis ===")
        async for token in c.stream_analyze(
            job_id,
            model_id="claude-sonnet-4-6",
            api_key="sk-ant-...",
        ):
            print(token, end="", flush=True)

        report = await c.get_analysis(job_id)
        print(f"\n\nRisk Level: {report.risk_level.upper()}")
        for f in report.findings:
            print(f"  [{f['severity'].upper()}] {f['technique_id']} — {f['title']}")

asyncio.run(run())
```

---

## JavaScript SDK Quick Start

```javascript
const { PentestClient, makeTarget, makeSelection } = require("./pentest_client");
// In Node.js: const WS = require("ws");
// const client = new PentestClient("http://localhost:8000", WS);

const client = new PentestClient("http://localhost:8000");

const dc = makeTarget({
  name: "DC01",
  target_id: "dc01",
  privilege: "admin",
  connection: "remote",
  domain_joined: true,
  host: "192.168.1.10",
  winrm_username: "Administrator",
  winrm_password: "Password123!",
});

const selections = [
  makeSelection("T1033", 0),
  makeSelection("T1082", 0),
  makeSelection("T1069.002", 0),
  makeSelection("T1087.002", 0),
  makeSelection("T1201", 5),
];

(async () => {
  const jobId = await client.createJob([dc], selections);
  console.log("Job:", jobId);

  for await (const ev of client.streamExecute(jobId)) {
    if (ev.type === "test_done") {
      console.log(`${ev.data.success ? "OK" : "FAIL"} ${ev.data.technique_id}`);
    }
    if (ev.type === "execution_complete") {
      console.log("Done:", ev.data);
    }
  }

  const results = await client.getResults(jobId);
  console.log("Summary:", results.summary);

  // AI analysis
  let fullText = "";
  for await (const token of client.streamAnalyze(jobId, "claude-sonnet-4-6", "sk-ant-...")) {
    process.stdout.write(token);
    fullText += token;
  }
  const report = await client.getAnalysis(jobId);
  console.log("\nRisk:", report.risk_level);
})();
```

---

## AI Agent Integration Pattern

For an AI agent that selects and runs TTPs autonomously:

```python
async def ai_pentest_agent(target_host, target_creds, objective, llm_client):
    async with PentestClient("http://localhost:8000") as pentest:

        # 1. Load available techniques
        tactics = await pentest.list_tactics()

        # 2. Agent selects relevant techniques based on objective
        # (your LLM decides which techniques to run)
        selected = agent_select_techniques(tactics, objective)

        # 3. Build target
        target = Target(
            name=target_host,
            connection="remote",
            privilege="admin",
            domain_joined=True,
            host=target_host,
            **target_creds,
        )

        # 4. Execute
        results = await pentest.run_job([target], selected, on_event=lambda e: ...)

        # 5. Analyze with the same LLM
        report = await pentest.run_full_analysis(...)

        return report
```

---

## Nmap Port Scan + AI Vulnerability Analysis

### Flow

```
1. POST /api/scans                  → scan_id
2. WS   /ws/scan/{id}              → stream scan progress events
3. GET  /api/scans/{id}            → full structured scan result (hosts, ports, banners)
4. POST /api/scans/analyze         → trigger AI vuln analysis   [OPTIONAL]
5. WS   /ws/scan-analyze/{id}      → stream AI vuln report tokens [OPTIONAL]
6. GET  /api/scans/{id}/analysis   → parsed VulnReport            [OPTIONAL]
```

### POST /api/scans

Request:
```json
{
  "target": "192.168.50.162",
  "profile": "ad-top-1000",
  "extra_args": []
}
```

Profiles:
| Profile | Description |
|---------|-------------|
| `top-1000` | Nmap default top 1000 TCP ports with service detection |
| `active-directory` | Common AD/Windows domain service ports (53,88,135,389,445,3389,5985…) |
| `ad-top-1000` | Top 1000 ports + explicit AD ports (default) |
| `full` | All 65535 TCP ports (slow) |

Response:
```json
{
  "scan_id": "<uuid>",
  "status": "running"
}
```

---

### GET /api/scans/{scan_id}

Response:
```json
{
  "scan_id": "<uuid>",
  "target": "192.168.50.162",
  "profile": "ad-top-1000",
  "command": "nmap -Pn -T4 -sV --top-ports 1000 -p 53,88,... -oX - 192.168.50.162",
  "status": "done",
  "start_time": "2026-06-13T10:00:00Z",
  "end_time": "2026-06-13T10:01:30Z",
  "hosts": [
    {
      "host": "192.168.50.162",
      "hostname": "WIN-G4RJOIM66GC",
      "state": "up",
      "os_guess": "",
      "ports": [
        {
          "port": 445,
          "protocol": "tcp",
          "state": "open",
          "service": "microsoft-ds",
          "product": "Windows Server 2019",
          "version": "",
          "extrainfo": "",
          "cpe": ["cpe:/o:microsoft:windows_server_2019"],
          "banner": ""
        }
      ]
    }
  ],
  "error": null
}
```

---

### POST /api/scans/analyze

Request:
```json
{
  "scan_id": "<uuid>",
  "provider": {
    "model_id": "claude-sonnet-4-6",
    "api_key": "sk-ant-..."
  }
}
```

Response: `{ "status": "started", "scan_id": "<uuid>" }`

Then connect to `WS /ws/scan-analyze/{scan_id}` to stream tokens.

---

### WS /ws/scan-analyze/{scan_id}

Streams raw AI text tokens. Final message is a JSON event:
```json
{ "type": "vuln_analysis_complete", "scan_id": "<uuid>" }
```

---

### GET /api/scans/{scan_id}/analysis

Returns parsed `VulnReport`:
```json
{
  "executive_summary": "...",
  "risk_level": "high",
  "attack_surface": "Windows DC with SMB, LDAP, RDP, WinRM exposed",
  "findings": [
    {
      "severity": "high",
      "confidence": "medium",
      "host": "192.168.50.162",
      "port": 445,
      "service": "microsoft-ds",
      "product": "Windows Server 2019",
      "version": "",
      "cve_ids": ["CVE-2020-0796"],
      "title": "SMBGhost — SMBv3 Compression RCE Candidate",
      "detail": "Windows Server 2019 with SMB port 445 open may be affected if unpatched.",
      "evidence": "port 445/tcp open microsoft-ds; cpe:/o:microsoft:windows_server_2019",
      "recommendation": "Apply KB4551762; disable SMBv3 compression if patching is not immediate."
    }
  ],
  "key_observations": [
    "RDP (3389) exposed — brute-force / credential-stuffing surface",
    "WinRM (5985) open — lateral movement risk if credentials are compromised"
  ],
  "timestamp": "2026-06-13T10:02:00Z",
  "error": null
}
```

> **Advisory only** — all findings are candidate hypotheses based on version banners. Validate against the real host before treating as confirmed.

---

## Error Handling

| HTTP | Meaning |
|------|---------|
| 400 | No targets or invalid payload |
| 404 | Job/technique/result not found |
| 500 | Server error |

**WebSocket `error` events:**

| message | Cause | Action |
|---------|-------|--------|
| `"Job {id} not found in memory or on disk"` | job_id never existed or results file missing | Re-run job |
| `"Job {id} already running"` | Second WS connect to same job while it's running | Don't retry — already in progress |
| `"Job {id} already done"` | Execution WS reconnect after completion | Fetch results via `GET /api/results/{id}` instead |
| `"Invalid request: ..."` | Malformed JSON or missing fields on analyze WS | Fix payload |
| `"Provider init failed: ..."` | Invalid model_id or provider config | Check model_id against `GET /api/providers` |

Connection closed without `execution_complete` = abnormal termination. Re-fetch `GET /api/jobs/{id}` to check status. If `status=done`, results are on disk.

**Idempotency note:** `POST /api/jobs` always creates a new job with a new `job_id`. It is not idempotent — do not retry on network failure without checking if the first request succeeded.

---

## Technique Index Reference (Windows-confirmed)

These technique+index combinations are confirmed to work on Windows (local and remote WinRM):

| Technique | Index | Executor | Description |
|-----------|-------|----------|-------------|
| T1033 | 0 | command_prompt | whoami |
| T1033 | 6 | command_prompt | System Owner/User (CMD variant) |
| T1082 | 0 | command_prompt | systeminfo |
| T1057 | 1 | command_prompt | tasklist |
| T1016 | 0 | command_prompt | ipconfig /all |
| T1049 | 0 | command_prompt | netstat -ano + net use |
| T1012 | 0 | command_prompt | reg query (needs admin) |
| T1087.001 | 7 | command_prompt | net user (local accounts) |
| T1087.002 | 0 | command_prompt | net user /domain (domain accounts) |
| T1069.001 | 1 | command_prompt | net localgroup |
| T1069.002 | 0 | command_prompt | domain groups |
| T1201 | 5 | command_prompt | net accounts (password policy) |
| T1135 | 3 | command_prompt | net view (network shares); pass `computer_name` arg |
| T1518 | 0 | command_prompt | reg query IE version (software discovery) |
| T1552.001 | 3 | powershell | findstr passwords in files |
| T1558.003 | 0 | powershell | Kerberoasting (will be AV-blocked on patched DC — expected) |
| T1003.001 | 0 | command_prompt | LSASS dump via ProcDump (AV/access-denied likely — expected) |

**T1135 arg_overrides:** `{ "computer_name": "YOUR-DC-HOSTNAME" }`

> Note: exit_code=1 on T1087.001/T1087.002 is normal DC behavior — stdout still contains user data.
> The AI analyzer handles exit_code=1 with non-empty stdout correctly.
