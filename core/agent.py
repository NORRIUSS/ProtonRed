"""
Autonomous AI pentest agent.
ReAct loop: Think → Act (tool call) → Observe → Repeat.
"""
import asyncio
import json
import platform
import socket
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, AsyncGenerator, Callable, Optional

from config import settings
from core.atomic_engine import AtomicEngine, ExecutionResult
from core.attack_mapper import get_attack_phases_for_objective, get_technique_context
from providers.base import AIProvider, Message

SYSTEM_PROMPT = """You are an autonomous penetration testing AI agent with access to the Atomic Red Team framework.

Your mission: systematically test the target system using available tools, document findings, and produce a comprehensive report.

## Available Tools (call as JSON)

```json
{{"tool": "system_info"}}
{{"tool": "list_techniques", "platform": "windows"}}
{{"tool": "search_techniques", "query": "credential dump"}}
{{"tool": "get_atomics", "technique_id": "T1003"}}
{{"tool": "execute_atomic", "technique_id": "T1003", "test_index": 0, "args": {{}}}}
{{"tool": "cleanup_atomic", "technique_id": "T1003", "test_index": 0}}
{{"tool": "note", "finding": "Found X", "severity": "high", "technique_id": "T1003"}}
{{"tool": "done", "summary": "Pentest complete. Found X issues."}}
```

## Response Format (STRICT JSON)

Always respond with exactly one JSON object:
```json
{{
  "thought": "Your reasoning about current state and next step",
  "tool": "tool_name",
  "args": {{...}},
  "done": false
}}
```

When finished set "done": true and "tool": "done" with a summary in args.

## Rules
- Work systematically through MITRE ATT&CK phases relevant to the objective
- Always start with system_info and discovery techniques
- Analyze execution results before deciding next steps
- If a test fails due to missing permissions, note it and move on
- Do NOT repeat the same test twice
- Prefer tests with supported_platforms matching the current OS
- After each execution, assess what it revealed and adapt your plan
- Maximum {max_iterations} iterations — be efficient
"""


@dataclass
class AgentEvent:
    type: str  # thought | tool_call | tool_result | finding | error | done
    data: Any
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat())


@dataclass
class Finding:
    severity: str  # critical | high | medium | low | info
    technique_id: str
    title: str
    detail: str
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat())


@dataclass
class AgentSession:
    session_id: str
    target: str
    objective: str
    provider_model: str
    status: str = "idle"  # idle | running | done | error
    iterations: int = 0
    findings: list[Finding] = field(default_factory=list)
    events: list[AgentEvent] = field(default_factory=list)
    executed_tests: set = field(default_factory=set)
    start_time: Optional[str] = None
    end_time: Optional[str] = None
    error: Optional[str] = None


class PentestAgent:
    def __init__(
        self,
        provider: AIProvider,
        atomic_engine: AtomicEngine,
        max_iterations: int = None,
        on_event: Optional[Callable[[AgentEvent], None]] = None,
    ):
        self.provider = provider
        self.engine = atomic_engine
        self.max_iterations = max_iterations or settings.MAX_AGENT_ITERATIONS
        self.on_event = on_event
        self._session: Optional[AgentSession] = None
        self._messages: list[Message] = []

    def _emit(self, event: AgentEvent):
        if self._session:
            self._session.events.append(event)
        if self.on_event:
            self.on_event(event)

    async def run(self, target: str, objective: str, session_id: Optional[str] = None) -> AgentSession:
        session = AgentSession(
            session_id=session_id or str(uuid.uuid4()),
            target=target,
            objective=objective,
            provider_model=self.provider.model_id,
            status="running",
            start_time=datetime.utcnow().isoformat(),
        )
        self._session = session
        self._messages = []

        system_content = SYSTEM_PROMPT.format(max_iterations=self.max_iterations)
        self._messages.append(Message(role="system", content=system_content))

        phases = get_attack_phases_for_objective(objective)
        phase_summary = "\n".join(f"- {p.tactic}: {', '.join(p.recommended_techniques[:3])}" for p in phases)

        user_msg = f"""Target: {target}
Objective: {objective}
Platform: {platform.system()} {platform.release()}

Recommended attack phases based on objective:
{phase_summary}

Begin the pentest. Start with system_info."""

        self._messages.append(Message(role="user", content=user_msg))

        for i in range(self.max_iterations):
            session.iterations = i + 1

            try:
                response = await self.provider.complete(self._messages, temperature=0.3, max_tokens=2048)
            except Exception as e:
                session.status = "error"
                session.error = str(e)
                self._emit(AgentEvent(type="error", data={"message": str(e)}))
                break

            parsed = self._parse_response(response)
            if not parsed:
                self._messages.append(Message(role="assistant", content=response))
                self._messages.append(Message(role="user", content='Respond only with valid JSON: {"thought": "...", "tool": "...", "args": {...}, "done": false}'))
                continue

            self._emit(AgentEvent(type="thought", data={"thought": parsed.get("thought", ""), "iteration": i + 1}))
            self._messages.append(Message(role="assistant", content=response))

            if parsed.get("done") or parsed.get("tool") == "done":
                session.status = "done"
                session.end_time = datetime.utcnow().isoformat()
                self._emit(AgentEvent(type="done", data={"summary": parsed.get("args", {}).get("summary", "Complete")}))
                break

            tool_result = await self._dispatch_tool(parsed)
            self._emit(AgentEvent(type="tool_result", data={"tool": parsed.get("tool"), "result": tool_result}))

            self._messages.append(Message(
                role="user",
                content=f"Tool result:\n```json\n{json.dumps(tool_result, indent=2, default=str)}\n```\nContinue. What is your next action?"
            ))

        if session.status == "running":
            session.status = "done"
            session.end_time = datetime.utcnow().isoformat()

        return session

    def _parse_response(self, response: str) -> Optional[dict]:
        response = response.strip()
        # Extract JSON from markdown code blocks if present
        if "```json" in response:
            start = response.find("```json") + 7
            end = response.find("```", start)
            response = response[start:end].strip()
        elif "```" in response:
            start = response.find("```") + 3
            end = response.find("```", start)
            response = response[start:end].strip()

        # Find first { and last }
        start = response.find("{")
        end = response.rfind("}") + 1
        if start == -1 or end == 0:
            return None

        try:
            return json.loads(response[start:end])
        except json.JSONDecodeError:
            return None

    async def _dispatch_tool(self, parsed: dict) -> dict:
        tool = parsed.get("tool", "")
        args = parsed.get("args", {})

        self._emit(AgentEvent(type="tool_call", data={"tool": tool, "args": args}))

        if tool == "system_info":
            return self._get_system_info()

        elif tool == "list_techniques":
            plat = args.get("platform", "windows")
            techniques = self.engine.list_techniques(platform_filter=plat)
            return {"count": len(techniques), "techniques": techniques[:50]}

        elif tool == "search_techniques":
            query = args.get("query", "")
            results = self.engine.search_techniques(query)
            return {"count": len(results), "results": results[:20]}

        elif tool == "get_atomics":
            tid = args.get("technique_id", "")
            technique = self.engine.get_technique(tid)
            if not technique:
                return {"error": f"Technique {tid} not found"}
            return {
                "technique_id": technique.technique_id,
                "display_name": technique.display_name,
                "tests": [
                    {
                        "index": i,
                        "name": t.name,
                        "guid": t.guid,
                        "platforms": t.supported_platforms,
                        "executor": t.executor.name,
                        "elevation_required": t.executor.elevation_required,
                        "description": t.description[:200],
                        "input_arguments": {k: {"default": v.default, "type": v.type} for k, v in t.input_arguments.items()},
                    }
                    for i, t in enumerate(technique.atomic_tests)
                ],
            }

        elif tool == "execute_atomic":
            tid = args.get("technique_id", "")
            test_index = int(args.get("test_index", 0))
            test_args = args.get("args", {})

            test_key = f"{tid}:{test_index}"
            if test_key in self._session.executed_tests:
                return {"skipped": True, "reason": "Already executed this test in this session"}
            self._session.executed_tests.add(test_key)

            result = await self.engine.execute_atomic(tid, test_index, test_args, timeout=60)
            return {
                "technique_id": result.technique_id,
                "test_name": result.test_name,
                "success": result.success,
                "exit_code": result.exit_code,
                "stdout": result.stdout[:2000],
                "stderr": result.stderr[:500],
                "command_executed": result.command_executed[:500],
            }

        elif tool == "cleanup_atomic":
            tid = args.get("technique_id", "")
            test_index = int(args.get("test_index", 0))
            result = await self.engine.cleanup_atomic(tid, test_index)
            return result

        elif tool == "note":
            finding = Finding(
                severity=args.get("severity", "info"),
                technique_id=args.get("technique_id", ""),
                title=args.get("finding", ""),
                detail=args.get("detail", ""),
            )
            self._session.findings.append(finding)
            self._emit(AgentEvent(type="finding", data={
                "severity": finding.severity,
                "technique_id": finding.technique_id,
                "title": finding.title,
            }))
            return {"noted": True, "finding_count": len(self._session.findings)}

        else:
            return {"error": f"Unknown tool: {tool}"}

    def _get_system_info(self) -> dict:
        try:
            hostname = socket.gethostname()
            ip = socket.gethostbyname(hostname)
        except Exception:
            hostname = "unknown"
            ip = "unknown"

        return {
            "hostname": hostname,
            "ip": ip,
            "platform": platform.system(),
            "platform_version": platform.version(),
            "architecture": platform.machine(),
            "python_version": platform.python_version(),
            "atomics_loaded": len(self.engine._cache),
            "atomics_available": self.engine.is_available(),
        }


async def stream_agent_run(
    provider: AIProvider,
    engine: AtomicEngine,
    target: str,
    objective: str,
    max_iterations: int = None,
) -> AsyncGenerator[AgentEvent, None]:
    queue: asyncio.Queue[Optional[AgentEvent]] = asyncio.Queue()

    def on_event(event: AgentEvent):
        queue.put_nowait(event)

    agent = PentestAgent(provider=provider, atomic_engine=engine, max_iterations=max_iterations, on_event=on_event)

    async def run_agent():
        try:
            await agent.run(target=target, objective=objective)
        finally:
            queue.put_nowait(None)

    task = asyncio.create_task(run_agent())

    while True:
        event = await queue.get()
        if event is None:
            break
        yield event

    await task
