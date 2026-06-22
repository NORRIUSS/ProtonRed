"""
AI Analyzer — receives deterministic execution results JSON, produces findings + report.
No tool calls, no loops. Single structured prompt → structured JSON output.
"""
import json
from dataclasses import dataclass, field
from datetime import datetime
from typing import AsyncGenerator, Optional

from providers.base import AIProvider, Message

ANALYSIS_SYSTEM_PROMPT = """You are a senior red team operator writing a penetration test findings report. You are direct, decisive, and evidence-driven.

RULES — read carefully:

1. EVIDENCE ONLY — Every finding must cite exact stdout/stderr lines. If you cannot quote output that proves the finding, do not create the finding. No speculation. No "could potentially" or "might be vulnerable". State facts.

2. SEVERITY IS DEFINITIVE — Pick one severity and defend it. Do not hedge. If LSASS memory dumped successfully → CRITICAL. If whoami shows SYSTEM → HIGH. If net user listed domain accounts → MEDIUM. Base severity on actual attacker impact given the target's privilege level.

3. ONLY SUCCESSFUL TESTS GET FINDINGS — Unless a failed test's error output itself reveals information (e.g., "Access denied" reveals the path exists). Skipped tests → never create findings.

4. PRIVILEGE MULTIPLIER — An admin/SYSTEM test success is always one level higher severity than the same test succeeding as a standard user.

5. MULTI-TARGET — Results are grouped by target. Each target has its own privilege, OS, and domain-join status. A finding is per-target: if T1003.001 succeeded on target A but failed on target B, create one finding for A only. Set target_id to the target's ID (from the results).

6. ATTACK PATH — Write the attack path as a real scenario. "Attacker ran X on [target], got Y, can now do Z." Concrete. Based only on what succeeded.

7. NO GENERIC RECOMMENDATIONS — Recommendations must be specific to what was found. "Implement least privilege" is not acceptable. "Remove SeDebugPrivilege from non-admin accounts" is acceptable.

Respond ONLY with this JSON, no text outside it:

{
  "executive_summary": "Direct statement of what was compromised across all targets and what it means. No fluff.",
  "risk_level": "critical|high|medium|low|info",
  "findings": [
    {
      "severity": "critical|high|medium|low|info",
      "technique_id": "T1003.001",
      "tactic": "credential-access",
      "target_id": "tgt-1",
      "title": "LSASS Memory Dumped — Credential Harvest Possible",
      "detail": "Exact statement of what happened, what was exposed, real-world impact.",
      "evidence": "Exact output lines from stdout that prove this finding. Quote verbatim.",
      "recommendation": "Specific, actionable control. References exact setting/policy/tool."
    }
  ],
  "succeeded_techniques": ["T1082", "T1033"],
  "failed_techniques": ["T1003.001"],
  "key_observations": [
    "Concrete observation derived directly from output data"
  ],
  "attack_path": "Step-by-step: Attacker ran X on [target] (exit 0) → output showed Y → can now pivot to Z. Based only on succeeded tests."
}"""


@dataclass
class AnalysisFinding:
    severity: str
    technique_id: str
    tactic: str
    title: str
    detail: str
    evidence: str
    recommendation: str
    target_id: str = ""


@dataclass
class AnalysisReport:
    executive_summary: str
    risk_level: str
    findings: list[AnalysisFinding]
    succeeded_techniques: list[str]
    failed_techniques: list[str]
    key_observations: list[str]
    attack_path: str
    raw_response: str
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    error: Optional[str] = None


def _build_user_message(execution_json: dict) -> str:
    return (
        "Analyze these penetration test execution results and return findings JSON:\n\n"
        "```json\n"
        + json.dumps(execution_json, indent=2)
        + "\n```\n\nReturn ONLY the JSON analysis object."
    )


def parse_analysis_response(response: str) -> AnalysisReport:
    """Parse raw AI text (streamed or not) into AnalysisReport. No API call."""
    raw = response.strip()
    if "```json" in raw:
        raw = raw[raw.find("```json") + 7 :]
        raw = raw[: raw.find("```")].strip() if "```" in raw else raw.strip()
    elif "```" in raw:
        raw = raw[raw.find("```") + 3 :]
        raw = raw[: raw.find("```")].strip() if "```" in raw else raw.strip()

    start = raw.find("{")
    end = raw.rfind("}") + 1
    if start == -1:
        return AnalysisReport(
            executive_summary="Parse failed",
            risk_level="info",
            findings=[],
            succeeded_techniques=[],
            failed_techniques=[],
            key_observations=[],
            attack_path="",
            raw_response=response,
            error="Could not parse JSON from AI response",
        )

    try:
        data = json.loads(raw[start:end])
    except json.JSONDecodeError as e:
        return AnalysisReport(
            executive_summary="Parse failed",
            risk_level="info",
            findings=[],
            succeeded_techniques=[],
            failed_techniques=[],
            key_observations=[],
            attack_path="",
            raw_response=response,
            error=f"JSON parse error: {e}",
        )

    findings = []
    for f in data.get("findings", []):
        findings.append(AnalysisFinding(
            severity=f.get("severity", "info"),
            technique_id=f.get("technique_id", ""),
            tactic=f.get("tactic", ""),
            title=f.get("title", ""),
            detail=f.get("detail", ""),
            evidence=f.get("evidence", ""),
            recommendation=f.get("recommendation", ""),
            target_id=f.get("target_id", ""),
        ))

    return AnalysisReport(
        executive_summary=data.get("executive_summary", ""),
        risk_level=data.get("risk_level", "info"),
        findings=findings,
        succeeded_techniques=data.get("succeeded_techniques", []),
        failed_techniques=data.get("failed_techniques", []),
        key_observations=data.get("key_observations", []),
        attack_path=data.get("attack_path", ""),
        raw_response=response,
    )


async def analyze_results(
    provider: AIProvider,
    execution_json: dict,
) -> AnalysisReport:
    """Non-streaming single-shot analysis. Prefer stream_analysis for live UI."""
    messages = [
        Message(role="system", content=ANALYSIS_SYSTEM_PROMPT),
        Message(role="user", content=_build_user_message(execution_json)),
    ]
    try:
        response = await provider.complete(messages, temperature=0.1, max_tokens=8192)
    except Exception as e:
        return AnalysisReport(
            executive_summary="Analysis failed",
            risk_level="info",
            findings=[],
            succeeded_techniques=[],
            failed_techniques=[],
            key_observations=[],
            attack_path="",
            raw_response="",
            error=str(e),
        )
    return parse_analysis_response(response)


async def stream_analysis(
    provider: AIProvider,
    execution_json: dict,
) -> AsyncGenerator[str, None]:
    """Stream raw AI response tokens for live display."""
    messages = [
        Message(role="system", content=ANALYSIS_SYSTEM_PROMPT),
        Message(role="user", content=_build_user_message(execution_json)),
    ]
    async for token in provider.stream(messages, temperature=0.1, max_tokens=8192):
        yield token
