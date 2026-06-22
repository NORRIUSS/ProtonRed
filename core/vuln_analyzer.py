"""
AI vulnerability analyzer - reads the JSON produced by core/nmap_scanner and
asks an LLM to surface *candidate* CVEs / weaknesses from the detected
services and version banners.

IMPORTANT: output is advisory only. The model proposes possible issues based
on product/version/CPE strings; every finding must be validated by a human
against the real host before it is treated as a confirmed vulnerability.
"""
import json
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import AsyncGenerator, Optional

from providers.base import AIProvider, Message


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


VULN_SYSTEM_PROMPT = """You are a vulnerability assessment assistant for AUTHORIZED penetration testing.
You are given JSON output from an nmap service/version scan (open ports, service names, products, versions, CPEs).

Your job: identify SPECIFIC, VERIFIABLE vulnerabilities by matching exact product+version strings to known CVEs.

CRITICAL RULES — violations produce false positives:
- NEVER flag a service as vulnerable simply because the port is open. An open port is NOT a vulnerability.
- NEVER say \"The exact version is not provided, but the service is running...\" and then guess at CVEs. If you don't have a specific version, report it as an observation ONLY with severity \"info\".
- NEVER flag standard Windows infrastructure services (Kerberos/88, LDAP/389, RPC/135, NetBIOS/139, SMB/445, WinRM/5985-5986) as vulnerable without a SPECIFIC version-matched CVE. These are expected on a Domain Controller.
- Microsoft HTTPAPI httpd 2.0 on port 5985/5986 is the STANDARD WinRM HTTP listener on modern Windows Server (2016/2019/2022). It is NOT an obsolete HTTP server. Do NOT flag it.
- Verify service identification against context: if the host is clearly a Windows Domain Controller (Kerberos/88, LDAP/389, DNS/53), then DNS on port 53 is almost certainly native Microsoft DNS, not third-party software like \"Simple DNS Plus\" — even if nmap's banner heuristic suggests otherwise.
- Base findings ONLY on the evidence in the scan (product, version, cpe, banner). Do not invent services that are not present.
- ONLY report findings where you can cite a SPECIFIC CVE ID matching the EXACT product AND version detected. Otherwise use severity \"info\".
- Set confidence \"high\" ONLY when exact product+version matches a known CVE. \"medium\" when product matches but version is approximate. NEVER \"high\" without version evidence.
- Limit findings to a maximum of 10 most critical/relevant issues. Quality over quantity.
- Do NOT provide exploit code, payloads, or step-by-step exploitation. Recommendations must be defensive (patch/upgrade/harden/validate).
- If a port is open but the service/version is unknown, note it as an observation, not a CVE.

Return ONLY a JSON object with this shape:
{
  \"executive_summary\": \"...\",
  \"risk_level\": \"critical|high|medium|low|info\",
  \"attack_surface\": \"short description of exposed surface\",
  \"findings\": [
    {
      \"severity\": \"critical|high|medium|low|info\",
      \"confidence\": \"high|medium|low\",
      \"host\": \"\",
      \"port\": 0,
      \"service\": \"\",
      \"product\": \"\",
      \"version\": \"\",
      \"cve_ids\": [\"CVE-YYYY-NNNNN\"],
      \"title\": \"\",
      \"detail\": \"why this version is likely affected\",
      \"evidence\": \"the exact banner/cpe/version that supports this\",
      \"recommendation\": \"defensive remediation\"
    }
  ],
  \"key_observations\": [\"...\"]
}
"""


@dataclass
class VulnFinding:
    severity: str = "info"
    confidence: str = "low"
    host: str = ""
    port: int = 0
    service: str = ""
    product: str = ""
    version: str = ""
    cve_ids: list = field(default_factory=list)
    title: str = ""
    detail: str = ""
    evidence: str = ""
    recommendation: str = ""


@dataclass
class VulnReport:
    executive_summary: str = ""
    risk_level: str = "info"
    attack_surface: str = ""
    findings: list = field(default_factory=list)
    key_observations: list = field(default_factory=list)
    raw_response: str = ""
    timestamp: str = field(default_factory=_now)
    error: Optional[str] = None

    def to_dict(self) -> dict:
        return asdict(self)


def _build_user_message(scan_json: dict) -> str:
    return (
        "Analyze this nmap scan result and return candidate-vulnerability JSON:\n\n"
        "```json\n"
        + json.dumps(scan_json, indent=2)
        + "\n```\n\nReturn ONLY the JSON analysis object."
    )


def _extract_json(response: str) -> Optional[str]:
    raw = (response or "").strip()
    if "```json" in raw:
        raw = raw[raw.find("```json") + 7 :]
        raw = raw[: raw.find("```")].strip() if "```" in raw else raw.strip()
    elif "```" in raw:
        raw = raw[raw.find("```") + 3 :]
        raw = raw[: raw.find("```")].strip() if "```" in raw else raw.strip()
    start = raw.find("{")
    end = raw.rfind("}") + 1
    if start == -1 or end <= start:
        return None
    return raw[start:end]


def parse_vuln_response(response: str) -> VulnReport:
    """Parse raw AI text into a VulnReport. No API call."""
    blob = _extract_json(response)
    if blob is None:
        return VulnReport(
            executive_summary="Parse failed",
            raw_response=response,
            error="Could not locate JSON object in AI response",
        )
    try:
        data = json.loads(blob)
    except json.JSONDecodeError as e:
        return VulnReport(
            executive_summary="Parse failed",
            raw_response=response,
            error=f"JSON parse error: {e}",
        )

    findings = []
    for f in data.get("findings", []):
        cve_ids = f.get("cve_ids", []) or []
        if isinstance(cve_ids, str):
            cve_ids = [cve_ids]
        try:
            port = int(f.get("port", 0) or 0)
        except (TypeError, ValueError):
            port = 0
        findings.append(VulnFinding(
            severity=f.get("severity", "info"),
            confidence=f.get("confidence", "low"),
            host=f.get("host", ""),
            port=port,
            service=f.get("service", ""),
            product=f.get("product", ""),
            version=f.get("version", ""),
            cve_ids=cve_ids,
            title=f.get("title", ""),
            detail=f.get("detail", ""),
            evidence=f.get("evidence", ""),
            recommendation=f.get("recommendation", ""),
        ))

    return VulnReport(
        executive_summary=data.get("executive_summary", ""),
        risk_level=data.get("risk_level", "info"),
        attack_surface=data.get("attack_surface", ""),
        findings=findings,
        key_observations=data.get("key_observations", []),
        raw_response=response,
    )


async def analyze_scan(provider: AIProvider, scan_json: dict) -> VulnReport:
    """Non-streaming single-shot scan analysis."""
    messages = [
        Message(role="system", content=VULN_SYSTEM_PROMPT),
        Message(role="user", content=_build_user_message(scan_json)),
    ]
    try:
        response = await provider.complete(messages, temperature=0.1, max_tokens=8192)
    except Exception as e:
        return VulnReport(executive_summary="Analysis failed", raw_response="", error=str(e))
    return parse_vuln_response(response)


async def stream_scan_analysis(provider: AIProvider, scan_json: dict) -> AsyncGenerator:
    """Stream raw AI tokens for live display. Parse with parse_vuln_response after."""
    messages = [
        Message(role="system", content=VULN_SYSTEM_PROMPT),
        Message(role="user", content=_build_user_message(scan_json)),
    ]
    async for token in provider.stream(messages, temperature=0.1, max_tokens=8192):
        yield token
