"""
Generates pentest reports from agent sessions.
"""
from datetime import datetime
from typing import Optional

from core.agent import AgentSession, Finding


SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
SEVERITY_COLORS = {
    "critical": "#ff0000",
    "high": "#ff4444",
    "medium": "#ff8800",
    "low": "#ffcc00",
    "info": "#00aaff",
}


def generate_html_report(session: AgentSession) -> str:
    findings_html = ""
    sorted_findings = sorted(session.findings, key=lambda f: SEVERITY_ORDER.get(f.severity, 99))

    for f in sorted_findings:
        color = SEVERITY_COLORS.get(f.severity, "#888")
        findings_html += f"""
        <div class="finding">
            <div class="finding-header">
                <span class="severity-badge" style="background:{color}">{f.severity.upper()}</span>
                <span class="technique-id">{f.technique_id}</span>
                <span class="finding-title">{f.title}</span>
            </div>
            {f'<div class="finding-detail">{f.detail}</div>' if f.detail else ''}
            <div class="finding-time">{f.timestamp}</div>
        </div>"""

    if not findings_html:
        findings_html = '<div class="no-findings">No findings recorded</div>'

    counts = {s: 0 for s in SEVERITY_ORDER}
    for f in session.findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1

    summary_badges = "".join(
        f'<span class="count-badge" style="background:{SEVERITY_COLORS[s]}">{counts[s]} {s.upper()}</span>'
        for s in SEVERITY_ORDER if counts.get(s, 0) > 0
    )
    if not summary_badges:
        summary_badges = '<span class="count-badge" style="background:#555">0 FINDINGS</span>'

    duration = ""
    if session.start_time and session.end_time:
        try:
            start = datetime.fromisoformat(session.start_time)
            end = datetime.fromisoformat(session.end_time)
            delta = end - start
            duration = f"{int(delta.total_seconds())}s"
        except Exception:
            pass

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>ProtonRed Report - {session.session_id[:8]}</title>
<style>
  body {{ font-family: 'Courier New', monospace; background: #0a0a0a; color: #e0e0e0; margin: 0; padding: 24px; }}
  h1 {{ color: #00ff88; border-bottom: 1px solid #333; padding-bottom: 12px; }}
  h2 {{ color: #00aaff; margin-top: 32px; }}
  .meta-grid {{ display: grid; grid-template-columns: repeat(2, 1fr); gap: 12px; margin: 16px 0; }}
  .meta-item {{ background: #111; border: 1px solid #222; padding: 12px; border-radius: 4px; }}
  .meta-label {{ color: #888; font-size: 11px; text-transform: uppercase; }}
  .meta-value {{ color: #00ff88; font-size: 14px; margin-top: 4px; }}
  .summary-badges {{ display: flex; gap: 8px; flex-wrap: wrap; margin: 16px 0; }}
  .count-badge {{ padding: 4px 12px; border-radius: 12px; font-size: 12px; font-weight: bold; color: #000; }}
  .finding {{ background: #111; border: 1px solid #222; border-left: 3px solid #444; padding: 16px; margin: 12px 0; border-radius: 4px; }}
  .finding-header {{ display: flex; align-items: center; gap: 12px; flex-wrap: wrap; }}
  .severity-badge {{ padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: bold; color: #000; }}
  .technique-id {{ color: #00aaff; font-size: 12px; }}
  .finding-title {{ color: #e0e0e0; font-weight: bold; }}
  .finding-detail {{ color: #aaa; font-size: 13px; margin-top: 8px; padding-top: 8px; border-top: 1px solid #222; }}
  .finding-time {{ color: #555; font-size: 11px; margin-top: 8px; }}
  .no-findings {{ color: #555; padding: 24px; text-align: center; border: 1px dashed #333; border-radius: 4px; }}
  .status-done {{ color: #00ff88; }}
  .status-error {{ color: #ff4444; }}
  footer {{ margin-top: 48px; color: #333; font-size: 12px; border-top: 1px solid #222; padding-top: 16px; }}
</style>
</head>
<body>
<h1>ProtonRed Report</h1>

<div class="meta-grid">
  <div class="meta-item">
    <div class="meta-label">Session ID</div>
    <div class="meta-value">{session.session_id}</div>
  </div>
  <div class="meta-item">
    <div class="meta-label">Target</div>
    <div class="meta-value">{session.target}</div>
  </div>
  <div class="meta-item">
    <div class="meta-label">Objective</div>
    <div class="meta-value">{session.objective}</div>
  </div>
  <div class="meta-item">
    <div class="meta-label">AI Model</div>
    <div class="meta-value">{session.provider_model}</div>
  </div>
  <div class="meta-item">
    <div class="meta-label">Status</div>
    <div class="meta-value status-{session.status}">{session.status.upper()}</div>
  </div>
  <div class="meta-item">
    <div class="meta-label">Iterations / Duration</div>
    <div class="meta-value">{session.iterations} iterations {f'| {duration}' if duration else ''}</div>
  </div>
  <div class="meta-item">
    <div class="meta-label">Started</div>
    <div class="meta-value">{session.start_time or 'N/A'}</div>
  </div>
  <div class="meta-item">
    <div class="meta-label">Tests Executed</div>
    <div class="meta-value">{len(session.executed_tests)}</div>
  </div>
</div>

<h2>Findings Summary</h2>
<div class="summary-badges">{summary_badges}</div>

<h2>Findings Detail</h2>
{findings_html}

<footer>Generated by ProtonRed Pentest Tool &bull; {datetime.utcnow().isoformat()} UTC</footer>
</body>
</html>"""


def generate_json_report(session: AgentSession) -> dict:
    return {
        "session_id": session.session_id,
        "target": session.target,
        "objective": session.objective,
        "provider_model": session.provider_model,
        "status": session.status,
        "iterations": session.iterations,
        "start_time": session.start_time,
        "end_time": session.end_time,
        "tests_executed": list(session.executed_tests),
        "findings": [
            {
                "severity": f.severity,
                "technique_id": f.technique_id,
                "title": f.title,
                "detail": f.detail,
                "timestamp": f.timestamp,
            }
            for f in session.findings
        ],
        "findings_summary": {
            "critical": sum(1 for f in session.findings if f.severity == "critical"),
            "high": sum(1 for f in session.findings if f.severity == "high"),
            "medium": sum(1 for f in session.findings if f.severity == "medium"),
            "low": sum(1 for f in session.findings if f.severity == "low"),
            "info": sum(1 for f in session.findings if f.severity == "info"),
            "total": len(session.findings),
        },
    }
