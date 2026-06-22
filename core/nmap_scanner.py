"""
Nmap port-scan module - runs nmap against a target and collects structured,
JSON-serializable results for later AI vulnerability analysis.

This is reconnaissance/assessment tooling: it enumerates open ports and the
service/version banners nmap reports. It does NOT exploit anything - the AI
vuln analyzer (core/vuln_analyzer.py) reads the JSON and suggests *candidate*
CVEs/weaknesses that a human must validate. Only scan hosts you are
authorized to test.
"""
import asyncio
import json
import shutil
import uuid
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Callable

from config import settings


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


# Active Directory / Windows domain relevant ports.
AD_PORTS = "53,88,135,139,389,445,464,593,636,3268,3269,3389,5985,5986,9389,49152-49175"

# A profile maps to nmap port/selection flags. Service/version detection (-sV)
# is always enabled so the analyzer has banners to reason about.
SCAN_PROFILES: dict = {
    "top-1000": {
        "description": "Nmap default top 1000 TCP ports with service detection",
        "args": ["-sV", "--top-ports", "1000"],
    },
    "active-directory": {
        "description": "Common Active Directory / Windows domain service ports",
        "args": ["-sV", "-p", AD_PORTS],
    },
    "ad-top-1000": {
        "description": "Top 1000 ports plus explicit AD service ports",
        "args": ["-sV", "--top-ports", "1000", "-p", AD_PORTS],
    },
    "full": {
        "description": "All 65535 TCP ports with service detection (slow)",
        "args": ["-sV", "-p-"],
    },
}

DEFAULT_PROFILE = "ad-top-1000"


@dataclass
class PortResult:
    port: int
    protocol: str
    state: str
    service: str = ""
    product: str = ""
    version: str = ""
    extrainfo: str = ""
    cpe: list = field(default_factory=list)
    banner: str = ""


@dataclass
class HostResult:
    host: str
    hostname: str = ""
    state: str = "unknown"
    os_guess: str = ""
    ports: list = field(default_factory=list)


@dataclass
class ScanResult:
    scan_id: str
    target: str
    profile: str
    command: str
    status: str = "pending"   # pending | running | done | error
    start_time: Optional[str] = None
    end_time: Optional[str] = None
    hosts: list = field(default_factory=list)
    raw_xml: str = ""
    error: Optional[str] = None


def find_nmap() -> Optional[str]:
    """Locate the nmap binary: settings.NMAP_PATH first, then PATH."""
    configured = getattr(settings, "NMAP_PATH", "") or ""
    if configured:
        p = Path(configured)
        if p.exists():
            return str(p)
    return shutil.which("nmap")


def _build_command(nmap_bin: str, target: str, profile: str, extra_args: Optional[list] = None) -> list:
    spec = SCAN_PROFILES.get(profile, SCAN_PROFILES[DEFAULT_PROFILE])
    cmd = [nmap_bin, "-Pn", "-T4", "-sT", "-sC"]
    cmd += spec["args"]
    if extra_args:
        cmd += extra_args
    cmd += ["-oX", "-", target]   # XML to stdout for structured parsing
    return cmd


def parse_nmap_xml(xml_text: str) -> list:
    hosts = []
    if not xml_text.strip():
        return hosts
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return hosts

    for host_el in root.findall("host"):
        addr = ""
        for a in host_el.findall("address"):
            if a.get("addrtype") in ("ipv4", "ipv6"):
                addr = a.get("addr", "")
                break
        if not addr:
            a = host_el.find("address")
            addr = a.get("addr", "") if a is not None else ""

        hostname = ""
        hn = host_el.find("hostnames/hostname")
        if hn is not None:
            hostname = hn.get("name", "")

        status_el = host_el.find("status")
        state = status_el.get("state", "unknown") if status_el is not None else "unknown"

        os_guess = ""
        osmatch = host_el.find("os/osmatch")
        if osmatch is not None:
            os_guess = osmatch.get("name", "")

        host = HostResult(host=addr, hostname=hostname, state=state, os_guess=os_guess)

        for port_el in host_el.findall("ports/port"):
            st = port_el.find("state")
            port_state = st.get("state", "") if st is not None else ""
            svc = port_el.find("service")
            service = product = version = extrainfo = ""
            cpes = []
            if svc is not None:
                service = svc.get("name", "")
                product = svc.get("product", "")
                version = svc.get("version", "")
                extrainfo = svc.get("extrainfo", "")
                cpes = [c.text for c in svc.findall("cpe") if c.text]
            banner_parts = [x for x in (product, version, extrainfo) if x]
            host.ports.append(PortResult(
                port=int(port_el.get("portid", "0") or 0),
                protocol=port_el.get("protocol", "tcp"),
                state=port_state,
                service=service,
                product=product,
                version=version,
                extrainfo=extrainfo,
                cpe=cpes,
                banner=" ".join(banner_parts),
            ))
        hosts.append(host)
    return hosts


def _results_path(scan_id: str) -> Path:
    results_dir = Path(settings.RESULTS_DIR) / "scans"
    results_dir.mkdir(parents=True, exist_ok=True)
    return results_dir / f"{scan_id}.json"


def serialize_scan(scan: ScanResult) -> dict:
    data = asdict(scan)
    data["raw_xml_present"] = bool(data.pop("raw_xml", ""))
    return data


def save_scan(scan: ScanResult) -> Path:
    path = _results_path(scan.scan_id)
    path.write_text(json.dumps(serialize_scan(scan), indent=2), encoding="utf-8")
    return path


def load_scan(scan_id: str) -> Optional[dict]:
    path = _results_path(scan_id)
    if not path.exists():
        return None
    return json.loads(path.read_text(encoding="utf-8"))


async def run_scan(
    target: str,
    profile: str = DEFAULT_PROFILE,
    scan_id: Optional[str] = None,
    extra_args: Optional[list] = None,
    on_event: Optional[Callable] = None,
) -> ScanResult:
    """Run an nmap scan asynchronously and persist the JSON result."""
    scan_id = scan_id or uuid.uuid4().hex
    nmap_bin = find_nmap()

    def emit(ev_type: str, data: dict):
        if on_event:
            on_event({"type": ev_type, "scan_id": scan_id, "timestamp": _now(), **data})

    if not nmap_bin:
        scan = ScanResult(
            scan_id=scan_id, target=target, profile=profile, command="",
            status="error", start_time=_now(), end_time=_now(),
            error="nmap binary not found. Set NMAP_PATH or install nmap and ensure it is on PATH.",
        )
        save_scan(scan)
        emit("error", {"error": scan.error})
        return scan

    cmd = _build_command(nmap_bin, target, profile, extra_args)
    scan = ScanResult(
        scan_id=scan_id, target=target, profile=profile,
        command=" ".join(cmd), status="running", start_time=_now(),
    )
    save_scan(scan)
    emit("started", {"command": scan.command, "profile": profile, "target": target})

    timeout = getattr(settings, "SCAN_TIMEOUT_SECONDS", 600)
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout_b, stderr_b = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        except asyncio.TimeoutError:
            proc.kill()
            await proc.wait()
            scan.status = "error"
            scan.end_time = _now()
            scan.error = f"nmap scan timed out after {timeout}s"
            save_scan(scan)
            emit("error", {"error": scan.error})
            return scan

        xml_text = stdout_b.decode("utf-8", errors="replace")
        stderr_text = stderr_b.decode("utf-8", errors="replace")
        scan.raw_xml = xml_text
        scan.hosts = parse_nmap_xml(xml_text)

        if proc.returncode != 0 and not scan.hosts:
            scan.status = "error"
            scan.error = stderr_text.strip()[:2000] or f"nmap exited with code {proc.returncode}"
        else:
            scan.status = "done"
        scan.end_time = _now()
        save_scan(scan)

        open_ports = sum(1 for h in scan.hosts for p in h.ports if p.state == "open")
        emit("done", {"status": scan.status, "host_count": len(scan.hosts), "open_ports": open_ports})
        return scan
    except Exception as exc:
        scan.status = "error"
        scan.end_time = _now()
        scan.error = f"Scan failed: {exc!r}"
        save_scan(scan)
        emit("error", {"error": scan.error})
        return scan
