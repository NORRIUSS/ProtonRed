"""
Maps objectives/targets to MITRE ATT&CK tactics and techniques.
Provides structured knowledge for the AI agent.
"""
from dataclasses import dataclass

TACTIC_ORDER = [
    "reconnaissance",
    "resource-development",
    "initial-access",
    "execution",
    "persistence",
    "privilege-escalation",
    "defense-evasion",
    "credential-access",
    "discovery",
    "lateral-movement",
    "collection",
    "command-and-control",
    "exfiltration",
    "impact",
]

TACTIC_DESCRIPTIONS = {
    "reconnaissance": "Gather info before attacking",
    "resource-development": "Acquire resources for operations",
    "initial-access": "Get into the network",
    "execution": "Run malicious code",
    "persistence": "Maintain foothold",
    "privilege-escalation": "Gain higher permissions",
    "defense-evasion": "Avoid detection",
    "credential-access": "Steal credentials",
    "discovery": "Understand the environment",
    "lateral-movement": "Move through the network",
    "collection": "Gather data of interest",
    "command-and-control": "Communicate with compromised systems",
    "exfiltration": "Steal data",
    "impact": "Disrupt, destroy, or manipulate",
}

# High-value technique clusters by objective
OBJECTIVE_TECHNIQUE_MAP = {
    "credential_theft": [
        "T1003",  # OS Credential Dumping
        "T1555",  # Credentials from Password Stores
        "T1552",  # Unsecured Credentials
        "T1056",  # Input Capture
        "T1539",  # Steal Web Session Cookie
    ],
    "persistence": [
        "T1053",  # Scheduled Task/Job
        "T1547",  # Boot/Logon Autostart Execution
        "T1543",  # Create or Modify System Process
        "T1574",  # Hijack Execution Flow
        "T1505",  # Server Software Component
    ],
    "privilege_escalation": [
        "T1548",  # Abuse Elevation Control Mechanism
        "T1134",  # Access Token Manipulation
        "T1068",  # Exploitation for Privilege Escalation
        "T1078",  # Valid Accounts
    ],
    "discovery": [
        "T1087",  # Account Discovery
        "T1083",  # File and Directory Discovery
        "T1046",  # Network Service Discovery
        "T1135",  # Network Share Discovery
        "T1082",  # System Information Discovery
        "T1016",  # System Network Configuration Discovery
        "T1033",  # System Owner/User Discovery
        "T1057",  # Process Discovery
        "T1012",  # Query Registry
    ],
    "lateral_movement": [
        "T1021",  # Remote Services
        "T1550",  # Use Alternate Authentication Material
        "T1534",  # Internal Spearphishing
        "T1570",  # Lateral Tool Transfer
    ],
    "defense_evasion": [
        "T1562",  # Impair Defenses
        "T1070",  # Indicator Removal
        "T1036",  # Masquerading
        "T1027",  # Obfuscated Files or Information
        "T1055",  # Process Injection
        "T1218",  # System Binary Proxy Execution
    ],
    "exfiltration": [
        "T1041",  # Exfiltration Over C2 Channel
        "T1048",  # Exfiltration Over Alternative Protocol
        "T1567",  # Exfiltration Over Web Service
        "T1052",  # Exfiltration Over Physical Medium
    ],
    "impact": [
        "T1486",  # Data Encrypted for Impact (ransomware)
        "T1490",  # Inhibit System Recovery
        "T1489",  # Service Stop
        "T1561",  # Disk Wipe
    ],
}

# Platform-specific common tests for quick wins
WINDOWS_QUICKWIN_TECHNIQUES = [
    "T1082",  # System Information Discovery
    "T1033",  # System Owner/User Discovery
    "T1057",  # Process Discovery
    "T1087",  # Account Discovery
    "T1012",  # Query Registry
    "T1016",  # System Network Configuration Discovery
    "T1049",  # System Network Connections Discovery
    "T1135",  # Network Share Discovery
]


@dataclass
class AttackPhase:
    tactic: str
    description: str
    recommended_techniques: list[str]
    priority: int


def get_attack_phases_for_objective(objective: str) -> list[AttackPhase]:
    obj_lower = objective.lower()
    phases = []

    # Always start with discovery
    phases.append(AttackPhase(
        tactic="discovery",
        description=TACTIC_DESCRIPTIONS["discovery"],
        recommended_techniques=OBJECTIVE_TECHNIQUE_MAP["discovery"],
        priority=1,
    ))

    if any(w in obj_lower for w in ["password", "credential", "hash", "ntlm", "kerberos", "dump"]):
        phases.append(AttackPhase(
            tactic="credential-access",
            description=TACTIC_DESCRIPTIONS["credential-access"],
            recommended_techniques=OBJECTIVE_TECHNIQUE_MAP["credential_theft"],
            priority=2,
        ))

    if any(w in obj_lower for w in ["persist", "backdoor", "startup", "boot", "service"]):
        phases.append(AttackPhase(
            tactic="persistence",
            description=TACTIC_DESCRIPTIONS["persistence"],
            recommended_techniques=OBJECTIVE_TECHNIQUE_MAP["persistence"],
            priority=3,
        ))

    if any(w in obj_lower for w in ["privilege", "admin", "root", "escalat", "uac"]):
        phases.append(AttackPhase(
            tactic="privilege-escalation",
            description=TACTIC_DESCRIPTIONS["privilege-escalation"],
            recommended_techniques=OBJECTIVE_TECHNIQUE_MAP["privilege_escalation"],
            priority=4,
        ))

    if any(w in obj_lower for w in ["lateral", "spread", "move", "network", "remote"]):
        phases.append(AttackPhase(
            tactic="lateral-movement",
            description=TACTIC_DESCRIPTIONS["lateral-movement"],
            recommended_techniques=OBJECTIVE_TECHNIQUE_MAP["lateral_movement"],
            priority=5,
        ))

    if any(w in obj_lower for w in ["evad", "bypass", "defense", "antivirus", "av", "edr"]):
        phases.append(AttackPhase(
            tactic="defense-evasion",
            description=TACTIC_DESCRIPTIONS["defense-evasion"],
            recommended_techniques=OBJECTIVE_TECHNIQUE_MAP["defense_evasion"],
            priority=6,
        ))

    if any(w in obj_lower for w in ["exfil", "steal", "data", "upload", "transfer"]):
        phases.append(AttackPhase(
            tactic="exfiltration",
            description=TACTIC_DESCRIPTIONS["exfiltration"],
            recommended_techniques=OBJECTIVE_TECHNIQUE_MAP["exfiltration"],
            priority=7,
        ))

    if any(w in obj_lower for w in ["impact", "ransomware", "destroy", "wipe", "disrupt"]):
        phases.append(AttackPhase(
            tactic="impact",
            description=TACTIC_DESCRIPTIONS["impact"],
            recommended_techniques=OBJECTIVE_TECHNIQUE_MAP["impact"],
            priority=8,
        ))

    # If no specific objective detected, do full assessment
    if len(phases) == 1:
        for tactic in ["credential-access", "persistence", "privilege-escalation", "defense-evasion"]:
            obj_key = tactic.replace("-", "_").replace("access", "theft")
            if obj_key in OBJECTIVE_TECHNIQUE_MAP:
                phases.append(AttackPhase(
                    tactic=tactic,
                    description=TACTIC_DESCRIPTIONS[tactic],
                    recommended_techniques=OBJECTIVE_TECHNIQUE_MAP.get(obj_key, []),
                    priority=len(phases) + 1,
                ))

    return sorted(phases, key=lambda p: p.priority)


def get_technique_context(technique_id: str) -> dict:
    """Return MITRE context for a technique ID."""
    tid = technique_id.upper()
    for obj, techniques in OBJECTIVE_TECHNIQUE_MAP.items():
        if tid in techniques:
            return {
                "technique_id": tid,
                "objective_category": obj,
                "related_techniques": [t for t in techniques if t != tid],
            }
    return {"technique_id": tid, "objective_category": "unknown", "related_techniques": []}
