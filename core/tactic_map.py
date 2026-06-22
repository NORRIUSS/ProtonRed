"""
Static MITRE ATT&CK tactic → technique mapping.
Used to group techniques in the UI and filter by scope/user context.
"""

TACTIC_GROUPS = [
    {
        "id": "discovery",
        "name": "Discovery",
        "icon": "🔍",
        "techniques": [
            "T1082", "T1033", "T1057", "T1087", "T1087.001", "T1087.002",
            "T1016", "T1016.001", "T1049", "T1135", "T1012", "T1083",
            "T1046", "T1069", "T1069.001", "T1069.002", "T1201", "T1217",
            "T1518", "T1518.001", "T1614", "T1619", "T1526", "T1538",
        ],
    },
    {
        "id": "credential-access",
        "name": "Credential Access",
        "icon": "🔑",
        "techniques": [
            "T1003", "T1003.001", "T1003.002", "T1003.003", "T1003.004",
            "T1003.005", "T1003.007", "T1003.008",
            "T1555", "T1555.001", "T1555.003", "T1555.004", "T1555.005",
            "T1552", "T1552.001", "T1552.002", "T1552.004", "T1552.006",
            "T1056", "T1056.001", "T1539", "T1558", "T1558.001",
            "T1558.003", "T1558.004", "T1110", "T1110.001", "T1110.002",
            "T1110.003", "T1110.004",
        ],
    },
    {
        "id": "persistence",
        "name": "Persistence",
        "icon": "🪝",
        "techniques": [
            "T1053", "T1053.002", "T1053.003", "T1053.005",
            "T1547", "T1547.001", "T1547.004", "T1547.009", "T1547.014",
            "T1543", "T1543.001", "T1543.003",
            "T1546", "T1546.001", "T1546.002", "T1546.003", "T1546.007",
            "T1546.008", "T1546.009", "T1546.010", "T1546.011",
            "T1574", "T1574.001", "T1574.002", "T1574.006", "T1574.007",
            "T1505", "T1505.003",
        ],
    },
    {
        "id": "privilege-escalation",
        "name": "Privilege Escalation",
        "icon": "⬆️",
        "techniques": [
            "T1548", "T1548.001", "T1548.002", "T1548.003", "T1548.004",
            "T1134", "T1134.001", "T1134.002", "T1134.004",
            "T1068", "T1078", "T1078.001", "T1078.002", "T1078.003",
        ],
    },
    {
        "id": "defense-evasion",
        "name": "Defense Evasion",
        "icon": "🛡️",
        "techniques": [
            "T1562", "T1562.001", "T1562.002", "T1562.004", "T1562.006",
            "T1070", "T1070.001", "T1070.003", "T1070.004", "T1070.006",
            "T1036", "T1036.003", "T1036.004", "T1036.005",
            "T1027", "T1027.001", "T1027.002", "T1027.004",
            "T1055", "T1055.001", "T1055.002", "T1055.003", "T1055.004",
            "T1055.012", "T1218", "T1218.001", "T1218.002", "T1218.003",
            "T1218.004", "T1218.005", "T1218.007", "T1218.008",
            "T1218.009", "T1218.010", "T1218.011",
        ],
    },
    {
        "id": "execution",
        "name": "Execution",
        "icon": "⚡",
        "techniques": [
            "T1059", "T1059.001", "T1059.003", "T1059.005",
            "T1059.006", "T1059.007",
            "T1047", "T1053.005", "T1569", "T1569.002",
            "T1204", "T1204.002",
        ],
    },
    {
        "id": "collection",
        "name": "Collection",
        "icon": "📦",
        "techniques": [
            "T1005", "T1039", "T1074", "T1074.001",
            "T1113", "T1114", "T1114.001", "T1115",
            "T1119", "T1213", "T1560", "T1560.001",
        ],
    },
    {
        "id": "exfiltration",
        "name": "Exfiltration",
        "icon": "📤",
        "techniques": [
            "T1041", "T1048", "T1048.001", "T1048.002", "T1048.003",
            "T1567", "T1567.002",
        ],
    },
    {
        "id": "impact",
        "name": "Impact",
        "icon": "💥",
        "techniques": [
            "T1486", "T1489", "T1490", "T1491", "T1491.001",
            "T1498", "T1529", "T1561", "T1561.001", "T1561.002",
        ],
    },
    {
        "id": "command-and-control",
        "name": "Command & Control",
        "icon": "📡",
        "techniques": [
            "T1071", "T1071.001", "T1071.004",
            "T1090", "T1090.001", "T1090.002",
            "T1095", "T1105", "T1571", "T1572",
        ],
    },
]

# Techniques that only work when the target is domain-joined / AD present.
# Per-target: if a target has domain_joined=False these are skipped with a reason
# (the executor enforces this). On domain-joined targets they run normally.
DOMAIN_REQUIRED_TECHNIQUES: frozenset[str] = frozenset({
    "T1558.001",   # Golden Ticket — needs domain DC krbtgt hash
    "T1558.003",   # Kerberoasting — needs domain SPN accounts
    "T1558.004",   # AS-REP Roasting — needs domain
    "T1087.002",   # Domain Account Discovery
    "T1069.002",   # Domain Groups discovery
    "T1003.003",   # NTDS.dit — needs domain controller
    "T1003.005",   # Cached Domain Credentials — needs domain auth
    "T1110.003",   # AD Password Spray
})

# Both scopes require domain membership — tool is designed for domain environments
DOMAIN_SCOPES: frozenset[str] = frozenset({"admin", "domain_user"})

# tactic lookup by technique_id
_TECHNIQUE_TACTIC_MAP: dict[str, str] = {}
for _tg in TACTIC_GROUPS:
    for _tid in _tg["techniques"]:
        _TECHNIQUE_TACTIC_MAP[_tid] = _tg["id"]


def get_tactic_for_technique(technique_id: str) -> str:
    tid = technique_id.upper()
    if tid in _TECHNIQUE_TACTIC_MAP:
        return _TECHNIQUE_TACTIC_MAP[tid]
    
    # Check parent ID if it's a sub-technique (e.g. T1087.001 -> T1087)
    if "." in tid:
        parent_id = tid.split(".")[0]
        if parent_id in _TECHNIQUE_TACTIC_MAP:
            return _TECHNIQUE_TACTIC_MAP[parent_id]
            
    # Try mapping via OBJECTIVE_TECHNIQUE_MAP in attack_mapper
    try:
        from core.attack_mapper import OBJECTIVE_TECHNIQUE_MAP
        for obj_tactic, techniques in OBJECTIVE_TECHNIQUE_MAP.items():
            mapped_tactic = obj_tactic.replace("_", "-").replace("theft", "access")
            if tid in techniques or ("." in tid and tid.split(".")[0] in techniques):
                return mapped_tactic
    except Exception:
        pass

    return "other"


def get_tactic_group(tactic_id: str) -> dict | None:
    for tg in TACTIC_GROUPS:
        if tg["id"] == tactic_id:
            return tg
    return None


# Scope → recommended technique filter
SCOPE_PROFILES = {
    "admin": {
        "label": "Admin / Elevated",
        "description": "Local admin, domain admin, SYSTEM, or elevated service account. Full elevation available.",
        "elevation_required_ok": True,
        "recommended_tactics": ["discovery", "credential-access", "persistence", "privilege-escalation", "defense-evasion", "execution", "collection", "exfiltration"],
        "icon": "👑",
    },
    "domain_user": {
        "label": "Domain User (Standard)",
        "description": "Standard domain member, no local admin, no elevation. Covers low-priv domain service accounts.",
        "elevation_required_ok": False,
        "recommended_tactics": ["discovery", "credential-access", "collection", "defense-evasion", "exfiltration"],
        "icon": "👤",
    },
}
