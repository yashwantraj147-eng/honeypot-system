"""
core/classifier.py
──────────────────
MITRE ATT&CK Heuristic & Regular Expression Categorization Engine.
Analyzes attacker commands, input vectors, credentials, and network payloads
in real time, returning mapped technique identifiers, descriptions, and tactics.
"""

import re
from typing import Dict, List

# MITRE ATT&CK Rule Matrix
# Structure: (technique_id, technique_name, tactic, compiled_regex)
CLASSIFICATION_RULES = [
    (
        "T1110",
        "Brute Force",
        "Credential Access",
        re.compile(
            r"(?i)\b(login|password|passwd|auth|admin|root|user\s+|pass\s+|credentials|"
            r"wp-login|authorization|mirai|hikari|combo|bruteforce)\b|"
            r"^(USER|PASS)\s+"
        )
    ),
    (
        "T1059.004",
        "Command and Scripting Interpreter: Unix Shell",
        "Execution",
        re.compile(
            r"(?i)(\b(sh|bash|zsh|dash|ash|python[0-9.]*|perl|php|ruby|lua)\b|"
            r"chmod\s+(\+x|[0-7]{3,4})|\.sh\b|eval\(|exec\(|echo.*\|\s*(sh|bash)|base64\s+-d)"
        )
    ),
    (
        "T1082",
        "System Information Discovery",
        "Discovery",
        re.compile(
            r"(?i)\b(uname(\s+-[a-zA-Z]+)?|lscpu|hostname|df(\s+-[a-zA-Z]+)?|"
            r"cat\s+/etc/[a-zA-Z0-9_\-\.]*release|uptime|arch|free|"
            r"cat\s+/proc/(version|cpuinfo|meminfo|mounts)|dmesg)\b"
        )
    ),
    (
        "T1087",
        "Account Discovery",
        "Discovery",
        re.compile(
            r"(?i)\b(whoami|id(\s+-[a-zA-Z]+)?|cat\s+/etc/(passwd|shadow|group)|"
            r"\bw\b|\blast\b|\busers\b|cut\s+-d:.*passwd|getent\s+passwd)\b"
        )
    ),
    (
        "T1105",
        "Ingress Tool Transfer",
        "Command and Control",
        re.compile(
            r"(?i)\b(wget|curl|tftp|sftp|scp|nc|netcat|busybox\s+wget|fetch|ftpget|bitsadmin|certutil)\b"
        )
    ),
    (
        "T1070.004",
        "Indicator Removal: File Deletion / Anti-Forensics",
        "Defense Evasion",
        re.compile(
            r"(?i)\b(rm\s+-[a-zA-Z]*[rf][a-zA-Z]*|history\s+-c|unset\s+HISTFILE|"
            r"export\s+HISTFILE=/dev/null|shred\b|truncate\s+-s\s*0|"
            r"rmdir\b|iptables\s+-F|systemctl\s+stop\s+auditd)\b"
        )
    ),
    (
        "T1046",
        "Network Service Discovery",
        "Discovery",
        re.compile(
            r"(?i)\b(netstat|ss(\s+-[a-zA-Z]+)?|nmap|arp(\s+-a)?|route|ip\s+(r|route|a|addr)|"
            r"ifconfig|ping(\s+-[a-zA-Z0-9]+)?|traceroute|nslookup|dig)\b"
        )
    ),
    (
        "T1190",
        "Exploit Public-Facing Application",
        "Initial Access",
        re.compile(
            r"(?i)(\.\./|\.\.\\|/etc/passwd|win\.ini|\.env|actuator/health|config\.json|"
            r"sqlmap|nikto|acunetix|dirbuster|union\s+select|<script|phpinfo\(\))"
        )
    ),
    (
        "T1083",
        "File and Directory Discovery",
        "Discovery",
        re.compile(
            r"(?i)\b(ls(\s+-[a-zA-Z]+)?|dir|pwd|find\s+[\/\.]|locate\b|tree\b)\b"
        )
    ),
]


def classify_payload(payload: str, is_auth: bool = False) -> List[Dict[str, str]]:
    """
    Classify a command, request path, or payload against MITRE ATT&CK techniques.

    Args:
        payload: Command or payload string to evaluate.
        is_auth: Explicit flag if the context represents an authentication attempt.

    Returns:
        List of dictionaries with technique_id, name, and tactic.
    """
    if not payload:
        payload = ""

    payload_clean = payload.strip()
    matches: List[Dict[str, str]] = []
    matched_ids = set()

    if is_auth:
        matches.append({
            "technique_id": "T1110",
            "name": "Brute Force",
            "tactic": "Credential Access"
        })
        matched_ids.add("T1110")

    for technique_id, name, tactic, regex in CLASSIFICATION_RULES:
        if technique_id in matched_ids:
            continue
        if regex.search(payload_clean):
            matches.append({
                "technique_id": technique_id,
                "name": name,
                "tactic": tactic
            })
            matched_ids.add(technique_id)

    # Heuristic fallback for piped or chained shell commands if not yet captured
    if not matches and payload_clean:
        if any(char in payload_clean for char in [";", "|", "&", "`", "$"]):
            matches.append({
                "technique_id": "T1059.004",
                "name": "Command and Scripting Interpreter: Unix Shell",
                "tactic": "Execution"
            })
        else:
            # Generic execution/recon fallback
            matches.append({
                "technique_id": "T1059",
                "name": "Command and Scripting Interpreter",
                "tactic": "Execution"
            })

    return matches

