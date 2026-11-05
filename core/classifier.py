"""
core/classifier.py
──────────────────
Enterprise MITRE ATT&CK (v14.1) Categorization, Threat Actor Profiling,
Automated IOC Extraction, and Dynamic Risk Scoring Engine.
"""

import ipaddress
import re
from typing import Any, Dict, List, Optional, Tuple

# Comprehensive MITRE ATT&CK Rules with Sub-Techniques
CLASSIFICATION_RULES = [
    (
        "T1110.001",
        "Password Guessing (Brute Force)",
        "Credential Access",
        re.compile(
            r"(?i)\b(login|password|passwd|auth|admin|root|user\s+|pass\s+|credentials|"
            r"authorization|combo|bruteforce|admin:admin|root:root)\b|"
            r"^(USER|PASS)\s+"
        )
    ),
    (
        "T1110.003",
        "Password Spraying (Botnet Combos)",
        "Credential Access",
        re.compile(
            r"(?i)\b(xc3511|vizxv|7ujMko0vizxv|888888|default|support|guest|hikari|mirai)\b"
        )
    ),
    (
        "T1059.004",
        "Unix Shell Execution",
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
        "T1087.001",
        "Local Account Discovery",
        "Discovery",
        re.compile(
            r"(?i)\b(whoami|id(\s+-[a-zA-Z]+)?|cat\s+/etc/(passwd|shadow|group)|"
            r"\bw\b|\blast\b|\busers\b|cut\s+-d:.*passwd|getent\s+passwd)\b"
        )
    ),
    (
        "T1105",
        "Ingress Tool Transfer (Malware Dropper)",
        "Command and Control",
        re.compile(
            r"(?i)\b(wget|curl|tftp|sftp|scp|nc|netcat|busybox\s+wget|fetch|ftpget|bitsadmin|certutil)\b"
        )
    ),
    (
        "T1070.004",
        "Indicator Removal: File Deletion",
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
            r"sqlmap|nikto|acunetix|dirbuster|union\s+select|<script|phpinfo\(\)|"
            r"\$\{jndi:(ldap|rmi|dns|corba):|xmlrpc\.php)"
        )
    ),
    (
        "T1552.001",
        "Credentials in Files",
        "Credential Access",
        re.compile(
            r"(?i)(\.env|\.aws/credentials|id_rsa|id_ed25519|\.pgpass|\.git-credentials|"
            r"wp-config\.php|web\.config|database\.yml)"
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
    (
        "T1499",
        "Endpoint Denial of Service",
        "Impact",
        re.compile(
            r"(?i)(:(){ :\|:& };:|fork\s+bomb|dd\s+if=/dev/zero|yes\s+>)"
        )
    ),
]

# Signature heuristics for Botnet & Recon Tool Fingerprinting
BOTNET_SIGNATURES = [
    ("Mirai IoT Botnet", re.compile(r"(?i)(xc3511|vizxv|busybox\s+wget|/bin/busybox)")),
    ("Gafgyt / BASHLITE", re.compile(r"(?i)(echo.*gayfgt|cat /proc/mounts; /bin/busybox)")),
    ("Log4j / Log4Shell Weaponization", re.compile(r"(?i)\$\{jndi:(ldap|rmi|dns)://")),
    ("Mass Vulnerability Scanner (Nikto/SQLMap)", re.compile(r"(?i)(nikto|sqlmap|acunetix|wpscan|masscan)")),
    ("Web Exploitation Prober (Directory Traversal)", re.compile(r"(\.\./\.\./|%2e%2e%2f|/etc/passwd)")),
    ("Spring4Shell / Actuator Recon", re.compile(r"(?i)actuator/(health|env|gateway)")),
    ("WordPress Exploit Scanner", re.compile(r"(?i)(wp-login\.php|xmlrpc\.php|wp-content)")),
]

# RegEx for Automated IOC Harvesting
URL_REGEX = re.compile(r"(?i)\b(?:https?|ldap|rmi|ftp)://[^\s<>\"'{}|\\^`\[\]]+")
IP_REGEX = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def classify_payload(payload: str, is_auth: bool = False) -> List[Dict[str, str]]:
    """
    Classify command, request path, or network payload against MITRE ATT&CK techniques.
    """
    if not payload:
        payload = ""

    payload_clean = payload.strip()
    matches: List[Dict[str, str]] = []
    matched_ids = set()

    if is_auth:
        matches.append({
            "technique_id": "T1110.001",
            "name": "Password Guessing (Brute Force)",
            "tactic": "Credential Access"
        })
        matched_ids.add("T1110.001")

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

    # Heuristic fallback for piped commands
    if not matches and payload_clean:
        if any(char in payload_clean for char in [";", "|", "&", "`", "$"]):
            matches.append({
                "technique_id": "T1059.004",
                "name": "Unix Shell Execution",
                "tactic": "Execution"
            })
        else:
            matches.append({
                "technique_id": "T1059",
                "name": "Command and Scripting Interpreter",
                "tactic": "Execution"
            })

    return matches


def profile_threat_actor(service: str, payload: str, credentials: Optional[str] = None) -> Dict[str, Any]:
    """
    Generate deep threat actor profile, fingerprint, confidence risk score (0-100),
    and extract IOCs from attacker activities.
    """
    text_corpus = f"{service} {payload or ''} {credentials or ''}"
    
    # 1. Identify Botnet / Tool Fingerprint
    detected_fingerprint = "Generic Reconnaissance Probe"
    for name, regex in BOTNET_SIGNATURES:
        if regex.search(text_corpus):
            detected_fingerprint = name
            break

    # 2. Extract IOCs
    iocs: Dict[str, List[str]] = {"urls": [], "ips": []}
    for url in URL_REGEX.findall(text_corpus):
        # Defang URL for safety: hxxp://...
        defanged = url.replace("http://", "hxxp://").replace("https://", "hxxps://")
        if defanged not in iocs["urls"]:
            iocs["urls"].append(defanged)

    for ip in IP_REGEX.findall(text_corpus):
        try:
            ip_obj = ipaddress.ip_address(ip)
            if not ip_obj.is_private and not ip_obj.is_loopback:
                if ip not in iocs["ips"]:
                    iocs["ips"].append(ip)
        except ValueError:
            pass

    # 3. Calculate Threat Risk Score (0-100)
    risk_score = 25  # Base score for any unsolicited prober
    
    # Severity adjustments based on targeted vector & payload malice
    if detected_fingerprint != "Generic Reconnaissance Probe":
        risk_score += 25
    if credentials:
        risk_score += 20
    if re.search(r"(?i)\b(wget|curl|busybox|chmod|\.sh|rm\s+-rf)\b", text_corpus):
        risk_score += 25
    if re.search(r"(?i)\$\{jndi:", text_corpus):
        risk_score += 35
    if service.upper() == "SSH":
        risk_score += 15

    risk_score = min(100, max(10, risk_score))

    if risk_score >= 80:
        severity = "CRITICAL"
        severity_color = "#ef4444"
    elif risk_score >= 60:
        severity = "ELEVATED"
        severity_color = "#f97316"
    elif risk_score >= 40:
        severity = "GUARDED"
        severity_color = "#eab308"
    else:
        severity = "LOW"
        severity_color = "#06b6d4"

    return {
        "fingerprint": detected_fingerprint,
        "risk_score": risk_score,
        "severity": severity,
        "severity_color": severity_color,
        "iocs": iocs,
    }
