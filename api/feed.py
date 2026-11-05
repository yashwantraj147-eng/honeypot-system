"""
api/feed.py
───────────
Enterprise Threat Intelligence Pipeline.
Generates consumable feeds:
1. Plain-text CIDR blocklists for perimeter firewalls (pfSense, OPNsense, FortiGate, iptables)
2. OASIS STIX 2.1 JSON bundles for enterprise SIEMs (Splunk, Elastic, Sentinel)
3. Dynamic Snort / Suricata IDS rule signatures
4. OpenCTI / MISP-compatible machine-readable IOC feeds
5. ArcSight Common Event Format (CEF) log exports
"""

import datetime
from typing import Any, Dict, List
import uuid

from fastapi import APIRouter
from fastapi.responses import PlainTextResponse

from core.config import settings
from core.database import get_high_confidence_ips, get_recent_attacks

router = APIRouter(prefix="/api/v1/feed", tags=["Threat Intelligence Feeds"])


@router.get("/firewall.txt", response_class=PlainTextResponse)
async def get_firewall_blocklist() -> PlainTextResponse:
    """
    Plain-text CIDR blocklist (<ip>/32\\n) format.
    Easily ingested as URL Table aliases in pfSense, OPNsense, FortiOS, and iptables.
    """
    ips = await get_high_confidence_ips(threshold=settings.MALICIOUS_IP_THRESHOLD)
    now_utc = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    lines = [
        "# ==========================================================================",
        "# Honeypot-System v2.0 Enterprise Threat Intelligence Blocklist",
        f"# Sensor Identifier : {settings.SENSOR_NAME}",
        f"# Generated At      : {now_utc}",
        f"# Threshold Filter  : >= {settings.MALICIOUS_IP_THRESHOLD} Malicious Events",
        f"# Total Blocked IPs : {len(ips)}",
        "# Integration       : pfSense, OPNsense, FortiGate, iptables, CrowdSec",
        "# ==========================================================================",
    ]

    for ip in ips:
        if ip not in ("127.0.0.1", "::1", "localhost") and not ip.startswith("10."):
            lines.append(f"{ip}/32")

    content = "\n".join(lines) + "\n"
    return PlainTextResponse(content=content, media_type="text/plain; charset=utf-8")


@router.get("/snort.rules", response_class=PlainTextResponse)
async def get_snort_rules() -> PlainTextResponse:
    """
    Auto-generated Snort and Suricata Network Intrusion Detection (NIDS) rule signatures.
    Directly deployable to /etc/snort/rules/honeypot.rules or Suricata rule directories.
    """
    ips = await get_high_confidence_ips(threshold=settings.MALICIOUS_IP_THRESHOLD)
    now_utc = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    lines = [
        f"# Honeypot-System v2.0 - Automated Snort/Suricata Rule Signatures ({now_utc})",
        "# Action: Drop/Alert on high-confidence honeypot probers",
        ""
    ]

    sid_base = 3900000
    for idx, ip in enumerate(ips):
        if ip in ("127.0.0.1", "::1", "localhost"):
            continue
        sid = sid_base + idx
        rule = (
            f"alert ip {ip} any -> $HOME_NET any "
            f"(msg:\"HONEYPOT-DETECTED Known Threat Actor [{ip}]\"; "
            f"reference:url,github.com/yashwantraj147-eng/honeypot-system; "
            f"classtype:trojan-activity; sid:{sid}; rev:1;)"
        )
        lines.append(rule)

    content = "\n".join(lines) + "\n"
    return PlainTextResponse(content=content, media_type="text/plain; charset=utf-8")


@router.get("/iocs.json")
async def get_iocs_feed() -> Dict[str, Any]:
    """
    Structured IOC feed for threat intelligence platforms (MISP, OpenCTI, Cortex XSOAR).
    """
    attacks = await get_recent_attacks(limit=100)
    seen_ips = set()
    indicators = []

    for attack in attacks:
        ip = attack.get("source_ip")
        if not ip or ip in seen_ips:
            continue
        seen_ips.add(ip)

        indicators.append({
            "type": "ipv4-addr",
            "value": ip,
            "reputation": "malicious",
            "threat_actor_fingerprint": attack.get("fingerprint", "Reconnaissance Prober"),
            "risk_score": attack.get("risk_score", 25),
            "severity": attack.get("severity", "LOW"),
            "target_service": attack.get("service"),
            "mitre_technique": attack.get("mitre_technique_id"),
            "mitre_tactic": attack.get("mitre_tactic"),
            "last_seen": attack.get("timestamp"),
            "geolocation": {
                "country": attack.get("geoip_country"),
                "city": attack.get("geoip_city"),
                "lat": attack.get("latitude"),
                "lon": attack.get("longitude")
            }
        })

    return {
        "generator": f"Honeypot-System v2.0 ({settings.SENSOR_NAME})",
        "generated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "total_iocs": len(indicators),
        "iocs": indicators
    }


@router.get("/syslog.cef", response_class=PlainTextResponse)
async def get_cef_syslog_export() -> PlainTextResponse:
    """
    ArcSight Common Event Format (CEF) / RFC 5424 export for enterprise SIEM ingestion.
    """
    attacks = await get_recent_attacks(limit=50)
    lines = []

    for a in attacks:
        # CEF:Version|Device Vendor|Device Product|Device Version|Device Event Class ID|Name|Severity|Extension
        severity_num = 3
        if a.get("severity") == "CRITICAL": severity_num = 10
        elif a.get("severity") == "ELEVATED": severity_num = 7
        elif a.get("severity") == "GUARDED": severity_num = 5

        cef_line = (
            f"CEF:0|Honeypot-System|DeceptionGrid|2.0|{a.get('mitre_technique_id', 'T1059')}|"
            f"{a.get('mitre_name', 'Intrusion Event')}|{severity_num}|"
            f"src={a.get('source_ip')} proto={a.get('service')} "
            f"cs1Label=Fingerprint cs1={a.get('fingerprint', 'Generic')} "
            f"cn1Label=RiskScore cn1={a.get('risk_score', 25)}"
        )
        lines.append(cef_line)

    content = "\n".join(lines) + "\n"
    return PlainTextResponse(content=content, media_type="text/plain; charset=utf-8")


@router.get("/stix.json")
async def get_stix_bundle() -> Dict[str, Any]:
    """
    OASIS STIX 2.1 Standard Compliant Threat Intelligence Bundle.
    Directly consumable by Splunk ES, Elastic Security, Microsoft Sentinel, and OpenCTI.
    """
    ips = await get_high_confidence_ips(threshold=settings.MALICIOUS_IP_THRESHOLD)
    recent = await get_recent_attacks(limit=100)

    ip_techniques: Dict[str, List[str]] = {}
    for attack in recent:
        ip = attack.get("source_ip")
        tech = attack.get("mitre_technique_id")
        if ip and tech:
            if ip not in ip_techniques:
                ip_techniques[ip] = []
            if tech not in ip_techniques[ip]:
                ip_techniques[ip].append(tech)

    now_iso = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    identity_id = f"identity--{uuid.uuid4()}"

    objects: List[Dict[str, Any]] = [
        {
            "type": "identity",
            "spec_version": "2.1",
            "id": identity_id,
            "created": now_iso,
            "modified": now_iso,
            "name": f"Honeypot-System v2.0 ({settings.SENSOR_NAME})",
            "description": "Autonomous Multi-Service Deception Grid & Threat Intelligence Sensor",
            "identity_class": "system"
        }
    ]

    for ip in ips:
        if ip in ("127.0.0.1", "::1", "localhost"):
            continue

        techniques = ip_techniques.get(ip, ["T1110.001"])
        tech_summary = ", ".join(techniques)

        indicator_obj = {
            "type": "indicator",
            "spec_version": "2.1",
            "id": f"indicator--{uuid.uuid4()}",
            "created": now_iso,
            "modified": now_iso,
            "name": f"Malicious Decoy Intruder: {ip}",
            "description": f"Autonomous intrusion detected across decoy services. MITRE ATT&CK: {tech_summary}",
            "indicator_types": ["malicious-activity", "anonymizing"],
            "pattern": f"[ipv4-addr:value = '{ip}']",
            "pattern_type": "stix",
            "pattern_version": "2.1",
            "valid_from": now_iso,
            "confidence": 90,
            "created_by_ref": identity_id,
            "external_references": [
                {
                    "source_name": "mitre-attack",
                    "external_id": tech
                } for tech in techniques
            ]
        }
        objects.append(indicator_obj)

    bundle = {
        "type": "bundle",
        "id": f"bundle--{uuid.uuid4()}",
        "objects": objects
    }
    return bundle
