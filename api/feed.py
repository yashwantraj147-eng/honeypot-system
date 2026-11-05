"""
api/feed.py
───────────
Threat Intelligence Feeds.
Provides consumable plain-text CIDR blocklists for perimeter firewalls
(pfSense, OPNsense, FortiGate, iptables) and OASIS STIX 2.1 JSON bundles for SIEMs.
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
        "# Honeypot-System v2.0 - Autonomous Threat Intelligence Blocklist",
        f"# Sensor Identifier : {settings.SENSOR_NAME}",
        f"# Generated At      : {now_utc}",
        f"# Threshold Filter  : >= {settings.MALICIOUS_IP_THRESHOLD} Malicious Events",
        f"# Total Blocked IPs : {len(ips)}",
        "# Integration       : pfSense, OPNsense, FortiGate, iptables, CrowdSec",
        "# ==========================================================================",
    ]

    for ip in ips:
        # Avoid blocking loopback or private ranges on accident
        if ip not in ("127.0.0.1", "::1", "localhost") and not ip.startswith("10."):
            lines.append(f"{ip}/32")

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

    # Map attack techniques per IP
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

        techniques = ip_techniques.get(ip, ["T1110"])
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

