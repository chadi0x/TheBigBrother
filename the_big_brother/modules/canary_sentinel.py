"""
CANARY SENTINEL — Tracking Token & Webhook Beacon Generator (Module #31)
Investigator trap generator for adversary de-anonymization, leak detection, and document tracking.
Generates forensic tracking tokens (zero-pixel transparent Web bugs, poisoned PDF/DOCX DNS beacons, and unique canary URLs).
Maintains an in-memory trigger log recording requester IP, User-Agent, and timestamps.
"""
import uuid
import datetime
from typing import Dict, Any, List

# In-memory token registry and trigger telemetry
CANARY_REGISTRY: Dict[str, Dict[str, Any]] = {}
CANARY_LOGS: List[Dict[str, Any]] = []

def generate_canary_token(label: str, token_type: str = "web_bug", host_url: str = "http://localhost:8000") -> Dict[str, Any]:
    token_id = str(uuid.uuid4())[:8]
    now_str = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    
    tracking_url = f"{host_url}/api/canary/track/{token_id}"
    dns_beacon = f"c-{token_id}.canary.thebigbrother.cloud"
    
    token_data = {
        "status": "success",
        "token_id": token_id,
        "label": label,
        "type": token_type,
        "created_at": now_str,
        "tracking_url": tracking_url,
        "dns_beacon": dns_beacon,
        "trigger_count": 0,
        "payload_snippet": "",
        "stealth_rating": "MIL_SPEC_TRANSPARENT",
        "threat_score": 0
    }
    
    if token_type == "web_bug":
        token_data["payload_snippet"] = f'<img src="{tracking_url}" width="1" height="1" style="display:none;" alt="" />'
    elif token_type == "redirect":
        token_data["payload_snippet"] = f'{tracking_url}?target=https://legitimate-redirect.com'
    elif token_type == "docx_beacon":
        token_data["payload_snippet"] = f'Add relation in word/_rels/document.xml.rels targeting: {tracking_url}'
    elif token_type == "dns_token":
        token_data["payload_snippet"] = f'dig +short {dns_beacon}'
    else:
        token_data["payload_snippet"] = tracking_url

    CANARY_REGISTRY[token_id] = token_data
    return token_data

def record_canary_hit(token_id: str, client_ip: str, user_agent: str, referer: str = "") -> Dict[str, Any]:
    now_str = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    token_info = CANARY_REGISTRY.get(token_id, {"label": "Unknown / Ephemeral", "type": "generic"})
    
    if token_id in CANARY_REGISTRY:
        CANARY_REGISTRY[token_id]["trigger_count"] += 1
        
    hit_entry = {
        "timestamp": now_str,
        "token_id": token_id,
        "label": token_info.get("label"),
        "type": token_info.get("type"),
        "client_ip": client_ip,
        "user_agent": user_agent,
        "referer": referer or "Direct / Image Render",
        "location_estimate": "Estimated Autonomous System (Direct Query)",
        "alert_level": "TRIGGERED"
    }
    CANARY_LOGS.insert(0, hit_entry)
    return hit_entry

def get_all_canaries() -> List[Dict[str, Any]]:
    return list(CANARY_REGISTRY.values())

def get_canary_logs() -> List[Dict[str, Any]]:
    return CANARY_LOGS
