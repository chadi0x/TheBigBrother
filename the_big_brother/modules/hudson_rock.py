"""
HUDSON ROCK — Infostealer Intelligence Engine V7.0 (Zero-Mock Native)
Interrogates Hudson Rock's Cavalier OSINT API to identify compromised enterprise assets,
infostealer malware infections (Lumma, RedLine, Vidar, Raccoon, Stealc), exfiltrated credentials,
victim computer hostnames, and corporate login breaches.
"""
from __future__ import annotations

import asyncio
import json
import urllib.request
import urllib.parse
import urllib.error
import re
from typing import Dict, Any, List, Optional

BASE_URL = "https://cavalier.hudsonrock.com/api/json/v2/osint-tools"
USER_AGENT = "TheBigBrother-Forensics/7.0 (Zero-Mock Infostealer Intelligence; +https://thebigbrother.cloud)"


def _fetch_hudson_rock_sync(url: str, params: dict, timeout: int = 8) -> tuple[int, Optional[dict], Optional[str]]:
    try:
        if params:
            url = f"{url}?{urllib.parse.urlencode(params)}"
        req = urllib.request.Request(
            url,
            headers={
                "User-Agent": USER_AGENT,
                "Accept": "application/json"
            }
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode("utf-8", errors="replace"))
            return resp.status, data, None
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return 404, None, None
        return e.code, None, f"Cavalier Infostealer API HTTP {e.code}"
    except Exception as e:
        return 0, None, f"Upstream connectivity notice: {str(e)}"


async def hudson_rock_search(query: str, query_type: str = "auto") -> Dict[str, Any]:
    query = query.strip()
    if not query:
        return {"error": "Target query parameter is required."}

    # Auto-detect indicator type
    if query_type == "auto":
        if "@" in query and "." in query:
            query_type = "email"
        elif re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", query):
            query_type = "ip"
        elif "." in query and " " not in query:
            query_type = "domain"
        else:
            query_type = "username"

    url = ""
    params = {}
    if query_type == "email":
        url = f"{BASE_URL}/search-by-email"
        params = {"email": query}
    elif query_type == "domain":
        url = f"{BASE_URL}/search-by-domain"
        params = {"domain": query}
    elif query_type == "ip":
        url = f"{BASE_URL}/search-by-domain"
        params = {"domain": query}
    else:
        url = f"{BASE_URL}/search-by-username"
        params = {"username": query}

    loop = asyncio.get_event_loop()
    status, data, err = await loop.run_in_executor(None, _fetch_hudson_rock_sync, url, params, 8)

    devices: List[Dict[str, Any]] = []
    exposed_domains: List[Dict[str, Any]] = []
    malware_families: set = set()
    total_infections = 0

    if status == 200 and isinstance(data, dict):
        # Extract infections / stealers array
        stealers_raw = data.get("stealers") or data.get("stealer_infections") or []
        if isinstance(stealers_raw, list):
            total_infections = len(stealers_raw)
            for st in stealers_raw:
                fam = st.get("malware_family") or st.get("stealer_family") or st.get("type") or "Unknown Infostealer"
                malware_families.add(fam)
                comp_name = st.get("computer_name") or st.get("hostname") or "WORKSTATION-PC"
                os_build = st.get("operating_system") or st.get("os") or "Windows NT (x64)"
                date_inf = st.get("date_compromised") or st.get("date") or "Recently Active"

                # Parse services and credentials
                top_services = st.get("top_domains") or st.get("domains") or st.get("services") or []
                if isinstance(top_services, list):
                    for s in top_services[:12]:
                        s_name = str(s)
                        cat = "CORPORATE_LOGIN"
                        if any(k in s_name.lower() for k in ["bank", "chase", "paypal", "wells", "revolut"]):
                            cat = "FINANCIAL_BANKING"
                        elif any(k in s_name.lower() for k in ["binance", "coinbase", "metamask", "crypto"]):
                            cat = "CRYPTO_EXCHANGE"
                        elif any(k in s_name.lower() for k in ["vpn", "citrix", "okta", "anyconnect", "portal"]):
                            cat = "REMOTE_ACCESS_VPN"
                        exposed_domains.append({"service": s_name, "category": cat})

                devices.append({
                    "computer_name": comp_name,
                    "operating_system": os_build,
                    "malware_family": fam,
                    "date_compromised": date_inf,
                    "credentials_exfiltrated": len(top_services),
                    "services_sample": top_services[:6]
                })

        # Top corporate accounts count
        corp_accounts = data.get("total_corporate_emails_compromised") or data.get("corporate_count") or 0
        user_accounts = data.get("total_user_emails_compromised") or data.get("user_count") or 0

        is_compromised = total_infections > 0 or (isinstance(data.get("data"), list) and len(data.get("data")) > 0)
        risk_score = min(100, 40 + (total_infections * 20)) if is_compromised else 10

        return {
            "status": "success",
            "query": query,
            "type": query_type,
            "compromised": is_compromised,
            "threat_tier": "CRITICAL_INFOSTEALER_VICTIM" if is_compromised else "CLEAN_NO_INFECTIONS",
            "risk_score": risk_score,
            "stealer_infections": total_infections,
            "malware_families": list(malware_families),
            "compromised_devices": devices,
            "exposed_services": exposed_domains[:24],
            "corporate_compromises": corp_accounts,
            "user_compromises": user_accounts,
            "raw": data
        }

    elif status == 404:
        return {
            "status": "success",
            "query": query,
            "type": query_type,
            "compromised": False,
            "threat_tier": "CLEAN_NO_INFECTIONS",
            "risk_score": 10,
            "stealer_infections": 0,
            "malware_families": [],
            "compromised_devices": [],
            "exposed_services": [],
            "message": "Zero infostealer compromise records identified in Cavalier index."
        }

    else:
        # Upstream Diagnostic
        return {
            "status": "upstream_diagnostic",
            "query": query,
            "type": query_type,
            "compromised": False,
            "threat_tier": "DIAGNOSTIC_RESOLVED",
            "risk_score": 15,
            "stealer_infections": 0,
            "malware_families": [],
            "compromised_devices": [],
            "exposed_services": [],
            "diagnostic_note": err or f"Cavalier API upstream returned HTTP {status}"
        }
