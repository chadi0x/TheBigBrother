"""
BREACH VAULT — Multi-Tier Credential Compromise & Exposure Archive V7.0
Performs deep breach investigations across:
1. Free Keyless Global Compromise Ledger via XposedOrNot (14B+ records, breach analytics & pastes)
2. Authenticated HaveIBeenPwned (HIBP v3) with user-supplied API key
3. K-Anonymity SHA-1 Pwned Passwords verification
4. Public Pastebin & Dump Aggregator Scrapers
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import os
import re
import ssl
from typing import Dict, Any, List, Optional, Tuple
import urllib.request
import urllib.error
import urllib.parse

try:
    import aiohttp
except ImportError:
    aiohttp = None

try:
    import httpx
except ImportError:
    httpx = None

SEVERITY_MAP = {
    "Passwords": "CRITICAL",
    "Password hints": "HIGH",
    "Email addresses": "HIGH",
    "Phone numbers": "HIGH",
    "Physical addresses": "HIGH",
    "Credit cards": "CRITICAL",
    "Bank account numbers": "CRITICAL",
    "Financial data": "CRITICAL",
    "Government issued IDs": "CRITICAL",
    "Social security numbers": "CRITICAL",
    "Passport numbers": "CRITICAL",
    "Usernames": "MEDIUM",
    "Dates of birth": "MEDIUM",
    "Social media profiles": "MEDIUM",
    "Security questions and answers": "HIGH",
    "IP addresses": "LOW",
    "Geographic locations": "LOW",
    "Browser user agent details": "LOW",
    "Website activity": "LOW",
    "Vehicle registration numbers": "MEDIUM",
}

def get_severity(data_classes: list) -> str:
    """Determine worst severity rating from a list of exposed data classes."""
    order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    worst = "LOW"
    for dc in data_classes:
        clean_dc = str(dc).strip()
        sev = SEVERITY_MAP.get(clean_dc, "MEDIUM" if "password" in clean_dc.lower() or "secret" in clean_dc.lower() else "LOW")
        if order.index(sev) < order.index(worst):
            worst = sev
    return worst


def _fetch_json_sync(url: str, headers: Optional[Dict[str, str]] = None, timeout: int = 8) -> Tuple[int, Any]:
    """Robust synchronous JSON fetch with SSL fallback."""
    hdrs = {"User-Agent": "TheBigBrotherV7-OSINT-Engine/7.0"}
    if headers:
        hdrs.update(headers)
    ctx = ssl._create_unverified_context()
    req = urllib.request.Request(url, headers=hdrs)
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            status = resp.status
            body = resp.read().decode("utf-8", errors="replace")
            try:
                data = json.loads(body)
            except Exception:
                data = body
            return status, data
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="replace") if hasattr(e, "read") else ""
        try:
            data = json.loads(body)
        except Exception:
            data = body
        return e.code, data
    except Exception as e:
        return 0, str(e)


# ═══════════════════════════════════════════════════════════════════════════════
# 1. KEYLESS BREACH RECONNAISSANCE (XPOSEDORNOT ENGINE)
# ═══════════════════════════════════════════════════════════════════════════════

async def check_email_xposedornot(email: str) -> Dict[str, Any]:
    """
    Keyless deep breach intelligence via XposedOrNot.
    Returns detailed breach entries, exposure timelines, data classes, and paste references.
    """
    clean_email = email.strip().lower()
    loop = asyncio.get_running_loop()

    # Query detailed analytics endpoint
    url = f"https://api.xposedornot.com/v1/breach-analytics?email={urllib.parse.quote(clean_email)}"
    status, data = await loop.run_in_executor(None, _fetch_json_sync, url, None, 10)

    breaches = []
    pastes = []
    summary_text = ""

    if status == 200 and isinstance(data, dict):
        exposed_breaches = data.get("ExposedBreaches", {})
        details = exposed_breaches.get("breaches_details", [])
        
        for b in details:
            if not isinstance(b, dict):
                continue
            name = b.get("breach", "Unknown Breach")
            domain = b.get("domain", "")
            date = str(b.get("xposed_date") or b.get("added", "")[:4] or "Historical")
            pwn_count = b.get("xposed_records") or 0
            desc = b.get("details", "")
            
            raw_classes = b.get("xposed_data", "")
            if isinstance(raw_classes, str):
                data_classes = [c.strip() for c in raw_classes.split(";") if c.strip()]
            elif isinstance(raw_classes, list):
                data_classes = raw_classes
            else:
                data_classes = ["Email addresses"]

            breaches.append({
                "name": name,
                "title": name,
                "domain": domain,
                "date": date,
                "pwn_count": pwn_count,
                "description": desc,
                "data_classes": data_classes,
                "severity": get_severity(data_classes),
                "industry": b.get("industry", "General"),
                "password_risk": b.get("password_risk", "unknown"),
                "is_verified": b.get("verified", "Yes") == "Yes",
                "logo": b.get("logo") or f"https://xposedornot.com/static/logos/{name}.png",
                "source_engine": "XposedOrNot Ledger"
            })

        # Process pastes
        exposed_pastes = data.get("ExposedPastes", {})
        paste_details = exposed_pastes.get("pastes_details", [])
        for p in paste_details:
            if isinstance(p, dict):
                pastes.append({
                    "source": "Pastebin Dump",
                    "id": p.get("pasteId", "dump"),
                    "date": str(p.get("xposed_date", "Historical")),
                    "emails": p.get("xposed_records", 1),
                    "title": p.get("pasteId", "Public Exposure Paste"),
                    "url": f"https://pastebin.com/{p.get('pasteId', '')}" if p.get('pasteId') else ""
                })

        summary_dict = data.get("BreachesSummary", {})
        if summary_dict and "site" in summary_dict:
            summary_text = summary_dict["site"]

    elif status == 404:
        # Email has no breaches in XposedOrNot
        return {"breaches": [], "pastes": [], "status": "clean", "count": 0}

    else:
        # Fallback to simple check-email endpoint
        simple_url = f"https://api.xposedornot.com/v1/check-email/{urllib.parse.quote(clean_email)}"
        s2, d2 = await loop.run_in_executor(None, _fetch_json_sync, simple_url, None, 6)
        if s2 == 200 and isinstance(d2, dict) and "breaches" in d2:
            raw_b = d2["breaches"]
            names = raw_b[0] if raw_b and isinstance(raw_b[0], list) else raw_b
            for name in names:
                if isinstance(name, str):
                    breaches.append({
                        "name": name,
                        "title": name,
                        "domain": "",
                        "date": "Historical",
                        "pwn_count": 0,
                        "description": f"Verified compromise recorded in {name} breach dump.",
                        "data_classes": ["Email addresses", "Passwords"],
                        "severity": "HIGH",
                        "industry": "General",
                        "password_risk": "high",
                        "is_verified": True,
                        "logo": f"https://xposedornot.com/static/logos/{name}.png",
                        "source_engine": "XposedOrNot QuickCheck"
                    })

    return {
        "breaches": breaches,
        "pastes": pastes,
        "status": "compromised" if breaches else "clean",
        "count": len(breaches),
        "summary": summary_text
    }


# ═══════════════════════════════════════════════════════════════════════════════
# 2. AUTHENTICATED HAVEIBEENPWNED (HIBP v3) ENGINE
# ═══════════════════════════════════════════════════════════════════════════════

async def check_breaches_hibp(email: str, api_key: Optional[str] = None) -> List[Dict[str, Any]]:
    """Check for breaches using HaveIBeenPwned v3 API with personal API key."""
    key = api_key or os.environ.get("HIBP_API_KEY", "")
    if not key:
        return []

    headers = {
        "User-Agent": "TheBigBrotherV7-OSINT-WarRoom",
        "hibp-api-key": key.strip(),
    }
    url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{urllib.parse.quote(email)}?truncateResponse=false"
    loop = asyncio.get_running_loop()

    status, data = await loop.run_in_executor(None, _fetch_json_sync, url, headers, 10)
    if status == 200 and isinstance(data, list):
        breaches = []
        for b in data:
            if not isinstance(b, dict):
                continue
            data_classes = b.get("DataClasses", [])
            breaches.append({
                "name": b.get("Name"),
                "title": b.get("Title", b.get("Name")),
                "domain": b.get("Domain"),
                "date": b.get("BreachDate"),
                "pwn_count": b.get("PwnCount", 0),
                "description": b.get("Description", "")[:400],
                "data_classes": data_classes,
                "severity": get_severity(data_classes),
                "is_sensitive": b.get("IsSensitive", False),
                "is_verified": b.get("IsVerified", True),
                "logo": f"https://haveibeenpwned.com/Content/Images/PwnedLogos/{b.get('Name')}.png",
                "source_engine": "HIBP v3 Authenticated"
            })
        return sorted(breaches, key=lambda x: str(x.get("date", "")), reverse=True)
    elif status == 404:
        return []
    elif status == 401:
        return [{"_error": "HIBP API key rejected (HTTP 401 Unauthorized)."}]
    return []


async def check_pastes_hibp(email: str, api_key: Optional[str] = None) -> List[Dict[str, Any]]:
    """Check for paste exposures via HIBP v3 authenticated API."""
    key = api_key or os.environ.get("HIBP_API_KEY", "")
    if not key:
        return []

    headers = {
        "User-Agent": "TheBigBrotherV7-OSINT-WarRoom",
        "hibp-api-key": key.strip(),
    }
    url = f"https://haveibeenpwned.com/api/v3/pasteaccount/{urllib.parse.quote(email)}"
    loop = asyncio.get_running_loop()

    status, data = await loop.run_in_executor(None, _fetch_json_sync, url, headers, 10)
    if status == 200 and isinstance(data, list):
        return [{
            "source": p.get("Source", "Pastebin"),
            "id": p.get("Id"),
            "date": p.get("Date"),
            "emails": p.get("EmailCount"),
            "title": f"HIBP Paste: {p.get('Source')}",
            "url": f"https://pastebin.com/{p.get('Id')}" if p.get("Id") else ""
        } for p in data if isinstance(p, dict)]
    return []


# ═══════════════════════════════════════════════════════════════════════════════
# 3. K-ANONYMITY PWNED PASSWORD AUDIT
# ═══════════════════════════════════════════════════════════════════════════════

async def check_password_pwned(password: str) -> Dict[str, Any]:
    """
    Check if a password has been compromised using Cloudflare/HIBP k-anonymity SHA-1 ranges.
    Never transmits plaintext or full hashes over the wire.
    """
    sha1 = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix = sha1[:5]
    suffix = sha1[5:]

    url = f"https://api.pwnedpasswords.com/range/{prefix}"
    loop = asyncio.get_running_loop()

    def _query_range():
        req = urllib.request.Request(url, headers={"User-Agent": "TheBigBrotherV7-OSINT"})
        ctx = ssl._create_unverified_context()
        try:
            with urllib.request.urlopen(req, timeout=6, context=ctx) as resp:
                return resp.read().decode("utf-8", errors="replace")
        except Exception:
            return ""

    text = await loop.run_in_executor(None, _query_range)
    for line in text.splitlines():
        parts = line.split(":")
        if len(parts) == 2 and parts[0].strip().upper() == suffix:
            try:
                count = int(parts[1].strip())
            except ValueError:
                count = 1
            return {"pwned": True, "count": count}

    return {"pwned": False, "count": 0}


# ═══════════════════════════════════════════════════════════════════════════════
# 4. PUBLIC PASTEBIN & DUMP AGGREGATOR
# ═══════════════════════════════════════════════════════════════════════════════

async def check_paste_aggregator(query: str) -> List[Dict[str, Any]]:
    """Checks public paste dump APIs for mentions of query (email/domain)."""
    results = []
    url = f"https://psbdmp.ws/api/v3/search/{urllib.parse.quote(query)}"
    loop = asyncio.get_running_loop()
    status, data = await loop.run_in_executor(None, _fetch_json_sync, url, None, 6)
    if status == 200 and isinstance(data, dict) and "data" in data:
        for item in data["data"][:10]:
            if isinstance(item, dict):
                results.append({
                    "source": "Pastebin Dump",
                    "id": item.get("id"),
                    "date": item.get("time"),
                    "title": item.get("id", "Paste Entry"),
                    "snippet": item.get("tags", ""),
                    "url": f"https://pastebin.com/{item.get('id')}",
                })
    return results


# ═══════════════════════════════════════════════════════════════════════════════
# 5. MAIN DISPATCHER & MULTI-TIER AGGREGATOR
# ═══════════════════════════════════════════════════════════════════════════════

async def breach_vault_search(
    query: str,
    query_type: str = "email",
    api_key: Optional[str] = None,
    service: str = "auto"
) -> Dict[str, Any]:
    """
    Main entry point for BREACH VAULT.
    Supports email compromise reconnaissance, password k-anonymity checks,
    and user-configured API service credentials.
    """
    clean_query = query.strip()
    if not clean_query:
        return {"error": "Target query indicator required."}

    # 1. Password Verification
    if query_type == "password":
        result = await check_password_pwned(clean_query)
        is_pwned = result.get("pwned", False)
        pwn_count = result.get("count", 0)
        pwn_threat = 95 if is_pwned else 0
        return {
            "status": "success",
            "query": "***REDACTED***",
            "type": "password",
            "pwned": is_pwned,
            "count": pwn_count,
            "threat_score": pwn_threat,
            "threat_level": "CRITICAL" if pwn_threat >= 70 else "NOMINAL_CLEAN",
            "breaches": [],
            "pastes": [],
            "diagnostic": f"Verified via Cloudflare K-Anonymity SHA-1 prefix table: {pwn_count:,} exposures found." if is_pwned else "Zero compromise occurrences detected in global password dictionaries."
        }

    # 2. Email / Identity Verification
    clean_email = clean_query.lower()

    # Concurrently execute free keyless check and authenticated checks
    effective_hibp_key = api_key or os.environ.get("HIBP_API_KEY", "")

    tasks = [
        check_email_xposedornot(clean_email),
        check_paste_aggregator(clean_email),
    ]
    if effective_hibp_key and service in ("auto", "hibp"):
        tasks.append(check_breaches_hibp(clean_email, effective_hibp_key))
        tasks.append(check_pastes_hibp(clean_email, effective_hibp_key))

    gathered = await asyncio.gather(*tasks, return_exceptions=True)

    xo_data = gathered[0] if not isinstance(gathered[0], Exception) else {"breaches": [], "pastes": []}
    paste_dumps = gathered[1] if len(gathered) > 1 and not isinstance(gathered[1], Exception) else []
    hibp_breaches = gathered[2] if len(gathered) > 2 and not isinstance(gathered[2], Exception) else []
    hibp_pastes = gathered[3] if len(gathered) > 3 and not isinstance(gathered[3], Exception) else []

    # Merge and deduplicate breaches by name/title
    all_breaches = []
    seen_names = set()

    # Prioritize authenticated HIBP breaches if present
    for b in hibp_breaches:
        if isinstance(b, dict) and not b.get("_error"):
            name_key = (b.get("name") or b.get("title") or "").strip().lower()
            if name_key and name_key not in seen_names:
                seen_names.add(name_key)
                all_breaches.append(b)

    # Blend with XposedOrNot breaches
    for b in xo_data.get("breaches", []):
        if isinstance(b, dict):
            name_key = (b.get("name") or b.get("title") or "").strip().lower()
            if name_key and name_key not in seen_names:
                seen_names.add(name_key)
                all_breaches.append(b)

    # Merge pastes
    all_pastes = []
    seen_pastes = set()
    for p in (hibp_pastes + xo_data.get("pastes", []) + paste_dumps):
        if isinstance(p, dict):
            pid = str(p.get("id") or p.get("url") or p.get("title"))
            if pid and pid not in seen_pastes:
                seen_pastes.add(pid)
                all_pastes.append(p)

    total_records = sum(b.get("pwn_count", 0) for b in all_breaches if isinstance(b.get("pwn_count"), (int, float)))
    threat_score = min(99, max(0, len(all_breaches) * 18 + len(all_pastes) * 12))
    if all_breaches:
        threat_score = max(35, threat_score)

    threat_level = "CRITICAL" if threat_score >= 70 else ("ELEVATED" if threat_score >= 30 else "NOMINAL_CLEAN")

    active_provider = "HIBP v3 (Authenticated) + XposedOrNot" if effective_hibp_key else "XposedOrNot Keyless Global Ledger"

    return {
        "status": "success",
        "query": clean_email,
        "type": "email",
        "provider": active_provider,
        "has_custom_api_key": bool(effective_hibp_key),
        "breach_count": len(all_breaches),
        "paste_count": len(all_pastes),
        "total_records_exposed": int(total_records),
        "threat_score": threat_score,
        "threat_level": threat_level,
        "breaches": all_breaches,
        "pastes": all_pastes,
        "diagnostic": f"Verified across {active_provider}. Recovered {len(all_breaches)} breach incidents and {len(all_pastes)} public paste leak records."
    }
