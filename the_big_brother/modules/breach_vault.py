"""
BREACH VAULT — Data breach checker.
Uses HaveIBeenPwned v3 k-anonymity API (no API key needed for passwords,
breaches endpoint uses public API). Also checks paste aggregators.
"""

import asyncio
import aiohttp
import hashlib
import requests
from typing import Optional

HIBP_BREACH_URL = "https://haveibeenpwned.com/api/v3/breachedaccount/{}"
HIBP_PASTE_URL  = "https://haveibeenpwned.com/api/v3/pasteaccount/{}"
HIBP_PWNED_URL  = "https://api.pwnedpasswords.com/range/{}"

HEADERS = {
    "User-Agent": "TheBigBrotherV4-OSINT",
    "hibp-api-key": "",  # Optional: set via env var HIBP_API_KEY for full access
}

# Paste sites for domain leak scraping
PASTE_SEARCH_URLS = [
    "https://psbdmp.ws/api/v3/search/{}",  # Pastebin dump search (public)
]

SEVERITY_MAP = {
    "Passwords": "CRITICAL",
    "Email addresses": "HIGH",
    "Phone numbers": "HIGH",
    "Physical addresses": "HIGH",
    "Credit cards": "CRITICAL",
    "Financial data": "CRITICAL",
    "Government issued IDs": "CRITICAL",
    "Usernames": "MEDIUM",
    "Dates of birth": "MEDIUM",
    "Social media profiles": "MEDIUM",
    "Security questions and answers": "HIGH",
    "IP addresses": "LOW",
    "Geographic locations": "LOW",
    "Browser user agent details": "LOW",
    "Website activity": "LOW",
}


def get_severity(data_classes: list) -> str:
    """Determine worst severity from breach data classes."""
    order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    worst = "LOW"
    for dc in data_classes:
        sev = SEVERITY_MAP.get(dc, "LOW")
        if order.index(sev) < order.index(worst):
            worst = sev
    return worst


async def check_breaches_hibp(email: str) -> list:
    """Check for breaches using HIBP v3 API."""
    import os
    api_key = os.environ.get("HIBP_API_KEY", "")
    
    headers = {
        "User-Agent": "TheBigBrotherV4-OSINT",
        "hibp-api-key": api_key,
    }

    url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}?truncateResponse=false"
    
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(url, headers=headers, timeout=aiohttp.ClientTimeout(total=10), ssl=False) as resp:
                if resp.status == 404:
                    return []
                if resp.status == 401:
                    return [{"_note": "HIBP API key required for breach lookup. Set HIBP_API_KEY env var."}]
                if resp.status == 200:
                    data = await resp.json()
                    breaches = []
                    for b in data:
                        breaches.append({
                            "name": b.get("Name"),
                            "domain": b.get("Domain"),
                            "date": b.get("BreachDate"),
                            "pwn_count": b.get("PwnCount"),
                            "description": b.get("Description", "")[:300],
                            "data_classes": b.get("DataClasses", []),
                            "severity": get_severity(b.get("DataClasses", [])),
                            "is_sensitive": b.get("IsSensitive", False),
                            "is_verified": b.get("IsVerified", True),
                            "logo": f"https://haveibeenpwned.com/Content/Images/PwnedLogos/{b.get('Name')}.png",
                        })
                    return sorted(breaches, key=lambda x: x["date"], reverse=True)
    except Exception as e:
        print(f"HIBP breach error: {e}")
    return []


async def check_pastes_hibp(email: str) -> list:
    """Check for paste exposures via HIBP."""
    import os
    api_key = os.environ.get("HIBP_API_KEY", "")
    if not api_key:
        return []

    headers = {
        "User-Agent": "TheBigBrotherV4-OSINT",
        "hibp-api-key": api_key,
    }
    url = f"https://haveibeenpwned.com/api/v3/pasteaccount/{email}"

    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(url, headers=headers, timeout=aiohttp.ClientTimeout(total=10), ssl=False) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    return [{"source": p.get("Source"), "id": p.get("Id"), "date": p.get("Date"), "emails": p.get("EmailCount")} for p in data]
    except Exception as e:
        print(f"HIBP paste error: {e}")
    return []


async def check_password_pwned(password: str) -> dict:
    """
    Check if a password has been seen in breaches using k-anonymity model.
    Never sends the full password — only first 5 chars of SHA1 hash.
    """
    sha1 = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix = sha1[:5]
    suffix = sha1[5:]

    url = f"https://api.pwnedpasswords.com/range/{prefix}"
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=8), ssl=False) as resp:
                if resp.status == 200:
                    text = await resp.text()
                    for line in text.splitlines():
                        parts = line.split(":")
                        if len(parts) == 2 and parts[0] == suffix:
                            return {"pwned": True, "count": int(parts[1])}
    except Exception as e:
        print(f"HIBP password check error: {e}")
    return {"pwned": False, "count": 0}


async def check_paste_aggregator(query: str) -> list:
    """Checks public paste dump APIs for mentions of query (email/domain)."""
    results = []
    url = f"https://psbdmp.ws/api/v3/search/{query}"
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=8), ssl=False) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    if isinstance(data, dict) and "data" in data:
                        for item in data["data"][:10]:
                            results.append({
                                "source": "Pastebin",
                                "id": item.get("id"),
                                "date": item.get("time"),
                                "snippet": item.get("tags", ""),
                                "url": f"https://pastebin.com/{item.get('id')}",
                            })
    except Exception as e:
        print(f"Paste aggregator error: {e}")
    return results


async def breach_vault_search(query: str, query_type: str = "email"):
    """
    Main entry point for BREACH VAULT.
    query_type: 'email' | 'password'
    """
    if query_type == "password":
        result = await check_password_pwned(query)
        return {
            "query": "***REDACTED***",
            "type": "password",
            "pwned": result["pwned"],
            "count": result["count"],
            "breaches": [],
            "pastes": [],
        }

    # Email query
    breaches, pastes, paste_dumps = await asyncio.gather(
        check_breaches_hibp(query),
        check_pastes_hibp(query),
        check_paste_aggregator(query),
    )

    total_exposed = sum(b.get("pwn_count", 0) for b in breaches if isinstance(b.get("pwn_count"), int))

    return {
        "query": query,
        "type": "email",
        "breach_count": len(breaches),
        "paste_count": len(pastes),
        "total_records_exposed": total_exposed,
        "breaches": breaches,
        "pastes": pastes,
        "paste_dumps": paste_dumps,
    }
