"""
SHADOW MAP — IP/Domain threat intelligence and reputation analysis.
Queries AbuseIPDB, VirusTotal (public API), Shodan, and URLhaus.
"""

import asyncio
import aiohttp
import os
import socket
from datetime import datetime


ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"
VIRUSTOTAL_URL = "https://www.virustotal.com/api/v3/ip_addresses/{}"
VIRUSTOTAL_DOMAIN_URL = "https://www.virustotal.com/api/v3/domains/{}"
URLHAUS_URL = "https://urlhaus-api.abuse.ch/v1/host/"
SHODAN_URL = "https://api.shodan.io/shodan/host/{}?key={}"
IPINFO_URL = "https://ipinfo.io/{}/json"

ABUSE_CATEGORIES = {
    1: "DNS Compromise", 2: "DNS Poisoning", 3: "Fraud Orders", 4: "DDoS Attack",
    5: "FTP Brute-Force", 6: "Ping of Death", 7: "Phishing", 8: "Fraud VoIP",
    9: "Open Proxy", 10: "Web Spam", 11: "Email Spam", 12: "Blog Spam",
    13: "VPN IP", 14: "Port Scan", 15: "Hacking", 16: "SQL Injection",
    17: "Spoofing", 18: "Brute-Force", 19: "Bad Web Bot", 20: "Exploited Host",
    21: "Web App Attack", 22: "SSH", 23: "IoT Targeted",
}


def resolve_to_ip(target: str) -> str:
    """Resolve domain to IP if needed."""
    try:
        socket.inet_aton(target)
        return target  # Already an IP
    except socket.error:
        try:
            return socket.gethostbyname(target)
        except:
            return target


async def check_abuseipdb(session: aiohttp.ClientSession, ip: str) -> dict:
    """Query AbuseIPDB for IP reputation."""
    api_key = os.environ.get("ABUSEIPDB_API_KEY", "")
    if not api_key:
        return {"error": "ABUSEIPDB_API_KEY not set", "available": False}

    headers = {"Key": api_key, "Accept": "application/json"}
    params = {"ipAddress": ip, "maxAgeInDays": 90, "verbose": ""}

    try:
        async with session.get(ABUSEIPDB_URL, headers=headers, params=params, timeout=aiohttp.ClientTimeout(total=10), ssl=False) as resp:
            if resp.status == 200:
                data = (await resp.json()).get("data", {})
                category_ids = data.get("reports", [{}])[-1].get("categories", []) if data.get("reports") else []
                categories = [ABUSE_CATEGORIES.get(c, f"Category {c}") for c in category_ids]
                return {
                    "available": True,
                    "ip": ip,
                    "abuse_score": data.get("abuseConfidenceScore", 0),
                    "country": data.get("countryCode"),
                    "isp": data.get("isp"),
                    "domain": data.get("domain"),
                    "is_tor": data.get("isTor", False),
                    "is_whitelisted": data.get("isWhitelisted", False),
                    "total_reports": data.get("totalReports", 0),
                    "last_reported": data.get("lastReportedAt"),
                    "categories": categories,
                    "usage_type": data.get("usageType"),
                }
    except Exception as e:
        return {"error": str(e), "available": False}
    return {"available": False}


async def check_virustotal(session: aiohttp.ClientSession, target: str, is_ip: bool = True) -> dict:
    """Query VirusTotal for IP or domain reputation."""
    api_key = os.environ.get("VIRUSTOTAL_API_KEY", "")
    if not api_key:
        return {"error": "VIRUSTOTAL_API_KEY not set", "available": False}

    url = VIRUSTOTAL_URL.format(target) if is_ip else VIRUSTOTAL_DOMAIN_URL.format(target)
    headers = {"x-apikey": api_key}

    try:
        async with session.get(url, headers=headers, timeout=aiohttp.ClientTimeout(total=10), ssl=False) as resp:
            if resp.status == 200:
                data = (await resp.json()).get("data", {}).get("attributes", {})
                stats = data.get("last_analysis_stats", {})
                malicious = stats.get("malicious", 0)
                suspicious = stats.get("suspicious", 0)
                harmless = stats.get("harmless", 0)
                undetected = stats.get("undetected", 0)
                total = malicious + suspicious + harmless + undetected
                return {
                    "available": True,
                    "malicious": malicious,
                    "suspicious": suspicious,
                    "harmless": harmless,
                    "undetected": undetected,
                    "total_engines": total,
                    "reputation": data.get("reputation", 0),
                    "tags": data.get("tags", []),
                    "country": data.get("country"),
                    "as_owner": data.get("as_owner"),
                    "threat_level": "CRITICAL" if malicious > 5 else ("HIGH" if malicious > 0 else ("SUSPICIOUS" if suspicious > 0 else "CLEAN")),
                }
    except Exception as e:
        return {"error": str(e), "available": False}
    return {"available": False}


async def check_urlhaus(session: aiohttp.ClientSession, target: str) -> dict:
    """Query URLhaus for malicious URL data."""
    try:
        async with session.post(URLHAUS_URL, data={"host": target}, timeout=aiohttp.ClientTimeout(total=8), ssl=False) as resp:
            if resp.status == 200:
                data = await resp.json()
                if data.get("query_status") == "is_host":
                    urls = data.get("urls", [])[:5]
                    return {
                        "available": True,
                        "found": True,
                        "url_count": len(data.get("urls", [])),
                        "urls": [
                            {"url": u.get("url"), "status": u.get("url_status"), "threat": u.get("threat"), "date": u.get("date_added")}
                            for u in urls
                        ],
                    }
                return {"available": True, "found": False}
    except Exception as e:
        return {"available": True, "found": False, "error": str(e)}
    return {"available": False}


async def check_ipinfo(session: aiohttp.ClientSession, ip: str) -> dict:
    """Get basic IP geolocation and ASN info from ipinfo.io (free tier)."""
    try:
        async with session.get(f"https://ipinfo.io/{ip}/json", timeout=aiohttp.ClientTimeout(total=8), ssl=False) as resp:
            if resp.status == 200:
                data = await resp.json()
                return {
                    "ip": data.get("ip"),
                    "city": data.get("city"),
                    "region": data.get("region"),
                    "country": data.get("country"),
                    "org": data.get("org"),
                    "timezone": data.get("timezone"),
                    "loc": data.get("loc"),
                    "hostname": data.get("hostname"),
                }
    except Exception as e:
        return {"error": str(e)}
    return {}


async def shadow_map_analyze(target: str):
    """
    Main SHADOW MAP entry: analyzes IP or domain for threat intelligence.
    """
    # Detect if IP or domain
    try:
        socket.inet_aton(target)
        is_ip = True
        ip = target
    except socket.error:
        is_ip = False
        ip = resolve_to_ip(target)

    connector = aiohttp.TCPConnector(ssl=False, limit=10)
    async with aiohttp.ClientSession(connector=connector) as session:
        geo_task = check_ipinfo(session, ip)
        abuse_task = check_abuseipdb(session, ip)
        vt_task = check_virustotal(session, target, is_ip=is_ip)
        urlhaus_task = check_urlhaus(session, target)

        geo, abuse, vt, urlhaus = await asyncio.gather(
            geo_task, abuse_task, vt_task, urlhaus_task,
            return_exceptions=True
        )

    # Handle exceptions from gather
    if isinstance(geo, Exception): geo = {}
    if isinstance(abuse, Exception): abuse = {"available": False}
    if isinstance(vt, Exception): vt = {"available": False}
    if isinstance(urlhaus, Exception): urlhaus = {"available": False}

    # Composite threat score (0-100)
    score = 0
    factors = []

    if isinstance(abuse, dict) and abuse.get("available"):
        abuse_score = abuse.get("abuse_score", 0)
        score += int(abuse_score * 0.5)
        if abuse_score > 50:
            factors.append(f"HIGH ABUSE SCORE ({abuse_score}%)")
        if abuse.get("is_tor"):
            score += 20
            factors.append("TOR EXIT NODE")

    if isinstance(vt, dict) and vt.get("available"):
        malicious = vt.get("malicious", 0)
        suspicious = vt.get("suspicious", 0)
        score += min(malicious * 5 + suspicious * 2, 40)
        if malicious > 0:
            factors.append(f"{malicious} VT ENGINES FLAGGED MALICIOUS")
        if suspicious > 0:
            factors.append(f"{suspicious} VT ENGINES FLAGGED SUSPICIOUS")

    if isinstance(urlhaus, dict) and urlhaus.get("found"):
        score += 15
        factors.append(f"FOUND IN URLHAUS ({urlhaus.get('url_count', 0)} MALICIOUS URLS)")

    score = min(score, 100)
    threat_level = "CRITICAL" if score >= 80 else ("HIGH" if score >= 50 else ("MEDIUM" if score >= 20 else "CLEAN"))

    return {
        "target": target,
        "resolved_ip": ip,
        "is_ip": is_ip,
        "threat_score": score,
        "threat_level": threat_level,
        "threat_factors": factors,
        "geo": geo if isinstance(geo, dict) else {},
        "abuseipdb": abuse if isinstance(abuse, dict) else {},
        "virustotal": vt if isinstance(vt, dict) else {},
        "urlhaus": urlhaus if isinstance(urlhaus, dict) else {},
    }
