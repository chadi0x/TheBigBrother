"""
MAIL TRACER — Email infrastructure forensics.
Inspects an email address: MX validity, SPF/DMARC presence, disposable/role flags,
gravatar lookup, and computes a deliverability/trust score.
"""
from __future__ import annotations

import asyncio
import hashlib
import re
from typing import Optional, Dict, Any, List

import json
import urllib.request
import urllib.error

try:
    import requests
except ImportError:
    requests = None

try:
    import dns.resolver
except ImportError:
    dns = None

from the_big_brother.modules.domain_oracle import _query, _spf, _dmarc


DISPOSABLE = {
    "10minutemail.com", "guerrillamail.com", "mailinator.com", "tempmail.com",
    "throwaway.email", "trashmail.com", "yopmail.com", "getairmail.com",
    "fakeinbox.com", "sharklasers.com", "tempr.email", "dispostable.com",
    "maildrop.cc", "mintemail.com", "mohmal.com", "tempinbox.com",
}

ROLE_LOCALS = {
    "admin", "administrator", "info", "support", "help", "contact", "sales",
    "noreply", "no-reply", "postmaster", "webmaster", "abuse", "security",
    "hr", "jobs", "careers", "marketing", "office", "team", "hello",
}

FREE_PROVIDERS = {
    "gmail.com", "yahoo.com", "outlook.com", "hotmail.com", "icloud.com",
    "protonmail.com", "proton.me", "tutanota.com", "aol.com", "yandex.com",
    "mail.com", "gmx.com", "zoho.com",
}


PROVIDER_SIGNATURES = {
    "google": ("Google Workspace / Gmail", ["aspmx.l.google.com", "googlemail.com", "smtp.google.com"]),
    "microsoft": ("Microsoft 365 / Exchange Online", ["mail.protection.outlook.com", "outlook.com", "pphosted.com"]),
    "proton": ("Proton Mail Secure Enterprise", ["protonmail.ch", "mailroute.proton.me"]),
    "zoho": ("Zoho Enterprise Mail", ["zoho.com", "zoho.eu"]),
    "fastmail": ("Fastmail Secure Infrastructure", ["messagingengine.com"]),
    "icloud": ("Apple iCloud Mail", ["mail.icloud.com"]),
    "mimecast": ("Mimecast Email Security Gateway", ["mimecast.com"]),
    "proofpoint": ("Proofpoint Targeted Attack Protection", ["pphosted.com"]),
    "cloudflare": ("Cloudflare Email Routing", ["mx.cloudflare.net"]),
}


def _detect_mail_provider(mx_records: list) -> str:
    parts = []
    for r in mx_records or []:
        if isinstance(r, dict):
            parts.extend([str(v) for v in r.values()])
        else:
            parts.append(str(r))
    combined = " ".join(parts).lower()
    for key, (label, signatures) in PROVIDER_SIGNATURES.items():
        if any(sig in combined for sig in signatures):
            return label
    return "Custom / Self-Hosted MTA"


def _fetch_gravatar_profile(email: str) -> dict:
    h = hashlib.md5(email.strip().lower().encode()).hexdigest()
    url = f"https://www.gravatar.com/avatar/{h}?s=256&d=404"
    json_url = f"https://en.gravatar.com/{h}.json"
    res = {"exists": False, "avatar_url": None, "display_name": None, "profile_url": None, "location": None}
    try:
        req = urllib.request.Request(json_url, headers={"User-Agent": "TheBigBrother/7.0"})
        with urllib.request.urlopen(req, timeout=4) as resp:
            if resp.getcode() == 200:
                data = json.loads(resp.read().decode("utf-8", errors="replace"))
                entry = data.get("entry", [{}])[0]
                res["exists"] = True
                res["avatar_url"] = url
                res["display_name"] = entry.get("displayName") or entry.get("preferredUsername")
                res["profile_url"] = entry.get("profileUrl")
                res["location"] = entry.get("currentLocation")
                return res
    except Exception:
        pass
    # Fallback to HEAD check
    try:
        req_head = urllib.request.Request(url, headers={"User-Agent": "TheBigBrother/7.0"}, method="HEAD")
        with urllib.request.urlopen(req_head, timeout=4) as resp:
            if resp.getcode() == 200:
                res["exists"] = True
                res["avatar_url"] = url
    except Exception:
        pass
    return res


def _github_user_by_email(email: str) -> Optional[dict]:
    try:
        from the_big_brother.modules.code_hunter import _get
        data, err = _get("/search/users", {"q": f"{email} in:email"})
        if data and isinstance(data, dict) and data.get("total_count", 0) > 0:
            top = data["items"][0]
            return {
                "login": top.get("login"),
                "avatar_url": top.get("avatar_url"),
                "html_url": top.get("html_url")
            }
    except Exception:
        pass
    return None


async def mail_tracer(email: str) -> dict:
    email = email.strip().lower()
    if not re.match(r"^[^\s@]+@[^\s@]+\.[^\s@]+$", email):
        return {"error": "Invalid email address format"}

    local, domain = email.rsplit("@", 1)

    mx_records = await asyncio.to_thread(_query, domain, "MX")
    txt_records = await asyncio.to_thread(_query, domain, "TXT")
    a_records = await asyncio.to_thread(_query, domain, "A")

    spf = _spf(txt_records)
    dmarc = await asyncio.to_thread(_dmarc, domain)

    is_disposable = domain in DISPOSABLE
    is_role = local in ROLE_LOCALS
    is_free = domain in FREE_PROVIDERS

    mail_provider = _detect_mail_provider(mx_records)
    gravatar_profile = await asyncio.to_thread(_fetch_gravatar_profile, email)
    github_user = await asyncio.to_thread(_github_user_by_email, email)

    # Trust score computation
    score = 100
    factors = []
    if not mx_records:
        score -= 50
        factors.append("No MX records — domain cannot receive mail")
    if not a_records and not mx_records:
        score -= 20
        factors.append("Domain has no DNS presence")
    if is_disposable:
        score -= 60
        factors.append(f"Disposable email service: {domain}")
    if is_role:
        score -= 15
        factors.append(f"Role-based local part: {local}")
    if not spf["present"]:
        score -= 10
        factors.append("No SPF record — spoofable domain")
    elif spf["grade"] in ("C", "F"):
        score -= 5
        factors.append(f"Weak SPF policy: {spf.get('policy')}")
    if not dmarc["present"]:
        score -= 10
        factors.append("No DMARC record — no quarantine/reject enforcement")
    elif dmarc["grade"] == "D":
        score -= 5
        factors.append("DMARC policy is 'none' (monitoring only)")
    if gravatar_profile["exists"]:
        score += 8
        factors.append("Gravatar identity record verified")
    if github_user:
        score += 10
        factors.append(f"Direct GitHub identity matched: @{github_user['login']}")

    score = max(0, min(100, score))

    trust_level = (
        "TRUSTED" if score >= 80 else
        "MODERATE" if score >= 60 else
        "WEAK" if score >= 40 else
        "SUSPICIOUS"
    )

    threat_val = 100 - score

    return {
        "status": "success",
        "email": email,
        "local": local,
        "domain": domain,
        "mail_provider": mail_provider,
        "trust_score": score,
        "threat_score": threat_val,
        "threat_level": "CRITICAL" if threat_val >= 70 else ("ELEVATED" if threat_val >= 40 else "NOMINAL"),
        "trust_level": trust_level,
        "factors": factors,
        "flags": {
            "disposable": is_disposable,
            "role_based": is_role,
            "free_provider": is_free,
            "deliverable": bool(mx_records),
        },
        "mx": mx_records,
        "mx_records": mx_records,
        "email_security": {"spf": spf, "dmarc": dmarc},
        "gravatar": gravatar_profile,
        "github_identity": github_user
    }
