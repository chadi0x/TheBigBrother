"""
MAIL TRACER — Email infrastructure forensics.
Inspects an email address: MX validity, SPF/DMARC presence, disposable/role flags,
gravatar lookup, and computes a deliverability/trust score.
"""
import asyncio
import hashlib
import re

import requests
import dns.resolver

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


def _gravatar(email: str) -> str:
    h = hashlib.md5(email.strip().lower().encode()).hexdigest()
    return f"https://www.gravatar.com/avatar/{h}?s=256&d=404"


def _gravatar_exists(url: str) -> bool:
    try:
        r = requests.head(url, timeout=5, allow_redirects=False)
        return r.status_code == 200
    except Exception:
        return False


async def mail_tracer(email: str) -> dict:
    email = email.strip().lower()
    if not re.match(r"^[^\s@]+@[^\s@]+\.[^\s@]+$", email):
        return {"error": "Invalid email"}

    local, domain = email.rsplit("@", 1)

    mx_records = await asyncio.to_thread(_query, domain, "MX")
    txt_records = await asyncio.to_thread(_query, domain, "TXT")
    a_records = await asyncio.to_thread(_query, domain, "A")

    spf = _spf(txt_records)
    dmarc = await asyncio.to_thread(_dmarc, domain)

    is_disposable = domain in DISPOSABLE
    is_role = local in ROLE_LOCALS
    is_free = domain in FREE_PROVIDERS

    gravatar_url = _gravatar(email)
    has_gravatar = await asyncio.to_thread(_gravatar_exists, gravatar_url)

    # Trust score
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
        factors.append(f"Disposable provider: {domain}")
    if is_role:
        score -= 15
        factors.append(f"Role-based local part: {local}")
    if not spf["present"]:
        score -= 10
        factors.append("No SPF record — spoofable")
    elif spf["grade"] in ("C", "F"):
        score -= 5
        factors.append(f"Weak SPF policy: {spf.get('policy')}")
    if not dmarc["present"]:
        score -= 10
        factors.append("No DMARC record — no enforcement")
    elif dmarc["grade"] == "D":
        score -= 5
        factors.append("DMARC policy is 'none' (monitor only)")
    if has_gravatar:
        score += 5
        factors.append("Gravatar exists — identity tied")

    score = max(0, min(100, score))

    trust_level = (
        "TRUSTED" if score >= 80 else
        "MODERATE" if score >= 60 else
        "WEAK" if score >= 40 else
        "SUSPICIOUS"
    )

    return {
        "email": email,
        "local": local,
        "domain": domain,
        "trust_score": score,
        "trust_level": trust_level,
        "factors": factors,
        "flags": {
            "disposable": is_disposable,
            "role_based": is_role,
            "free_provider": is_free,
            "deliverable": bool(mx_records),
        },
        "mx": mx_records,
        "email_security": {"spf": spf, "dmarc": dmarc},
        "gravatar": {
            "url": gravatar_url if has_gravatar else None,
            "exists": has_gravatar,
        },
    }
