"""
DOMAIN ORACLE — Passive deep domain intelligence.
Pulls WHOIS (RDAP), full DNS set, SPF/DMARC/DKIM posture, HTTP security headers,
TLS basic info, and subdomain enumeration via crt.sh — no auth keys required.
"""
import asyncio
import socket
import ssl
import re
from urllib.parse import urlparse

import requests
import dns.resolver


SECURITY_HEADERS = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy",
]


def _resolver():
    r = dns.resolver.Resolver()
    r.timeout = 2
    r.lifetime = 3
    return r


def _query(domain: str, rtype: str):
    out = []
    try:
        for rec in _resolver().resolve(domain, rtype):
            out.append(str(rec).strip('"'))
    except Exception:
        pass
    return out


def _rdap(domain: str) -> dict:
    try:
        r = requests.get(f"https://rdap.org/domain/{domain}", timeout=6)
        if r.status_code != 200:
            return {}
        data = r.json()
        events = {e.get("eventAction"): e.get("eventDate") for e in data.get("events", [])}
        registrar = "Unknown"
        for ent in data.get("entities", []):
            if "registrar" in ent.get("roles", []):
                v = ent.get("vcardArray")
                if v and len(v) > 1:
                    for item in v[1]:
                        if item[0] == "fn":
                            registrar = item[3]
                            break
        ns = []
        for n in data.get("nameservers", []):
            ld = n.get("ldhName")
            if ld:
                ns.append(ld.lower())
        return {
            "registrar": registrar,
            "status": data.get("status", []),
            "created": events.get("registration", "Unknown"),
            "updated": events.get("last changed", events.get("last update of RDAP database", "Unknown")),
            "expires": events.get("expiration", "Unknown"),
            "nameservers": ns,
        }
    except Exception:
        return {}


def _spf(txt_records: list) -> dict:
    spf = next((t for t in txt_records if t.lower().startswith("v=spf1")), None)
    if not spf:
        return {"present": False, "policy": None, "grade": "F"}
    policy = "neutral"
    if " -all" in spf:
        policy = "strict (-all)"
        grade = "A"
    elif " ~all" in spf:
        policy = "softfail (~all)"
        grade = "B"
    elif " ?all" in spf:
        policy = "neutral (?all)"
        grade = "C"
    elif " +all" in spf:
        policy = "pass-all (+all) — DANGEROUS"
        grade = "F"
    else:
        grade = "C"
    return {"present": True, "record": spf, "policy": policy, "grade": grade}


def _dmarc(domain: str) -> dict:
    recs = _query(f"_dmarc.{domain}", "TXT")
    rec = next((r for r in recs if r.lower().startswith("v=dmarc1")), None)
    if not rec:
        return {"present": False, "grade": "F"}
    policy = "none"
    if "p=reject" in rec.lower():
        policy, grade = "reject", "A"
    elif "p=quarantine" in rec.lower():
        policy, grade = "quarantine", "B"
    else:
        policy, grade = "none", "D"
    return {"present": True, "record": rec, "policy": policy, "grade": grade}


def _dkim(domain: str) -> dict:
    selectors = ["default", "google", "selector1", "selector2", "k1", "mail", "dkim", "smtp"]
    found = {}
    for s in selectors:
        recs = _query(f"{s}._domainkey.{domain}", "TXT")
        rec = next((r for r in recs if "v=DKIM" in r or "k=" in r), None)
        if rec:
            found[s] = rec[:200]
    return {
        "present": len(found) > 0,
        "selectors_found": list(found.keys()),
        "samples": found,
        "grade": "A" if found else "F",
    }


def _http_security_headers(domain: str) -> dict:
    out = {"https_reachable": False, "headers": {}, "missing": [], "grade": "F"}
    for scheme in ("https", "http"):
        try:
            r = requests.get(f"{scheme}://{domain}", timeout=6, allow_redirects=True)
            present = {}
            for h in SECURITY_HEADERS:
                if h in r.headers:
                    present[h] = r.headers[h][:200]
            out["https_reachable"] = scheme == "https"
            out["status"] = r.status_code
            out["server"] = r.headers.get("Server", "—")
            out["powered_by"] = r.headers.get("X-Powered-By", "—")
            out["headers"] = present
            out["missing"] = [h for h in SECURITY_HEADERS if h not in present]
            score = len(present) / len(SECURITY_HEADERS)
            out["grade"] = (
                "A" if score >= 0.83 else
                "B" if score >= 0.66 else
                "C" if score >= 0.5 else
                "D" if score >= 0.33 else "F"
            )
            return out
        except Exception:
            continue
    return out


def _tls_meta(domain: str) -> dict:
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                return {
                    "tls_version": ssock.version(),
                    "cipher": ssock.cipher()[0] if ssock.cipher() else None,
                    "issuer": dict(x[0] for x in cert.get("issuer", [])),
                    "subject": dict(x[0] for x in cert.get("subject", [])),
                    "not_before": cert.get("notBefore"),
                    "not_after": cert.get("notAfter"),
                }
    except Exception as e:
        return {"error": str(e)}


def _subdomains(domain: str) -> list:
    try:
        r = requests.get(f"https://crt.sh/?q=%.{domain}&output=json", timeout=8)
        if r.status_code != 200:
            return []
        subs = set()
        for entry in r.json():
            for n in entry.get("name_value", "").split("\n"):
                n = n.strip().lower()
                if n.endswith(domain) and n != domain and "*" not in n:
                    subs.add(n)
        return sorted(subs)
    except Exception:
        return []


def _reverse_ip(ip: str) -> list:
    try:
        r = requests.get(f"https://api.hackertarget.com/reverseiplookup/?q={ip}", timeout=5)
        if r.status_code == 200 and "error" not in r.text.lower():
            return [x for x in r.text.splitlines() if x.strip()][:50]
    except Exception:
        pass
    return []


async def domain_oracle(domain: str) -> dict:
    domain = domain.strip().lower()
    if domain.startswith(("http://", "https://")):
        domain = urlparse(domain).netloc
    if not re.match(r"^[a-z0-9.-]+\.[a-z]{2,}$", domain):
        return {"error": "Invalid domain"}

    try:
        ip = socket.gethostbyname(domain)
    except Exception:
        return {"error": "Could not resolve domain"}

    dns_records = {}
    for rtype in ("A", "AAAA", "MX", "NS", "TXT", "CAA", "SOA"):
        dns_records[rtype] = await asyncio.to_thread(_query, domain, rtype)

    rdap = await asyncio.to_thread(_rdap, domain)
    spf = _spf(dns_records.get("TXT", []))
    dmarc = await asyncio.to_thread(_dmarc, domain)
    dkim = await asyncio.to_thread(_dkim, domain)
    headers = await asyncio.to_thread(_http_security_headers, domain)
    tls = await asyncio.to_thread(_tls_meta, domain)
    subs = await asyncio.to_thread(_subdomains, domain)
    neighbors = await asyncio.to_thread(_reverse_ip, ip)

    grades = [spf["grade"], dmarc["grade"], dkim["grade"], headers["grade"]]
    score = 100 - (sum({"A": 0, "B": 10, "C": 20, "D": 30, "F": 40}[g] for g in grades))
    score = max(0, min(100, score))

    return {
        "domain": domain,
        "ip": ip,
        "score": score,
        "rdap": rdap,
        "dns": dns_records,
        "email_security": {
            "spf": spf,
            "dmarc": dmarc,
            "dkim": dkim,
        },
        "http_security": headers,
        "tls": tls,
        "subdomains": subs,
        "neighbors": neighbors,
    }
