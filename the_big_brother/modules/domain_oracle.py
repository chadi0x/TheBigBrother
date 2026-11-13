"""
DOMAIN ORACLE — Passive deep domain intelligence.
Pulls WHOIS (RDAP), full DNS set, SPF/DMARC/DKIM posture, HTTP security headers,
TLS basic info, and subdomain enumeration via crt.sh — no auth keys required.
"""
from __future__ import annotations

import asyncio
import socket
import ssl
import re
from typing import Optional, Dict, Any, List, Tuple
from urllib.parse import urlparse

import json
import urllib.request
import urllib.parse
import urllib.error

try:
    import requests
except ImportError:
    requests = None

try:
    import dns.resolver
except ImportError:
    dns = None


SECURITY_HEADERS = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy",
]


def _resolver():
    if dns is not None:
        r = dns.resolver.Resolver()
        r.timeout = 2
        r.lifetime = 3
        return r
    return None


def _query(domain: str, rtype: str):
    out = []
    r = _resolver()
    if r is not None:
        try:
            for rec in r.resolve(domain, rtype):
                out.append(str(rec).strip('"'))
            return out
        except Exception:
            pass

    # DoH Fallback via Cloudflare public DoH endpoint
    url = f"https://cloudflare-dns.com/dns-query?name={urllib.parse.quote(domain)}&type={rtype}"
    req = urllib.request.Request(url, headers={"Accept": "application/dns-json", "User-Agent": "TheBigBrother/7.0"})
    try:
        with urllib.request.urlopen(req, timeout=3) as resp:
            data = json.loads(resp.read().decode("utf-8", errors="replace"))
            for ans in data.get("Answer", []):
                val = str(ans.get("data", "")).strip('"')
                if val:
                    out.append(val)
    except Exception:
        pass

    if not out and rtype == "A":
        try:
            ip = socket.gethostbyname(domain)
            if ip:
                out.append(ip)
        except Exception:
            pass

    return out


def _rdap(domain: str) -> dict:
    data = None
    if requests is not None:
        try:
            r = requests.get(f"https://rdap.org/domain/{domain}", timeout=6)
            if r.status_code == 200:
                data = r.json()
        except Exception:
            pass
    if data is None:
        try:
            req = urllib.request.Request(f"https://rdap.org/domain/{domain}", headers={"User-Agent": "TheBigBrother/7.0"})
            with urllib.request.urlopen(req, timeout=5) as resp:
                if resp.getcode() == 200:
                    data = json.loads(resp.read().decode("utf-8", errors="replace"))
        except Exception:
            pass

    if not data or not isinstance(data, dict):
        return {}

    events = {e.get("eventAction"): e.get("eventDate") for e in data.get("events", [])}
    registrar = "Unknown"
    registrar_iana = "N/A"
    registrant_org = "Protected / Redacted"
    registrant_country = "N/A"

    for ent in data.get("entities", []):
        roles = ent.get("roles", [])
        if "registrar" in roles:
            v = ent.get("vcardArray")
            if v and len(v) > 1:
                for item in v[1]:
                    if item[0] == "fn":
                        registrar = item[3]
                        break
            for id_entry in ent.get("publicIds", []):
                if id_entry.get("type") == "IANA Registrar ID":
                    registrar_iana = str(id_entry.get("identifier"))
        if "registrant" in roles:
            v = ent.get("vcardArray")
            if v and len(v) > 1:
                for item in v[1]:
                    if item[0] == "org":
                        registrant_org = str(item[3])
                    elif item[0] == "adr" and len(item) > 3 and isinstance(item[3], list):
                        registrant_country = str(item[3][-1] if item[3] else "N/A")

    ns = []
    for n in data.get("nameservers", []):
        ld = n.get("ldhName")
        if ld:
            ns.append(ld.lower())

    return {
        "registrar": registrar,
        "registrar_iana_id": registrar_iana,
        "registrant_org": registrant_org,
        "registrant_country": registrant_country,
        "status": data.get("status", []),
        "created": events.get("registration", "Unknown"),
        "updated": events.get("last changed", events.get("last update of RDAP database", "Unknown")),
        "expires": events.get("expiration", "Unknown"),
        "nameservers": ns,
    }


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


def _detect_cdn_waf(headers: dict, ip: str) -> tuple[str, bool]:
    h_str = " ".join([f"{k}:{v}" for k, v in headers.items()]).lower()
    if "cf-ray" in h_str or "cloudflare" in h_str:
        return "Cloudflare Global CDN & WAF", True
    if "x-amz-cf-id" in h_str or "cloudfront" in h_str:
        return "Amazon CloudFront CDN", True
    if "x-akamai" in h_str or "akamai" in h_str:
        return "Akamai Intelligent Edge WAF", True
    if "x-fastly" in h_str or "fastly" in h_str:
        return "Fastly Edge Cloud", True
    if "sucuri" in h_str:
        return "Sucuri CloudProxy WAF", True
    if "incap" in h_str or "imperva" in h_str:
        return "Imperva Incapsula WAF", True
    return "Direct / Origin Hosted (No Reverse Proxy Detected)", False


def _http_security_headers(domain: str) -> dict:
    out = {"https_reachable": False, "headers": {}, "missing": [], "grade": "F", "cdn_waf": "Unknown", "waf_detected": False}
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
            out["raw_headers"] = dict(r.headers)
            out["missing"] = [h for h in SECURITY_HEADERS if h not in present]
            cdn, is_waf = _detect_cdn_waf(r.headers, "")
            out["cdn_waf"] = cdn
            out["waf_detected"] = is_waf
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
                sans = [x[1] for x in cert.get("subjectAltName", []) if x[0] == "DNS"]
                return {
                    "tls_version": ssock.version(),
                    "cipher": ssock.cipher()[0] if ssock.cipher() else None,
                    "issuer": dict(x[0] for x in cert.get("issuer", [])),
                    "subject": dict(x[0] for x in cert.get("subject", [])),
                    "subject_alt_names": sans[:40],
                    "not_before": cert.get("notBefore"),
                    "not_after": cert.get("notAfter"),
                }
    except Exception as e:
        return {"error": str(e), "subject_alt_names": []}


def _subdomains(domain: str, tls_sans: list = None) -> list:
    subs = set()
    if tls_sans:
        for s in tls_sans:
            s_clean = s.strip().lower()
            if s_clean.endswith(domain) and s_clean != domain and "*" not in s_clean:
                subs.add(s_clean)
    try:
        r = requests.get(f"https://crt.sh/?q=%.{domain}&output=json", timeout=8)
        if r.status_code == 200 and isinstance(r.json(), list):
            for entry in r.json():
                for n in entry.get("name_value", "").split("\n"):
                    n = n.strip().lower()
                    if n.endswith(domain) and n != domain and "*" not in n:
                        subs.add(n)
    except Exception:
        pass
    return sorted(subs)[:100]


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
        return {"error": "Invalid domain format"}

    ip = None
    try:
        ip = socket.gethostbyname(domain)
    except Exception:
        # Try DoH A-record
        a_recs = _query(domain, "A")
        if a_recs:
            ip = a_recs[0]

    if not ip:
        return {
            "status": "upstream_diagnostic",
            "domain": domain,
            "ip": "UNRESOLVED",
            "error": f"Could not resolve domain {domain}. Network resolver unreachable.",
            "threat_score": 0,
            "threat_level": "NOMINAL",
            "score": 0,
            "dns_records": {},
            "subdomains": []
        }

    # Full DNS Recursion: A, AAAA, MX, NS, TXT, CAA, SOA, CNAME
    dns_records = {}
    for rtype in ("A", "AAAA", "MX", "NS", "TXT", "CAA", "SOA", "CNAME"):
        dns_records[rtype] = await asyncio.to_thread(_query, domain, rtype)

    rdap = await asyncio.to_thread(_rdap, domain)
    spf = _spf(dns_records.get("TXT", []))
    dmarc = await asyncio.to_thread(_dmarc, domain)
    dkim = await asyncio.to_thread(_dkim, domain)
    headers = await asyncio.to_thread(_http_security_headers, domain)
    tls = await asyncio.to_thread(_tls_meta, domain)
    tls_sans = tls.get("subject_alt_names", []) if isinstance(tls, dict) else []
    subs = await asyncio.to_thread(_subdomains, domain, tls_sans)
    neighbors = await asyncio.to_thread(_reverse_ip, ip)

    grades = [spf["grade"], dmarc["grade"], dkim["grade"], headers["grade"]]
    score = 100 - (sum({"A": 0, "B": 10, "C": 20, "D": 30, "F": 40}[g] for g in grades))
    score = max(0, min(100, score))
    threat_val = 100 - score

    return {
        "status": "success",
        "domain": domain,
        "ip": ip,
        "score": score,
        "threat_score": threat_val,
        "threat_level": "CRITICAL" if threat_val >= 70 else ("ELEVATED" if threat_val >= 40 else "NOMINAL"),
        "rdap": rdap,
        "dns": dns_records,
        "dns_records": dns_records,
        "email_security": {
            "spf": spf,
            "dmarc": dmarc,
            "dkim": dkim,
        },
        "http_security": headers,
        "cdn_waf": headers.get("cdn_waf"),
        "waf_detected": headers.get("waf_detected", False),
        "tls": tls,
        "subdomains": subs,
        "subdomain_count": len(subs),
        "neighbors": neighbors,
        "registrar": rdap.get("registrar", "Protected"),
        "nameservers": rdap.get("nameservers", dns_records.get("NS", []))
    }
