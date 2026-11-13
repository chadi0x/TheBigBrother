"""
VX ARSENAL // NETWORK & INFRASTRUCTURE ENGINES

Nine live, keyless reconnaissance engines:
  dns_intel, cert_transparency, typosquat_radar, http_audit, waf_fingerprint,
  ip_intel, bucket_hunter, exposed_files, link_forensics
"""
from __future__ import annotations

import asyncio
import ipaddress
import json
import re
import socket
import time
import urllib.parse
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from .common import (
    SEVERITY_WEIGHT,
    doh_query,
    doh_raw,
    envelope,
    error_envelope,
    finding,
    gather_limited,
    http_json,
    http_request,
    is_domain,
    is_private_ip,
    normalize_domain,
    normalize_url,
    ptr_lookup,
    random_label,
    rdap_domain,
    rdap_ip,
    resolve_a,
    resolve_aaaa,
    resolve_mx,
    resolve_txt,
    risk_tier,
    root_domain,
    tls_peer,
    utc_now,
)


# ===========================================================================
# 1. DNS INTELLIGENCE
# ===========================================================================

DKIM_SELECTORS = (
    "default", "google", "selector1", "selector2", "k1", "mail", "dkim",
    "smtp", "s1", "s2", "mandrill", "everlytics", "protonmail", "zoho",
)

MAIL_PROVIDERS = {
    "google": "Google Workspace / Gmail",
    "googlemail": "Google Workspace / Gmail",
    "outlook": "Microsoft 365 / Outlook",
    "protection.outlook": "Microsoft 365 / Exchange Online Protection",
    "pphosted": "Proofpoint",
    "mimecast": "Mimecast",
    "barracuda": "Barracuda",
    "messagelabs": "Symantec MessageLabs",
    "zoho": "Zoho Mail",
    "yandex": "Yandex Mail",
    "icloud": "Apple iCloud",
    "protonmail": "ProtonMail",
    "amazonaws": "Amazon SES / WorkMail",
    "mailgun": "Mailgun",
    "sendgrid": "SendGrid",
    "mandrill": "Mailchimp Mandrill",
    "postmark": "Postmark",
    "fastmail": "Fastmail",
}

NS_PROVIDERS = {
    "cloudflare": "Cloudflare",
    "awsdns": "Amazon Route 53",
    "azure-dns": "Azure DNS",
    "googledomains": "Google Cloud DNS",
    "domaincontrol": "GoDaddy",
    "registrar-servers": "Namecheap",
    "dnsmadeeasy": "DNS Made Easy",
    "nsone": "NS1",
    "ultradns": "UltraDNS",
    "akam": "Akamai Edge DNS",
    "dnspod": "DNSPod / Tencent",
    "alidns": "Alibaba Cloud DNS",
    "hostinger": "Hostinger",
    "digitalocean": "DigitalOcean",
    "linode": "Linode",
}


def _parse_spf(record: str) -> Dict[str, Any]:
    tokens = (record or "").split()
    mechanisms = []
    includes = []
    ip4 = []
    ip6 = []
    all_qualifier = ""
    for tok in tokens[1:]:
        low = tok.lower()
        if low.startswith("include:"):
            includes.append(tok.split(":", 1)[1])
            mechanisms.append(tok)
        elif low.startswith("ip4:"):
            ip4.append(tok.split(":", 1)[1])
            mechanisms.append(tok)
        elif low.startswith("ip6:"):
            ip6.append(tok.split(":", 1)[1])
            mechanisms.append(tok)
        elif low.endswith("all") or low.endswith("all".lstrip()):
            all_qualifier = low
            mechanisms.append(tok)
        elif low.startswith(("a", "mx", "ptr", "exists", "redirect=")):
            mechanisms.append(tok)
    strict = all_qualifier in ("-all",)
    soft = all_qualifier in ("~all",)
    dangerous = all_qualifier in ("+all", "?all")
    lookup_count = len(includes) + sum(1 for m in mechanisms if re.match(r"^(a|mx|ptr|exists)", m))
    return {
        "record": record,
        "present": True,
        "mechanisms": mechanisms,
        "includes": includes,
        "include_count": len(includes),
        "ip4": ip4,
        "ip6": ip6,
        "all_qualifier": all_qualifier or "none",
        "strict": strict,
        "soft": soft,
        "dangerous": dangerous,
        "dns_lookup_estimate": lookup_count,
        "lookup_limit_risk": lookup_count > 10,
        "grade": "A" if strict else ("B" if soft else ("F" if dangerous else "C")),
    }


def _parse_dmarc(records: List[str]) -> Dict[str, Any]:
    rec = next((r for r in records if r.lower().startswith("v=dmarc1")), "")
    if not rec:
        return {"present": False, "grade": "F", "record": ""}
    tags: Dict[str, str] = {}
    for part in rec.split(";"):
        if "=" in part:
            k, v = part.split("=", 1)
            tags[k.strip().lower()] = v.strip()
    p = tags.get("p", "none").lower()
    sp = tags.get("sp", p).lower()
    pct = tags.get("pct", "100")
    try:
        pct_int = int(pct)
    except Exception:
        pct_int = 100
    grade = "A" if p == "reject" and pct_int >= 100 else (
        "B" if p == "quarantine" else ("C" if p == "reject" and pct_int < 100 else "D")
    )
    return {
        "record": rec,
        "present": True,
        "policy": p,
        "subdomain_policy": sp,
        "pct": pct_int,
        "rua": tags.get("rua", ""),
        "ruf": tags.get("ruf", ""),
        "adkim": tags.get("adkim", "r"),
        "aspf": tags.get("aspf", "r"),
        "fo": tags.get("fo", ""),
        "grade": grade,
        "enforcing": p in ("quarantine", "reject"),
    }


def _parse_caa(records: List[str]) -> List[Dict[str, Any]]:
    out = []
    for rec in records:
        m = re.match(r'(\d+)\s+(\w+)\s+"?([^"]+)"?', rec)
        if m:
            out.append({"flags": int(m.group(1)), "tag": m.group(2).lower(), "value": m.group(3)})
    return out


def _provider_for(host: str, mapping: Dict[str, str], default: str) -> str:
    low = (host or "").lower()
    for key, name in mapping.items():
        if key in low:
            return name
    return default


def _analyze_dns(domain: str) -> Tuple[Dict[str, Any], List[Dict[str, Any]], int, str]:
    findings: List[Dict[str, Any]] = []
    records: Dict[str, List[str]] = {}
    raw: Dict[str, Any] = {}

    for rtype in ("A", "AAAA", "NS", "MX", "SOA", "CAA", "TXT", "CNAME", "SRV"):
        records[rtype] = doh_query(domain, rtype)

    raw["A"] = doh_raw(domain, "A")
    raw["DNSKEY"] = doh_raw(domain, "DNSKEY")
    raw["DS"] = doh_raw(domain, "DS")

    mx = resolve_mx(domain)
    ns = records.get("NS", [])
    txt = records.get("TXT", [])
    spf = _parse_spf(next((t for t in txt if t.lower().startswith("v=spf1")), ""))
    if not spf.get("present"):
        spf = {"present": False, "grade": "F", "record": "", "strict": False, "dangerous": False}

    dmarc = _parse_dmarc(doh_query(f"_dmarc.{domain}", "TXT"))
    dkim = {}
    for selector in DKIM_SELECTORS:
        recs = doh_query(f"{selector}._domainkey.{domain}", "TXT")
        hit = next((r for r in recs if "v=dkim1" in r.lower() or "k=" in r.lower() or "p=" in r.lower()), "")
        if hit:
            dkim[selector] = hit[:300]
    mta_sts_txt = doh_query(f"_mta-sts.{domain}", "TXT")
    bimi = doh_query(f"default._bimi.{domain}", "TXT")
    caa = _parse_caa(records.get("CAA", []))
    wildcard = doh_query(f"{random_label(18)}.{domain}", "A")

    # DNSSEC: AD flag from a validating resolver is the most portable signal.
    dnssec_signed = False
    ad_flag = bool(raw["A"].get("AD"))
    if ad_flag or raw["DNSKEY"].get("Answer") or raw["DS"].get("Answer"):
        dnssec_signed = True

    # Email authentication score
    email_score = 0
    if spf.get("present"):
        email_score += 20 if spf.get("strict") else 12
    if dmarc.get("present"):
        email_score += 25 if dmarc.get("enforcing") else 10
    if dkim:
        email_score += 20
    if mta_sts_txt:
        email_score += 8
    if bimi:
        email_score += 5
    if dnssec_signed:
        email_score += 12

    if not spf.get("present"):
        findings.append(finding("high", "SPF record missing", "Any host can forge mail from this domain.", recommendation="Publish a strict SPF record ending in -all."))
    elif spf.get("dangerous"):
        findings.append(finding("critical", "SPF allows all senders", f"The SPF record ends in {spf.get('all_qualifier')}, which authorizes every sender on the internet.", evidence=spf.get("record"), recommendation="Replace +all/?all with -all and explicitly list authorized senders."))
    elif not spf.get("strict"):
        findings.append(finding("medium", "SPF is not strict", "SPF does not end in -all, leaving room for envelope spoofing.", evidence=spf.get("record"), recommendation="Tighten the SPF all qualifier to -all."))
    if spf.get("lookup_limit_risk"):
        findings.append(finding("medium", "SPF may exceed 10 DNS lookups", f"Estimated {spf.get('dns_lookup_estimate')} lookup mechanisms; receivers may permerror.", recommendation="Flatten or reduce SPF includes."))

    if not dmarc.get("present"):
        findings.append(finding("high", "DMARC record missing", "No DMARC policy means spoofed mail has no enforcement path.", recommendation="Publish _dmarc TXT with p=reject and rua reporting."))
    elif not dmarc.get("enforcing"):
        findings.append(finding("medium", "DMARC policy is not enforcing", f"Current policy is p={dmarc.get('policy')} pct={dmarc.get('pct')}.", evidence=dmarc.get("record"), recommendation="Move to p=quarantine, then p=reject with pct=100."))
    elif dmarc.get("pct", 100) < 100:
        findings.append(finding("medium", "DMARC coverage is partial", f"pct={dmarc.get('pct')} leaves part of mail unprotected.", evidence=dmarc.get("record"), recommendation="Set pct=100 after monitoring."))

    if not dkim:
        findings.append(finding("medium", "No DKIM selector discovered", "Common selectors returned no public key. Mail may fail alignment or the selector is custom.", recommendation="Publish DKIM and rotate selectors; verify alignment with DMARC."))
    if not dnssec_signed:
        findings.append(finding("low", "DNSSEC not confirmed", "No DS/DNSKEY or authenticated-data signal was observed.", recommendation="Enable DNSSEC at the registrar and sign the zone."))
    if not caa:
        findings.append(finding("low", "No CAA policy", "Any certificate authority may issue certificates for this domain.", recommendation="Publish CAA records pinning authorized CAs."))
    if wildcard:
        findings.append(finding("info", "Wildcard DNS detected", "Random subdomains resolve, which can mask dangling records and broaden attack surface.", evidence=wildcard[:5]))

    mx_primary = mx[0]["host"] if mx else ""
    mail_provider = _provider_for(mx_primary, MAIL_PROVIDERS, "Unknown / self-hosted")
    ns_provider = _provider_for(ns[0] if ns else "", NS_PROVIDERS, "Unknown / self-hosted")

    # Risk model: weak email auth, no DNSSEC, no CAA, wildcard.
    risk = 0
    risk += 0 if spf.get("strict") else (25 if not spf.get("present") else 15)
    risk += 0 if dmarc.get("enforcing") else (25 if not dmarc.get("present") else 15)
    risk += 0 if dkim else 12
    risk += 0 if dnssec_signed else 8
    risk += 0 if caa else 5
    risk += 6 if wildcard else 0
    risk += 18 if spf.get("dangerous") else 0
    risk = min(100, risk)

    data = {
        "domain": domain,
        "ipv4": records.get("A", []),
        "ipv6": records.get("AAAA", []),
        "nameservers": ns,
        "ns_provider": ns_provider,
        "mx": mx,
        "mail_provider": mail_provider,
        "txt": txt,
        "soa": records.get("SOA", []),
        "caa": caa,
        "srv": records.get("SRV", []),
        "cname": records.get("CNAME", []),
        "wildcard": wildcard,
        "dnssec": {
            "signed": dnssec_signed,
            "authenticated_data": ad_flag,
            "dnskey_present": bool(raw["DNSKEY"].get("Answer")),
            "ds_present": bool(raw["DS"].get("Answer")),
            "resolver": raw["A"].get("_resolver", ""),
        },
        "email_security": {
            "spf": spf,
            "dmarc": dmarc,
            "dkim": {"present": bool(dkim), "selectors": list(dkim.keys()), "samples": dkim},
            "mta_sts": {"present": bool(mta_sts_txt), "records": mta_sts_txt},
            "bimi": {"present": bool(bimi), "records": bimi},
            "score": min(100, email_score),
            "grade": "A" if email_score >= 80 else ("B" if email_score >= 65 else ("C" if email_score >= 45 else ("D" if email_score >= 25 else "F"))),
        },
        "mx_records": mx,
        "resolver_latency_ms": raw["A"].get("_resolver", ""),
    }
    summary = (
        f"{domain} resolves to {', '.join(records.get('A', [])[:3]) or 'no A record'}; "
        f"mail via {mail_provider}; DNS via {ns_provider}. "
        f"Email posture {data['email_security']['grade']} / risk {risk}/100."
    )
    return data, findings, risk, summary


async def run_dns_intel(target: str) -> Dict[str, Any]:
    started = time.perf_counter()
    domain = normalize_domain(target)
    if not is_domain(domain):
        return error_envelope("dns_intel", target, "Enter a valid domain, e.g. example.com")
    data, findings, risk, summary = await asyncio.to_thread(_analyze_dns, domain)
    iocs = [{"type": "domain", "value": domain}]
    for ip in (data.get("ipv4") or [])[:8]:
        iocs.append({"type": "ip", "value": ip})
    return envelope(
        "dns_intel", domain, risk=risk, summary=summary, findings=findings, data=data,
        iocs=iocs, sources=["Cloudflare DoH", "Google DoH", "Public DNS"],
        elapsed_ms=int((time.perf_counter() - started) * 1000),
    )


# ===========================================================================
# 2. CERTIFICATE TRANSPARENCY
# ===========================================================================

def _ct_crtsh(domain: str) -> List[Dict[str, Any]]:
    r = http_request(
        f"https://crt.sh/?q=%25.{urllib.parse.quote(domain)}&output=json",
        timeout=18,
        max_bytes=6_000_000,
        headers={"Accept": "application/json"},
    )
    if r.get("status") != 200:
        return []
    try:
        data = json.loads(r["text"])
        return data if isinstance(data, list) else []
    except Exception:
        return []


def _ct_otx_passive(domain: str) -> List[Dict[str, Any]]:
    r = http_json(
        f"https://otx.alienvault.com/api/v1/indicators/domain/{urllib.parse.quote(domain)}/passive_dns",
        timeout=12,
    )
    rows = (r.get("json") or {}).get("passive_dns", []) if isinstance(r.get("json"), dict) else []
    out = []
    for row in rows[:800]:
        host = (row.get("hostname") or "").strip().lower()
        if host:
            out.append({
                "name_value": host,
                "common_name": host,
                "issuer_name": "",
                "not_before": row.get("first", ""),
                "not_after": row.get("last", ""),
                "entry_timestamp": row.get("first", ""),
                "_fallback": "OTX passive DNS",
            })
    return out


def _ct_hackertarget(domain: str) -> List[Dict[str, Any]]:
    r = http_request(
        f"https://api.hackertarget.com/hostsearch/?q={urllib.parse.quote(domain)}",
        timeout=12, max_bytes=300000,
    )
    if r.get("status") != 200:
        return []
    out = []
    for line in (r.get("text") or "").splitlines():
        bits = line.split(",")
        if len(bits) >= 2 and domain in bits[0].lower():
            host = bits[0].strip().lower()
            out.append({
                "name_value": host,
                "common_name": host,
                "issuer_name": "",
                "not_before": "",
                "not_after": "",
                "entry_timestamp": "",
                "_fallback": "HackerTarget hostsearch",
            })
    return out


def _ct_certspotter(domain: str) -> List[Dict[str, Any]]:
    r = http_json(
        f"https://api.certspotter.com/v1/issuances?domain={urllib.parse.quote(domain)}"
        "&include_subdomains=true&expand=dns_names&expand=issuer",
        timeout=14,
    )
    data = r.get("json")
    if not isinstance(data, list):
        return []
    out = []
    for item in data:
        out.append(
            {
                "name_value": "\n".join(item.get("dns_names", []) or []),
                "issuer_name": (item.get("issuer") or {}).get("name", ""),
                "not_before": item.get("not_before", ""),
                "not_after": item.get("not_after", ""),
                "entry_timestamp": item.get("not_before", ""),
                "common_name": (item.get("dns_names") or [""])[0],
            }
        )
    return out


def _analyze_ct(domain: str) -> Tuple[Dict[str, Any], List[Dict[str, Any]], int, str]:
    findings: List[Dict[str, Any]] = []
    entries = _ct_crtsh(domain)
    source = "crt.sh"
    if not entries:
        entries = _ct_certspotter(domain)
        source = "Cert Spotter"
    if not entries:
        entries = _ct_otx_passive(domain)
        source = "OTX passive DNS (CT fallback)"
    if not entries:
        entries = _ct_hackertarget(domain)
        source = "HackerTarget hostsearch (CT fallback)"

    subs = set()
    wildcards = set()
    issuers: Dict[str, int] = {}
    expired = 0
    not_before_min = ""
    not_after_max = ""
    unique_certs = set()
    for e in entries:
        names = str(e.get("name_value") or e.get("common_name") or "").split("\n")
        for name in names:
            n = name.strip().lower().lstrip("*.").rstrip(".")
            if not n or not n.endswith(domain):
                continue
            if n == domain:
                continue
            if "*" in name:
                wildcards.add(n)
            subs.add(n)
        iss = str(e.get("issuer_name") or e.get("issuer") or "Unknown")
        if isinstance(iss, dict):
            iss = str(iss.get("name", "Unknown"))
        issuers[iss] = issuers.get(iss, 0) + 1
        nb = str(e.get("not_before") or "")
        na = str(e.get("not_after") or "")
        cert_key = (e.get("serial_number") or e.get("id") or nb + na + str(names[0] if names else ""))
        unique_certs.add(str(cert_key))
        if nb and (not not_before_min or nb < not_before_min):
            not_before_min = nb
        if na and (not not_after_max or na > not_after_max):
            not_after_max = na
        try:
            dt = datetime.fromisoformat(na.replace("Z", "+00:00"))
            if dt < datetime.now(timezone.utc):
                expired += 1
        except Exception:
            pass

    sub_list = sorted(subs)
    # Resolve a bounded slice of subdomains to distinguish live hosts.
    live: List[Dict[str, Any]] = []
    sample = sub_list[:90]

    def _resolve_one(sub: str) -> Dict[str, Any]:
        ips = resolve_a(sub)
        return {"host": sub, "ips": ips, "live": bool(ips)}

    resolved = asyncio.run(gather_limited([asyncio.to_thread(_resolve_one, s) for s in sample], 18)) if sample else []
    for item in resolved:
        if isinstance(item, dict) and item.get("live"):
            live.append(item)

    if wildcards:
        findings.append(finding("info", "Wildcard certificates detected", f"{len(wildcards)} wildcard SAN(s) found in CT logs.", evidence=sorted(wildcards)[:8]))
    if len(sub_list) > 25:
        findings.append(finding("medium", "Large external attack surface", f"{len(sub_list)} unique subdomains appear in public certificate transparency logs.", recommendation="Inventory every CT-discovered host and retire stale DNS entries."))
    if live and len(live) < max(1, len(sample)) * 0.35:
        findings.append(finding("low", "Stale certificate inventory", f"Only {len(live)} of {len(sample)} resolved subdomains are live; dangling entries may be takeover candidates.", evidence=[x['host'] for x in live[:5]], recommendation="Remove stale DNS records and monitor CT for forgotten hosts."))
    if expired > max(3, len(entries) // 4):
        findings.append(finding("low", "Many historical certificates are expired", f"{expired} expired certificates appear in CT history. This is normal over time but confirms long-lived issuance.", recommendation="Track current certificate expiry and automate renewal."))

    fallback_mode = "fallback" in source.lower()
    if fallback_mode:
        findings.append(finding("info", "Certificate Transparency unavailable — passive DNS fallback used", f"{source} supplied host records because crt.sh and Cert Spotter did not respond.", recommendation="Retry later for certificate issuer and validity detail."))

    risk = min(100, 8 + min(28, len(sub_list) // 4) + (8 if wildcards else 0) + (10 if len(live) > 30 else 0))
    data = {
        "domain": domain,
        "source": source,
        "fallback_mode": fallback_mode,
        "certificate_count": len(entries),
        "unique_certificate_count": len(unique_certs),
        "first_seen": not_before_min,
        "last_expiry": not_after_max,
        "subdomain_count": len(sub_list),
        "live_subdomain_count": len(live),
        "subdomains": sub_list,
        "live_subdomains": live,
        "wildcards": sorted(wildcards),
        "issuers": [{"issuer": k, "count": v} for k, v in sorted(issuers.items(), key=lambda kv: -kv[1])[:12]],
        "expired_certificates": expired,
    }
    if fallback_mode:
        summary = (
            f"CT feeds unavailable; {source} returned {len(entries)} host records → "
            f"{len(sub_list)} unique subdomains ({len(live)} live)."
        )
    else:
        summary = (
            f"{len(entries)} CT certificates reveal {len(sub_list)} unique subdomains "
            f"({len(live)} live), {len(wildcards)} wildcard SAN(s), and {len(issuers)} issuing CA(s)."
        )
    return data, findings, risk, summary


async def run_cert_transparency(target: str) -> Dict[str, Any]:
    started = time.perf_counter()
    domain = normalize_domain(target)
    if not is_domain(domain):
        return error_envelope("cert_transparency", target, "Enter a valid domain, e.g. example.com")
    data, findings, risk, summary = await asyncio.to_thread(_analyze_ct, domain)
    iocs = [{"type": "domain", "value": s} for s in data.get("live_subdomains", [])[:30]]
    if not iocs:
        iocs = [{"type": "domain", "value": domain}]
    return envelope(
        "cert_transparency", domain, risk=risk, summary=summary, findings=findings, data=data,
        iocs=iocs, sources=[data.get("source", "crt.sh"), "Certificate Transparency logs"],
        elapsed_ms=int((time.perf_counter() - started) * 1000),
    )


# ===========================================================================
# 3. TYPOSQUAT / LOOKALIKE RADAR
# ===========================================================================

QWERTY = {
    "q": "wa", "w": "qes", "e": "wrd", "r": "etf", "t": "ryg", "y": "tuh",
    "u": "yij", "i": "uok", "o": "ipl", "p": "ol", "a": "qsz", "s": "awdx",
    "d": "sefc", "f": "drgv", "g": "fthb", "h": "gyjn", "j": "hukm",
    "k": "jiln", "l": "kop", "z": "asx", "x": "zsdc", "c": "xdfv",
    "v": "cfgb", "b": "vghn", "n": "bhjm", "m": "njk",
}
HOMOGLYPHS = {
    "a": "аα4", "b": "Ь6", "c": "сϲ", "d": "ԁ", "e": "е3", "g": "ɡ", "i": "і1l",
    "l": "ӏ1i", "m": "м", "n": "п", "o": "о0", "p": "р", "q": "ԛ", "s": "ѕ5",
    "t": "т", "u": "υ", "v": "ν", "w": "ԝ", "x": "х", "y": "у", "z": "2",
}
SUSPICIOUS_TLDS = {"xyz", "top", "club", "online", "site", "shop", "live", "icu", "buzz", "monster", "cyou", "sbs", "cfd", "rest", "click", "link", "work", "kim", "loan"}


def _permutations(name: str, tld: str, brand: str) -> List[Dict[str, str]]:
    out: List[Dict[str, str]] = []
    seen = set()

    def add(candidate: str, tactic: str, ctld: Optional[str] = None):
        cand = (candidate + (ctld if ctld is not None else tld)).lower()
        if cand == (brand + tld).lower() or cand in seen:
            return
        if len(cand) > 253 or not cand:
            return
        seen.add(cand)
        out.append({"domain": cand, "tactic": tactic})

    # Omission, repetition, transposition, replacement, insertion
    for i in range(len(name)):
        add(name[:i] + name[i + 1:], "character omission")
        add(name[:i] + name[i] + name[i:], "character repetition")
        if i < len(name) - 1 and name[i] != name[i + 1]:
            add(name[:i] + name[i + 1] + name[i] + name[i + 2:], "transposition")
        for repl in QWERTY.get(name[i], ""):
            add(name[:i] + repl + name[i + 1:], "keyboard replacement")
        for ins in QWERTY.get(name[i], "")[:2]:
            add(name[:i] + ins + name[i:], "keyboard insertion")
        for glyph in HOMOGLYPHS.get(name[i], ""):
            add(name[:i] + glyph + name[i + 1:], "IDN homograph")

    # Hyphenation and common bait words
    add(name[:2] + "-" + name[2:], "hyphen insertion")
    add(name + "-" + "secure", "credential bait")
    add(name + "-" + "login", "credential bait")
    add(name + "-" + "verify", "credential bait")
    add(name + "-" + "support", "support bait")
    add(name + "-" + "wallet", "crypto bait")
    add(name + "s", "plural clone")
    add("get" + name, "prefix bait")
    add("my" + name, "prefix bait")

    # TLD swaps
    for ctld in (".com", ".net", ".org", ".co", ".io", ".app", ".dev", ".info",
                 ".online", ".site", ".shop", ".cloud", ".ai", ".xyz", ".top"):
        if ctld != tld.lower():
            add(name, "TLD swap", ctld)
    return out


def _probe_lookalike(item: Dict[str, str], brand: str) -> Dict[str, Any]:
    domain = item["domain"]
    result: Dict[str, Any] = dict(item)
    try:
        ascii_domain = domain.encode("idna").decode("ascii")
    except Exception:
        ascii_domain = domain
    ips = resolve_a(ascii_domain)
    result["punycode"] = ascii_domain if ascii_domain != domain else ""
    result["registered"] = bool(ips)
    result["ips"] = ips[:4]
    result["mx"] = resolve_mx(ascii_domain) if ips else []
    result["has_mail"] = bool(result["mx"])
    if ips:
        url = f"https://{ascii_domain}"
        r = http_request(url, timeout=6, max_bytes=40000, verify_tls=False)
        if r.get("status") in (0, 403, 429) or not r.get("status"):
            url = f"http://{ascii_domain}"
            r = http_request(url, timeout=6, max_bytes=40000)
        result["http_status"] = r.get("status", 0)
        result["server"] = r.get("headers", {}).get("server", "")
        text = r.get("text", "") or ""
        title_m = re.search(r"<title[^>]*>(.*?)</title>", text, re.I | re.S)
        result["title"] = re.sub(r"\s+", " ", title_m.group(1)).strip()[:160] if title_m else ""
        low = (result["title"] + " " + text[:20000]).lower()
        credential_terms = ("login", "sign in", "password", "wallet", "seed phrase", "verify account", "airdrop", "account suspended")
        result["credential_lure"] = any(k in low for k in credential_terms)
        # Brand mention alone is noisy (parking pages, security vendors, press).
        # Require the brand in the page title, or in body near a credential lure.
        result["brand_impersonation"] = (brand.lower() in (result["title"] or "").lower()) or (
            brand.lower() in low and result["credential_lure"]
        )
    result["risk"] = (
        45 if result.get("brand_impersonation")
        else 28 if result.get("credential_lure")
        else 18 if result["registered"] and result["has_mail"]
        else 10 if result["registered"]
        else 0
    )
    if result["punycode"]:
        result["risk"] += 12
    if domain.rsplit(".", 1)[-1] in SUSPICIOUS_TLDS:
        result["risk"] += 6
    result["risk"] = min(100, result["risk"])
    return result


def _analyze_typosquat(domain: str) -> Tuple[Dict[str, Any], List[Dict[str, Any]], int, str]:
    findings: List[Dict[str, Any]] = []
    brand, tld = root_domain(domain)
    if not brand:
        return {}, [finding("info", "Unable to split brand name", domain)], 0, "Invalid domain."
    perms = _permutations(brand, tld, brand)
    # Keep a deterministic, breadth-first slice so the scan stays fast.
    perms = perms[:160]
    probes = asyncio.run(gather_limited([asyncio.to_thread(_probe_lookalike, p, brand) for p in perms], 16))
    probes = [p for p in probes if isinstance(p, dict) and p.get("domain")]
    base_ips = set(resolve_a(domain))
    for probe in probes:
        probe["same_infrastructure"] = bool(base_ips and set(probe.get("ips") or []) & base_ips)
        if probe["same_infrastructure"]:
            probe["risk"] = 0
    registered = [p for p in probes if p.get("registered")]
    owned = [p for p in registered if p.get("same_infrastructure")]
    impersonating = [p for p in registered if p.get("brand_impersonation") and not p.get("same_infrastructure")]
    mail_ready = [p for p in registered if p.get("has_mail") and not p.get("same_infrastructure")]

    if impersonating:
        findings.append(finding("critical", "Active brand impersonation", f"{len(impersonating)} registered lookalike domain(s) reference the brand in page content.", evidence=[p["domain"] for p in impersonating[:10]], recommendation="Submit abuse reports to the registrar/host and file takedown notices."))
    if mail_ready:
        findings.append(finding("high", "Lookalikes with mail capability", f"{len(mail_ready)} lookalike domain(s) publish MX records and can send phishing email.", evidence=[p["domain"] for p in mail_ready[:10]], recommendation="Block lookalike domains at the mail gateway and monitor DMARC reports."))
    if owned:
        findings.append(finding("info", "Defensive registrations detected", f"{len(owned)} lookalike(s) resolve to the same infrastructure as the primary domain and were excluded from impersonation scoring.", evidence=[p["domain"] for p in owned[:10]]))
    if registered:
        findings.append(finding("medium", "Registered lookalike domains", f"{len(registered)} of {len(probes)} generated permutations resolve ({len(owned)} share primary infrastructure).", evidence=[p["domain"] for p in registered[:12]], recommendation="Add high-value lookalikes to a defensive domain portfolio and blocklist."))

    risk = min(100, (10 if registered else 0) + min(45, len(impersonating) * 15) + min(20, len(mail_ready) * 4) + (8 if any(p.get("punycode") for p in impersonating) else 0))
    registered.sort(key=lambda x: (-x.get("risk", 0), x["domain"]))
    data = {
        "brand": brand,
        "tld": tld,
        "generated": len(perms),
        "checked": len(probes),
        "registered_count": len(registered),
        "owned_infrastructure_count": len(owned),
        "impersonation_count": len(impersonating),
        "mail_ready_count": len(mail_ready),
        "lookalikes": registered,
        "all_generated": perms,
    }
    summary = (
        f"Generated {len(perms)} permutations of {brand}{tld}; {len(registered)} are registered "
        f"({len(owned)} owned/defensive), {len(impersonating)} actively impersonate the brand, "
        f"{len(mail_ready)} can send mail."
    )
    return data, findings, risk, summary


async def run_typosquat_radar(target: str) -> Dict[str, Any]:
    started = time.perf_counter()
    domain = normalize_domain(target)
    if not is_domain(domain):
        return error_envelope("typosquat_radar", target, "Enter a valid domain, e.g. example.com")
    data, findings, risk, summary = await asyncio.to_thread(_analyze_typosquat, domain)
    iocs = [{"type": "domain", "value": d["domain"]} for d in data.get("lookalikes", [])[:40]]
    return envelope(
        "typosquat_radar", domain, risk=risk, summary=summary, findings=findings, data=data,
        iocs=iocs, sources=["DoH resolution", "Live HTTPS fingerprint", "IDN homograph map"],
        elapsed_ms=int((time.perf_counter() - started) * 1000),
    )


# ===========================================================================
# 4. HTTP SECURITY AUDIT
# ===========================================================================

SECURITY_HEADER_WEIGHTS = {
    "strict-transport-security": 15,
    "content-security-policy": 20,
    "x-frame-options": 10,
    "x-content-type-options": 10,
    "referrer-policy": 8,
    "permissions-policy": 8,
    "cross-origin-opener-policy": 7,
    "cross-origin-resource-policy": 6,
    "cross-origin-embedder-policy": 5,
    "x-xss-protection": 2,
}

TECH_PATTERNS = {
    "wordpress": ["wp-content", "wp-includes", "wordpress"],
    "drupal": ["drupal", "sites/default/files", "x-generator: drupal"],
    "joomla": ["joomla", "/media/system/js/"],
    "react": ["__next", "react", "_next/static"],
    "nextjs": ["_next/static", "__next_data__"],
    "vue": ["vue.js", "data-v-", "__vue__"],
    "angular": ["ng-version", "angular", "ng-app"],
    "shopify": ["cdn.shopify.com", "shopify"],
    "magento": ["mage/", "magento", "static/version"],
    "laravel": ["laravel_session", "x-powered-by: laravel"],
    "django": ["csrftoken", "django"],
    "rails": ["_rails_session", "rails"],
    "nginx": ["server: nginx"],
    "apache": ["server: apache"],
    "iis": ["server: microsoft-iis"],
    "cloudflare": ["cf-ray", "__cf_bm"],
    "php": ["x-powered-by: php", "phpsessid"],
    "aspnet": ["x-aspnet-version", "asp.net"],
    "java": ["jsessionid", "x-powered-by: servlet"],
    "graphql": ["graphql", "__typename"],
    "firebase": ["firebase", "firebaseio.com"],
}


def _parse_csp(csp: str) -> Dict[str, Any]:
    directives: Dict[str, List[str]] = {}
    for part in (csp or "").split(";"):
        bits = part.strip().split()
        if bits:
            directives[bits[0].lower()] = bits[1:]
    issues = []
    low = (csp or "").lower()
    if "'unsafe-inline'" in low:
        issues.append("unsafe-inline permits inline script injection")
    if "'unsafe-eval'" in low:
        issues.append("unsafe-eval permits dynamic code execution")
    if re.search(r"(^|\s)\*(\s|;|$)", low):
        issues.append("wildcard source permits arbitrary origins")
    if "default-src" not in directives:
        issues.append("missing default-src fallback")
    if "object-src" not in directives:
        issues.append("object-src not locked down")
    if "base-uri" not in directives:
        issues.append("base-uri not restricted")
    if "frame-ancestors" not in directives:
        issues.append("frame-ancestors not restricted")
    return {"directives": directives, "issues": issues, "present": bool(csp)}


def _parse_cookies(set_cookie: str) -> List[Dict[str, Any]]:
    out = []
    for raw in (set_cookie or "").split("\n"):
        if not raw.strip():
            continue
        parts = [p.strip() for p in raw.split(";")]
        if not parts or "=" not in parts[0]:
            continue
        name = parts[0].split("=", 1)[0].strip()
        attrs = {p.split("=", 1)[0].strip().lower(): (p.split("=", 1)[1].strip() if "=" in p else True) for p in parts[1:]}
        out.append({
            "name": name,
            "secure": "secure" in attrs,
            "httponly": "httponly" in attrs,
            "samesite": str(attrs.get("samesite", "none")).lower() if attrs.get("samesite") else "",
            "domain": attrs.get("domain", ""),
            "path": attrs.get("path", ""),
            "max_age": attrs.get("max-age", ""),
        })
    return out


def _fingerprint_tech(headers: Dict[str, str], text: str) -> List[str]:
    hay = " ".join(f"{k}: {v}" for k, v in headers.items()).lower() + " " + (text or "")[:120000].lower()
    found = []
    for name, needles in TECH_PATTERNS.items():
        if any(n in hay for n in needles):
            found.append(name)
    return sorted(set(found))


def _analyze_http(target: str) -> Tuple[Dict[str, Any], List[Dict[str, Any]], int, str]:
    findings: List[Dict[str, Any]] = []
    url = normalize_url(target)
    parsed = urllib.parse.urlparse(url)
    host = parsed.hostname or ""
    if not host:
        return {}, [finding("info", "Invalid URL", target)], 0, "Invalid URL."

    r = http_request(url, timeout=10, max_bytes=180000)
    if not r.get("status") and parsed.scheme == "https":
        http_url = "http://" + url.split("://", 1)[1]
        r2 = http_request(http_url, timeout=10, max_bytes=180000)
        if r2.get("status"):
            r = r2
            url = http_url
    if not r.get("status"):
        return (
            {"url": url, "reachable": False, "error": r.get("error")},
            [finding("medium", "Target did not respond", f"HTTP request failed: {r.get('error') or 'no response'}")],
            10,
            f"{url} did not respond to HTTP probes.",
        )

    headers = r.get("headers", {})
    text = r.get("text", "")
    status = r.get("status", 0)
    score = 100
    present = {}
    missing = []
    for h, weight in SECURITY_HEADER_WEIGHTS.items():
        if h in headers and str(headers[h]).strip():
            present[h] = headers[h][:400]
            score -= 0
        else:
            missing.append(h)
            score -= weight
    cookies = _parse_cookies(headers.get("set-cookie", ""))
    for c in cookies:
        if not c["secure"]:
            score -= 5
        if not c["httponly"]:
            score -= 4
        if c["samesite"] in ("", "none"):
            score -= 3
    cors = headers.get("access-control-allow-origin", "")
    if cors == "*" and headers.get("access-control-allow-credentials", "").lower() == "true":
        score -= 15
        findings.append(finding("high", "CORS wildcard with credentials", "Access-Control-Allow-Origin: * combined with credentials enables cross-origin data theft.", recommendation="Reflect an explicit allowlist and never combine '*' with credentials."))
    elif cors == "*":
        score -= 4
    if headers.get("server"):
        findings.append(finding("info", "Server banner disclosed", f"Server: {headers.get('server')}", recommendation="Suppress version banners at the edge."))
    if headers.get("x-powered-by"):
        findings.append(finding("low", "Technology stack disclosed", f"X-Powered-By: {headers.get('x-powered-by')}", recommendation="Remove X-Powered-By."))

    hsts = headers.get("strict-transport-security", "")
    if hsts:
        m = re.search(r"max-age\s*=\s*(\d+)", hsts)
        if m and int(m.group(1)) < 15552000:
            score -= 4
            findings.append(finding("low", "HSTS max-age is short", f"max-age={m.group(1)} is below the recommended 6-month floor.", evidence=hsts, recommendation="Use max-age=31536000; includeSubDomains; preload."))
        if "includesubdomains" not in hsts.lower():
            score -= 2
    csp = _parse_csp(headers.get("content-security-policy", ""))
    if csp["present"]:
        for issue in csp["issues"]:
            findings.append(finding("medium", "CSP weakness", issue, evidence=headers.get("content-security-policy", "")[:400], recommendation="Tighten CSP and remove unsafe directives."))
            score -= 3
    if cookies:
        insecure = [c["name"] for c in cookies if not c["secure"]]
        if insecure:
            findings.append(finding("high", "Cookie missing Secure flag", f"Insecure cookies: {', '.join(insecure[:8])}", recommendation="Mark session cookies Secure, HttpOnly and SameSite=Lax/Strict."))
    if "x-frame-options" not in headers and "frame-ancestors" not in csp.get("directives", {}):
        findings.append(finding("medium", "Clickjacking protection absent", "Neither X-Frame-Options nor CSP frame-ancestors is set.", recommendation="Set X-Frame-Options: DENY or frame-ancestors 'none'."))
    for h in missing:
        if h in ("content-security-policy", "strict-transport-security"):
            findings.append(finding("high" if h == "strict-transport-security" else "medium", f"Missing {h}", f"The response does not set {h}.", recommendation=f"Add a hardened {h} header."))
        elif h in ("x-content-type-options", "x-frame-options", "referrer-policy"):
            findings.append(finding("medium", f"Missing {h}", f"The response does not set {h}."))

    https_redirect = None
    if url.startswith("https://"):
        http_probe = http_request("http://" + url.split("://", 1)[1], timeout=8, max_bytes=20000, allow_redirects=False)
        https_redirect = {
            "status": http_probe.get("status"),
            "location": http_probe.get("headers", {}).get("location", ""),
            "redirects_to_https": str(http_probe.get("headers", {}).get("location", "")).lower().startswith("https://"),
        }
        if http_probe.get("status") in (200, 204):
            score -= 8
            findings.append(finding("high", "Plain HTTP served without redirect", "The HTTP endpoint returns content instead of redirecting to HTTPS.", recommendation="Force a 301 redirect to HTTPS at the edge."))

    tls = tls_peer(host, parsed.port or 443)
    if tls.get("ok"):
        if tls.get("version") not in ("TLSv1.2", "TLSv1.3"):
            score -= 15
            findings.append(finding("high", "Deprecated TLS version", f"Negotiated {tls.get('version')}.", recommendation="Require TLS 1.2+ and prefer TLS 1.3."))
        if not (tls.get("expires_in_days") is None or tls.get("expires_in_days") > 14):
            score -= 10
            findings.append(finding("high", "Certificate expires soon", f"{tls.get('expires_in_days')} day(s) remaining.", recommendation="Automate certificate renewal."))
    else:
        findings.append(finding("info", "TLS handshake unavailable", tls.get("error", "No TLS session")))

    score = max(0, min(100, score))
    risk = 100 - score
    data = {
        "url": url,
        "final_url": r.get("final_url", url),
        "reachable": True,
        "status": status,
        "server": headers.get("server", ""),
        "powered_by": headers.get("x-powered-by", ""),
        "redirect_chain": r.get("chain", []),
        "http_to_https": https_redirect,
        "security_score": score,
        "grade": "A" if score >= 90 else "B" if score >= 75 else "C" if score >= 60 else "D" if score >= 40 else "F",
        "headers_present": present,
        "headers_missing": missing,
        "csp": csp,
        "cookies": cookies,
        "cors": {
            "allow_origin": cors,
            "allow_credentials": headers.get("access-control-allow-credentials", ""),
            "allow_methods": headers.get("access-control-allow-methods", ""),
        },
        "technologies": _fingerprint_tech(headers, text),
        "tls": tls,
        "raw_headers": headers,
    }
    summary = (
        f"{host} answered HTTP {status} with a security grade of {data['grade']} ({score}/100). "
        f"{len(missing)} recommended header(s) missing, {len(cookies)} cookie(s) observed, "
        f"{len(data['technologies'])} technology signal(s)."
    )
    return data, findings, risk, summary


async def run_http_audit(target: str) -> Dict[str, Any]:
    started = time.perf_counter()
    data, findings, risk, summary = await asyncio.to_thread(_analyze_http, target)
    iocs = [{"type": "url", "value": data.get("final_url") or target}]
    for tech in data.get("technologies", []):
        iocs.append({"type": "technology", "value": tech})
    return envelope(
        "http_audit", data.get("url") or target, risk=risk, summary=summary, findings=findings,
        data=data, iocs=iocs, sources=["Live HTTP response", "TLS handshake", "Header heuristics"],
        elapsed_ms=int((time.perf_counter() - started) * 1000),
    )


# ===========================================================================
# 5. WAF / CDN FINGERPRINT
# ===========================================================================

WAF_SIGNATURES = {
    "Cloudflare": {
        "headers": ["cf-ray", "cf-cache-status", "server: cloudflare"],
        "cookies": ["__cf_bm", "cf_clearance", "_cfuvid"],
        "body": ["attention required! | cloudflare", "cf-error-details", "cloudflare ray id"],
    },
    "Akamai": {
        "headers": ["x-akamai-transformed", "akamai-grn", "server: akamaighost"],
        "cookies": ["ak_bmsc", "bm_sv", "_abck"],
        "body": ["reference #", "akamai"],
    },
    "Imperva / Incapsula": {
        "headers": ["x-iinfo", "x-cdn: incapsula"],
        "cookies": ["incap_ses", "visid_incap", "nlbi_"],
        "body": ["incapsula incident id", "_incapsula_resource"],
    },
    "F5 BIG-IP ASM": {
        "headers": ["x-wa-info", "server: big-ip"],
        "cookies": ["bigipserver", "ts", "f5_cspm"],
        "body": ["the requested url was rejected", "big-ip"],
    },
    "Sucuri": {
        "headers": ["x-sucuri-id", "x-sucuri-cache", "server: sucuri"],
        "cookies": ["sucuri_cloudproxy"],
        "body": ["sucuri website firewall", "access denied - sucuri"],
    },
    "AWS WAF / CloudFront": {
        "headers": ["x-amz-cf-id", "x-amz-cf-pop", "via: cloudfront", "x-amzn-waf"],
        "cookies": ["awsalb", "awsalbcors"],
        "body": ["request blocked", "generated by cloudfront"],
    },
    "Azure Front Door / WAF": {
        "headers": ["x-azure-ref", "x-fd-healthprobe", "server: azurefd"],
        "cookies": ["afd", "azure"],
        "body": ["azure front door", "our services aren't available"],
    },
    "Fastly": {
        "headers": ["x-fastly-request-id", "fastly-io-info", "x-served-by"],
        "cookies": [],
        "body": ["fastly error", "fastly global network"],
    },
    "DDoS-Guard": {
        "headers": ["server: ddos-guard", "x-ddos-guard"],
        "cookies": ["__ddg"],
        "body": ["ddos-guard", "ddos protection"],
    },
    "Vercel": {
        "headers": ["x-vercel-id", "x-vercel-cache", "server: vercel"],
        "cookies": [],
        "body": ["vercel"],
    },
    "Netlify": {
        "headers": ["x-nf-request-id", "server: netlify"],
        "cookies": ["nf_jwt"],
        "body": ["netlify"],
    },
    "Bunny CDN": {
        "headers": ["server: bunnycdn", "cdn-pullzone"],
        "cookies": [],
        "body": ["bunnycdn"],
    },
}


def _analyze_waf(target: str) -> Tuple[Dict[str, Any], List[Dict[str, Any]], int, str]:
    url = normalize_url(target)
    normal = http_request(url, timeout=9, max_bytes=60000)
    probe_url = url + ("&" if "?" in url else "?") + "vx_probe=%3Cscript%3Ealert(1)%3C/script%3E%27%20OR%201%3D1--"
    attack = http_request(probe_url, timeout=9, max_bytes=60000)

    headers_n = normal.get("headers", {})
    headers_a = attack.get("headers", {})
    body_n = (normal.get("text", "") or "").lower()
    body_a = (attack.get("text", "") or "").lower()
    cookies_a = headers_a.get("set-cookie", "").lower()
    combined_headers = " ".join(f"{k}:{v}" for k, v in {**headers_n, **headers_a}.items()).lower()

    matches = []
    for name, sig in WAF_SIGNATURES.items():
        evidence = []
        for h in sig["headers"]:
            if h in combined_headers:
                evidence.append(f"header:{h}")
        for c in sig["cookies"]:
            if c in cookies_a:
                evidence.append(f"cookie:{c}")
        for b in sig["body"]:
            if b in body_a or b in body_n:
                evidence.append(f"body:{b}")
        if evidence:
            blocked = attack.get("status") in (403, 406, 429, 503) and normal.get("status") not in (403, 406, 429, 503)
            matches.append({"provider": name, "evidence": evidence[:6], "confidence": min(99, 45 + len(evidence) * 18), "blocked_probe": blocked})

    findings = []
    # CDN hints from DNS
    domain = urllib.parse.urlparse(url).hostname or ""
    ns = doh_query(domain, "NS")
    dns_cdn = ""
    if any("cloudflare" in n for n in ns):
        dns_cdn = "Cloudflare"
    elif any("awsdns" in n for n in ns):
        dns_cdn = "AWS Route 53 (not proof of WAF)"
    if dns_cdn and not any(m["provider"] == "Cloudflare" for m in matches):
        matches.append({"provider": dns_cdn, "evidence": [f"ns:{ns[0]}"], "confidence": 60, "blocked_probe": False})

    attack_blocked = attack.get("status") in (403, 406, 429, 503)
    if not matches:
        findings.append(finding("medium", "No WAF/CDN fingerprint detected", "Headers, cookies and a benign XSS probe did not reveal an edge security layer.", recommendation="Front untrusted origins with a WAF and enable managed OWASP rules."))
        risk = 38
    else:
        top = max(matches, key=lambda x: x["confidence"])
        if attack_blocked:
            findings.append(finding("info", f"{top['provider']} blocked the probe", "The edge returned a block/challenge status for a harmless XSS probe.", evidence=top["evidence"]))
        else:
            findings.append(finding("low", f"{top['provider']} detected but probe was not blocked", "Fingerprint exists, but the edge did not block an obvious XSS payload.", evidence=top["evidence"], recommendation="Verify WAF rules are in blocking mode, not monitor-only."))
        risk = 8 if attack_blocked else 24

    data = {
        "url": url,
        "normal_status": normal.get("status"),
        "probe_status": attack.get("status"),
        "probe_blocked": attack_blocked,
        "detected_waf": bool(matches),
        "providers": sorted(matches, key=lambda x: -x["confidence"]),
        "primary": max(matches, key=lambda x: x["confidence"]) if matches else None,
        "dns_nameservers": ns,
        "server": headers_n.get("server", ""),
        "via": headers_n.get("via", ""),
        "cdn_headers": {k: v for k, v in headers_n.items() if any(x in k for x in ("cf-", "x-cache", "x-served", "x-amz", "x-vercel", "x-akamai", "x-azure", "x-fastly", "x-sucuri", "x-nf"))},
        "probe_evidence": {"status": attack.get("status"), "content_type": headers_a.get("content-type", ""), "excerpt": (body_a[:300] if attack_blocked else "")},
    }
    provider = data["primary"]["provider"] if data["primary"] else "none"
    summary = (
        f"{provider} fingerprint on {url}; probe returned HTTP {attack.get('status')} "
        f"({'blocked' if attack_blocked else 'not blocked'})."
    )
    return data, findings, risk, summary


async def run_waf_fingerprint(target: str) -> Dict[str, Any]:
    started = time.perf_counter()
    data, findings, risk, summary = await asyncio.to_thread(_analyze_waf, target)
    return envelope(
        "waf_fingerprint", data.get("url") or target, risk=risk, summary=summary,
        findings=findings, data=data, iocs=[{"type": "url", "value": data.get("url", target)}],
        sources=["Live edge response", "Active XSS canary probe", "DNS NS hints"],
        elapsed_ms=int((time.perf_counter() - started) * 1000),
    )


# ===========================================================================
# 6. IP INTELLIGENCE
# ===========================================================================

RISKY_PORTS = {
    21: ("FTP", "critical"), 22: ("SSH", "medium"), 23: ("Telnet", "critical"),
    25: ("SMTP", "low"), 53: ("DNS", "medium"), 135: ("MSRPC", "high"),
    139: ("NetBIOS", "high"), 445: ("SMB", "critical"), 1433: ("MSSQL", "critical"),
    1521: ("Oracle DB", "critical"), 2049: ("NFS", "critical"), 2375: ("Docker API", "critical"),
    3306: ("MySQL", "critical"), 3389: ("RDP", "critical"), 5432: ("PostgreSQL", "critical"),
    5900: ("VNC", "critical"), 6379: ("Redis", "critical"), 8080: ("HTTP-alt", "medium"),
    8443: ("HTTPS-alt", "low"), 9200: ("Elasticsearch", "critical"), 27017: ("MongoDB", "critical"),
}


def _analyze_ip(ip: str) -> Tuple[Dict[str, Any], List[Dict[str, Any]], int, str]:
    findings: List[Dict[str, Any]] = []
    try:
        addr = ipaddress.ip_address(ip)
    except Exception:
        return {}, [finding("info", "Invalid IP address", ip)], 0, "Invalid IP address."

    geo = {}
    for api in (
        f"http://ip-api.com/json/{ip}?fields=status,message,country,countryCode,regionName,city,zip,lat,lon,timezone,isp,org,as,asname,reverse,mobile,proxy,hosting,query",
        f"https://ipinfo.io/{ip}/json",
    ):
        try:
            r = http_json(api, timeout=7)
            j = r.get("json") or {}
            if j and j.get("status") != "fail" and not j.get("bogon"):
                geo = j
                break
        except Exception:
            continue

    rdap = rdap_ip(ip)
    idb_r = http_json(f"https://internetdb.shodan.io/{ip}", timeout=8)
    idb = idb_r.get("json") or {}
    if not isinstance(idb, dict) or idb.get("detail"):
        idb = {}
    ptr = ptr_lookup(ip)

    ports = idb.get("ports", []) or []
    vulns = idb.get("vulns", []) or []
    hostnames = idb.get("hostnames", []) or []
    tags = idb.get("tags", []) or []
    cpes = idb.get("cpes", []) or []

    risky = []
    for p in ports:
        try:
            pi = int(p)
        except Exception:
            continue
        if pi in RISKY_PORTS:
            service, sev = RISKY_PORTS[pi]
            risky.append({"port": pi, "service": service, "severity": sev})
    if risky:
        crit = [p for p in risky if p["severity"] == "critical"]
        findings.append(finding("critical" if crit else "high", "Exposed high-risk service ports", f"InternetDB reports {len(risky)} sensitive port(s) open.", evidence=[f"{p['port']}/{p['service']}" for p in risky], recommendation="Close or authenticate management/database ports at the firewall."))
    if vulns:
        findings.append(finding("high", f"{len(vulns)} known CVE(s) advertised", "Shodan InternetDB associates known vulnerabilities with this host.", evidence=vulns[:12], recommendation="Patch exposed services and re-scan after remediation."))
    if geo.get("proxy"):
        findings.append(finding("high", "Proxy/VPN/Tor exit detected", "The IP intelligence provider flags this address as a proxy or anonymizer.", recommendation="Apply enhanced authentication and rate limiting for anonymized traffic."))
    if geo.get("hosting"):
        findings.append(finding("info", "Datacenter / hosting IP", "The address belongs to hosting infrastructure rather than residential ISP space.", evidence=geo.get("org") or geo.get("isp")))
    if not ptr:
        findings.append(finding("low", "No reverse DNS (PTR)", "The address has no PTR record, common for ephemeral cloud infrastructure."))
    if addr.version == 6:
        findings.append(finding("info", "IPv6 address", "IPv6 intelligence coverage varies by source; verify firewall parity."))

    risk = 0
    risk += min(40, len([p for p in risky if p["severity"] == "critical"]) * 14)
    risk += min(25, len([p for p in risky if p["severity"] == "high"]) * 8)
    risk += min(25, len(vulns) * 4)
    risk += 12 if geo.get("proxy") else 0
    risk += 5 if geo.get("hosting") else 0
    risk = min(100, risk)

    data = {
        "ip": ip,
        "version": addr.version,
        "is_private": addr.is_private,
        "geo": {
            "country": geo.get("country", rdap.get("country", "")),
            "country_code": geo.get("countryCode", ""),
            "region": geo.get("regionName") or geo.get("region", ""),
            "city": geo.get("city", ""),
            "latitude": geo.get("lat", ""),
            "longitude": geo.get("lon", ""),
            "timezone": geo.get("timezone", ""),
            "isp": geo.get("isp", ""),
            "org": geo.get("org") or geo.get("asname", ""),
            "asn": geo.get("as", rdap.get("name", "")),
            "hosting": geo.get("hosting", False),
            "proxy": geo.get("proxy", False),
            "mobile": geo.get("mobile", False),
        },
        "rdap": rdap,
        "ptr": ptr,
        "hostnames": hostnames,
        "ports": sorted(ports),
        "risky_ports": risky,
        "vulns": vulns,
        "cpes": cpes,
        "tags": tags,
        "sources": {
            "geo": "ip-api.com" if geo.get("query") else "ipinfo.io",
            "exposure": "internetdb.shodan.io" if idb else "unavailable",
            "registry": "rdap.org" if rdap else "unavailable",
        },
    }
    summary = (
        f"{ip} in {data['geo'].get('city') or 'unknown city'}, {data['geo'].get('country') or 'unknown country'}; "
        f"ASN {data['geo'].get('asn') or 'unknown'}; {len(ports)} open port(s), {len(vulns)} CVE(s), "
        f"{len(hostnames)} hostname(s)."
    )
    return data, findings, risk, summary


async def run_ip_intel(target: str) -> Dict[str, Any]:
    started = time.perf_counter()
    ip = (target or "").strip().strip("[]")
    data, findings, risk, summary = await asyncio.to_thread(_analyze_ip, ip)
    if not data:
        return error_envelope("ip_intel", target, summary)
    return envelope(
        "ip_intel", ip, risk=risk, summary=summary, findings=findings, data=data,
        iocs=[{"type": "ip", "value": ip}], sources=["ip-api.com", "RDAP", "Shodan InternetDB", "PTR"],
        elapsed_ms=int((time.perf_counter() - started) * 1000),
    )


# ===========================================================================
# 7. CLOUD BUCKET HUNTER
# ===========================================================================

BUCKET_SUFFIXES = (
    "", "-assets", "-static", "-media", "-files", "-uploads", "-backup", "-backups",
    "-dev", "-prod", "-production", "-staging", "-test", "-data", "-logs", "-cdn",
    "-public", "-private", "-images", "-docs", "-downloads",
)


def _bucket_candidates(target: str) -> List[str]:
    domain = normalize_domain(target)
    brand, _tld = root_domain(domain)
    raw = re.sub(r"[^a-z0-9-]", "-", brand.lower()).strip("-")
    bases = {raw, raw.replace("-", ""), domain.replace(".", "-")}
    out = []
    seen = set()
    for b in bases:
        if not b:
            continue
        for suf in BUCKET_SUFFIXES:
            cand = (b + suf).strip("-")
            if 3 <= len(cand) <= 63 and cand not in seen:
                seen.add(cand)
                out.append(cand)
    return out[:54]


def _probe_s3(bucket: str) -> Dict[str, Any]:
    r = http_request(
        f"https://{bucket}.s3.amazonaws.com/?list-type=2&max-keys=3",
        timeout=7, max_bytes=12000, allow_redirects=False,
    )
    status = r.get("status", 0)
    text = r.get("text", "") or ""
    region = r.get("headers", {}).get("x-amz-bucket-region", "")
    if status == 200 and "ListBucketResult" in text:
        keys = re.findall(r"<Key>(.*?)</Key>", text)[:3]
        return {"provider": "AWS S3", "bucket": bucket, "state": "public_listing", "status": status, "region": region, "sample_keys": keys}
    if status == 403:
        return {"provider": "AWS S3", "bucket": bucket, "state": "exists_private", "status": status, "region": region}
    if status in (301, 307) and region:
        return {"provider": "AWS S3", "bucket": bucket, "state": "exists_other_region", "status": status, "region": region}
    return {"provider": "AWS S3", "bucket": bucket, "state": "not_found", "status": status}


def _probe_gcs(bucket: str) -> Dict[str, Any]:
    r = http_json(f"https://storage.googleapis.com/storage/v1/b/{urllib.parse.quote(bucket)}", timeout=7, max_bytes=12000)
    status = r.get("status", 0)
    data = r.get("json") or {}
    if status == 200 and isinstance(data, dict) and data.get("name"):
        return {"provider": "Google Cloud Storage", "bucket": bucket, "state": "public_metadata", "status": status, "location": data.get("location", "")}
    if status in (401, 403):
        return {"provider": "Google Cloud Storage", "bucket": bucket, "state": "exists_private", "status": status}
    if status == 404:
        # Try the public XML listing endpoint to catch uniform bucket-level access.
        r2 = http_request(f"https://storage.googleapis.com/{urllib.parse.quote(bucket)}", timeout=6, max_bytes=8000, allow_redirects=False)
        if r2.get("status") == 200 and "ListBucketResult" in (r2.get("text") or ""):
            return {"provider": "Google Cloud Storage", "bucket": bucket, "state": "public_listing", "status": 200}
    return {"provider": "Google Cloud Storage", "bucket": bucket, "state": "not_found", "status": status}


def _probe_azure(account: str) -> Dict[str, Any]:
    for container in ("$web", "public", "assets", "static", "media"):
        url = f"https://{account}.blob.core.windows.net/{urllib.parse.quote(container)}?restype=container&comp=list&maxresults=3"
        r = http_request(url, timeout=6, max_bytes=12000, allow_redirects=False)
        status = r.get("status", 0)
        if status == 200 and "EnumerationResults" in (r.get("text") or ""):
            return {"provider": "Azure Blob", "bucket": f"{account}/{container}", "state": "public_listing", "status": status}
        if status == 403:
            return {"provider": "Azure Blob", "bucket": f"{account}/{container}", "state": "exists_private", "status": status}
    return {"provider": "Azure Blob", "bucket": account, "state": "not_found", "status": 0}


def _analyze_buckets(target: str) -> Tuple[Dict[str, Any], List[Dict[str, Any]], int, str]:
    findings: List[Dict[str, Any]] = []
    candidates = _bucket_candidates(target)

    async def _check(bucket: str) -> List[Dict[str, Any]]:
        out = []
        for fn in (_probe_s3, _probe_gcs, _probe_azure):
            try:
                out.append(await asyncio.to_thread(fn, bucket))
            except Exception:
                continue
        return out

    results = asyncio.run(gather_limited([_check(b) for b in candidates], 10))
    hits: List[Dict[str, Any]] = []
    for group in results:
        for item in group if isinstance(group, list) else []:
            if isinstance(item, dict) and item.get("state") not in ("not_found",):
                hits.append(item)

    public = [h for h in hits if h["state"] in ("public_listing", "public_metadata")]
    private = [h for h in hits if h["state"] in ("exists_private", "exists_other_region")]
    if public:
        findings.append(finding("critical", "Public cloud storage discovered", f"{len(public)} bucket(s) expose public listings or metadata.", evidence=[f"{h['provider']}: {h['bucket']}" for h in public[:10]], recommendation="Enable public access prevention, remove anonymous principals, and audit object ACLs."))
    if private:
        findings.append(finding("low", "Existing but private buckets", f"{len(private)} bucket name(s) exist without public access. This leaks naming and confirms cloud footprint.", evidence=[h["bucket"] for h in private[:10]], recommendation="Review bucket policies and monitor for accidental public exposure."))

    # Private bucket discovery is a footprint leak, not a breach. Keep it capped.
    risk = min(100, len(public) * 40 + min(22, len(private)))
    data = {
        "target": normalize_domain(target),
        "candidates_checked": len(candidates),
        "providers_checked": ["AWS S3", "Google Cloud Storage", "Azure Blob"],
        "existing_count": len(hits),
        "public_count": len(public),
        "private_count": len(private),
        "hits": sorted(hits, key=lambda h: (h["state"] != "public_listing", h["state"] != "public_metadata", h["provider"])),
        "public_buckets": public,
        "candidates": candidates,
    }
    summary = (
        f"Checked {len(candidates)} candidate names across S3, GCS and Azure: "
        f"{len(public)} public bucket(s), {len(private)} existing private bucket(s)."
    )
    return data, findings, risk, summary


async def run_bucket_hunter(target: str) -> Dict[str, Any]:
    started = time.perf_counter()
    data, findings, risk, summary = await asyncio.to_thread(_analyze_buckets, target)
    iocs = []
    for h in data.get("public_buckets", []):
        iocs.append({"type": "cloud_bucket", "value": f"{h['provider']}://{h['bucket']}"})
    return envelope(
        "bucket_hunter", data.get("target") or target, risk=risk, summary=summary,
        findings=findings, data=data, iocs=iocs,
        sources=["AWS S3 API", "Google Cloud Storage JSON API", "Azure Blob REST"],
        elapsed_ms=int((time.perf_counter() - started) * 1000),
    )


# ===========================================================================
# 8. EXPOSED FILES HUNTER
# ===========================================================================

EXPOSED_PATHS = [
    # path, category, severity, signature(s), description
    ("/.git/config", "Source control", "critical", ("[core]", "repositoryformatversion"), "Git repository metadata exposed"),
    ("/.git/HEAD", "Source control", "critical", ("ref: refs/",), "Git HEAD exposed"),
    ("/.git/logs/HEAD", "Source control", "high", ("commit", "checkout"), "Git reflog exposed"),
    ("/.svn/entries", "Source control", "high", ("dir", "svn"), "Subversion metadata exposed"),
    ("/.hg/requires", "Source control", "high", ("revlog", "store"), "Mercurial metadata exposed"),
    ("/.env", "Secrets", "critical", ("=",), "Environment file exposed"),
    ("/.env.local", "Secrets", "critical", ("=",), "Local environment file exposed"),
    ("/.env.production", "Secrets", "critical", ("=",), "Production environment file exposed"),
    ("/.env.backup", "Secrets", "critical", ("=",), "Backup environment file exposed"),
    ("/.aws/credentials", "Secrets", "critical", ("aws_access_key_id",), "AWS credentials exposed"),
    ("/id_rsa", "Secrets", "critical", ("BEGIN RSA PRIVATE KEY", "BEGIN OPENSSH PRIVATE KEY", "BEGIN PRIVATE KEY"), "SSH private key exposed"),
    ("/server.key", "Secrets", "critical", ("BEGIN PRIVATE KEY", "BEGIN RSA PRIVATE KEY"), "TLS private key exposed"),
    ("/wp-config.php.bak", "Secrets", "critical", ("DB_NAME", "DB_PASSWORD"), "WordPress config backup exposed"),
    ("/config.php.bak", "Secrets", "critical", ("password", "db_"), "PHP config backup exposed"),
    ("/.htpasswd", "Secrets", "high", (":$", ":$apr1$", ":{SHA}"), "Password hash file exposed"),
    ("/.DS_Store", "Metadata", "low", ("Bud1",), "macOS metadata file exposed"),
    ("/web.config", "Configuration", "high", ("<configuration", "<system.web"), "IIS configuration exposed"),
    ("/WEB-INF/web.xml", "Configuration", "high", ("<web-app", "<servlet"), "Java web descriptor exposed"),
    ("/nginx.conf", "Configuration", "high", ("server {", "http {"), "Nginx config exposed"),
    ("/docker-compose.yml", "Configuration", "high", ("services:", "version:"), "Docker Compose manifest exposed"),
    ("/docker-compose.yaml", "Configuration", "high", ("services:",), "Docker Compose manifest exposed"),
    ("/Dockerfile", "Configuration", "medium", ("FROM ", "RUN "), "Dockerfile exposed"),
    ("/composer.lock", "Dependency", "medium", ('"packages"', '"content-hash"'), "Composer lockfile exposed"),
    ("/package.json", "Dependency", "low", ('"dependencies"', '"name"'), "Node package manifest exposed"),
    ("/yarn.lock", "Dependency", "low", ("resolved ", "integrity "), "Yarn lockfile exposed"),
    ("/phpinfo.php", "Diagnostics", "high", ("PHP Version", "phpinfo()"), "PHP info page exposed"),
    ("/server-status", "Diagnostics", "high", ("Apache Server Status", "Total Accesses"), "Apache status page exposed"),
    ("/actuator/env", "Diagnostics", "critical", ("propertySources", "activeProfiles"), "Spring Boot env actuator exposed"),
    ("/actuator/health", "Diagnostics", "low", ('"status"',), "Spring Boot health actuator exposed"),
    ("/metrics", "Diagnostics", "medium", ("# HELP", "# TYPE"), "Prometheus metrics exposed"),
    ("/debug", "Diagnostics", "medium", ("debug", "trace"), "Debug endpoint exposed"),
    ("/console", "Diagnostics", "high", ("console", "login"), "Admin console reachable"),
    ("/elmah.axd", "Diagnostics", "high", ("Error Log", "elmah"), "ELMAH error log exposed"),
    ("/trace.axd", "Diagnostics", "high", ("Application Trace", "trace.axd"), "ASP.NET trace exposed"),
    ("/swagger.json", "API", "medium", ('"swagger"', '"openapi"'), "Swagger definition exposed"),
    ("/openapi.json", "API", "medium", ('"openapi"', '"paths"'), "OpenAPI definition exposed"),
    ("/api/swagger.json", "API", "medium", ('"swagger"', '"paths"'), "API Swagger definition exposed"),
    ("/graphql", "API", "medium", ("graphql", "query"), "GraphQL endpoint reachable"),
    ("/backup.zip", "Backup", "critical", ("PK\x03\x04",), "Backup archive exposed"),
    ("/backup.tar.gz", "Backup", "critical", ("\x1f\x8b",), "Backup archive exposed"),
    ("/backup.sql", "Backup", "critical", ("INSERT INTO", "CREATE TABLE"), "Database dump exposed"),
    ("/db.sql", "Backup", "critical", ("CREATE TABLE", "INSERT INTO"), "Database dump exposed"),
    ("/dump.sql", "Backup", "critical", ("CREATE TABLE",), "Database dump exposed"),
    ("/sitemap.xml", "Informational", "info", ("<urlset", "<sitemapindex"), "Sitemap published"),
    ("/robots.txt", "Informational", "info", ("user-agent", "disallow"), "Robots policy published"),
    ("/.well-known/security.txt", "Informational", "info", ("contact:",), "Security contact policy published"),
    ("/crossdomain.xml", "Configuration", "low", ("cross-domain-policy",), "Legacy crossdomain policy exposed"),
    ("/clientaccesspolicy.xml", "Configuration", "low", ("access-policy",), "Silverlight access policy exposed"),
    ("/app.js.map", "Source", "medium", ('"version"', '"sources"'), "JavaScript source map exposed"),
    ("/static/js/main.js.map", "Source", "medium", ('"sources"', '"mappings"'), "JavaScript source map exposed"),
]


def _path_matches(text: str, signatures: Tuple[str, ...]) -> bool:
    low = text.lower()
    for sig in signatures:
        if sig in low:
            return True
        if sig in text:
            return True
    return False


def _analyze_exposed(target: str) -> Tuple[Dict[str, Any], List[Dict[str, Any]], int, str]:
    findings: List[Dict[str, Any]] = []
    base = normalize_url(target).rstrip("/")
    parsed = urllib.parse.urlparse(base)
    if not parsed.hostname:
        return {}, [finding("info", "Invalid URL", target)], 0, "Invalid URL."
    base = f"{parsed.scheme}://{parsed.netloc}"

    def _check(item: Tuple[str, str, str, Tuple[str, ...], str]) -> Dict[str, Any]:
        path, category, severity, sigs, desc = item
        r = http_request(
            base + path, timeout=6, max_bytes=40000, allow_redirects=False,
            headers={"Accept": "*/*"},
        )
        status = r.get("status", 0)
        text = r.get("text", "") or ""
        ctype = r.get("headers", {}).get("content-type", "")
        matched = status == 200 and _path_matches(text, sigs)
        protected = status in (401, 403)
        redirect = status in (301, 302, 307, 308)
        # A 200 with a login page is not an exposure.
        soft_404 = status == 200 and any(x in text[:2000].lower() for x in ("not found", "404", "page not found", "sign in"))
        if matched and soft_404 and path not in ("/robots.txt", "/sitemap.xml"):
            matched = False
        return {
            "path": path, "category": category, "severity": severity, "description": desc,
            "status": status, "content_type": ctype, "exposed": matched,
            "protected": protected, "redirect": redirect,
            "redirect_location": r.get("headers", {}).get("location", ""),
            "bytes": len(r.get("body") or b""),
            "excerpt": re.sub(r"\s+", " ", text[:220]) if matched else "",
        }

    results = asyncio.run(gather_limited([asyncio.to_thread(_check, item) for item in EXPOSED_PATHS], 14))
    results = [r for r in results if isinstance(r, dict) and "path" in r]
    exposed = [r for r in results if r.get("exposed")]
    protected = [r for r in results if r.get("protected")]
    informational = [r for r in exposed if r.get("category") == "Informational"]
    exposed = [r for r in exposed if r.get("category") != "Informational"]

    for r in exposed:
        findings.append(finding(r["severity"], r["description"], f"{r['path']} returned HTTP {r['status']} with expected content.", evidence=r["path"], recommendation="Remove the file from the web root, rotate any exposed secrets, and block dotfiles at the edge."))
    if protected:
        findings.append(finding("info", "Sensitive paths exist but are protected", f"{len(protected)} candidate path(s) returned 401/403.", evidence=[r["path"] for r in protected[:12]]))

    risk = 0
    for r in exposed:
        risk += SEVERITY_WEIGHT.get(r["severity"], 0)
    risk = min(100, risk)
    data = {
        "base_url": base,
        "paths_checked": len(results),
        "exposed_count": len(exposed),
        "protected_count": len(protected),
        "exposed": sorted(exposed, key=lambda r: SEVERITY_WEIGHT.get(r["severity"], 0), reverse=True),
        "protected": protected,
        "informational": informational,
        "all_results": results,
    }
    summary = (
        f"Probed {len(results)} sensitive paths on {parsed.netloc}: "
        f"{len(exposed)} exposed, {len(protected)} protected, {len(informational)} informational."
    )
    return data, findings, risk, summary


async def run_exposed_files(target: str) -> Dict[str, Any]:
    started = time.perf_counter()
    data, findings, risk, summary = await asyncio.to_thread(_analyze_exposed, target)
    iocs = [{"type": "url", "value": data.get("base_url", target) + r["path"]} for r in data.get("exposed", [])]
    return envelope(
        "exposed_files", data.get("base_url") or target, risk=risk, summary=summary,
        findings=findings, data=data, iocs=iocs,
        sources=["Live HTTP path probes", "Content signature validation"],
        elapsed_ms=int((time.perf_counter() - started) * 1000),
    )


# ===========================================================================
# 9. LINK FORENSICS / REDIRECT CHAIN
# ===========================================================================

SHORTENERS = {
    "bit.ly", "t.co", "tinyurl.com", "goo.gl", "ow.ly", "is.gd", "buff.ly",
    "rebrand.ly", "cutt.ly", "shorturl.at", "rb.gy", "s.id", "tiny.cc",
    "v.gd", "bl.ink", "lnkd.in", "t.ly", "short.gy", "clck.ru", "u.to",
}
TRACKING_PARAMS = {
    "utm_source", "utm_medium", "utm_campaign", "utm_term", "utm_content",
    "fbclid", "gclid", "dclid", "msclkid", "mc_cid", "mc_eid", "igshid",
    "twclid", "ttclid", "yclid", "wickedid", "oly_enc_id", "oly_anon_id",
    "vero_id", "rb_clickid", "s_cid", "mkt_tok", "trk", "ref_src", "ref_url",
}
SUSPICIOUS_TLDS_LINK = {"zip", "mov", "top", "xyz", "click", "link", "rest", "country", "kim", "work", "party", "gq", "tk", "ml", "cf", "ga"}
REDIRECT_PARAMS = {"url", "redirect", "redirect_uri", "next", "return", "returnurl", "continue", "dest", "destination", "target", "r", "u", "to", "out", "view", "go"}


def _idn_unicode(host: str) -> str:
    try:
        return host.encode("ascii").decode("idna")
    except Exception:
        try:
            return host.encode("idna").decode("utf-8")
        except Exception:
            return host


def _analyze_link(raw: str) -> Tuple[Dict[str, Any], List[Dict[str, Any]], int, str]:
    findings: List[Dict[str, Any]] = []
    url = normalize_url(raw)
    parsed = urllib.parse.urlparse(url)
    host = (parsed.hostname or "").lower()
    if not host:
        return {}, [finding("info", "Invalid URL", raw)], 0, "Invalid URL."

    r = http_request(url, timeout=10, max_bytes=20000, allow_redirects=True, max_redirects=10)
    final_url = r.get("final_url", url)
    final = urllib.parse.urlparse(final_url)
    qs = urllib.parse.parse_qs(parsed.query)
    final_qs = urllib.parse.parse_qs(final.query)

    tracking = sorted({k for k in list(qs.keys()) + list(final_qs.keys()) if k.lower() in TRACKING_PARAMS})
    redirect_params = sorted({k for k in qs.keys() if k.lower() in REDIRECT_PARAMS})
    if tracking:
        findings.append(finding("low", "Tracking parameters present", f"{len(tracking)} analytics/tracking parameter(s) identified.", evidence=tracking, recommendation="Strip tracking parameters before sharing links."))
    if redirect_params:
        findings.append(finding("medium", "Open-redirect style parameter", f"URL carries redirect parameter(s): {', '.join(redirect_params)}", recommendation="Validate redirect destinations and allowlist external hosts."))

    punycode = host.startswith("xn--") or any(part.startswith("xn--") for part in host.split("."))
    ip_literal = False
    try:
        ipaddress.ip_address(host)
        ip_literal = True
    except Exception:
        pass
    userinfo = bool(parsed.username or parsed.password)
    many_subdomains = host.count(".") >= 4
    suspicious_tld = host.rsplit(".", 1)[-1] in SUSPICIOUS_TLDS_LINK
    long_url = len(url) > 180
    shortener = host in SHORTENERS
    at_trick = "@" in raw.split("://", 1)[-1].split("/", 1)[0]
    http_only = final.scheme == "http"
    port_weird = final.port not in (None, 80, 443)

    if punycode:
        findings.append(finding("high", "Punycode / IDN host", "The host uses punycode, a common homograph phishing technique.", evidence=host, recommendation="Decode the Unicode form and verify visually before trusting."))
    if ip_literal:
        findings.append(finding("high", "Raw IP address destination", "The link resolves directly to an IP instead of a domain.", evidence=host, recommendation="Treat raw-IP links as high risk."))
    if userinfo or at_trick:
        findings.append(finding("critical", "@ userinfo trick detected", "A userinfo segment can disguise the true destination host.", evidence=raw[:180], recommendation="Inspect the host after the last '@' before clicking."))
    if many_subdomains:
        findings.append(finding("medium", "Deeply nested subdomains", f"The host has {host.count('.')+1} labels, often used to bury the real domain.", evidence=host))
    if suspicious_tld:
        findings.append(finding("high", "High-abuse TLD", f".{host.rsplit('.',1)[-1]} is frequently abused for phishing and malware.", evidence=host))
    if http_only:
        findings.append(finding("high", "Final destination is plain HTTP", "Traffic is unencrypted and can be modified in transit.", evidence=final_url))
    if shortener:
        findings.append(finding("info", "URL shortener expanded", f"{host} is a known shortener; the final destination is shown below.", evidence=final_url))
    if port_weird:
        findings.append(finding("medium", "Non-standard port", f"Destination uses port {final.port}.", evidence=final_url))
    if long_url:
        findings.append(finding("low", "Unusually long URL", f"{len(url)} characters — long URLs can hide the true destination.", evidence=len(url)))

    risk = 0
    for sev, cond in (
        ("critical", userinfo or at_trick), ("high", punycode), ("high", ip_literal),
        ("high", suspicious_tld), ("high", http_only), ("medium", many_subdomains),
        ("medium", port_weird), ("medium", bool(redirect_params)), ("low", bool(tracking)),
        ("low", long_url),
    ):
        if cond:
            risk += SEVERITY_WEIGHT[sev]
    risk = min(100, risk)

    chain = r.get("chain", [])
    data = {
        "input_url": raw,
        "normalized_url": url,
        "final_url": final_url,
        "final_host": final.hostname or "",
        "scheme": final.scheme,
        "status": r.get("status", 0),
        "redirect_count": r.get("redirect_count", 0),
        "redirect_chain": chain,
        "is_shortener": shortener,
        "punycode": punycode,
        "unicode_host": _idn_unicode(host) if punycode else host,
        "ip_literal": ip_literal,
        "userinfo_trick": userinfo or at_trick,
        "tracking_params": tracking,
        "redirect_params": redirect_params,
        "suspicious_tld": suspicious_tld,
        "http_only": http_only,
        "url_length": len(url),
        "sanitized_url": urllib.parse.urlunparse(final._replace(query="")) if tracking else final_url,
        "server": r.get("headers", {}).get("server", ""),
        "content_type": r.get("headers", {}).get("content-type", ""),
        "error": r.get("error"),
    }
    summary = (
        f"{host} → {final.hostname or 'unresolved'} via {r.get('redirect_count', 0)} redirect(s), "
        f"HTTP {r.get('status', 0)}. Risk {risk}/100."
    )
    return data, findings, risk, summary


async def run_link_forensics(target: str) -> Dict[str, Any]:
    started = time.perf_counter()
    data, findings, risk, summary = await asyncio.to_thread(_analyze_link, target)
    if not data:
        return error_envelope("link_forensics", target, summary)
    iocs = [{"type": "url", "value": data.get("final_url", target)}]
    return envelope(
        "link_forensics", target, risk=risk, summary=summary, findings=findings, data=data, iocs=iocs,
        sources=["Live redirect chain", "URL lexical heuristics", "Shortener registry"],
        elapsed_ms=int((time.perf_counter() - started) * 1000),
    )
