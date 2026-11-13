"""
VX ARSENAL // THREAT INTELLIGENCE ENGINES

  cve_intel    — NVD + CISA KEV + FIRST EPSS correlation
  ioc_enrich   — AlienVault OTX + URLhaus + infrastructure context
"""
from __future__ import annotations

import asyncio
import hashlib
import ipaddress
import json
import re
import time
import urllib.parse
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from .common import (
    envelope,
    error_envelope,
    finding,
    http_json,
    http_request,
    is_domain,
    normalize_domain,
    post_json,
    resolve_a,
    resolve_mx,
    root_domain,
    tls_peer,
)

_KEV_CACHE: Dict[str, Any] = {"ts": 0.0, "items": [], "error": ""}
_KEV_TTL = 6 * 3600


def _load_kev(force: bool = False) -> Dict[str, Any]:
    now = time.time()
    if not force and _KEV_CACHE["items"] and (now - _KEV_CACHE["ts"] < _KEV_TTL):
        return _KEV_CACHE
    r = http_json(
        "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
        timeout=18, max_bytes=4_000_000,
    )
    data = r.get("json") or {}
    items = data.get("vulnerabilities", []) if isinstance(data, dict) else []
    if items:
        _KEV_CACHE.update({"ts": now, "items": items, "error": "", "catalog": data.get("catalogVersion", ""), "released": data.get("dateReleased", "")})
    else:
        _KEV_CACHE["error"] = r.get("error") or f"HTTP {r.get('status')}"
    return _KEV_CACHE


def _kev_index() -> Dict[str, Dict[str, Any]]:
    kev = _load_kev()
    return {str(i.get("cveID", "")).upper(): i for i in kev.get("items", [])}


def _nvd_parse(raw: Dict[str, Any], kev: Optional[Dict[str, Any]] = None, epss: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    cve = raw.get("cve", raw) if isinstance(raw, dict) else {}
    cve_id = cve.get("id", "")
    descriptions = cve.get("descriptions", []) or []
    desc = next((d.get("value", "") for d in descriptions if d.get("lang") == "en"), "")
    metrics = cve.get("metrics", {}) or {}
    cvss = {}
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV40", "cvssMetricV2"):
        arr = metrics.get(key) or []
        if arr:
            m = arr[0]
            cdata = m.get("cvssData", {}) or {}
            cvss = {
                "version": cdata.get("version", key.replace("cvssMetric", "").replace("V", "")),
                "base_score": cdata.get("baseScore"),
                "base_severity": (m.get("baseSeverity") or cdata.get("baseSeverity") or "").upper(),
                "vector": cdata.get("vectorString", ""),
                "exploitability": cdata.get("exploitabilityScore"),
                "impact": cdata.get("impactScore"),
                "source": m.get("source", ""),
                "type": m.get("type", ""),
            }
            break
    weaknesses = []
    for w in cve.get("weaknesses", []) or []:
        for d in w.get("description", []) or []:
            if d.get("value", "").startswith("CWE-"):
                weaknesses.append(d["value"])
    refs = [{"url": r.get("url"), "source": r.get("source"), "tags": r.get("tags", [])} for r in (cve.get("references", []) or [])[:12]]
    published = cve.get("published", "")
    modified = cve.get("lastModified", "")
    k = kev or {}
    e = epss or {}
    return {
        "cve_id": cve_id,
        "description": desc,
        "published": published,
        "modified": modified,
        "cvss": cvss,
        "severity": cvss.get("base_severity") or "UNKNOWN",
        "base_score": cvss.get("base_score"),
        "weaknesses": sorted(set(weaknesses)),
        "references": refs,
        "kev": {
            "known_exploited": bool(k),
            "date_added": k.get("dateAdded", ""),
            "due_date": k.get("dueDate", ""),
            "vendor": k.get("vendorProject", ""),
            "product": k.get("product", ""),
            "vulnerability_name": k.get("vulnerabilityName", ""),
            "required_action": k.get("requiredAction", ""),
            "known_ransomware": (k.get("knownRansomwareCampaignUse", "") or "").lower(),
            "notes": k.get("notes", ""),
        },
        "epss": {
            "score": e.get("epss"),
            "percentile": e.get("percentile"),
            "date": e.get("date", ""),
        },
        "status": cve.get("vulnStatus", ""),
    }


def _epss_for(cve_id: str) -> Dict[str, Any]:
    r = http_json(f"https://api.first.org/data/v1/epss?cve={urllib.parse.quote(cve_id)}", timeout=9)
    data = r.get("json") or {}
    rows = data.get("data", []) if isinstance(data, dict) else []
    return rows[0] if rows else {}


def _nvd_lookup(cve_id: str) -> Optional[Dict[str, Any]]:
    for timeout in (18, 30):
        r = http_json(
            f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={urllib.parse.quote(cve_id)}",
            timeout=timeout,
        )
        j = r.get("json") or {}
        vulns = j.get("vulnerabilities", []) if isinstance(j, dict) else []
        if vulns:
            return vulns[0]
        if r.get("status") == 404:
            break
    return None


def _mitre_lookup(cve_id: str, kev: Optional[Dict[str, Any]] = None, epss: Optional[Dict[str, Any]] = None) -> Optional[Dict[str, Any]]:
    """Parse the CVE Services (MITRE) record into our common CVE shape."""
    r = http_json(f"https://cveawg.mitre.org/api/cve/{urllib.parse.quote(cve_id)}", timeout=14)
    j = r.get("json") or {}
    if not isinstance(j, dict) or not j.get("containers"):
        return None
    meta = j.get("cveMetadata") or {}
    cna = (j.get("containers") or {}).get("cna") or {}
    adp = (j.get("containers") or {}).get("adp") or []
    descriptions = cna.get("descriptions") or []
    desc = next((d.get("value", "") for d in descriptions if d.get("lang", "").startswith("en")), "")
    cvss = {}
    metrics = list(cna.get("metrics") or [])
    for block in adp if isinstance(adp, list) else []:
        metrics.extend((block or {}).get("metrics") or [])
    for m in metrics:
        for key in ("cvssV4_0", "cvssV3_1", "cvssV3_0", "cvssV2_0"):
            if key in m and isinstance(m[key], dict):
                c = m[key]
                cvss = {
                    "version": key.replace("cvssV", "").replace("_", "."),
                    "base_score": c.get("baseScore"),
                    "base_severity": (m.get("baseSeverity") or c.get("baseSeverity") or "").upper(),
                    "vector": c.get("vectorString", ""),
                    "exploitability": c.get("exploitabilityScore"),
                    "impact": c.get("impactScore"),
                    "source": m.get("source", ""),
                    "type": m.get("type", ""),
                }
                break
        if cvss:
            break
    weaknesses = []
    for pt in cna.get("problemTypes") or []:
        for d in pt.get("descriptions") or []:
            if d.get("cweId"):
                weaknesses.append(d["cweId"])
    refs = [{"url": ref.get("url"), "source": ref.get("name", ""), "tags": ref.get("tags", [])} for ref in (cna.get("references") or [])[:12]]
    k = kev or {}
    e = epss or {}
    return {
        "cve_id": meta.get("cveId", cve_id),
        "description": desc,
        "published": meta.get("datePublished", ""),
        "modified": meta.get("dateUpdated", ""),
        "cvss": cvss,
        "severity": cvss.get("base_severity") or "UNKNOWN",
        "base_score": cvss.get("base_score"),
        "weaknesses": sorted(set(weaknesses)),
        "references": refs,
        "kev": {
            "known_exploited": bool(k),
            "date_added": k.get("dateAdded", ""),
            "due_date": k.get("dueDate", ""),
            "vendor": k.get("vendorProject", ""),
            "product": k.get("product", ""),
            "vulnerability_name": k.get("vulnerabilityName", ""),
            "required_action": k.get("requiredAction", ""),
            "known_ransomware": (k.get("knownRansomwareCampaignUse", "") or "").lower(),
            "notes": k.get("notes", ""),
        },
        "epss": {
            "score": e.get("epss"),
            "percentile": e.get("percentile"),
            "date": e.get("date", ""),
        },
        "status": meta.get("state", ""),
        "source": "MITRE CVE Services",
    }


def _cve_severity_score(item: Dict[str, Any]) -> int:
    s = 0
    sev = (item.get("severity") or "").upper()
    s += {"CRITICAL": 40, "HIGH": 28, "MEDIUM": 14, "LOW": 5}.get(sev, 8)
    if item.get("kev", {}).get("known_exploited"):
        s += 35
    if item.get("kev", {}).get("known_ransomware") == "known":
        s += 10
    try:
        epss = float(item.get("epss", {}).get("score") or 0)
        s += int(epss * 25)
    except Exception:
        pass
    return min(100, s)


def _analyze_cve(target: str) -> Tuple[Dict[str, Any], List[Dict[str, Any]], int, str]:
    findings: List[Dict[str, Any]] = []
    query = (target or "").strip()
    kev = _kev_index()
    cve_m = re.search(r"CVE-\d{4}-\d{4,7}", query, re.I)
    items: List[Dict[str, Any]] = []
    mode = "cve" if cve_m else "keyword"
    if cve_m:
        cve_id = cve_m.group(0).upper()
        epss = _epss_for(cve_id)
        raw = _nvd_lookup(cve_id)
        item = _nvd_parse(raw, kev.get(cve_id), epss) if raw else _mitre_lookup(cve_id, kev.get(cve_id), epss)
        if not item:
            return {}, [finding("medium", "CVE not found", f"No NVD or MITRE record for {cve_id}.")], 0, f"No record for {cve_id}."
        # CIRCL enrichment when the primary feed omits CVSS.
        if not item.get("base_score"):
            c = http_json(f"https://cve.circl.lu/api/cve/{urllib.parse.quote(cve_id)}", timeout=10).get("json") or {}
            if isinstance(c, dict):
                if c.get("cvss"):
                    item["base_score"] = c.get("cvss")
                    item["severity"] = str(c.get("cvss3") or c.get("cvss") or "").upper() if isinstance(c.get("cvss3"), str) else item.get("severity")
                if c.get("summary") and not item.get("description"):
                    item["description"] = c["summary"]
                item["circl"] = {"cvss": c.get("cvss"), "cvss3": c.get("cvss3"), "capec": (c.get("capec") or [])[:6], "vulnerable_product": (c.get("vulnerable_product") or [])[:10]}
        items.append(item)
    else:
        if not query:
            return {}, [finding("info", "No query", "Enter a CVE ID or a product/keyword.")], 0, "Empty query."
        r = http_json(
            f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={urllib.parse.quote(query)}&resultsPerPage=12",
            timeout=18,
        )
        j = r.get("json") or {}
        vulns = j.get("vulnerabilities", []) if isinstance(j, dict) else []
        for v in vulns[:12]:
            cid = (v.get("cve") or {}).get("id", "")
            items.append(_nvd_parse(v, kev.get(cid), _epss_for(cid) if cid else None))
        if not items:
            findings.append(finding("medium", "No matching CVEs", f"NVD keyword search returned no results for '{query}'.", recommendation="Try a vendor/product keyword, e.g. 'apache http server'."))

    items = [i for i in items if i.get("cve_id")]
    items.sort(key=lambda x: _cve_severity_score(x), reverse=True)

    kev_hits = [i for i in items if i["kev"]["known_exploited"]]
    ransomware = [i for i in items if i["kev"]["known_ransomware"] == "known"]
    critical = [i for i in items if (i.get("severity") or "").upper() == "CRITICAL"]
    high_epss = [i for i in items if float(i.get("epss", {}).get("score") or 0) >= 0.1]

    if kev_hits:
        findings.append(finding("critical", "CISA KEV match", f"{len(kev_hits)} result(s) are in the Known Exploited Vulnerabilities catalog.", evidence=[i["cve_id"] for i in kev_hits[:10]], recommendation="Treat as actively exploited; patch by the KEV due date."))
    if ransomware:
        findings.append(finding("critical", "Known ransomware exploitation", "CISA flags ransomware campaign use for at least one result.", evidence=[i["cve_id"] for i in ransomware[:8]]))
    if high_epss:
        findings.append(finding("high", "Elevated exploitation probability", f"{len(high_epss)} CVE(s) have EPSS ≥ 0.10.", evidence=[{"cve": i["cve_id"], "epss": i.get("epss", {}).get("score")} for i in high_epss[:8]]))
    if critical and not kev_hits:
        findings.append(finding("high", "Critical CVSS severity", f"{len(critical)} result(s) are rated CRITICAL.", evidence=[i["cve_id"] for i in critical[:8]]))

    risk = max((_cve_severity_score(i) for i in items), default=0)
    if mode == "keyword":
        risk = min(100, risk + min(15, len(kev_hits) * 3))
    summary = (
        f"{mode.upper()} query '{query}': {len(items)} CVE(s), {len(kev_hits)} KEV, "
        f"{len(ransomware)} ransomware-linked, {len(critical)} critical. Highest risk {risk}/100."
    )
    data = {
        "query": query,
        "mode": mode,
        "count": len(items),
        "kev_count": len(kev_hits),
        "ransomware_count": len(ransomware),
        "critical_count": len(critical),
        "cves": items,
        "kev_catalog_version": _KEV_CACHE.get("catalog", ""),
        "kev_catalog_released": _KEV_CACHE.get("released", ""),
    }
    return data, findings, risk, summary


async def run_cve_intel(target: str) -> Dict[str, Any]:
    started = time.perf_counter()
    data, findings, risk, summary = await asyncio.to_thread(_analyze_cve, target)
    if not data:
        return error_envelope("cve_intel", target, summary)
    iocs = [{"type": "cve", "value": i["cve_id"]} for i in data.get("cves", [])[:20]]
    return envelope(
        "cve_intel", data.get("query", target), risk=risk, summary=summary, findings=findings,
        data=data, iocs=iocs,
        sources=["NVD API 2.0", "CISA KEV catalog", "FIRST EPSS", "MITRE CVE Services"],
        elapsed_ms=int((time.perf_counter() - started) * 1000),
    )


# ===========================================================================
# IOC ENRICHMENT
# ===========================================================================

def _detect_ioc(value: str) -> Tuple[str, str]:
    v = (value or "").strip()
    if re.fullmatch(r"[a-fA-F0-9]{64}", v):
        return "sha256", v.lower()
    if re.fullmatch(r"[a-fA-F0-9]{40}", v):
        return "sha1", v.lower()
    if re.fullmatch(r"[a-fA-F0-9]{32}", v):
        return "md5", v.lower()
    try:
        ipaddress.ip_address(v)
        return ("ipv6" if ":" in v else "ipv4"), v
    except Exception:
        pass
    if re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", v):
        return "email", v.lower()
    if "://" in v or v.startswith("www."):
        return "url", v
    if is_domain(normalize_domain(v)):
        return "domain", normalize_domain(v)
    return "unknown", v


OTX_SECTION = {
    "ipv4": "IPv4", "ipv6": "IPv6", "domain": "domain", "hostname": "hostname",
    "url": "url", "sha256": "file", "sha1": "file", "md5": "file",
}


def _otx_lookup(kind: str, value: str) -> Dict[str, Any]:
    section = OTX_SECTION.get(kind)
    if not section:
        return {"available": False, "error": "unsupported type"}
    encoded = urllib.parse.quote(value, safe="")
    base = f"https://otx.alienvault.com/api/v1/indicators/{section}/{encoded}"
    general = http_json(f"{base}/general", timeout=12)
    g = general.get("json") or {}
    result: Dict[str, Any] = {"available": bool(g), "general": g}
    if section in ("IPv4", "IPv6", "domain", "hostname"):
        pdns = http_json(f"{base}/passive_dns", timeout=12)
        result["passive_dns"] = (pdns.get("json") or {}).get("passive_dns", [])[:40]
    if section == "url":
        url_list = http_json(f"{base}/url_list", timeout=12)
        result["url_list"] = (url_list.get("json") or {}).get("url_list", [])[:10]
    if section == "file":
        analysis = http_json(f"{base}/analysis", timeout=15)
        result["analysis"] = analysis.get("json") or {}
    return result


def _urlhaus_lookup(kind: str, value: str) -> Dict[str, Any]:
    """abuse.ch now requires an Auth-Key on most endpoints; try and degrade cleanly."""
    try:
        if kind == "url":
            r = post_json("https://urlhaus-api.abuse.ch/v1/url/", {"url": value}, timeout=10)
        elif kind in ("domain", "hostname"):
            r = post_json("https://urlhaus-api.abuse.ch/v1/host/", {"host": value}, timeout=10)
        elif kind in ("md5", "sha1", "sha256"):
            key = "sha256_hash" if kind == "sha256" else ("md5_hash" if kind == "md5" else "sha1_hash")
            r = post_json("https://urlhaus-api.abuse.ch/v1/payload/", {key: value}, timeout=10)
        else:
            return {"available": False}
        j = r.get("json") or {}
        if r.get("status") == 200 and isinstance(j, dict) and j.get("query_status") not in ("no_results", "illegal_search_term"):
            return {"available": True, "data": j}
        return {"available": False, "status": r.get("status"), "query_status": (j or {}).get("query_status", "")}
    except Exception as exc:
        return {"available": False, "error": str(exc)}


def _analyze_ioc(target: str) -> Tuple[Dict[str, Any], List[Dict[str, Any]], int, str]:
    findings: List[Dict[str, Any]] = []
    kind, value = _detect_ioc(target)
    if kind == "unknown":
        return {}, [finding("info", "Unrecognized IOC", "Supply an IP, domain, URL, email, or MD5/SHA1/SHA256 hash.")], 0, "Unrecognized IOC format."

    otx = _otx_lookup(kind, value)
    g = otx.get("general") or {}
    pulse_info = g.get("pulse_info") or {}
    pulses = pulse_info.get("pulses", []) or []
    pulse_count = int(pulse_info.get("count") or len(pulses))

    def _labels(values: Any) -> List[str]:
        out = []
        for item in values or []:
            if isinstance(item, dict):
                label = item.get("name") or item.get("display_name") or item.get("value") or item.get("id")
                if label:
                    out.append(str(label))
            elif item:
                out.append(str(item))
        return sorted(set(out))

    tags = _labels([tag for p in pulses for tag in (p.get("tags") or [])])
    malware = _labels([m for p in pulses for m in (p.get("malware_families") or [])])
    adversaries = _labels([a for p in pulses for a in (p.get("adversary") or [])])
    industries = _labels([i for p in pulses for i in (p.get("industries") or [])])
    validation = [{"source": v.get("source"), "name": v.get("name"), "confidence": v.get("confidence")} for v in (g.get("validation") or [])]
    urlhaus = _urlhaus_lookup(kind, value)

    geo = {}
    dns = {}
    tls = {}
    if kind == "ipv4":
        r = http_json(f"http://ip-api.com/json/{value}?fields=status,country,regionName,city,isp,org,as,proxy,hosting,query", timeout=7)
        geo = r.get("json") or {}
        if geo.get("proxy"):
            findings.append(finding("high", "Proxy / anonymizer IP", "Infrastructure provider flags this address as a proxy or anonymizer.", recommendation="Block or step-up authentication for anonymized traffic."))
    if kind in ("domain", "hostname", "url"):
        host = value if kind == "domain" else (urllib.parse.urlparse(value).hostname or "")
        if host:
            dns = {"a": resolve_a(host), "mx": resolve_mx(host)}
            if kind == "domain":
                tls = tls_peer(host, 443, timeout=5)
    if kind == "email":
        dom = value.split("@")[-1]
        dns = {"domain": dom, "a": resolve_a(dom), "mx": resolve_mx(dom)}

    if pulse_count:
        sev = "critical" if pulse_count >= 10 else "high" if pulse_count >= 3 else "medium"
        findings.append(finding(sev, "OTX threat pulses reference this IOC", f"{pulse_count} AlienVault OTX pulse(s) mention the indicator.", evidence=[p.get("name") for p in pulses[:8]], recommendation="Correlate with internal telemetry before blocking; OTX pulses vary in quality."))
    if malware:
        findings.append(finding("high", "Malware family association", f"Associated families: {', '.join(malware[:8])}.", evidence=malware[:10]))
    if adversaries:
        findings.append(finding("high", "Threat actor association", f"Named adversaries: {', '.join(adversaries[:6])}.", evidence=adversaries[:10]))
    uh = urlhaus.get("data") or {}
    if uh:
        uh_status = str(uh.get("url_status") or uh.get("urlhaus_reference") or "")
        findings.append(finding("high", "URLhaus malware record", f"Abuse.ch URLhaus returned a record ({uh_status}).", evidence=uh.get("threat", "") or uh.get("tags", []), recommendation="Block the URL/hash at the edge and hunt for related payloads."))

    risk = 0
    risk += min(55, pulse_count * 7)
    risk += min(20, len(malware) * 8)
    risk += min(15, len(adversaries) * 7)
    risk += 20 if urlhaus.get("data") else 0
    risk += 10 if geo.get("proxy") else 0
    risk = min(100, risk)

    pdns = otx.get("passive_dns", []) or []
    summary = (
        f"{kind.upper()} {value}: {pulse_count} OTX pulse(s), {len(malware)} malware family signal(s), "
        f"{len(adversaries)} actor link(s), {len(pdns)} passive DNS record(s); risk {risk}/100."
    )
    data = {
        "ioc": value,
        "type": kind,
        "otx": {
            "available": otx.get("available", False),
            "pulse_count": pulse_count,
            "pulses": [
                {
                    "name": p.get("name"), "description": (p.get("description") or "")[:280],
                    "created": p.get("created"), "modified": p.get("modified"),
                    "tags": p.get("tags", []), "tlp": p.get("tlp"),
                    "adversary": p.get("adversary", []), "malware_families": p.get("malware_families", []),
                    "targeted_countries": p.get("targeted_countries", []),
                }
                for p in pulses[:20]
            ],
            "tags": tags[:30],
            "malware_families": malware[:20],
            "adversaries": adversaries[:20],
            "industries": industries[:20],
            "validation": validation[:12],
            "passive_dns": [
                {"hostname": r.get("hostname"), "address": r.get("address"), "first": r.get("first"), "last": r.get("last"), "record_type": r.get("record_type")}
                for r in pdns[:40]
            ],
        },
        "urlhaus": urlhaus,
        "geo": geo,
        "dns": dns,
        "tls": {k: v for k, v in tls.items() if k in ("ok", "version", "cipher", "issuer", "not_after", "expires_in_days")},
    }
    return data, findings, risk, summary


async def run_ioc_enrich(target: str) -> Dict[str, Any]:
    started = time.perf_counter()
    data, findings, risk, summary = await asyncio.to_thread(_analyze_ioc, target)
    if not data:
        return error_envelope("ioc_enrich", target, summary)
    return envelope(
        "ioc_enrich", data.get("ioc", target), risk=risk, summary=summary, findings=findings,
        data=data, iocs=[{"type": data.get("type"), "value": data.get("ioc")}],
        sources=["AlienVault OTX", "URLhaus / abuse.ch", "ip-api.com", "Public DNS", "TLS"],
        notes=["abuse.ch endpoints may require an Auth-Key; the tool degrades cleanly when absent."],
        elapsed_ms=int((time.perf_counter() - started) * 1000),
    )
