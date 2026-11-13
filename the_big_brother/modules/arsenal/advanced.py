"""
VX ARSENAL // FLAGSHIP ENGINES (VX.1)

Four high-signal additions:
  attack_surface     — orchestrates six engines into one weighted exposure index
  origin_unmasker    — historical DNS + Host-header validation behind CDN/WAF
  graphql_inspector  — endpoint discovery, introspection and schema-risk audit
  supply_chain_audit — npm / PyPI package, typosquat and install-time risk audit
"""
from __future__ import annotations

import asyncio
import difflib
import io
import ipaddress
import json
import re
import tarfile
import time
import urllib.parse
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Dict, List, Optional, Tuple

from .common import (
    envelope,
    error_envelope,
    finding,
    http_json,
    http_request,
    is_domain,
    normalize_domain,
    normalize_url,
    resolve_a,
    resolve_mx,
    root_domain,
)
from .network import (
    run_bucket_hunter,
    run_cert_transparency,
    run_dns_intel,
    run_exposed_files,
    run_http_audit,
    run_waf_fingerprint,
)


# ===========================================================================
# 1. ATTACK SURFACE SCORECARD
# ===========================================================================

SCORECARD_WEIGHTS = {
    "dns_intel": 15,
    "http_audit": 25,
    "waf_fingerprint": 10,
    "exposed_files": 25,
    "bucket_hunter": 15,
    "cert_transparency": 10,
}

SCORECARD_LABELS = {
    "dns_intel": "DNS & email authentication",
    "http_audit": "HTTP / TLS hardening",
    "waf_fingerprint": "Edge & WAF posture",
    "exposed_files": "Sensitive file exposure",
    "bucket_hunter": "Cloud storage exposure",
    "cert_transparency": "Certificate & subdomain surface",
}


async def _run_scorecard_engine(name: str, runner, target: str, timeout: float) -> Dict[str, Any]:
    started = time.perf_counter()
    try:
        result = await asyncio.wait_for(runner(target), timeout=timeout)
        return {
            "engine": name,
            "ok": result.get("status") == "success",
            "risk": int(result.get("risk_score") or 0),
            "grade": result.get("grade", "?"),
            "summary": result.get("summary", ""),
            "findings": result.get("findings") or [],
            "iocs": result.get("iocs") or [],
            "elapsed_ms": int((time.perf_counter() - started) * 1000),
        }
    except asyncio.TimeoutError:
        return {"engine": name, "ok": False, "risk": 0, "grade": "?", "summary": f"Timed out after {timeout:.0f}s", "findings": [], "iocs": [], "elapsed_ms": int(timeout * 1000)}
    except Exception as exc:
        return {"engine": name, "ok": False, "risk": 0, "grade": "?", "summary": f"{type(exc).__name__}: {exc}", "findings": [], "iocs": [], "elapsed_ms": int((time.perf_counter() - started) * 1000)}


async def run_attack_surface(target: str) -> Dict[str, Any]:
    started = time.perf_counter()
    domain = normalize_domain(target)
    if not is_domain(domain):
        return error_envelope("attack_surface", target, "Enter a valid domain, e.g. example.com")

    runners = {
        "dns_intel": (run_dns_intel, 35),
        "http_audit": (run_http_audit, 35),
        "waf_fingerprint": (run_waf_fingerprint, 35),
        "exposed_files": (run_exposed_files, 45),
        "bucket_hunter": (run_bucket_hunter, 50),
        "cert_transparency": (run_cert_transparency, 45),
    }
    results = await asyncio.gather(*[
        _run_scorecard_engine(name, runner, domain, timeout)
        for name, (runner, timeout) in runners.items()
    ])

    total_weight = 0
    weighted = 0
    categories = []
    all_findings = []
    iocs = []
    seen_iocs = set()
    for item in results:
        weight = SCORECARD_WEIGHTS.get(item["engine"], 0)
        if item["ok"]:
            total_weight += weight
            weighted += item["risk"] * weight
        categories.append({
            "engine": item["engine"],
            "label": SCORECARD_LABELS.get(item["engine"], item["engine"]),
            "weight": weight,
            "risk": item["risk"],
            "grade": item["grade"],
            "ok": item["ok"],
            "findings": len(item["findings"]),
            "summary": item["summary"],
            "elapsed_ms": item["elapsed_ms"],
        })
        for f in item["findings"]:
            entry = dict(f)
            entry["source_engine"] = item["engine"]
            all_findings.append(entry)
        for ioc in item["iocs"]:
            key = (str(ioc.get("type")), str(ioc.get("value")))
            if key not in seen_iocs:
                seen_iocs.add(key)
                iocs.append(ioc)

    risk = round(weighted / total_weight) if total_weight else 0
    grade = "A" if risk < 18 else "B" if risk < 35 else "C" if risk < 55 else "D" if risk < 72 else "F"
    coverage = sum(1 for c in categories if c["ok"])
    severity_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    all_findings.sort(key=lambda f: (severity_rank.get(f.get("severity", "info"), 9), -SCORECARD_WEIGHTS.get(f.get("source_engine"), 0)))
    top_findings = all_findings[:18]
    quick_wins = []
    for f in all_findings:
        rec = f.get("recommendation")
        if rec and rec not in quick_wins:
            quick_wins.append(rec)
        if len(quick_wins) >= 6:
            break

    findings = []
    for f in top_findings:
        findings.append(f)
    findings.append(finding(
        "info" if coverage == len(categories) else "low",
        f"Scorecard coverage: {coverage}/{len(categories)} engines",
        "All six engines completed." if coverage == len(categories) else "One or more engines timed out or returned an upstream fault.",
        evidence={c["engine"]: c["summary"] for c in categories},
    ))

    data = {
        "domain": domain,
        "attack_surface_index": risk,
        "grade": grade,
        "coverage": f"{coverage}/{len(categories)}",
        "weighted_score": risk,
        "counts": {
            "critical": sum(1 for f in all_findings if f.get("severity") == "critical"),
            "high": sum(1 for f in all_findings if f.get("severity") == "high"),
            "medium": sum(1 for f in all_findings if f.get("severity") == "medium"),
            "low": sum(1 for f in all_findings if f.get("severity") == "low"),
        },
        "categories": categories,
        "top_findings": top_findings,
        "quick_wins": quick_wins,
        "ioc_count": len(iocs),
        "weights": SCORECARD_WEIGHTS,
    }
    summary = (
        f"Attack Surface Index {risk}/100 (grade {grade}) across {coverage}/{len(categories)} engines. "
        f"{data['counts']['critical']} critical and {data['counts']['high']} high findings; "
        f"{len(iocs)} unique indicators collected."
    )
    return envelope(
        "attack_surface", domain, risk=risk, summary=summary, findings=findings, data=data,
        iocs=iocs[:150], sources=[SCORECARD_LABELS[x] for x in SCORECARD_WEIGHTS],
        notes=["Weighted index: DNS 15, HTTP 25, edge 10, files 25, cloud 15, certificate 10."],
        elapsed_ms=int((time.perf_counter() - started) * 1000),
    )


# ===========================================================================
# 2. ORIGIN IP UNMASKER
# ===========================================================================

CLOUDFLARE_NETWORKS = [
    "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
    "141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20",
    "197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
    "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
    "2400:cb00::/32", "2606:4700::/32", "2803:f800::/32", "2405:b500::/32",
    "2405:8100::/32", "2a06:98c0::/29", "2c0f:f248::/32",
]
CLOUDFLARE_OBJECTS = [ipaddress.ip_network(n) for n in CLOUDFLARE_NETWORKS]
ORIGIN_HOST_PREFIXES = ("direct", "origin", "origin-www", "dev", "staging", "stage", "ftp", "mail", "webmail", "cpanel", "portal", "backend", "api-origin", "internal")


def _parallel_map(fn, items: List[Any], workers: int = 10) -> List[Any]:
    if not items:
        return []
    with ThreadPoolExecutor(max_workers=min(workers, len(items))) as pool:
        return list(pool.map(fn, items))


def _is_cloudflare(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        return any(addr in net for net in CLOUDFLARE_OBJECTS)
    except Exception:
        return False


def _title(text: str) -> str:
    m = re.search(r"<title[^>]*>(.*?)</title>", text or "", re.I | re.S)
    return re.sub(r"\s+", " ", m.group(1)).strip().lower()[:180] if m else ""


def _visible_words(text: str, limit: int = 60000) -> set:
    raw = re.sub(r"<script.*?</script>|<style.*?</style>", " ", text or "", flags=re.I | re.S)
    raw = re.sub(r"<[^>]+>", " ", raw)
    words = re.findall(r"[a-z0-9]{4,}", raw.lower()[:limit])
    return set(words[:4000])


def _probe_candidate(ip: str, domain: str) -> Dict[str, Any]:
    last: Dict[str, Any] = {}
    for scheme in ("https", "http"):
        try:
            r = http_request(
                f"{scheme}://{ip}/", timeout=6, max_bytes=45000, allow_redirects=False,
                verify_tls=False, headers={"Host": domain, "Accept": "text/html,*/*"},
            )
            if r.get("status"):
                last = {
                    "scheme": scheme,
                    "status": r.get("status"),
                    "server": r.get("headers", {}).get("server", ""),
                    "location": r.get("headers", {}).get("location", ""),
                    "title": _title(r.get("text", "")),
                    "text": r.get("text", "")[:60000],
                    "bytes": len(r.get("body") or b""),
                }
                if r.get("status") not in (400, 403, 421, 404):
                    break
        except Exception:
            continue
    return last


def _analyze_origin(domain: str) -> Tuple[Dict[str, Any], List[Dict[str, Any]], int, str]:
    findings: List[Dict[str, Any]] = []
    current = resolve_a(domain)
    mx = resolve_mx(domain)
    candidates: Dict[str, Dict[str, Any]] = {}

    def add(ip: str, source: str, host: str = ""):
        if not ip or not re.fullmatch(r"[0-9a-fA-F:.]+", ip):
            return
        try:
            addr = ipaddress.ip_address(ip)
        except Exception:
            return
        if addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_reserved:
            return
        entry = candidates.setdefault(str(addr), {"ip": str(addr), "sources": [], "hosts": [], "cdn": _is_cloudflare(str(addr))})
        if source not in entry["sources"]:
            entry["sources"].append(source)
        if host and host not in entry["hosts"]:
            entry["hosts"].append(host)

    for ip in current:
        add(ip, "current_dns", domain)
    for item in mx:
        for ip in resolve_a(item["host"]):
            add(ip, "mx", item["host"])

    pdns = http_json(f"https://otx.alienvault.com/api/v1/indicators/domain/{urllib.parse.quote(domain)}/passive_dns", timeout=12).get("json") or {}
    for row in (pdns.get("passive_dns") or [])[:220]:
        add(str(row.get("address") or ""), "otx_passive_dns", str(row.get("hostname") or ""))

    ht = http_request(f"https://api.hackertarget.com/hostsearch/?q={urllib.parse.quote(domain)}", timeout=10, max_bytes=200000)
    if ht.get("status") == 200:
        for line in (ht.get("text") or "").splitlines():
            bits = line.split(",")
            if len(bits) >= 2:
                add(bits[1].strip(), "hackertarget", bits[0].strip())

    ct = http_request(f"https://crt.sh/?q=%25.{urllib.parse.quote(domain)}&output=json", timeout=14, max_bytes=2_000_000)
    subdomains = set()
    if ct.get("status") == 200:
        try:
            for entry in json.loads(ct.get("text") or "[]"):
                for name in str(entry.get("name_value") or "").split("\n"):
                    name = name.strip().lower().lstrip("*.")
                    if name.endswith(domain) and name != domain:
                        subdomains.add(name)
        except Exception:
            pass
    for host, ips in _parallel_map(lambda h: (h, resolve_a(h)), list(subdomains)[:24], workers=12):
        for ip in ips:
            add(ip, "certificate_transparency", host)

    for prefix in ORIGIN_HOST_PREFIXES:
        host = f"{prefix}.{domain}"
        for ip in resolve_a(host):
            add(ip, "origin_hostname", host)

    edge = http_request(f"https://{domain}", timeout=8, max_bytes=60000)
    if not edge.get("status"):
        edge = http_request(f"http://{domain}", timeout=8, max_bytes=60000)
    edge_headers = edge.get("headers", {})
    edge_text = edge.get("text", "") or ""
    edge_title = _title(edge_text)
    edge_words = _visible_words(edge_text)
    edge_server = edge_headers.get("server", "").lower()

    header_blob = " ".join(f"{k}:{v}" for k, v in edge_headers.items()).lower()
    ns = []
    for rtype in ("NS",):
        ns_r = http_json(f"https://cloudflare-dns.com/dns-query?name={urllib.parse.quote(domain)}&type=NS&ct=application/dns-json", timeout=5).get("json") or {}
        ns = [str(a.get("data", "")).rstrip(".") for a in ns_r.get("Answer", [])]
    ns_blob = " ".join(ns).lower()
    cdn = ""
    if "cf-ray" in header_blob or "cloudflare" in header_blob or "cloudflare" in ns_blob:
        cdn = "Cloudflare"
    elif "x-akamai" in header_blob or "akamai" in header_blob or "akamai" in ns_blob:
        cdn = "Akamai"
    elif "x-amz-cf-id" in header_blob or "cloudfront" in header_blob:
        cdn = "AWS CloudFront"
    elif "x-fastly" in header_blob or "fastly" in header_blob:
        cdn = "Fastly"
    elif "x-sucuri" in header_blob or "sucuri" in header_blob:
        cdn = "Sucuri"
    elif "x-vercel" in header_blob:
        cdn = "Vercel"
    elif "x-nf-request-id" in header_blob:
        cdn = "Netlify"

    candidate_list = []
    candidate_items = list(candidates.items())[:28]
    probes = dict(_parallel_map(lambda item: (item[0], _probe_candidate(item[0], domain)), candidate_items, workers=10))
    for ip, meta in candidate_items:
        probe = probes.get(ip, {})
        title = probe.get("title", "")
        text = probe.get("text", "")
        direct_words = _visible_words(text)
        intersection = len(edge_words & direct_words) if edge_words and direct_words else 0
        union = len(edge_words | direct_words) if edge_words or direct_words else 1
        similarity = round(intersection / union, 3) if union else 0
        title_match = bool(edge_title and title and (edge_title in title or title in edge_title))
        brand_match = root_domain(domain)[0] in text.lower() if text else False
        server_match = bool(probe.get("server") and edge_server and probe.get("server", "").lower() == edge_server)
        status = int(probe.get("status") or 0)
        confidence = 0
        if title_match:
            confidence += 35
        if brand_match:
            confidence += 25
        if similarity >= 0.55:
            confidence += 18
        elif similarity >= 0.3:
            confidence += 8
        if server_match:
            confidence += 10
        if status == 200:
            confidence += 10
        if any(s in meta["sources"] for s in ("otx_passive_dns", "hackertarget", "certificate_transparency")):
            confidence += 8
        if meta.get("cdn"):
            confidence -= 45
        if status in (400, 403, 421):
            confidence -= 15
        confidence = max(0, min(100, confidence))
        item = {
            "ip": ip,
            "sources": meta["sources"],
            "hosts": meta["hosts"][:8],
            "cdn_edge": meta.get("cdn", False),
            "probe_scheme": probe.get("scheme", ""),
            "status": status,
            "server": probe.get("server", ""),
            "title": title[:160],
            "redirect": probe.get("location", ""),
            "bytes": probe.get("bytes", 0),
            "title_match": title_match,
            "brand_match": brand_match,
            "server_match": server_match,
            "body_similarity": similarity,
            "confidence": confidence,
            "likely_origin": confidence >= 50,
        }
        candidate_list.append(item)

    candidate_list.sort(key=lambda x: (-x["confidence"], x["ip"]))
    likely = [c for c in candidate_list if c["likely_origin"]]
    origin_hosts = sorted({h for c in candidate_list for h in c["hosts"] if any(h.startswith(p + ".") for p in ORIGIN_HOST_PREFIXES)})

    if cdn and likely:
        findings.append(finding(
            "critical", "Origin IP likely exposed behind CDN",
            f"{len(likely)} candidate IP(s) responded with matching content while the target is fronted by {cdn}.",
            evidence=[{"ip": c["ip"], "confidence": c["confidence"], "title": c["title"], "sources": c["sources"]} for c in likely[:8]],
            recommendation="Restrict origin firewall ingress to the CDN's published IP ranges and rotate exposed origin addresses.",
        ))
    elif likely:
        findings.append(finding(
            "high", "Direct server fingerprints discovered",
            f"{len(likely)} candidate IP(s) appear to serve the same application. No CDN was conclusively identified.",
            evidence=[c["ip"] for c in likely[:8]],
            recommendation="Confirm whether these are intended public origins and remove unnecessary direct exposure.",
        ))
    elif cdn:
        findings.append(finding(
            "info", f"{cdn} fronting confirmed", "No likely origin IP was validated through Host-header probing.", recommendation="Keep direct origin access firewalled to CDN ranges."
        ))
    else:
        findings.append(finding("info", "No CDN detected", "The domain appears directly hosted; origin unmasking is less relevant."))

    if origin_hosts:
        findings.append(finding("high", "Origin-style hostnames resolve", "Common direct/origin/staging hostnames resolve publicly.", evidence=origin_hosts[:15], recommendation="Remove or firewall non-public origin hostnames."))
    historical = [c for c in candidate_list if any(s in c["sources"] for s in ("otx_passive_dns", "hackertarget"))]
    if historical:
        findings.append(finding("medium", "Historical IP infrastructure disclosed", f"{len(historical)} candidate(s) came from passive DNS or hostsearch history.", evidence=[c["ip"] for c in historical[:12]], recommendation="Review historical IPs for stale services and firewall rules."))

    risk = max((c["confidence"] for c in likely), default=0)
    if cdn and likely:
        risk = max(risk, 82)
    elif likely:
        risk = max(risk, 58)
    if origin_hosts:
        risk = max(risk, 46 if cdn else 56)
    if historical and not likely:
        risk = max(risk, 22)
    risk = min(100, risk)

    summary = (
        f"Target {domain}: CDN/WAF {cdn or 'not detected'}; {len(candidate_list)} candidate IPs tested, "
        f"{len(likely)} likely origin(s), {len(origin_hosts)} origin-style hostname(s)."
    )
    data = {
        "domain": domain,
        "cdn_waf": cdn or "None detected",
        "edge": {
            "status": edge.get("status", 0),
            "server": edge_headers.get("server", ""),
            "title": edge_title,
            "nameservers": ns,
        },
        "current_dns": current,
        "candidate_count": len(candidate_list),
        "likely_origin_count": len(likely),
        "origin_hostnames": origin_hosts,
        "candidates": candidate_list,
        "likely_origins": likely,
        "sources": ["current DNS", "OTX passive DNS", "HackerTarget hostsearch", "crt.sh", "MX", "origin hostnames"],
        "method": "Host-header probe on HTTP/HTTPS + title/body/server fingerprint comparison",
    }
    iocs = [{"type": "ip", "value": c["ip"]} for c in candidate_list[:40]]
    return data, findings, risk, summary


async def run_origin_unmasker(target: str) -> Dict[str, Any]:
    started = time.perf_counter()
    domain = normalize_domain(target)
    if not is_domain(domain):
        return error_envelope("origin_unmasker", target, "Enter a valid domain behind a CDN, e.g. example.com")
    data, findings, risk, summary = await asyncio.to_thread(_analyze_origin, domain)
    iocs = [{"type": "ip", "value": c["ip"]} for c in data.get("candidates", [])[:40]]
    return envelope(
        "origin_unmasker", domain, risk=risk, summary=summary, findings=findings, data=data, iocs=iocs,
        sources=data.get("sources", []),
        notes=["Host-header probes are unauthenticated and may be blocked by origin firewalls. Confirm findings manually."],
        elapsed_ms=int((time.perf_counter() - started) * 1000),
    )


# ===========================================================================
# 3. GRAPHQL INSPECTOR
# ===========================================================================

GRAPHQL_PATHS = ("/graphql", "/graphiql", "/api/graphql", "/v1/graphql", "/query", "/api/v1/graphql", "/gql")
INTROSPECTION_QUERY = """
query VXIntrospection {
  __schema {
    queryType { name }
    mutationType { name }
    subscriptionType { name }
    types {
      kind
      name
      description
      fields {
        name
        isDeprecated
        deprecationReason
        args { name type { kind name ofType { kind name } } }
        type { kind name ofType { kind name ofType { kind name } } }
      }
    }
  }
}
"""
SENSITIVE_FIELD_RE = re.compile(r"(password|passwd|secret|token|api[_-]?key|private|credential|auth|session|jwt|email|phone|ssn|social|dob|birth|address|credit|card|payment|billing|invoice|admin|role|permission|internal|debug|config|backup|dump)", re.I)
DESTRUCTIVE_MUTATION_RE = re.compile(r"(delete|remove|drop|destroy|reset|impersonate|transfer|refund|revoke|disable|ban|updateRole|createUser|updateUser|changePassword)", re.I)


def _type_ref(ref: Dict[str, Any], depth: int = 0) -> str:
    if not isinstance(ref, dict) or depth > 8:
        return ""
    if ref.get("name"):
        return str(ref["name"])
    inner_ref = ref.get("ofType")
    if not isinstance(inner_ref, dict):
        return ""
    inner = _type_ref(inner_ref, depth + 1)
    kind = str(ref.get("kind") or "")
    if kind == "LIST":
        return f"[{inner}]"
    if kind == "NON_NULL":
        return f"{inner}!"
    return inner


def _extract_fields(types: List[Dict[str, Any]], type_name: str) -> List[Dict[str, Any]]:
    for t in types:
        if t.get("name") == type_name:
            return t.get("fields") or []
    return []


def _parse_schema(schema: Dict[str, Any]) -> Dict[str, Any]:
    types = schema.get("types") or []
    query_name = (schema.get("queryType") or {}).get("name") or "Query"
    mutation_name = (schema.get("mutationType") or {}).get("name") or ""
    subscription_name = (schema.get("subscriptionType") or {}).get("name") or ""
    queries = _extract_fields(types, query_name)
    mutations = _extract_fields(types, mutation_name) if mutation_name else []
    subscriptions = _extract_fields(types, subscription_name) if subscription_name else []
    object_types = [t for t in types if t.get("kind") == "OBJECT" and not str(t.get("name", "")).startswith("__")]
    field_count = sum(len(t.get("fields") or []) for t in object_types)
    sensitive = []
    for t in object_types:
        for f in (t.get("fields") or []):
            name = str(f.get("name") or "")
            args = ",".join(str(a.get("name")) for a in (f.get("args") or []))
            hay = f"{t.get('name')}.{name} {args}"
            if SENSITIVE_FIELD_RE.search(hay):
                sensitive.append({
                    "type": t.get("name"),
                    "field": name,
                    "return_type": _type_ref(f.get("type") or {}),
                    "args": args,
                    "deprecated": bool(f.get("isDeprecated")),
                })
    destructive = []
    for m in mutations:
        name = str(m.get("name") or "")
        if DESTRUCTIVE_MUTATION_RE.search(name):
            destructive.append({"name": name, "args": ",".join(str(a.get("name")) for a in (m.get("args") or [])), "return_type": _type_ref(m.get("type") or {})})
    deprecated = []
    for t in object_types:
        for f in (t.get("fields") or []):
            if f.get("isDeprecated"):
                deprecated.append({"type": t.get("name"), "field": f.get("name"), "reason": f.get("deprecationReason", "")})
    return {
        "query_type": query_name,
        "mutation_type": mutation_name,
        "subscription_type": subscription_name,
        "type_count": len(types),
        "object_type_count": len(object_types),
        "field_count": field_count,
        "query_count": len(queries),
        "mutation_count": len(mutations),
        "subscription_count": len(subscriptions),
        "queries": [{"name": q.get("name"), "return_type": _type_ref(q.get("type") or {}), "args": [a.get("name") for a in (q.get("args") or [])]} for q in queries[:120]],
        "mutations": [{"name": m.get("name"), "return_type": _type_ref(m.get("type") or {}), "args": [a.get("name") for a in (m.get("args") or [])]} for m in mutations[:120]],
        "subscriptions": [{"name": s.get("name"), "return_type": _type_ref(s.get("type") or {})} for s in subscriptions[:80]],
        "sensitive_fields": sensitive[:80],
        "destructive_mutations": destructive[:40],
        "deprecated_fields": deprecated[:40],
        "types": [{"kind": t.get("kind"), "name": t.get("name"), "fields": len(t.get("fields") or [])} for t in object_types[:120]],
    }


def _graphql_post(url: str, payload: Any) -> Dict[str, Any]:
    return http_json(url, method="POST", data=payload, body_encoding="json", timeout=12, max_bytes=3_000_000)


def _analyze_graphql(target: str) -> Tuple[Dict[str, Any], List[Dict[str, Any]], int, str]:
    findings: List[Dict[str, Any]] = []
    raw = normalize_url(target)
    parsed = urllib.parse.urlparse(raw)
    host = parsed.hostname or ""
    if not host:
        return {}, [finding("info", "Invalid URL", target)], 0, "Invalid URL."
    base = f"{parsed.scheme}://{parsed.netloc}"
    paths = []
    if parsed.path and parsed.path not in ("", "/"):
        paths.append(parsed.path)
    paths.extend(p for p in GRAPHQL_PATHS if p not in paths)

    endpoint = ""
    introspection = None
    tested = []
    for path in paths[:8]:
        url = base.rstrip("/") + path
        r = _graphql_post(url, {"query": INTROSPECTION_QUERY, "operationName": "VXIntrospection"})
        payload = r.get("json") or {}
        has_schema = isinstance(payload, dict) and isinstance(payload.get("data"), dict) and isinstance(payload["data"].get("__schema"), dict)
        errors = payload.get("errors") if isinstance(payload, dict) else None
        tested.append({"url": url, "status": r.get("status", 0), "graphql": bool(has_schema or errors), "introspection": has_schema})
        if has_schema:
            endpoint = url
            introspection = payload["data"]["__schema"]
            break
        if errors and not endpoint:
            endpoint = url

    if not endpoint:
        return (
            {"url": raw, "endpoint": "", "tested": tested, "graphql_detected": False},
            [finding("info", "No GraphQL endpoint detected", "Common GraphQL paths did not return a GraphQL response.", evidence=[t["url"] for t in tested])],
            0,
            f"No GraphQL endpoint found for {host}.",
        )

    schema_info = _parse_schema(introspection) if introspection else {}
    tests = {"introspection": bool(introspection)}
    get_r = http_request(endpoint + ("&" if "?" in endpoint else "?") + "query=%7B__typename%7D", timeout=8)
    tests["get_supported"] = bool(get_r.get("status") == 200 and "__typename" in (get_r.get("text") or ""))
    batch = _graphql_post(endpoint, [{"query": "{__typename}"}, {"query": "{__typename}"}])
    tests["batch_supported"] = isinstance(batch.get("json"), list)
    suggestion = _graphql_post(endpoint, {"query": "{ thisFieldDoesNotExistVX }"})
    sj = suggestion.get("json") or {}
    err_text = json.dumps(sj.get("errors", "")) if isinstance(sj, dict) else ""
    tests["field_suggestions"] = "did you mean" in err_text.lower()
    playground = http_request(endpoint, timeout=8, max_bytes=120000, headers={"Accept": "text/html"})
    ptext = (playground.get("text") or "").lower()
    tests["graphiql"] = any(x in ptext for x in ("graphiql", "graphql playground", "apollo sandbox", "altair"))

    if introspection:
        findings.append(finding("high", "GraphQL introspection enabled", f"The schema is fully queryable: {schema_info.get('object_type_count')} object types and {schema_info.get('field_count')} fields.", evidence=endpoint, recommendation="Disable introspection in production or restrict it to trusted networks."))
    else:
        findings.append(finding("info", "GraphQL endpoint detected without introspection", "The endpoint responds to GraphQL queries but introspection is disabled.", evidence=endpoint))
    if schema_info.get("sensitive_fields"):
        findings.append(finding("high", "Sensitive fields exposed in schema", f"{len(schema_info['sensitive_fields'])} fields relate to credentials, PII, admin roles or internal configuration.", evidence=[f"{x['type']}.{x['field']}" for x in schema_info["sensitive_fields"][:15]], recommendation="Remove sensitive fields from the public schema and enforce field-level authorization."))
    if schema_info.get("destructive_mutations"):
        findings.append(finding("high", "Destructive mutations present", f"{len(schema_info['destructive_mutations'])} mutation(s) can delete, transfer, reset or impersonate.", evidence=[x["name"] for x in schema_info["destructive_mutations"][:12]], recommendation="Require strong authorization, confirmation and audit logging for destructive operations."))
    if tests.get("batch_supported"):
        findings.append(finding("medium", "Query batching enabled", "Multiple operations can be sent in one request, increasing brute-force and rate-limit bypass risk.", recommendation="Disable batching or cap operations per request."))
    if tests.get("get_supported"):
        findings.append(finding("medium", "GET queries accepted", "GraphQL over GET can enable CSRF-style requests via simple cross-origin links.", recommendation="Require POST with a CSRF token or same-site cookies."))
    if tests.get("graphiql"):
        findings.append(finding("medium", "GraphiQL / Playground exposed", "An interactive GraphQL IDE is served from the endpoint.", recommendation="Disable the IDE in production."))
    if tests.get("field_suggestions"):
        findings.append(finding("low", "Field-name suggestions leak schema hints", "Invalid queries return 'Did you mean' suggestions, aiding schema discovery when introspection is disabled.", recommendation="Disable field suggestions in production."))

    risk = 0
    if introspection:
        risk += 30
    if schema_info.get("sensitive_fields"):
        risk += 25
    if schema_info.get("destructive_mutations"):
        risk += 15
    if tests.get("batch_supported"):
        risk += 10
    if tests.get("get_supported"):
        risk += 10
    if tests.get("graphiql"):
        risk += 10
    risk = min(100, risk)

    summary = (
        f"GraphQL endpoint {endpoint}: introspection {'enabled' if introspection else 'disabled'}, "
        f"{schema_info.get('query_count', 0)} queries, {schema_info.get('mutation_count', 0)} mutations, "
        f"{len(schema_info.get('sensitive_fields', []))} sensitive fields; risk {risk}/100."
    )
    data = {
        "input": raw,
        "endpoint": endpoint,
        "graphql_detected": True,
        "tests": tests,
        "endpoints_tested": tested,
        "schema": schema_info,
        "query_fields": schema_info.get("queries", []),
        "mutation_fields": schema_info.get("mutations", []),
        "subscription_fields": schema_info.get("subscriptions", []),
        "sensitive_fields": schema_info.get("sensitive_fields", []),
        "destructive_mutations": schema_info.get("destructive_mutations", []),
        "deprecated_fields": schema_info.get("deprecated_fields", []),
    }
    return data, findings, risk, summary


async def run_graphql_inspector(target: str) -> Dict[str, Any]:
    started = time.perf_counter()
    data, findings, risk, summary = await asyncio.to_thread(_analyze_graphql, target)
    if not data:
        return error_envelope("graphql_inspector", target, summary)
    return envelope(
        "graphql_inspector", data.get("endpoint") or target, risk=risk, summary=summary,
        findings=findings, data=data,
        iocs=[{"type": "url", "value": data.get("endpoint", target)}] if data.get("endpoint") else [],
        sources=["GraphQL introspection", "POST/GET probes", "Batching and suggestion tests"],
        elapsed_ms=int((time.perf_counter() - started) * 1000),
    )


# ===========================================================================
# 4. SUPPLY CHAIN AUDITOR
# ===========================================================================

NPM_TOP = {
    "react", "react-dom", "lodash", "axios", "express", "next", "vue", "angular", "chalk",
    "commander", "debug", "typescript", "webpack", "vite", "eslint", "prettier", "dotenv",
    "moment", "dayjs", "zod", "uuid", "cors", "body-parser", "mongoose", "socket.io",
    "tailwindcss", "jest", "vitest", "nodemon", "ts-node", "passport", "jsonwebtoken",
    "bcrypt", "bcryptjs", "stripe", "openai", "langchain", "playwright", "puppeteer",
}
PYPI_TOP = {
    "requests", "numpy", "pandas", "flask", "django", "fastapi", "uvicorn", "pydantic",
    "sqlalchemy", "aiohttp", "httpx", "beautifulsoup4", "scrapy", "selenium", "playwright",
    "pillow", "openpyxl", "python-dateutil", "pyyaml", "cryptography", "boto3", "botocore",
    "tensorflow", "torch", "transformers", "openai", "langchain", "scipy", "matplotlib",
    "pytest", "setuptools", "wheel", "pip", "rich", "click", "typer", "jinja2", "redis",
}


def _levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def _typosquat_match(name: str, top: set) -> Optional[str]:
    low = name.lower()
    for candidate in top:
        if low == candidate:
            return None
        dist = _levenshtein(low, candidate)
        if dist == 1 or (dist == 2 and len(low) >= 6):
            return candidate
    return None


def _npm_downloads(name: str) -> Optional[int]:
    data = http_json(f"https://api.npmjs.org/downloads/point/last-week/{urllib.parse.quote(name)}", timeout=8).get("json") or {}
    try:
        return int(data.get("downloads"))
    except Exception:
        return None


def _audit_npm(name: str) -> Optional[Dict[str, Any]]:
    # The /latest endpoint is small even for giant packages such as typescript,
    # while the full registry document can exceed 12 MB. Use latest first.
    latest_r = http_json(f"https://registry.npmjs.org/{urllib.parse.quote(name)}/latest", timeout=14, max_bytes=1_000_000)
    meta = latest_r.get("json") or {}
    if not isinstance(meta, dict) or not meta.get("name"):
        return None

    full = http_json(f"https://registry.npmjs.org/{urllib.parse.quote(name)}", timeout=14, max_bytes=6_000_000).get("json") or {}
    if not isinstance(full, dict):
        full = {}
    versions = full.get("versions") or {}
    tags = full.get("dist-tags") or {"latest": meta.get("version", "")}
    latest = tags.get("latest") or meta.get("version", "")
    if latest in versions and isinstance(versions[latest], dict):
        merged = dict(meta)
        merged.update(versions[latest])
        meta = merged
    time_info = full.get("time") or {}
    scripts = meta.get("scripts") or {}
    install_scripts = {k: v for k, v in scripts.items() if k in ("preinstall", "install", "postinstall", "prepare", "prepublish")}
    maintainers = meta.get("maintainers") or full.get("maintainers") or []
    deps = meta.get("dependencies") or {}
    downloads = _npm_downloads(name)
    created = time_info.get("created", "")
    modified = time_info.get("modified", "")
    age_days = None
    try:
        import datetime
        dt = datetime.datetime.fromisoformat(created.replace("Z", "+00:00"))
        age_days = (datetime.datetime.now(datetime.timezone.utc) - dt).days
    except Exception:
        pass
    typo = _typosquat_match(name, NPM_TOP)
    deprecated = meta.get("deprecated") or full.get("deprecated")
    repository = meta.get("repository") or full.get("repository")
    license_name = meta.get("license") or full.get("license")

    findings = []
    risk = 0
    if install_scripts:
        risk += 32
        findings.append(finding("high", "Install-time scripts present", "The package runs code during install, a common supply-chain persistence vector.", evidence=install_scripts, recommendation="Review the script contents and pin the exact package version/digest."))
    if deprecated:
        risk += 18
        findings.append(finding("medium", "Package is deprecated", str(deprecated), recommendation="Migrate to a maintained alternative; deprecated packages stop receiving security fixes."))
    if typo:
        risk += 38
        findings.append(finding("critical", "Possible typosquat", f"'{name}' is one or two edits away from the popular package '{typo}'.", evidence={"name": name, "popular": typo, "distance": _levenshtein(name.lower(), typo)}, recommendation="Verify the exact package name and publisher before installing."))
    if len(maintainers) <= 1 and install_scripts:
        risk += 10
        findings.append(finding("medium", "Single maintainer with install scripts", "Compromise of one maintainer account can execute code on every install.", evidence=[m.get("name") for m in maintainers]))
    if downloads is not None and downloads < 100:
        risk += 10
        findings.append(finding("medium", "Very low weekly downloads", f"{downloads} weekly downloads. Low-volume packages are harder to vet and often used in impersonation.", evidence=downloads))
    if age_days is not None and age_days < 30:
        risk += 12
        findings.append(finding("medium", "Recently created package", f"Registry record is {age_days} day(s) old.", evidence=created))
    if not repository:
        risk += 6
        findings.append(finding("low", "No repository metadata", "The package does not declare a source repository."))
    if not license_name:
        risk += 6
        findings.append(finding("low", "No license declared", "Missing license metadata reduces provenance confidence."))
    if len(deps) > 25:
        risk += 6
        findings.append(finding("low", "Large dependency graph", f"{len(deps)} direct dependencies expand the transitive attack surface."))
    risk = min(100, risk)
    if not findings:
        findings.append(finding("info", "No major NPM supply-chain risks detected", "Install scripts, deprecation, typosquat distance and provenance checks passed."))

    return {
        "ecosystem": "npm",
        "package": meta.get("name", name),
        "version": latest,
        "description": meta.get("description", ""),
        "license": license_name or "",
        "repository": repository if isinstance(repository, str) else (repository or {}).get("url", ""),
        "homepage": meta.get("homepage", ""),
        "created": created,
        "modified": modified,
        "age_days": age_days,
        "maintainers": [{"name": m.get("name"), "email": m.get("email")} for m in maintainers[:12]],
        "maintainer_count": len(maintainers),
        "versions_count": len(versions) or 1,
        "dependencies": list(deps.keys())[:60],
        "dependency_count": len(deps),
        "scripts": scripts,
        "install_scripts": install_scripts,
        "deprecated": deprecated or "",
        "weekly_downloads": downloads,
        "typosquat_of": typo or "",
        "dist": {
            "tarball": (meta.get("dist") or {}).get("tarball", ""),
            "unpacked_size": (meta.get("dist") or {}).get("unpackedSize", 0),
            "integrity": (meta.get("dist") or {}).get("integrity", ""),
        },
        "risk_reasons": [f["title"] for f in findings if f["severity"] != "info"],
    }, findings, risk, meta.get("name", name)


def _inspect_pypi_sdist(url: str) -> Dict[str, Any]:
    if not url:
        return {"available": False, "suspicious": []}
    r = http_request(url, timeout=14, max_bytes=8_000_000)
    if r.get("status") != 200 or not r.get("body"):
        return {"available": False, "suspicious": []}
    suspicious = []
    inspected = []
    try:
        with tarfile.open(fileobj=io.BytesIO(r["body"]), mode="r:gz") as tf:
            for member in tf.getmembers():
                if not member.isfile() or member.size > 400_000:
                    continue
                if not re.search(r"(^|/)(setup\.py|pyproject\.toml|setup\.cfg)$", member.name):
                    continue
                fh = tf.extractfile(member)
                if not fh:
                    continue
                text = fh.read().decode("utf-8", errors="replace")
                inspected.append(member.name)
                patterns = {
                    "subprocess": "subprocess execution",
                    "os.system": "os.system execution",
                    "curl ": "curl download",
                    "wget ": "wget download",
                    "base64 -d": "base64 decode pipe",
                    "eval(": "eval() call",
                    "exec(": "exec() call",
                    "urllib.request": "network download",
                    "requests.get": "network download",
                    "socket.": "raw socket",
                }
                for token, label in patterns.items():
                    if token in text:
                        suspicious.append({"file": member.name, "indicator": label, "token": token})
                if len(inspected) >= 6:
                    break
    except Exception as exc:
        return {"available": False, "error": str(exc), "suspicious": []}
    return {"available": True, "inspected": inspected, "suspicious": suspicious[:20]}


def _audit_pypi(name: str) -> Optional[Dict[str, Any]]:
    r = http_json(f"https://pypi.org/pypi/{urllib.parse.quote(name)}/json", timeout=12, max_bytes=2_000_000)
    data = r.get("json")
    if not isinstance(data, dict) or not data.get("info"):
        return None
    info = data.get("info") or {}
    releases = data.get("releases") or {}
    latest = info.get("version", "")
    latest_files = releases.get(latest) or []
    upload_times = [f.get("upload_time_iso_8601") or f.get("upload_time") for f in latest_files if f.get("upload_time_iso_8601") or f.get("upload_time")]
    sdist = next((f.get("url") for f in latest_files if f.get("packagetype") == "sdist"), "")
    stats = http_json(f"https://pypistats.org/api/packages/{urllib.parse.quote(name)}/recent", timeout=8).get("json") or {}
    downloads = (stats.get("data") or {}) if isinstance(stats, dict) else {}
    typo = _typosquat_match(name, PYPI_TOP)
    requires = info.get("requires_dist") or []
    project_urls = info.get("project_urls") or {}
    author = info.get("author") or info.get("author_email") or ""
    maintainer = info.get("maintainer") or info.get("maintainer_email") or ""
    age_days = None
    try:
        import datetime
        ts = min([t for t in upload_times if t]) if upload_times else ""
        if ts:
            dt = datetime.datetime.fromisoformat(ts.replace("Z", "+00:00"))
            age_days = (datetime.datetime.now(datetime.timezone.utc) - dt).days
    except Exception:
        pass
    sdist_scan = _inspect_pypi_sdist(sdist)
    direct_url_deps = [d for d in requires if "http://" in d or "https://" in d or " @ " in d]
    yanked = [f for f in latest_files if f.get("yanked")]

    findings = []
    risk = 0
    if typo:
        risk += 38
        findings.append(finding("critical", "Possible typosquat", f"'{name}' is one or two edits away from the popular PyPI package '{typo}'.", evidence={"name": name, "popular": typo, "distance": _levenshtein(name.lower(), typo)}, recommendation="Verify the exact package name and publisher before installing."))
    if sdist_scan.get("suspicious"):
        risk += 34
        findings.append(finding("critical", "Install-time code indicators in source distribution", "setup.py/pyproject contains execution or network-download primitives.", evidence=sdist_scan["suspicious"][:12], recommendation="Inspect the sdist line-by-line before installing; prefer a wheel from a verified publisher."))
    if direct_url_deps:
        risk += 22
        findings.append(finding("high", "Direct URL dependencies", "Requirements reference remote URLs or direct VCS targets, bypassing normal registry provenance.", evidence=direct_url_deps[:10], recommendation="Pin direct dependencies to hashes and trusted domains."))
    if yanked:
        risk += 16
        findings.append(finding("medium", "Latest release is yanked", "The current version was withdrawn by the publisher.", evidence=latest, recommendation="Do not pin a yanked release; review the advisory reason."))
    if not author and not maintainer:
        risk += 8
        findings.append(finding("low", "No author or maintainer metadata", "Publisher attribution is missing."))
    if not info.get("license"):
        risk += 6
        findings.append(finding("low", "No license declared", "Missing license metadata reduces provenance confidence."))
    if len(releases) <= 1:
        risk += 8
        findings.append(finding("low", "Single release", "A one-release package has little public scrutiny."))
    if age_days is not None and age_days < 30:
        risk += 12
        findings.append(finding("medium", "Recently published release", f"Latest release is {age_days} day(s) old.", evidence=upload_times[:3]))
    if downloads and downloads.get("last_week", 0) < 50:
        risk += 8
        findings.append(finding("low", "Very low weekly downloads", f"{downloads.get('last_week')} downloads in the last week.", evidence=downloads))
    risk = min(100, risk)
    if not findings:
        findings.append(finding("info", "No major PyPI supply-chain risks detected", "Typosquat, sdist scripts, URL dependencies and provenance checks passed."))

    return {
        "ecosystem": "pypi",
        "package": info.get("name", name),
        "version": latest,
        "description": info.get("summary", ""),
        "license": info.get("license", ""),
        "author": author,
        "maintainer": maintainer,
        "homepage": info.get("home_page", ""),
        "project_urls": project_urls,
        "releases_count": len(releases),
        "release_files": len(latest_files),
        "upload_times": upload_times[:5],
        "age_days": age_days,
        "requires_dist": requires[:60],
        "dependency_count": len(requires),
        "direct_url_dependencies": direct_url_deps,
        "yanked": bool(yanked),
        "weekly_downloads": downloads.get("last_week") if isinstance(downloads, dict) else None,
        "downloads": downloads,
        "typosquat_of": typo or "",
        "sdist": sdist,
        "sdist_scan": sdist_scan,
        "classifiers": (info.get("classifiers") or [])[:20],
        "risk_reasons": [f["title"] for f in findings if f["severity"] != "info"],
    }, findings, risk, info.get("name", name)


async def run_supply_chain_audit(target: str) -> Dict[str, Any]:
    started = time.perf_counter()
    raw = (target or "").strip()
    ecosystem = ""
    name = raw
    if ":" in raw and raw.split(":", 1)[0].lower() in ("npm", "pypi", "pip"):
        ecosystem, name = raw.split(":", 1)
        ecosystem = "pypi" if ecosystem.lower() in ("pypi", "pip") else "npm"
    if not re.fullmatch(r"[A-Za-z0-9@._/-]{2,120}", name or ""):
        return error_envelope("supply_chain_audit", target, "Enter an npm or PyPI package name, e.g. lodash or pypi:requests")

    # Prefer the ecosystem of well-known packages when auto-detecting.
    if not ecosystem:
        if str(name).lower() in NPM_TOP:
            ecosystem = "npm"
        elif str(name).lower() in PYPI_TOP:
            ecosystem = "pypi"

    result = None
    if ecosystem != "pypi":
        result = await asyncio.to_thread(_audit_npm, name)
        if result:
            ecosystem = "npm"
    if not result and ecosystem != "npm":
        result = await asyncio.to_thread(_audit_pypi, name)
        if result:
            ecosystem = "pypi"
    if not result and not ecosystem:
        # Try the other ecosystem as a final fallback.
        result = await asyncio.to_thread(_audit_pypi, name)
        if result:
            ecosystem = "pypi"
    if not result:
        return error_envelope("supply_chain_audit", target, f"Package '{name}' was not found on npm or PyPI.")

    data, findings, risk, resolved = result
    summary = (
        f"{ecosystem.upper()} package {resolved}@{data.get('version')}: "
        f"{len(findings)} finding(s), risk {risk}/100. "
        f"{'Typosquat of ' + data['typosquat_of'] if data.get('typosquat_of') else 'No typosquat match'}."
    )
    return envelope(
        "supply_chain_audit", f"{ecosystem}:{resolved}", risk=risk, summary=summary,
        findings=findings, data=data,
        iocs=[{"type": "package", "value": f"{ecosystem}:{resolved}"}],
        sources=["npm registry", "npm downloads API", "PyPI JSON API", "pypistats.org", "Source distribution inspection"],
        elapsed_ms=int((time.perf_counter() - started) * 1000),
    )
