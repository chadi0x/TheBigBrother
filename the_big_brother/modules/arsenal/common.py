"""
THE BIG BROTHER // VX SOVEREIGN
Arsenal shared transport, DNS, scoring and result-envelope utilities.

Everything here is dependency-optional and pure-stdlib first. Tools must keep
working on a bare-metal install with no API keys and gracefully report upstream
faults instead of raising.
"""
from __future__ import annotations

import asyncio
import base64
import hashlib
import ipaddress
import json
import random
import re
import socket
import ssl
import string
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

USER_AGENT = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36 "
    "BigBrother-VX/1.0 (+https://thebigbrother.cloud)"
)
API_UA = "TheBigBrother-VX/1.0 OSINT Arsenal"

SEVERITY_WEIGHT = {
    "critical": 32,
    "high": 20,
    "medium": 11,
    "low": 4,
    "info": 0,
}

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def clean(value: Any) -> Any:
    """Recursively make a value JSON-safe."""
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    if isinstance(value, dict):
        return {str(k): clean(v) for k, v in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [clean(v) for v in value]
    try:
        return str(value)
    except Exception:
        return None


def risk_grade(risk: int) -> str:
    if risk >= 85:
        return "F"
    if risk >= 70:
        return "E"
    if risk >= 55:
        return "D"
    if risk >= 35:
        return "C"
    if risk >= 18:
        return "B"
    return "A"


def risk_tier(risk: int) -> str:
    if risk >= 80:
        return "CRITICAL"
    if risk >= 60:
        return "HIGH"
    if risk >= 35:
        return "ELEVATED"
    if risk >= 15:
        return "GUARDED"
    return "NOMINAL"


def finding(
    severity: str,
    title: str,
    detail: str = "",
    evidence: Any = None,
    recommendation: str = "",
) -> Dict[str, Any]:
    sev = str(severity or "info").lower()
    if sev not in SEVERITY_WEIGHT:
        sev = "info"
    item = {
        "severity": sev,
        "title": title,
        "detail": detail,
    }
    if evidence not in (None, "", [], {}):
        item["evidence"] = clean(evidence)
    if recommendation:
        item["recommendation"] = recommendation
    return item


def dedupe_findings(findings: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
    seen = set()
    out: List[Dict[str, Any]] = []
    for f in findings:
        if not isinstance(f, dict):
            continue
        key = (f.get("severity"), f.get("title"), str(f.get("detail", ""))[:90])
        if key in seen:
            continue
        seen.add(key)
        out.append(f)
    out.sort(key=lambda x: SEVERITY_ORDER.get(x.get("severity", "info"), 9))
    return out


def envelope(
    tool: str,
    target: str,
    *,
    risk: int = 0,
    summary: str = "",
    findings: Optional[List[Dict[str, Any]]] = None,
    data: Optional[Dict[str, Any]] = None,
    iocs: Optional[List[Any]] = None,
    artifacts: Optional[List[Any]] = None,
    sources: Optional[List[str]] = None,
    notes: Optional[List[str]] = None,
    status: str = "success",
    elapsed_ms: int = 0,
    grade: Optional[str] = None,
) -> Dict[str, Any]:
    risk = int(max(0, min(100, risk)))
    fs = dedupe_findings(findings or [])
    return {
        "status": status,
        "tool": tool,
        "target": target,
        "generated_at": utc_now(),
        "elapsed_ms": elapsed_ms,
        "risk_score": risk,
        "score": risk,
        "risk_tier": risk_tier(risk),
        "grade": grade or risk_grade(risk),
        "summary": summary,
        "findings": fs,
        "iocs": clean(iocs or []),
        "artifacts": clean(artifacts or []),
        "sources": sources or [],
        "notes": notes or [],
        "data": clean(data or {}),
    }


def error_envelope(tool: str, target: str, message: str, *, details: Any = None) -> Dict[str, Any]:
    return {
        "status": "error",
        "tool": tool,
        "target": target,
        "generated_at": utc_now(),
        "elapsed_ms": 0,
        "risk_score": 0,
        "score": 0,
        "risk_tier": "UNKNOWN",
        "grade": "?",
        "summary": message,
        "findings": [],
        "iocs": [],
        "artifacts": [],
        "sources": [],
        "notes": [],
        "error": message,
        "details": clean(details),
        "data": {},
    }


# ---------------------------------------------------------------------------
# HTTP TRANSPORT (manual redirect chain, bounded body, duplicate headers)
# ---------------------------------------------------------------------------

def _decode_body(raw: bytes, headers: Dict[str, str]) -> bytes:
    enc = (headers.get("content-encoding") or "").lower()
    if enc == "gzip":
        try:
            import gzip

            return gzip.decompress(raw)
        except Exception:
            return raw
    if enc == "deflate":
        try:
            import zlib

            return zlib.decompress(raw, -zlib.MAX_WBITS)
        except Exception:
            return raw
    return raw


def http_request(
    url: str,
    *,
    method: str = "GET",
    data: Any = None,
    headers: Optional[Dict[str, str]] = None,
    timeout: float = 9.0,
    max_bytes: int = 262144,
    allow_redirects: bool = True,
    max_redirects: int = 6,
    verify_tls: bool = True,
    body_encoding: Optional[str] = None,
) -> Dict[str, Any]:
    """Fetch a URL with manual redirect tracking. Never raises."""
    started = time.perf_counter()
    chain: List[Dict[str, Any]] = []
    current = url
    if data is not None and not isinstance(data, (bytes, bytearray)):
        if body_encoding == "json" or isinstance(data, (dict, list)):
            data = json.dumps(data).encode("utf-8")
            headers = {**(headers or {})}
            headers.setdefault("Content-Type", "application/json")
        elif isinstance(data, str):
            data = data.encode("utf-8")
    hdrs = {
        "User-Agent": USER_AGENT,
        "Accept": "text/html,application/xhtml+xml,application/json;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
        "Accept-Encoding": "identity",
        "Connection": "close",
    }
    if headers:
        hdrs.update({str(k): str(v) for k, v in headers.items()})

    body = b""
    final_status = 0
    final_headers: Dict[str, str] = {}
    resp_obj = None
    error: Optional[str] = None

    ctx = None
    if url.lower().startswith("https://") and not verify_tls:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

    for hop in range(max_redirects + 1):
        req = urllib.request.Request(current, data=data, method=method, headers=hdrs)
        try:
            resp_obj = urllib.request.urlopen(req, timeout=timeout, context=ctx)
        except urllib.error.HTTPError as exc:
            resp_obj = exc
        except Exception as exc:
            error = f"{type(exc).__name__}: {exc}"
            chain.append({"url": current, "status": 0, "error": error})
            break

        try:
            raw = resp_obj.read(max_bytes) if method.upper() != "HEAD" else b""
        except Exception:
            raw = b""
        try:
            status = int(resp_obj.getcode() or 0)
        except Exception:
            status = int(getattr(resp_obj, "status", 0) or 0)
        rh = {str(k).lower(): str(v) for k, v in (resp_obj.headers.items() if resp_obj.headers else [])}
        try:
            set_cookies = resp_obj.headers.get_all("Set-Cookie") or []
        except Exception:
            set_cookies = []
        if set_cookies:
            rh["set-cookie"] = "\n".join(set_cookies)
        location = rh.get("location")
        body = _decode_body(raw, rh)
        final_status, final_headers = status, rh
        chain.append(
            {
                "url": current,
                "status": status,
                "server": rh.get("server", ""),
                "content_type": rh.get("content-type", ""),
                "location": location or "",
                "bytes": len(body),
            }
        )
        if allow_redirects and status in (301, 302, 303, 307, 308) and location and hop < max_redirects:
            current = urllib.parse.urljoin(current, location)
            if status == 303 or (status in (301, 302) and method.upper() == "POST"):
                method = "GET"
                data = None
                hdrs.pop("Content-Type", None)
            continue
        break

    text = body.decode("utf-8", errors="replace")
    elapsed_ms = int((time.perf_counter() - started) * 1000)
    return {
        "ok": 200 <= final_status < 400,
        "status": final_status,
        "headers": final_headers,
        "body": body,
        "text": text,
        "url": current,
        "final_url": current,
        "chain": chain,
        "redirect_count": max(0, len(chain) - 1),
        "error": error,
        "elapsed_ms": elapsed_ms,
    }


def http_json(url: str, **kwargs: Any) -> Dict[str, Any]:
    kwargs.setdefault("headers", {})
    kwargs["headers"].setdefault("Accept", "application/json")
    r = http_request(url, **kwargs)
    data = None
    if r.get("body"):
        try:
            data = json.loads(r["text"])
        except Exception:
            data = None
    r["json"] = data
    return r


def post_json(url: str, payload: Any, **kwargs: Any) -> Dict[str, Any]:
    return http_json(url, method="POST", data=payload, body_encoding="json", **kwargs)


# ---------------------------------------------------------------------------
# DNS OVER HTTPS
# ---------------------------------------------------------------------------

DOH_ENDPOINTS = (
    "https://cloudflare-dns.com/dns-query",
    "https://dns.google/resolve",
)


def doh_raw(name: str, rtype: str, timeout: float = 5.0) -> Dict[str, Any]:
    """Return the raw DoH JSON answer plus which resolver served it."""
    last_err = ""
    for endpoint in DOH_ENDPOINTS:
        if endpoint.endswith("/resolve"):
            url = f"{endpoint}?name={urllib.parse.quote(name)}&type={urllib.parse.quote(rtype)}"
        else:
            url = (
                f"{endpoint}?name={urllib.parse.quote(name)}"
                f"&type={urllib.parse.quote(rtype)}&ct=application/dns-json"
            )
        r = http_request(
            url,
            headers={"Accept": "application/dns-json", "User-Agent": API_UA},
            timeout=timeout,
            max_bytes=131072,
        )
        if r.get("status") == 200 and r.get("body"):
            try:
                data = json.loads(r["text"])
                if isinstance(data, dict):
                    data["_resolver"] = urllib.parse.urlparse(endpoint).netloc
                    return data
            except Exception as exc:
                last_err = str(exc)
        else:
            last_err = r.get("error") or f"HTTP {r.get('status')}"
    return {"Status": -1, "Answer": [], "_error": last_err}


def doh_query(name: str, rtype: str) -> List[str]:
    data = doh_raw(name, rtype)
    out: List[str] = []
    for ans in data.get("Answer", []) or []:
        val = str(ans.get("data", "")).strip().strip('"')
        if val:
            out.append(val)
    return out


def resolve_a(host: str, *, fallback_socket: bool = False) -> List[str]:
    vals = [v for v in doh_query(host, "A") if _is_ipv4(v)]
    if not vals and fallback_socket:
        try:
            ip = socket.gethostbyname(host)
            if ip:
                vals = [ip]
        except Exception:
            pass
    return _dedupe(vals)


def resolve_aaaa(host: str) -> List[str]:
    return _dedupe([v for v in doh_query(host, "AAAA") if ":" in v])


def resolve_mx(host: str) -> List[Dict[str, Any]]:
    out = []
    for val in doh_query(host, "MX"):
        bits = val.split()
        if len(bits) == 2:
            try:
                out.append({"priority": int(bits[0]), "host": bits[1].rstrip(".")})
            except Exception:
                pass
        elif bits:
            out.append({"priority": 0, "host": bits[0].rstrip(".")})
    out.sort(key=lambda x: x["priority"])
    return out


def resolve_txt(host: str) -> List[str]:
    return _dedupe([v for v in doh_query(host, "TXT") if v])


def ptr_lookup(ip: str) -> str:
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        pass
    rev = _reverse_name(ip)
    if rev:
        vals = doh_query(rev, "PTR")
        if vals:
            return vals[0].rstrip(".")
    return ""


def _reverse_name(ip: str) -> str:
    try:
        addr = ipaddress.ip_address(ip)
        if addr.version == 4:
            return ".".join(reversed(str(addr).split("."))) + ".in-addr.arpa"
        exploded = addr.exploded.replace(":", "")
        return ".".join(reversed(list(exploded))) + ".ip6.arpa"
    except Exception:
        return ""


def _is_ipv4(value: str) -> bool:
    try:
        ipaddress.IPv4Address(value)
        return True
    except Exception:
        return False


def _dedupe(values: Sequence[Any]) -> List[Any]:
    seen = set()
    out = []
    for v in values:
        key = str(v)
        if key and key not in seen:
            seen.add(key)
            out.append(v)
    return out


# ---------------------------------------------------------------------------
# VALIDATION / NORMALISATION
# ---------------------------------------------------------------------------

DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"[a-z][a-z0-9-]{1,62}[a-z0-9]$",
    re.IGNORECASE,
)


def normalize_domain(value: str) -> str:
    value = (value or "").strip().lower()
    if "://" in value:
        value = urllib.parse.urlparse(value).hostname or value
    else:
        value = value.split("/")[0].split("?")[0]
    value = value.strip().strip(".").split(":")[0]
    if value.startswith("www."):
        value = value[4:]
    return value


def is_domain(value: str) -> bool:
    return bool(DOMAIN_RE.match(value or ""))


def normalize_url(value: str) -> str:
    value = (value or "").strip()
    if not value:
        return ""
    if not re.match(r"^[a-z][a-z0-9+.-]*://", value, re.I):
        value = "https://" + value
    return value


def root_domain(domain: str) -> Tuple[str, str]:
    """Small public-suffix-aware-ish splitter (handles common 2-level TLDs)."""
    parts = normalize_domain(domain).split(".")
    if len(parts) <= 2:
        return (parts[0] if parts else ""), ("." + parts[-1] if len(parts) == 2 else "")
    two_level = {
        "co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "net.au", "org.au",
        "co.nz", "co.za", "com.br", "com.tr", "com.cn", "com.hk", "com.sg",
        "co.jp", "co.kr", "co.in", "com.mx", "com.ar", "com.pl", "com.ua",
    }
    suffix = ".".join(parts[-2:])
    if suffix in two_level:
        return parts[-3], "." + suffix
    return parts[-2], "." + parts[-1]


def is_private_ip(value: str) -> bool:
    try:
        addr = ipaddress.ip_address(value)
        return (
            addr.is_private
            or addr.is_loopback
            or addr.is_link_local
            or addr.is_multicast
            or addr.is_reserved
            or addr.is_unspecified
        )
    except Exception:
        return True


# ---------------------------------------------------------------------------
# TLS
# ---------------------------------------------------------------------------

def tls_peer(host: str, port: int = 443, timeout: float = 5.0) -> Dict[str, Any]:
    out: Dict[str, Any] = {"ok": False, "sans": []}
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                der = ssock.getpeercert(binary_form=True) or b""
                out.update(
                    {
                        "ok": True,
                        "version": ssock.version(),
                        "cipher": (ssock.cipher() or ["", "", 0])[0],
                        "key_bits": (ssock.cipher() or ["", "", 0])[2],
                        "sans": [v for k, v in cert.get("subjectAltName", []) if k == "DNS"],
                        "issuer": {k: v for k, v in cert.get("issuer", []) if k},
                        "subject": {k: v for k, v in cert.get("subject", []) if k},
                        "not_before": cert.get("notBefore", ""),
                        "not_after": cert.get("notAfter", ""),
                        "serial": cert.get("serialNumber", ""),
                        "sha256": hashlib.sha256(der).hexdigest() if der else "",
                    }
                )
                out["expires_in_days"] = _cert_days_left(cert.get("notAfter", ""))
    except Exception as exc:
        out["error"] = f"{type(exc).__name__}: {exc}"
    return out


def _cert_days_left(not_after: str) -> Optional[int]:
    if not not_after:
        return None
    for fmt in ("%b %d %H:%M:%S %Y %Z", "%b %d %H:%M:%S %Y GMT"):
        try:
            dt = datetime.strptime(not_after, fmt).replace(tzinfo=timezone.utc)
            return int((dt - datetime.now(timezone.utc)).total_seconds() // 86400)
        except Exception:
            continue
    return None


# ---------------------------------------------------------------------------
# RDAP
# ---------------------------------------------------------------------------

def rdap_domain(domain: str) -> Dict[str, Any]:
    r = http_json(f"https://rdap.org/domain/{urllib.parse.quote(domain)}", timeout=9)
    data = r.get("json")
    if not isinstance(data, dict):
        return {}
    events = {}
    for ev in data.get("events", []) or []:
        events[str(ev.get("eventAction", "")).lower()] = ev.get("eventDate")
    registrar = ""
    registrar_iana = ""
    registrant = ""
    country = ""
    for ent in data.get("entities", []) or []:
        roles = ent.get("roles", []) or []
        vcard = ent.get("vcardArray") or []
        vals = vcard[1] if len(vcard) > 1 and isinstance(vcard[1], list) else []
        if "registrar" in roles:
            for item in vals:
                if item and item[0] == "fn":
                    registrar = item[3]
            for pid in ent.get("publicIds", []) or []:
                if "IANA" in str(pid.get("type", "")):
                    registrar_iana = str(pid.get("identifier", ""))
        if "registrant" in roles:
            for item in vals:
                if item and item[0] == "org":
                    registrant = str(item[3])
                if item and item[0] == "adr" and len(item) > 3 and isinstance(item[3], list):
                    country = str(item[3][-1])
    return {
        "registrar": registrar or "Unknown",
        "registrar_iana": registrar_iana,
        "registrant": registrant or "Redacted / Privacy",
        "country": country,
        "status": data.get("status", []) or [],
        "created": events.get("registration", ""),
        "updated": events.get("last changed", events.get("last update of rdap database", "")),
        "expires": events.get("expiration", ""),
        "nameservers": [
            str(ns.get("ldhName", "")).lower()
            for ns in data.get("nameservers", []) or []
            if ns.get("ldhName")
        ],
        "secure_dns": bool(data.get("secureDNS", {}).get("delegationSigned")) if isinstance(data.get("secureDNS"), dict) else False,
        "handle": data.get("handle", ""),
    }


def rdap_ip(ip: str) -> Dict[str, Any]:
    r = http_json(f"https://rdap.org/ip/{urllib.parse.quote(ip)}", timeout=9)
    data = r.get("json")
    if not isinstance(data, dict):
        return {}
    return {
        "name": data.get("name", ""),
        "handle": data.get("handle", ""),
        "country": data.get("country", ""),
        "type": data.get("type", ""),
        "start": data.get("startAddress", ""),
        "end": data.get("endAddress", ""),
        "parent": data.get("parentHandle", ""),
        "status": data.get("status", []) or [],
    }


# ---------------------------------------------------------------------------
# MISC HELPERS
# ---------------------------------------------------------------------------

def md5(value: str) -> str:
    return hashlib.md5(value.encode("utf-8")).hexdigest()


def sha1(value: str) -> str:
    return hashlib.sha1(value.encode("utf-8")).hexdigest()


def sha256(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def b64url_decode(data: str) -> bytes:
    pad = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + pad)


def human_bytes(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(n) < 1024:
            return f"{n:.1f} {unit}" if unit != "B" else f"{n} B"
        n /= 1024.0
    return f"{n:.1f} PB"


def entropy(value: str) -> float:
    """Shannon entropy in bits per character."""
    if not value:
        return 0.0
    import math

    counts: Dict[str, int] = {}
    for ch in value:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(value)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def random_label(length: int = 16) -> str:
    alphabet = string.ascii_lowercase + string.digits
    return "".join(random.choice(alphabet) for _ in range(length))


async def gather_limited(coros: Sequence[Any], limit: int = 10) -> List[Any]:
    sem = asyncio.Semaphore(max(1, limit))

    async def _wrap(coro):
        async with sem:
            try:
                return await coro
            except Exception as exc:
                return {"error": str(exc)}

    return list(await asyncio.gather(*(_wrap(c) for c in coros)))


def sync_to_thread(fn, *args, **kwargs):
    """Helper kept for readability around asyncio.to_thread."""
    return asyncio.to_thread(fn, *args, **kwargs)
