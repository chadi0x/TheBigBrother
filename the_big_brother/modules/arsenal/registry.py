"""
VX SOVEREIGN ARSENAL REGISTRY

Single source of truth for the 24 keyless engines. The frontend renders
forms directly from this metadata, so adding a tool requires no HTML edits.
"""
from __future__ import annotations

import asyncio
import time
from typing import Any, Callable, Dict, List, Optional

from .common import error_envelope
from .advanced import (
    run_attack_surface,
    run_graphql_inspector,
    run_origin_unmasker,
    run_supply_chain_audit,
)
from .identity import run_bin_lookup, run_jwt_analyzer, run_password_pwned, run_vin_decoder
from .network import (
    run_bucket_hunter,
    run_cert_transparency,
    run_dns_intel,
    run_exposed_files,
    run_http_audit,
    run_ip_intel,
    run_link_forensics,
    run_typosquat_radar,
    run_waf_fingerprint,
)
from .social import (
    run_bluesky_intel,
    run_discord_intel,
    run_gravatar_intel,
    run_reddit_intel,
    run_telegram_intel,
)
from .threat import run_cve_intel, run_ioc_enrich

ARSENAL_VERSION = "10.1.0"
ARSENAL_CODENAME = "SOVEREIGN"

CATEGORIES = [
    {
        "id": "network",
        "name": "Network & Infrastructure",
        "description": "DNS, certificates, edge posture, cloud storage and exposed files.",
        "icon": "globe",
    },
    {
        "id": "forensics",
        "name": "Link & Token Forensics",
        "description": "Redirect chains, phishing URL anatomy and JWT/key confusion.",
        "icon": "link",
    },
    {
        "id": "identity",
        "name": "Credential & Identity",
        "description": "Breach-aware password audits and public Gravatar identity surfaces.",
        "icon": "fingerprint",
    },
    {
        "id": "threat",
        "name": "Threat Intelligence",
        "description": "CVE/KEV/EPSS correlation and multi-source IOC enrichment.",
        "icon": "shield",
    },
    {
        "id": "asset",
        "name": "Vehicle & Financial",
        "description": "VIN provenance/recalls and card issuer/BIN intelligence.",
        "icon": "car",
    },
    {
        "id": "appsec",
        "name": "Application & Supply Chain",
        "description": "GraphQL schema risk, npm/PyPI provenance and install-time code auditing.",
        "icon": "code",
    },
    {
        "id": "social",
        "name": "Social Surface",
        "description": "Bluesky, Reddit, Discord and Telegram public-profile intelligence.",
        "icon": "users",
    },
]


def _field(name: str, label: str, placeholder: str, *, kind: str = "text", required: bool = True, hint: str = "", autocomplete: str = "off", monospace: bool = True) -> Dict[str, Any]:
    return {
        "name": name,
        "label": label,
        "placeholder": placeholder,
        "type": kind,
        "required": required,
        "hint": hint,
        "autocomplete": autocomplete,
        "monospace": monospace,
    }


TOOLS: List[Dict[str, Any]] = [
    {
        "id": "dns_intel",
        "name": "DNS Intelligence",
        "short": "DNS INTEL",
        "category": "network",
        "icon": "globe",
        "tag": "VX CORE",
        "accent": "cyan",
        "description": "Full DNS matrix, email authentication (SPF/DKIM/DMARC/MTA-STS/BIMI), DNSSEC, CAA, wildcard detection and provider attribution.",
        "run_label": "RESOLVE DNS MATRIX",
        "fields": [_field("target", "DOMAIN", "example.com", hint="Bare domain; no scheme required.")],
        "sources": ["Cloudflare DoH", "Google DoH", "Public DNS"],
        "sample": "github.com",
    },
    {
        "id": "cert_transparency",
        "name": "Certificate Transparency",
        "short": "CT HARVEST",
        "category": "network",
        "icon": "certificate",
        "tag": "PASSIVE",
        "accent": "violet",
        "description": "Harvest every subdomain ever seen in CT logs, measure live hosts, wildcard certificates, issuing CAs and stale attack surface.",
        "run_label": "HARVEST CERTIFICATE LOGS",
        "fields": [_field("target", "DOMAIN", "example.com")],
        "sources": ["crt.sh", "Cert Spotter", "DNS resolution"],
        "sample": "cloudflare.com",
    },
    {
        "id": "typosquat_radar",
        "name": "Typosquat Radar",
        "short": "TYPOSQUAT",
        "category": "network",
        "icon": "radar",
        "tag": "BRAND DEFENSE",
        "accent": "amber",
        "description": "Generate omission, keyboard, transposition, IDN homograph and TLD-swap permutations, then resolve and fingerprint live lookalikes for impersonation.",
        "run_label": "SCAN LOOKALIKE DOMAINS",
        "fields": [_field("target", "BRAND DOMAIN", "example.com")],
        "sources": ["DNS resolution", "Live HTTPS fingerprint", "IDN homograph map"],
        "sample": "paypal.com",
    },
    {
        "id": "http_audit",
        "name": "HTTP Security Audit",
        "short": "HTTP AUDIT",
        "category": "network",
        "icon": "shield",
        "tag": "HARDENING",
        "accent": "emerald",
        "description": "Grade security headers, CSP directives, cookie flags, CORS, TLS posture, HTTP→HTTPS redirects, server disclosure and technology fingerprints.",
        "run_label": "AUDIT HTTP POSTURE",
        "fields": [_field("target", "URL / HOST", "https://example.com")],
        "sources": ["Live HTTP response", "TLS handshake", "Header heuristics"],
        "sample": "https://github.com",
    },
    {
        "id": "waf_fingerprint",
        "name": "WAF & CDN Fingerprint",
        "short": "WAF PROBE",
        "category": "network",
        "icon": "wall",
        "tag": "ACTIVE PROBE",
        "accent": "cyan",
        "description": "Detect Cloudflare, Akamai, Imperva, F5, Sucuri, AWS, Azure, Fastly, Vercel and more, then verify whether a harmless XSS canary is actually blocked.",
        "run_label": "FINGERPRINT EDGE DEFENSES",
        "fields": [_field("target", "URL / HOST", "https://example.com")],
        "sources": ["Live edge response", "Active XSS canary", "DNS NS hints"],
        "sample": "https://www.cloudflare.com",
    },
    {
        "id": "ip_intel",
        "name": "IP Intelligence",
        "short": "IP INTEL",
        "category": "network",
        "icon": "pin",
        "tag": "MULTI-SOURCE",
        "accent": "violet",
        "description": "Geo/ASN attribution, RDAP registry, reverse DNS, internet-exposed ports, CVEs and hosting/proxy classification from Shodan InternetDB.",
        "run_label": "ENRICH IP ADDRESS",
        "fields": [_field("target", "IP ADDRESS", "8.8.8.8", hint="IPv4 or IPv6. Private ranges are rejected by upstream sources.")],
        "sources": ["ip-api.com", "ipinfo.io", "RDAP", "Shodan InternetDB", "PTR"],
        "sample": "1.1.1.1",
    },
    {
        "id": "bucket_hunter",
        "name": "Cloud Bucket Hunter",
        "short": "BUCKET HUNT",
        "category": "network",
        "icon": "cloud",
        "tag": "CLOUD EXPOSURE",
        "accent": "amber",
        "description": "Derive brand-based bucket names and test AWS S3, Google Cloud Storage and Azure Blob for public listings, private existence and naming leaks.",
        "run_label": "HUNT CLOUD BUCKETS",
        "fields": [_field("target", "DOMAIN / BRAND", "example.com")],
        "sources": ["AWS S3 API", "Google Cloud Storage API", "Azure Blob REST"],
        "sample": "shopify.com",
    },
    {
        "id": "exposed_files",
        "name": "Exposed Files Hunter",
        "short": "EXPOSED FILES",
        "category": "network",
        "icon": "file-warning",
        "tag": "CONTENT VALIDATED",
        "accent": "red",
        "description": "Fifty high-signal paths (.git, .env, keys, dumps, actuators, source maps, backups) validated against content signatures to suppress soft-404 noise.",
        "run_label": "PROBE SENSITIVE PATHS",
        "fields": [_field("target", "URL / HOST", "https://example.com")],
        "sources": ["Live HTTP path probes", "Content signature validation"],
        "sample": "https://example.com",
    },
    {
        "id": "link_forensics",
        "name": "Link Forensics",
        "short": "LINK FORENSICS",
        "category": "forensics",
        "icon": "link",
        "tag": "PHISH DEFENSE",
        "accent": "cyan",
        "description": "Expand shorteners and full redirect chains, expose punycode/@ tricks, raw-IP destinations, high-abuse TLDs, open-redirect parameters and tracking residue.",
        "run_label": "TRACE LINK DESTINATION",
        "fields": [_field("target", "URL", "https://bit.ly/example")],
        "sources": ["Live redirect chain", "URL lexical heuristics", "Shortener registry"],
        "sample": "https://bit.ly/3example",
    },
    {
        "id": "jwt_analyzer",
        "name": "JWT Analyzer",
        "short": "JWT AUDIT",
        "category": "forensics",
        "icon": "key",
        "tag": "LOCAL ONLY",
        "accent": "violet",
        "description": "Decode header/claims, audit exp/nbf/lifetime, flag alg=none, jku/x5u key injection, PII, and run a dictionary attack against HS256/384/512 secrets.",
        "run_label": "AUDIT TOKEN",
        "fields": [_field("target", "JWT / JWS", "eyJhbGciOi...", kind="textarea", hint="Paste a compact JWT. It never leaves this process.")],
        "sources": ["Local base64url decode", "HMAC dictionary attack"],
        "sample": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
    },
    {
        "id": "password_pwned",
        "name": "Pwned Password Audit",
        "short": "PASSWORD AUDIT",
        "category": "identity",
        "icon": "lock",
        "tag": "K-ANONYMITY",
        "accent": "red",
        "description": "Estimate real cryptographic strength, detect common patterns, and check the HIBP Pwned Passwords corpus using only a 5-character SHA-1 prefix.",
        "run_label": "AUDIT PASSWORD",
        "fields": [_field("target", "PASSWORD", "Enter a password to test", kind="password", hint="The plaintext is never returned or logged. Only a 5-char SHA-1 prefix is transmitted.", autocomplete="new-password")],
        "sources": ["HIBP Pwned Passwords range API", "Local entropy model"],
        "sample": "correct horse battery staple",
    },
    {
        "id": "gravatar_intel",
        "name": "Gravatar Surface",
        "short": "GRAVATAR",
        "category": "identity",
        "icon": "user",
        "tag": "PUBLIC PROFILE",
        "accent": "emerald",
        "description": "Resolve email-hash or username Gravatar profiles, enumerate linked verified accounts, public phone numbers, location, biography and avatar artifacts.",
        "run_label": "RESOLVE GRAVATAR",
        "fields": [_field("target", "EMAIL OR USERNAME", "user@example.com")],
        "sources": ["Gravatar public JSON profile API"],
        "sample": "support@github.com",
    },
    {
        "id": "cve_intel",
        "name": "CVE Intelligence",
        "short": "CVE INTEL",
        "category": "threat",
        "icon": "bug",
        "tag": "KEV + EPSS",
        "accent": "red",
        "description": "Correlate NVD CVSS/CWE data with CISA Known Exploited Vulnerabilities, ransomware use and FIRST EPSS exploitation probability. Accepts CVE IDs or keywords.",
        "run_label": "CORRELATE VULNERABILITY",
        "fields": [_field("target", "CVE ID / KEYWORD", "CVE-2024-3400  or  apache http server")],
        "sources": ["NVD API 2.0", "CISA KEV", "FIRST EPSS", "MITRE CVE Services"],
        "sample": "CVE-2024-3400",
    },
    {
        "id": "ioc_enrich",
        "name": "IOC Enrichment",
        "short": "IOC ENRICH",
        "category": "threat",
        "icon": "crosshair",
        "tag": "MULTI-FEED",
        "accent": "amber",
        "description": "Enrich IPs, domains, URLs, emails or file hashes with OTX pulses, malware families, adversaries, passive DNS, URLhaus records, geo and TLS context.",
        "run_label": "ENRICH INDICATOR",
        "fields": [_field("target", "IOC", "8.8.8.8 / domain / URL / hash")],
        "sources": ["AlienVault OTX", "URLhaus / abuse.ch", "ip-api.com", "DNS", "TLS"],
        "sample": "45.155.205.233",
    },
    {
        "id": "vin_decoder",
        "name": "VIN Provenance",
        "short": "VIN DECODER",
        "category": "asset",
        "icon": "car",
        "tag": "NHTSA",
        "accent": "cyan",
        "description": "Validate the VIN check digit, decode make/model/trim/engine/plant/safety features via NHTSA vPIC, and pull recall campaigns for the year/make/model.",
        "run_label": "DECODE VEHICLE",
        "fields": [_field("target", "17-CHARACTER VIN", "1HGCM82633A004352")],
        "sources": ["NHTSA vPIC", "NHTSA Recalls API", "WMI registry"],
        "sample": "1HGCM82633A004352",
    },
    {
        "id": "bin_lookup",
        "name": "Card BIN Intelligence",
        "short": "BIN LOOKUP",
        "category": "asset",
        "icon": "card",
        "tag": "ISSUER INTEL",
        "accent": "violet",
        "description": "Identify card network, type, brand, prepaid status, issuing bank and country from a BIN/IIN, with local Luhn validation and prefix fallback.",
        "run_label": "RESOLVE BIN",
        "fields": [_field("target", "BIN / CARD NUMBER", "45717360", hint="Only the first 8 digits are transmitted to the lookup provider.")],
        "sources": ["binlist.net", "Local IIN registry", "Luhn algorithm"],
        "sample": "45717360",
    },
    {
        "id": "bluesky_intel",
        "name": "Bluesky Intelligence",
        "short": "BLUESKY",
        "category": "social",
        "icon": "at",
        "tag": "AT PROTOCOL",
        "accent": "cyan",
        "description": "Resolve handles/DIDs, profile metrics, account age, follow ratio, posting-hour rhythm, hashtags, external links, moderation labels and scam-language signals.",
        "run_label": "PROFILE BLUESKY ACTOR",
        "fields": [_field("target", "HANDLE OR DID", "@user.bsky.social")],
        "sources": ["Bluesky public AT Protocol API"],
        "sample": "bsky.app",
    },
    {
        "id": "reddit_intel",
        "name": "Reddit Intelligence",
        "short": "REDDIT",
        "category": "social",
        "icon": "message",
        "tag": "PUBLIC JSON",
        "accent": "amber",
        "description": "Karma breakdown, account age, recent posts/comments, top subreddits and domains, UTC posting histogram, NSFW ratio and bot/spam behavior signals.",
        "run_label": "PROFILE REDDITOR",
        "fields": [_field("target", "REDDIT USERNAME", "spez")],
        "sources": ["Reddit public JSON endpoints"],
        "sample": "spez",
    },
    {
        "id": "discord_intel",
        "name": "Discord Invite Intel",
        "short": "DISCORD",
        "category": "social",
        "icon": "discord",
        "tag": "INVITE API",
        "accent": "violet",
        "description": "Resolve invite metadata: server identity/age, member vs online counts, verification level, features, inviter, expiration, NSFW and scam-language signals.",
        "run_label": "RESOLVE INVITE",
        "fields": [_field("target", "INVITE URL OR CODE", "discord.gg/example")],
        "sources": ["Discord public invite API v10"],
        "sample": "discord.gg/python",
    },
    {
        "id": "telegram_intel",
        "name": "Telegram Intelligence",
        "short": "TELEGRAM",
        "category": "social",
        "icon": "send",
        "tag": "PUBLIC PREVIEW",
        "accent": "cyan",
        "description": "Resolve public channels, groups and profiles; extract title, description, subscriber/member counts, verification, recent posts, links, hashtags and scam signals.",
        "run_label": "PROFILE TELEGRAM",
        "fields": [_field("target", "USERNAME OR T.ME URL", "@durov")],
        "sources": ["t.me public preview", "t.me/s public feed"],
        "sample": "durov",
    },    {
        "id": "attack_surface",
        "name": "Attack Surface Scorecard",
        "short": "SURFACE SCORE",
        "category": "network",
        "icon": "gauge",
        "tag": "FLAGSHIP",
        "accent": "amber",
        "description": "Orchestrates DNS, CT, HTTP, WAF, exposed-file and cloud-bucket engines into one weighted Attack Surface Index with a unified grade, critical findings and quick wins.",
        "run_label": "RUN FULL SURFACE SCORECARD",
        "fields": [_field("target", "DOMAIN", "example.com", hint="Runs six engines in parallel. Expect 20–60 seconds.")],
        "sources": ["6 VX engines", "Weighted risk model", "Unified evidence model"],
        "sample": "github.com",
    },
    {
        "id": "origin_unmasker",
        "name": "Origin IP Unmasker",
        "short": "ORIGIN UNMASK",
        "category": "network",
        "icon": "eye",
        "tag": "CDN BYPASS",
        "accent": "red",
        "description": "Correlates current DNS, OTX passive DNS, HackerTarget, CT subdomains and origin-style hostnames, then validates candidates with Host-header probes to find real servers behind CDN/WAF.",
        "run_label": "HUNT ORIGIN INFRASTRUCTURE",
        "fields": [_field("target", "DOMAIN", "example.com")],
        "sources": ["Current DNS", "OTX passive DNS", "HackerTarget", "crt.sh", "Host-header validation"],
        "sample": "cloudflare.com",
    },
    {
        "id": "graphql_inspector",
        "name": "GraphQL Inspector",
        "short": "GRAPHQL AUDIT",
        "category": "appsec",
        "icon": "graph",
        "tag": "SCHEMA RISK",
        "accent": "violet",
        "description": "Discovers GraphQL endpoints, runs introspection, inventories queries/mutations, flags sensitive and destructive fields, and tests batching, GET queries and field suggestions.",
        "run_label": "AUDIT GRAPHQL SCHEMA",
        "fields": [_field("target", "URL / DOMAIN", "https://example.com/graphql")],
        "sources": ["Introspection query", "POST/GET probes", "Batching test", "Suggestion leak test"],
        "sample": "https://countries.trevorblades.com/graphql",
    },
    {
        "id": "supply_chain_audit",
        "name": "Supply Chain Auditor",
        "short": "SUPPLY CHAIN",
        "category": "appsec",
        "icon": "package",
        "tag": "NPM + PYPI",
        "accent": "emerald",
        "description": "Audits npm and PyPI packages for typosquatting, install-time scripts, deprecation, direct-URL dependencies, provenance gaps and suspicious setup.py execution primitives.",
        "run_label": "AUDIT PACKAGE PROVENANCE",
        "fields": [_field("target", "PACKAGE", "lodash  or  pypi:requests", hint="Prefix with npm: or pypi: to force an ecosystem.")],
        "sources": ["npm registry", "npm downloads API", "PyPI JSON API", "pypistats.org", "sdist inspection"],
        "sample": "lodash",
    },
]

TOOL_MAP: Dict[str, Dict[str, Any]] = {t["id"]: t for t in TOOLS}

RUNNERS: Dict[str, Callable] = {
    "dns_intel": run_dns_intel,
    "cert_transparency": run_cert_transparency,
    "typosquat_radar": run_typosquat_radar,
    "http_audit": run_http_audit,
    "waf_fingerprint": run_waf_fingerprint,
    "ip_intel": run_ip_intel,
    "bucket_hunter": run_bucket_hunter,
    "exposed_files": run_exposed_files,
    "link_forensics": run_link_forensics,
    "jwt_analyzer": run_jwt_analyzer,
    "password_pwned": run_password_pwned,
    "gravatar_intel": run_gravatar_intel,
    "cve_intel": run_cve_intel,
    "ioc_enrich": run_ioc_enrich,
    "vin_decoder": run_vin_decoder,
    "bin_lookup": run_bin_lookup,
    "bluesky_intel": run_bluesky_intel,
    "reddit_intel": run_reddit_intel,
    "discord_intel": run_discord_intel,
    "telegram_intel": run_telegram_intel,
    "attack_surface": run_attack_surface,
    "origin_unmasker": run_origin_unmasker,
    "graphql_inspector": run_graphql_inspector,
    "supply_chain_audit": run_supply_chain_audit,
}


def get_registry() -> Dict[str, Any]:
    return {
        "version": ARSENAL_VERSION,
        "codename": ARSENAL_CODENAME,
        "total": len(TOOLS),
        "categories": CATEGORIES,
        "tools": TOOLS,
    }


def _normalize_id(tool_id: str) -> str:
    key = (tool_id or "").strip().lower().replace("-", "_")
    for prefix in ("vx_", "v8_", "v7_", "arsenal_"):
        if key.startswith(prefix):
            key = key[len(prefix):]
    return key


async def run_tool(tool_id: str, payload: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    started = time.perf_counter()
    payload = payload if isinstance(payload, dict) else {}
    key = _normalize_id(tool_id)
    runner = RUNNERS.get(key)
    if not runner:
        return error_envelope(key, str(payload.get("target", "")), f"Unknown arsenal tool '{tool_id}'.")
    target = (
        payload.get("target")
        or payload.get("query")
        or payload.get("value")
        or payload.get("input")
        or ""
    )
    if key == "password_pwned":
        target = payload.get("target") or payload.get("password") or payload.get("value") or ""
    target = str(target)
    if not target.strip():
        meta = TOOL_MAP.get(key, {})
        return error_envelope(key, "", f"Input required: {meta.get('fields', [{}])[0].get('label', 'target')}")
    try:
        result = await runner(target)
        if isinstance(result, dict):
            result.setdefault("elapsed_ms", int((time.perf_counter() - started) * 1000))
            result.setdefault("arsenal_version", ARSENAL_VERSION)
        return result
    except asyncio.CancelledError:
        raise
    except Exception as exc:
        import traceback
        traceback.print_exc()
        return error_envelope(key, target, f"Engine failure: {type(exc).__name__}: {exc}")
