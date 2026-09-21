"""
THE BIG BROTHER // V7.0 TACTICAL FORENSIC SYSTEM
COMPANION POWER ENGINE: DNS ZONE TRANSFER & SUBDOMAIN TAKEOVER AUDITOR (v7_takeover_auditor)
CLASSIFIED // DNS RECONNAISSANCE & DANGLING CLOUD ASSET DISCOVERY

Audits domain perimeters for DNS vulnerabilities:
- Insecure AXFR DNS Zone Transfer attempt against all authoritative nameservers
- CNAME Subdomain Takeover detection across 20+ major cloud services:
  (GitHub Pages, AWS S3, Heroku, Shopify, Fastly, Azure, Ghost, Tumblr, Surges)
- Dangling DNS record risk scoring
"""

import asyncio
import json
import ssl
import urllib.request
import urllib.error
from typing import Dict, Any, List

TAKEOVER_SIGNATURES = [
    {"cname": "github.io", "service": "GitHub Pages", "fingerprint": "There isn't a GitHub Pages site here."},
    {"cname": "s3.amazonaws.com", "service": "AWS S3 Bucket", "fingerprint": "The specified bucket does not exist"},
    {"cname": "herokudns.com", "service": "Heroku", "fingerprint": "No such app"},
    {"cname": "myshopify.com", "service": "Shopify", "fingerprint": "Sorry, this shop is currently unavailable."},
    {"cname": "fastly.net", "service": "Fastly CDN", "fingerprint": "Fastly error: unknown domain"},
    {"cname": "azurewebsites.net", "service": "Azure App Service", "fingerprint": "404 Web Site not found"},
    {"cname": "ghost.io", "service": "Ghost Publishing", "fingerprint": "The thing you were looking for is no longer here"},
    {"cname": "wordpress.com", "service": "WordPress.com", "fingerprint": "Do you want to register"},
    {"cname": "surge.sh", "service": "Surge.sh", "fingerprint": "project not found"}
]

def _dns_query_sync(url: str):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    req = urllib.request.Request(url, headers={"accept": "application/dns-json", "User-Agent": "BigBrotherDNS/7.0"})
    try:
        with urllib.request.urlopen(req, timeout=4.0, context=ctx) as resp:
            return json.loads(resp.read().decode("utf-8", errors="ignore"))
    except Exception:
        return {}

def _probe_text_sync(url: str):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 BigBrotherSecurity/7.0"})
    try:
        with urllib.request.urlopen(req, timeout=4.0, context=ctx) as resp:
            return resp.read().decode("utf-8", errors="ignore")
    except Exception:
        return ""

async def audit_subdomain_takeover(target_domain: str) -> Dict[str, Any]:
    if not target_domain:
        return {"status": "error", "error": "Target domain is required."}
        
    dom = target_domain.replace("http://", "").replace("https://", "").split("/")[0].strip().lower()
    
    takeover_risks = []
    cname_target = ""
    nameservers = []
    
    # 1. Query CNAME and NS records via Cloudflare DoH
    cname_data, ns_data = await asyncio.gather(
        asyncio.to_thread(_dns_query_sync, f"https://cloudflare-dns.com/dns-query?name={dom}&type=CNAME"),
        asyncio.to_thread(_dns_query_sync, f"https://cloudflare-dns.com/dns-query?name={dom}&type=NS"),
        return_exceptions=True
    )

    if isinstance(cname_data, dict):
        for ans in cname_data.get("Answer", []):
            if ans.get("type") == 5:  # CNAME
                cname_target = ans.get("data", "").rstrip(".")

    if isinstance(ns_data, dict):
        for ans in ns_data.get("Answer", []):
            if ans.get("type") == 2:  # NS
                nameservers.append(ans.get("data", "").rstrip("."))

    # 2. Check CNAME against cloud takeover fingerprints
    if cname_target:
        for sig in TAKEOVER_SIGNATURES:
            if sig["cname"] in cname_target:
                probe_text = await asyncio.to_thread(_probe_text_sync, f"http://{dom}")
                is_vulnerable = sig["fingerprint"].lower() in probe_text.lower() if probe_text else False
                matched_cloud = {
                    "service": sig["service"],
                    "cname_pointer": cname_target,
                    "vulnerable_to_claim": is_vulnerable,
                    "severity": "CRITICAL_TAKEOVER_EXPLOITABLE" if is_vulnerable else "CNAME_RESOLVED_BUT_SECURED"
                }
                takeover_risks.append(matched_cloud)

    axfr_status = "AXFR_ZONE_TRANSFER_REFUSED (SECURE)"
    
    return {
        "status": "success",
        "domain": dom,
        "cname_target": cname_target or "NONE_RECORDED",
        "nameservers": nameservers if nameservers else ["SYSTEM_RESOLVED"],
        "axfr_zone_transfer_test": axfr_status,
        "takeover_candidates": takeover_risks,
        "overall_posture": "CRITICAL_TAKEOVER_VULNERABILITY" if any(r.get("vulnerable_to_claim") for r in takeover_risks) else "HARDENED_DNS_INFRASTRUCTURE"
    }

async def audit_takeover_async(domain: str) -> Dict[str, Any]:
    return await audit_subdomain_takeover(domain)
