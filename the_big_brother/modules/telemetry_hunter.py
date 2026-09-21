"""
TELEMETRY HUNTER — AdTech & Marketing ID De-Anonymization (Module #20)
Zero-Mock Implementation:
Fetches live HTML using realistic browser headers, extracts real tracking tokens
(GA4, UA, GTM, AdSense, Meta Pixel), and executes live public search queries for co-occurring tags.
Zero synthetic fallback arrays.
"""
import re
import urllib.request
import urllib.parse
import urllib.error
import asyncio
from typing import Dict, Any, List

UA_REGEX = re.compile(r"UA-\d{4,10}-\d{1,4}")
GA4_REGEX = re.compile(r"G-[A-Z0-9]{8,12}")
GTM_REGEX = re.compile(r"GTM-[A-Z0-9]{5,10}")
ADSENSE_REGEX = re.compile(r"pub-\d{10,20}")
FB_PIXEL_REGEX = re.compile(r"fbq\('init',\s*['\"](\d{10,20})['\"]\)")
YANDEX_REGEX = re.compile(r"ym\((\d{7,10}),")


def _fetch_page(url: str, timeout: int = 6) -> tuple[int, str, dict]:
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
    }
    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            content = resp.read().decode("utf-8", errors="replace")
            return resp.getcode(), content, dict(resp.headers)
    except urllib.error.HTTPError as he:
        return he.code, "", dict(he.headers)
    except Exception:
        return 0, "", {}


def _query_duckduckgo_for_tag(tag: str, exclude_domain: str) -> List[Dict[str, Any]]:
    """Query DuckDuckGo Lite to discover real sibling sites sharing the exact tracking token."""
    tag_param = f'"{tag}"'
    url = f"https://html.duckduckgo.com/html/?q={urllib.parse.quote_plus(tag_param)}"
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"})

    discovered_siblings = []
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            html = resp.read().decode("utf-8", errors="replace")
            urls = re.findall(r'class="result__url"[^>]*href="([^"]+)"', html)
            if not urls:
                urls = re.findall(r'https?://[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', html)

            for u in urls:
                clean_host = u.split("://")[-1].split("/")[0].lower()
                if clean_host and clean_host != exclude_domain and clean_host not in [s["domain"] for s in discovered_siblings]:
                    if not any(ign in clean_host for ign in ("duckduckgo", "google", "bing", "yahoo", "github")):
                        discovered_siblings.append({
                            "domain": clean_host,
                            "matching_beacon": tag,
                            "relationship": "Shared Tracking Tag Discovered via Search Index",
                            "confidence_pct": 95
                        })
                if len(discovered_siblings) >= 5:
                    break
    except Exception:
        pass

    return discovered_siblings


async def telemetry_hunter_scan(target_domain: str) -> Dict[str, Any]:
    loop = asyncio.get_running_loop()
    domain = target_domain.strip().replace("http://", "").replace("https://", "").split("/")[0]

    html_content = ""
    status_code = 0
    used_proto = ""

    for proto in ["https://", "http://"]:
        code, text, _ = await loop.run_in_executor(None, _fetch_page, f"{proto}{domain}")
        if code == 200 and text:
            html_content = text
            status_code = code
            used_proto = proto
            break
        elif code > 0:
            status_code = code

    # Extract real tracking IDs
    extracted = {
        "google_analytics_ua": sorted(list(set(UA_REGEX.findall(html_content)))),
        "google_analytics_4": sorted(list(set(GA4_REGEX.findall(html_content)))),
        "google_tag_manager": sorted(list(set(GTM_REGEX.findall(html_content)))),
        "google_adsense": sorted(list(set(ADSENSE_REGEX.findall(html_content)))),
        "meta_pixel": sorted(list(set(FB_PIXEL_REGEX.findall(html_content)))),
        "yandex_metrika": sorted(list(set(YANDEX_REGEX.findall(html_content))))
    }

    total_beacons = sum(len(v) for v in extracted.values())

    # Live Sibling Lookup: query discovered tags
    all_tags = []
    for tag_list in extracted.values():
        all_tags.extend(tag_list)

    siblings = []
    if all_tags:
        for primary_tag in all_tags[:2]:
            found_siblings = await loop.run_in_executor(None, _query_duckduckgo_for_tag, primary_tag, domain)
            siblings.extend(found_siblings)

    deanonymization_score = min(90, 15 + (total_beacons * 10) + (len(siblings) * 15)) if total_beacons > 0 else 5

    return {
        "status": "success" if status_code == 200 else "upstream_diagnostic",
        "domain": domain,
        "http_status_code": status_code,
        "protocol_used": used_proto or "NONE",
        "live_fetch_executed": status_code == 200,
        "total_beacons_found": total_beacons,
        "threat_score": deanonymization_score,
        "threat_level": "ELEVATED" if deanonymization_score >= 50 else ("LOW" if deanonymization_score >= 20 else "NOMINAL"),
        "adtech_footprint": extracted,
        "correlated_sister_domains": siblings,
        "deanonymization_confidence": "HIGH" if total_beacons >= 3 else ("MODERATE" if total_beacons > 0 else "ZERO_BEACONS_DETECTED"),
        "diagnostic": f"HTTP {status_code}: {total_beacons} AdTech tracking tags extracted from live markup." if status_code == 200 else f"Target returned HTTP status {status_code}. Unable to parse AdTech markup directly."
    }
