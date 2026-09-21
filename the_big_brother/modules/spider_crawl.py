"""
SPIDER CRAWL — Deep Recursive Site Intelligence & Secrets Harvester V7.0 (Zero-Mock Native)
Performs depth-controlled recursive crawling (depth 2-3) within domain boundaries,
harvests high-value API keys and credentials (AWS, GitHub, Stripe, OpenAI, Anthropic, RSA, JWT),
probes sensitive endpoints (/.env, /.git/HEAD, etc.), and aggregates internal/external forensic assets.
"""
from __future__ import annotations

import asyncio
import re
import urllib.request
import urllib.error
from urllib.parse import urlparse, urljoin
from typing import Dict, Any, List, Set, Optional

# Verified Secret Regex Signatures
SECRET_PATTERNS = {
    "AWS_ACCESS_KEY": re.compile(r'AKIA[0-9A-Z]{16}'),
    "AWS_SECRET_KEY": re.compile(r'(?i)aws(.{0,20})?(?:key|secret|token)\s*[:=]\s*["\']([A-Za-z0-9/+=]{40})["\']'),
    "GITHUB_PAT": re.compile(r'(?:ghp|gho|ghu|ghs|ghr)_[a-zA-Z0-9]{36}'),
    "GITHUB_FINE_GRAINED": re.compile(r'github_pat_[a-zA-Z0-9]{22}_[a-zA-Z0-9]{59}'),
    "STRIPE_LIVE_KEY": re.compile(r'sk_live_[0-9a-zA-Z]{24,}'),
    "OPENAI_API_KEY": re.compile(r'sk-(?:proj-)?[a-zA-Z0-9_\-]{32,70}'),
    "ANTHROPIC_API_KEY": re.compile(r'sk-ant-[a-zA-Z0-9_\-]{32,95}'),
    "GOOGLE_API_KEY": re.compile(r'AIza[0-9A-Za-z\-_]{35}'),
    "PRIVATE_KEY_BLOCK": re.compile(r'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----'),
    "JWT_TOKEN": re.compile(r'eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}'),
    "SLACK_TOKEN": re.compile(r'xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24,32}'),
}

SENSITIVE_PATHS = [
    "/.env",
    "/.git/HEAD",
    "/.git/config",
    "/wp-config.php.bak",
    "/robots.txt",
    "/sitemap.xml",
    "/.well-known/security.txt",
    "/config.json",
    "/server-status"
]

EMAIL_RE = re.compile(r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+')
PHONE_RE = re.compile(r'(?:\+?[0-9]{1,3}[-.\s]?)?\(?[0-9]{2,4}\)?[-.\s]?[0-9]{3,4}[-.\s]?[0-9]{3,4}')
LINK_RE = re.compile(r'href=["\'](https?://[^"\']+|/[^"\']*)["\']', re.IGNORECASE)
ENDPOINT_RE = re.compile(r'["\'](/api/v[0-9]/[^"\']+|/api/[^"\']+|/v[0-9]/[^"\']+)["\']')


def _fetch_sync(url: str, timeout: int = 5) -> Tuple[int, str, dict]:
    try:
        req = urllib.request.Request(
            url,
            headers={
                "User-Agent": "TheBigBrother-Forensics/7.0 (Spider Crawl Harvester; +https://thebigbrother.cloud)",
                "Accept": "text/html,application/json,text/plain,*/*"
            }
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            text = resp.read().decode("utf-8", errors="replace")
            headers = dict(resp.headers)
            return resp.status, text, headers
    except urllib.error.HTTPError as e:
        return e.code, "", {}
    except Exception:
        return 0, "", {}


async def spider_crawl(target_url: str, max_depth: int = 2, max_pages: int = 20) -> Dict[str, Any]:
    target_url = target_url.strip()
    if not target_url.startswith(("http://", "https://")):
        target_url = "https://" + target_url

    parsed = urlparse(target_url)
    target_domain = parsed.netloc.lower()

    visited_urls: Set[str] = set()
    crawl_queue: List[Tuple[str, int]] = [(target_url, 0)]

    discovered_secrets: List[Dict[str, Any]] = []
    discovered_emails: Set[str] = set()
    discovered_phones: Set[str] = set()
    discovered_endpoints: Set[str] = set()
    external_links: Set[str] = set()
    crawl_log: List[str] = []

    loop = asyncio.get_event_loop()

    crawl_log.append(f"[START] Initializing recursive harvest on {target_url} (Domain: {target_domain})")

    # 1. Recursive Link Walker & Secrets Extractor
    while crawl_queue and len(visited_urls) < max_pages:
        curr_url, depth = crawl_queue.pop(0)
        if curr_url in visited_urls:
            continue
        visited_urls.add(curr_url)

        crawl_log.append(f"[CRAWL:D{depth}] Requesting {curr_url}")
        status, content, headers = await loop.run_in_executor(None, _fetch_sync, curr_url, 5)
        if status != 200 or not content:
            continue

        # Extract Secrets
        for sec_name, pattern in SECRET_PATTERNS.items():
            for m in pattern.finditer(content):
                val = m.group(0)
                # Mask sensitive middle characters
                masked = val[:6] + "..." + val[-4:] if len(val) > 12 else val[:3] + "..."
                discovered_secrets.append({
                    "type": sec_name,
                    "masked_value": masked,
                    "source_url": curr_url,
                    "severity": "CRITICAL" if "KEY" in sec_name or "TOKEN" in sec_name else "HIGH"
                })
                crawl_log.append(f"[SECRET_ALERT] Found {sec_name} on {curr_url}")

        # Extract Emails & Phones
        for em in EMAIL_RE.findall(content):
            if not any(em.endswith(ext) for ext in [".png", ".jpg", ".svg", ".css", ".js"]):
                discovered_emails.add(em)
        for ph in PHONE_RE.findall(content):
            if len(re.sub(r'\D', '', ph)) >= 8:
                discovered_phones.add(ph.strip())

        # Extract Internal Endpoints
        for ep in ENDPOINT_RE.findall(content):
            discovered_endpoints.add(ep)

        # Extract Links for Next Depth
        if depth < max_depth:
            for m in LINK_RE.finditer(content):
                href = m.group(1)
                full = urljoin(curr_url, href)
                u_parsed = urlparse(full)
                if u_parsed.netloc.lower() == target_domain:
                    # Ignore binary media assets
                    if not any(full.lower().endswith(ext) for ext in [".png", ".jpg", ".gif", ".pdf", ".zip", ".mp4", ".mp3"]):
                        if full not in visited_urls:
                            crawl_queue.append((full, depth + 1))
                elif u_parsed.scheme in ("http", "https"):
                    external_links.add(full)

    # 2. Sensitive Path Probing
    crawl_log.append(f"[PATH_AUDIT] Concurrently auditing {len(SENSITIVE_PATHS)} critical paths...")
    path_tasks = []
    for sp in SENSITIVE_PATHS:
        probe_url = urljoin(f"{parsed.scheme}://{target_domain}", sp)
        path_tasks.append((sp, probe_url))

    async def _audit_path(sp, url):
        st, body, _ = await loop.run_in_executor(None, _fetch_sync, url, 4)
        is_exposed = False
        notes = f"HTTP {st}"
        if st == 200:
            if sp == "/.env" and ("DB_" in body or "API_" in body or "=" in body):
                is_exposed = True
                notes = "CONFIRMED_ENV_VARIABLES_EXPOSED"
            elif sp == "/.git/HEAD" and "ref: refs/" in body:
                is_exposed = True
                notes = "CONFIRMED_GIT_REPOSITORY_EXPOSED"
            elif sp == "/robots.txt" and "Disallow:" in body:
                is_exposed = True
                notes = "DISCLOSED_CRAWL_RESTRICTIONS"
            elif sp == "/.well-known/security.txt":
                is_exposed = True
                notes = "SECURITY_TXT_PRESENT"
            else:
                is_exposed = True
                notes = "ENDPOINT_ACCESSIBLE"

        return {
            "path": sp,
            "url": url,
            "status_code": st,
            "exposed": is_exposed,
            "audit_note": notes
        }

    path_results = await asyncio.gather(*[_audit_path(sp, u) for sp, u in path_tasks])

    exposed_secrets_cnt = len(discovered_secrets)
    exposed_paths_cnt = len([p for p in path_results if p["exposed"] and p["path"] in ("/.env", "/.git/HEAD", "/wp-config.php.bak")])

    threat_score = min(100, (exposed_secrets_cnt * 30) + (exposed_paths_cnt * 35) + 10)
    risk_level = "CRITICAL_COMPROMISE" if threat_score >= 70 else ("ELEVATED_SURFACE" if threat_score >= 35 else "NOMINAL")

    return {
        "status": "success",
        "target": target_url,
        "domain": target_domain,
        "pages_crawled": len(visited_urls),
        "threat_score": threat_score,
        "risk_level": risk_level,
        "exposed_secrets": discovered_secrets,
        "security_path_audit": path_results,
        "internal_assets": {
            "emails": list(discovered_emails)[:30],
            "phone_numbers": list(discovered_phones)[:15],
            "api_endpoints": list(discovered_endpoints)[:40],
            "external_links_count": len(external_links)
        },
        "crawl_log": crawl_log
    }
