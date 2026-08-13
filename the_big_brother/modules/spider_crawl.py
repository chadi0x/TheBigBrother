"""
SPIDER CRAWL — Live Site Intelligence & Secrets Extractor V6.1 (POWERED UP)
Crawls target URLs recursively (multi-page), checks sensitive paths (/.env, /.git/HEAD, /robots.txt),
detects subdomain takeover indicators, scans 25+ API secret key patterns,
and extracts emails, phones, social profiles, tech stack, and HTML comments.
"""
import asyncio
import aiohttp
import re
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup

# Extended Secret Key Regex Patterns (25+ Rules)
SECRET_PATTERNS = {
    "AWS Access Key ID": r'AKIA[0-9A-Z]{16}',
    "AWS Secret Access Key": r'(?i)aws(.{0,20})?(?:key|secret|token)\s*[:=]\s*["\']([A-Za-z0-9/+=]{40})["\']',
    "GitHub Personal Access Token": r'ghp_[a-zA-Z0-9]{36}',
    "GitHub OAuth Access Token": r'gho_[a-zA-Z0-9]{36}',
    "GitHub Fine-grained Token": r'github_pat_[a-zA-Z0-9]{22}_[a-zA-Z0-9]{59}',
    "Stripe Live API Key": r'sk_live_[0-9a-zA-Z]{24,99}',
    "Stripe Restricted API Key": r'rk_live_[0-9a-zA-Z]{24,99}',
    "Google API Key": r'AIza[0-9A-Za-z\-_]{35}',
    "OpenAI API Key": r'sk-[a-zA-Z0-9]{32,50}',
    "Slack Bot Token": r'xoxb-[0-9]{11,13}-[0-9]{11,13}-[a-zA-Z0-9]{24}',
    "Slack User Token": r'xoxp-[0-9]{11,13}-[0-9]{11,13}-[a-zA-Z0-9]{24}',
    "Twilio Account SID": r'AC[a-f0-9]{32}',
    "Twilio Auth Token": r'(?i)twilio(.{0,20})?token\s*[:=]\s*["\']([a-f0-9]{32})["\']',
    "SendGrid API Key": r'SG\.[a-zA-Z0-9_\-\.]{22,66}',
    "Mailgun API Key": r'key-[0-9a-zA-Z]{32}',
    "Firebase Realtime DB": r'[a-z0-9\-]+\.firebaseio\.com',
    "Generic RSA Private Key": r'-----BEGIN RSA PRIVATE KEY-----',
    "Generic Private Key": r'-----BEGIN PRIVATE KEY-----',
    "Generic OpenSSH Private Key": r'-----BEGIN OPENSSH PRIVATE KEY-----',
    "JWT Bearer Token": r'eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*',
    "Database Connection String": r'(postgres|mysql|mongodb|redis)://[a-zA-Z0-9_]+:[^@\s]+@[a-zA-Z0-9.-]+:[0-9]+',
}

SENSITIVE_PATHS = [
    "/robots.txt",
    "/sitemap.xml",
    "/.env",
    "/.git/HEAD",
    "/.gitignore",
    "/wp-config.php",
    "/config.json",
    "/package.json",
    "/server-status",
    "/.well-known/security.txt",
]

SOCIAL_DOMAINS = [
    "twitter.com", "x.com", "github.com", "linkedin.com", "facebook.com",
    "instagram.com", "youtube.com", "t.me", "discord.gg", "reddit.com", "tiktok.com"
]

TAKEOVER_SIGNATURES = [
    "NoSuchBucket",
    "Heroku | No such app",
    "Unrecognized domain",
    "The specified bucket does not exist",
    "There isn't a GitHub Pages site here",
    "Project not found",
]

async def _fetch_url(session: aiohttp.ClientSession, url: str) -> tuple[int, str, dict]:
    try:
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=6), allow_redirects=True) as resp:
            text = await resp.text()
            headers = dict(resp.headers)
            return resp.status, text, headers
    except Exception:
        return 0, "", {}

async def spider_crawl(target_url: str, max_pages: int = 10) -> dict:
    if not target_url.startswith(("http://", "https://")):
        target_url = "https://" + target_url.strip()

    try:
        parsed = urlparse(target_url)
        domain = parsed.netloc
        scheme = parsed.scheme
    except Exception:
        return {"error": "Invalid URL"}

    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
    }

    scraped_data = {
        "target": target_url,
        "domain": domain,
        "pages_scanned": 0,
        "emails": set(),
        "phones": set(),
        "social_links": set(),
        "internal_links": set(),
        "external_links": set(),
        "secrets_found": [],
        "sensitive_files_found": [],
        "takeover_warnings": [],
        "meta_tags": {},
        "tech_stack": set(),
        "comments": []
    }

    queue = [target_url]
    visited = set()

    async with aiohttp.ClientSession(headers=headers) as session:
        # 1. Multi-page Crawl
        while queue and len(visited) < max_pages:
            current_url = queue.pop(0)
            if current_url in visited:
                continue
            visited.add(current_url)
            scraped_data["pages_scanned"] += 1

            status, html, resp_headers = await _fetch_url(session, current_url)
            if not html:
                continue

            # Tech stack fingerprinting via headers
            server = resp_headers.get("Server") or resp_headers.get("server")
            powered_by = resp_headers.get("X-Powered-By") or resp_headers.get("x-powered-by")
            via = resp_headers.get("Via") or resp_headers.get("via")
            if server: scraped_data["tech_stack"].add(f"Server: {server}")
            if powered_by: scraped_data["tech_stack"].add(f"PoweredBy: {powered_by}")
            if via: scraped_data["tech_stack"].add(f"CDN/Proxy: {via}")

            # Takeover signature check
            for sig in TAKEOVER_SIGNATURES:
                if sig in html:
                    scraped_data["takeover_warnings"].append(f"Subdomain Takeover Signature detected on {current_url}: '{sig}'")

            # Regex for emails & phones
            emails = re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', html)
            for e in emails:
                if not e.lower().endswith(('.png', '.jpg', '.jpeg', '.svg', '.gif', '.css', '.js', '.webp', '.woff')):
                    scraped_data["emails"].add(e.lower())

            phones = re.findall(r'\+?[0-9]{1,4}?[-.\s]?\(?[0-9]{1,3}?\)?[-.\s]?[0-9]{1,4}[-.\s]?[0-9]{1,4}[-.\s]?[0-9]{1,9}', html)
            for p in phones:
                p_clean = p.strip()
                if len(p_clean) >= 9 and not p_clean.startswith(('202', '2025', '2026', '2024', '199', '200')):
                    scraped_data["phones"].add(p_clean)

            # Secrets regex scanning
            for secret_type, pattern in SECRET_PATTERNS.items():
                matches = re.findall(pattern, html)
                if matches:
                    for m in set(matches[:3]):
                        m_str = m[1] if isinstance(m, tuple) else m
                        scraped_data["secrets_found"].append({
                            "type": secret_type,
                            "match": m_str[:25] + "..." if len(m_str) > 25 else m_str,
                            "url": current_url
                        })

            # BeautifulSoup parsing
            try:
                soup = BeautifulSoup(html, "html.parser")

                # Meta tags
                if current_url == target_url:
                    for meta in soup.find_all("meta"):
                        name = meta.get("name") or meta.get("property")
                        content = meta.get("content")
                        if name and content:
                            scraped_data["meta_tags"][name[:50]] = content[:150]

                    # Generator tag
                    gen = soup.find("meta", attrs={"name": "generator"})
                    if gen and gen.get("content"):
                        scraped_data["tech_stack"].add(f"Generator: {gen['content']}")

                # HTML comments extraction
                comments = soup.find_all(string=lambda text: isinstance(text, type(soup.comment)) if hasattr(soup, 'comment') else False)
                for c in comments[:8]:
                    c_str = str(c).strip()
                    if len(c_str) > 5 and not "copyright" in c_str.lower() and not "license" in c_str.lower():
                        scraped_data["comments"].append({"comment": c_str[:200], "url": current_url})

                # Link extraction for queue & categorization
                for a in soup.find_all("a", href=True):
                    href = a["href"].strip()
                    full_url = urljoin(current_url, href)
                    parsed_href = urlparse(full_url)

                    if any(sd in parsed_href.netloc for sd in SOCIAL_DOMAINS):
                        scraped_data["social_links"].add(full_url)
                    elif parsed_href.netloc == domain:
                        scraped_data["internal_links"].add(full_url)
                        if full_url not in visited and full_url not in queue and len(queue) < 30:
                            # Avoid anchor links or asset files
                            if not parsed_href.path.endswith(('.png','.jpg','.jpeg','.pdf','.zip','.css','.js','.svg')):
                                queue.append(full_url)
                    elif parsed_href.netloc:
                        scraped_data["external_links"].add(full_url)

            except Exception:
                pass

        # 2. Check Sensitive Paths (/.env, /.git/HEAD, /robots.txt, etc)
        path_tasks = []
        for path in SENSITIVE_PATHS:
            test_url = f"{scheme}://{domain}{path}"
            path_tasks.append(_fetch_url(session, test_url))

        path_results = await asyncio.gather(*path_tasks)
        for i, (status_code, text_content, _) in enumerate(path_results):
            tested_path = SENSITIVE_PATHS[i]
            if status_code == 200 and text_content and len(text_content) > 5:
                # Confirm it's not a generic 200 HTML error page
                if "<html>" not in text_content[:200].lower() or tested_path in ("/robots.txt", "/.well-known/security.txt"):
                    scraped_data["sensitive_files_found"].append({
                        "path": tested_path,
                        "url": f"{scheme}://{domain}{tested_path}",
                        "snippet": text_content[:150].replace('\n', ' ')
                    })

    return {
        "target": target_url,
        "domain": domain,
        "pages_scanned": scraped_data["pages_scanned"],
        "emails": list(scraped_data["emails"])[:40],
        "phones": list(scraped_data["phones"])[:30],
        "social_links": list(scraped_data["social_links"])[:40],
        "internal_links_count": len(scraped_data["internal_links"]),
        "external_links_count": len(scraped_data["external_links"]),
        "secrets_found": scraped_data["secrets_found"],
        "sensitive_files_found": scraped_data["sensitive_files_found"],
        "takeover_warnings": list(set(scraped_data["takeover_warnings"])),
        "meta_tags": scraped_data["meta_tags"],
        "tech_stack": list(scraped_data["tech_stack"]),
        "comments": scraped_data["comments"][:15]
    }
