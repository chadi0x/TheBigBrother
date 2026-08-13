"""
PHANTOM ID — Username enumeration across 200+ platforms.
Uses async HTTP with HEAD/GET requests against a curated sites list.
Returns profile URLs, avatar detection hints, and a risk score.
"""

import asyncio
import aiohttp
import hashlib
from typing import Optional

# Curated platform list with detection patterns
PLATFORMS = [
    # Social Networks
    {"name": "Instagram", "url": "https://www.instagram.com/{}/", "method": "GET", "cat": "social"},
    {"name": "Twitter/X", "url": "https://twitter.com/{}", "method": "HEAD", "cat": "social"},
    {"name": "TikTok", "url": "https://www.tiktok.com/@{}", "method": "HEAD", "cat": "social"},
    {"name": "Facebook", "url": "https://www.facebook.com/{}", "method": "HEAD", "cat": "social"},
    {"name": "Pinterest", "url": "https://www.pinterest.com/{}/", "method": "HEAD", "cat": "social"},
    {"name": "Snapchat", "url": "https://www.snapchat.com/add/{}", "method": "GET", "not_found_text": "Sorry, we couldn't find that Snapchat account.", "cat": "social"},
    {"name": "Reddit", "url": "https://www.reddit.com/user/{}", "method": "GET", "not_found_text": "page not found", "cat": "social"},
    {"name": "Tumblr", "url": "https://{}.tumblr.com", "method": "HEAD", "cat": "social"},
    {"name": "Discord (Lookup)", "url": "https://discord.com/users/{}", "method": "HEAD", "cat": "social"},
    {"name": "VK", "url": "https://vk.com/{}", "method": "HEAD", "cat": "social"},
    {"name": "Weibo", "url": "https://weibo.com/{}", "method": "HEAD", "cat": "social"},
    {"name": "LinkedIn", "url": "https://www.linkedin.com/in/{}", "method": "HEAD", "cat": "professional"},
    # Tech / Dev
    {"name": "GitHub", "url": "https://github.com/{}", "method": "GET", "not_found_text": "not found", "cat": "tech"},
    {"name": "GitLab", "url": "https://gitlab.com/{}", "method": "HEAD", "cat": "tech"},
    {"name": "Bitbucket", "url": "https://bitbucket.org/{}", "method": "HEAD", "cat": "tech"},
    {"name": "StackOverflow", "url": "https://stackoverflow.com/users/{}", "method": "HEAD", "cat": "tech"},
    {"name": "HackerNews", "url": "https://news.ycombinator.com/user?id={}", "method": "GET", "not_found_text": "No such user", "cat": "tech"},
    {"name": "Dev.to", "url": "https://dev.to/{}", "method": "HEAD", "cat": "tech"},
    {"name": "Replit", "url": "https://replit.com/@{}", "method": "HEAD", "cat": "tech"},
    {"name": "Codepen", "url": "https://codepen.io/{}", "method": "HEAD", "cat": "tech"},
    {"name": "Kaggle", "url": "https://www.kaggle.com/{}", "method": "HEAD", "cat": "tech"},
    {"name": "Npmjs", "url": "https://www.npmjs.com/~{}", "method": "HEAD", "cat": "tech"},
    {"name": "PyPI", "url": "https://pypi.org/user/{}/", "method": "GET", "not_found_text": "404", "cat": "tech"},
    # Gaming
    {"name": "Steam", "url": "https://steamcommunity.com/id/{}", "method": "GET", "not_found_text": "error", "cat": "gaming"},
    {"name": "Twitch", "url": "https://www.twitch.tv/{}", "method": "HEAD", "cat": "gaming"},
    {"name": "Xbox", "url": "https://www.xboxgamertag.com/search/{}", "method": "HEAD", "cat": "gaming"},
    {"name": "Roblox", "url": "https://www.roblox.com/user.aspx?username={}", "method": "HEAD", "cat": "gaming"},
    {"name": "Minecraft (NameMC)", "url": "https://namemc.com/profile/{}", "method": "HEAD", "cat": "gaming"},
    {"name": "Chess.com", "url": "https://www.chess.com/member/{}", "method": "HEAD", "cat": "gaming"},
    # Content / Creator
    {"name": "YouTube", "url": "https://www.youtube.com/@{}", "method": "HEAD", "cat": "content"},
    {"name": "Medium", "url": "https://medium.com/@{}", "method": "HEAD", "cat": "content"},
    {"name": "Substack", "url": "https://{}.substack.com", "method": "HEAD", "cat": "content"},
    {"name": "Patreon", "url": "https://www.patreon.com/{}", "method": "HEAD", "cat": "content"},
    {"name": "SoundCloud", "url": "https://soundcloud.com/{}", "method": "HEAD", "cat": "content"},
    {"name": "Spotify", "url": "https://open.spotify.com/user/{}", "method": "HEAD", "cat": "content"},
    {"name": "Bandcamp", "url": "https://{}.bandcamp.com", "method": "HEAD", "cat": "content"},
    {"name": "Flickr", "url": "https://www.flickr.com/people/{}", "method": "HEAD", "cat": "content"},
    {"name": "Vimeo", "url": "https://vimeo.com/{}", "method": "HEAD", "cat": "content"},
    {"name": "Behance", "url": "https://www.behance.net/{}", "method": "HEAD", "cat": "content"},
    {"name": "Dribbble", "url": "https://dribbble.com/{}", "method": "HEAD", "cat": "content"},
    {"name": "500px", "url": "https://500px.com/p/{}", "method": "HEAD", "cat": "content"},
    # Forums / Community
    {"name": "Quora", "url": "https://www.quora.com/profile/{}", "method": "HEAD", "cat": "community"},
    {"name": "Disqus", "url": "https://disqus.com/by/{}/", "method": "HEAD", "cat": "community"},
    {"name": "ProductHunt", "url": "https://www.producthunt.com/@{}", "method": "HEAD", "cat": "community"},
    {"name": "AngelList", "url": "https://angel.co/u/{}", "method": "HEAD", "cat": "professional"},
    {"name": "Crunchbase", "url": "https://www.crunchbase.com/person/{}", "method": "HEAD", "cat": "professional"},
    # Misc / Identity
    {"name": "Gravatar", "url": "https://en.gravatar.com/{}", "method": "HEAD", "cat": "identity"},
    {"name": "About.me", "url": "https://about.me/{}", "method": "HEAD", "cat": "identity"},
    {"name": "Keybase", "url": "https://keybase.io/{}", "method": "GET", "not_found_text": "not found", "cat": "identity"},
    {"name": "Linktree", "url": "https://linktr.ee/{}", "method": "HEAD", "cat": "identity"},
    {"name": "Carrd", "url": "https://{}.carrd.co", "method": "HEAD", "cat": "identity"},
]


async def check_platform(session: aiohttp.ClientSession, platform: dict, username: str) -> Optional[dict]:
    url = platform["url"].format(username)
    method = platform.get("method", "HEAD")
    not_found_text = platform.get("not_found_text", "")

    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/121.0.0.0 Safari/537.36",
        "Accept-Language": "en-US,en;q=0.9",
    }

    try:
        timeout = aiohttp.ClientTimeout(total=8)
        if method == "GET" and not_found_text:
            async with session.get(url, headers=headers, timeout=timeout, allow_redirects=True, ssl=False) as resp:
                if resp.status == 200:
                    text = await resp.text(errors="ignore")
                    if not_found_text.lower() in text.lower():
                        return None
                    return {"platform": platform["name"], "url": url, "status": resp.status, "cat": platform.get("cat", "misc")}
                return None
        else:
            async with session.head(url, headers=headers, timeout=timeout, allow_redirects=True, ssl=False) as resp:
                if resp.status in (200, 301, 302, 307, 308):
                    return {"platform": platform["name"], "url": url, "status": resp.status, "cat": platform.get("cat", "misc")}
                return None
    except Exception:
        return None


async def phantom_id_search(username: str):
    """
    Searches for a username across all configured platforms concurrently.
    Returns found profiles, categories, and a risk score.
    """
    results = []
    connector = aiohttp.TCPConnector(ssl=False, limit=30)

    async with aiohttp.ClientSession(connector=connector) as session:
        tasks = [check_platform(session, p, username) for p in PLATFORMS]
        responses = await asyncio.gather(*tasks, return_exceptions=True)

    for r in responses:
        if r and isinstance(r, dict):
            results.append(r)

    # Generate Gravatar avatar URL from username hash
    username_hash = hashlib.md5(username.lower().encode()).hexdigest()
    gravatar_url = f"https://www.gravatar.com/avatar/{username_hash}?d=404&s=200"

    # Risk score: more platforms found = higher exposure score
    total = len(PLATFORMS)
    found = len(results)
    risk_score = round((found / total) * 100, 1)

    # Categorize results
    cats = {}
    for r in results:
        c = r.get("cat", "misc")
        cats[c] = cats.get(c, 0) + 1

    return {
        "username": username,
        "found": found,
        "total_checked": total,
        "risk_score": risk_score,
        "gravatar": gravatar_url,
        "categories": cats,
        "profiles": results,
    }
