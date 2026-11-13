"""
RANSOM DISCLOSE — Leak Site & Extortion Aggregator (Module #11)
Zero-Mock Implementation:
Queries live public Ransomwatch JSON feed aggregating active darknet ransomware blogs
(LockBit, RansomHub, Play, Akira, Medusa, BlackCat/ALPHV).
Zero synthetic sample databases.
"""
import urllib.request
import urllib.error
import json
import asyncio
from typing import Dict, Any, List

RANSOMWATCH_FEED = "https://raw.githubusercontent.com/joshhighet/ransomwatch/main/posts.json"


def _fetch_ransomwatch_feed(timeout: int = 6) -> tuple[int, List[dict]]:
    req = urllib.request.Request(
        RANSOMWATCH_FEED,
        headers={"User-Agent": "TheBigBrother-OSINT/7.0 (Ransomware Extortion Monitor)"}
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode("utf-8", errors="replace"))
            return resp.getcode(), data if isinstance(data, list) else []
    except urllib.error.HTTPError as he:
        return he.code, []
    except Exception:
        return 0, []


async def ransom_disclose_search(query: str) -> Dict[str, Any]:
    loop = asyncio.get_running_loop()
    q = query.strip().lower()

    if not q:
        return {
            "status": "error",
            "error": "Query parameter required to search extortion shame blogs."
        }

    code, posts = await loop.run_in_executor(None, _fetch_ransomwatch_feed, 6)

    hits = []
    if code == 200 and posts:
        for item in posts:
            title = (item.get("post_title") or "").lower()
            group = (item.get("group_name") or "")
            desc = (item.get("description") or "")

            if q in title or q in group.lower() or q in desc.lower():
                hits.append({
                    "gang": group,
                    "victim": item.get("post_title"),
                    "date_disclosed": item.get("discovered", "Recently Indexed"),
                    "status": "INDEXED_ON_DARKNET_BLOG",
                    "claim": desc[:200] if desc else "Exfiltrated enterprise data listing."
                })
                if len(hits) >= 15:
                    break

    is_compromised = len(hits) > 0
    threat_score = 95 if is_compromised else 0

    return {
        "status": "success" if code == 200 else "upstream_diagnostic",
        "query": query,
        "feed_http_status": code,
        "total_extortion_incidents": len(hits),
        "threat_score": threat_score,
        "threat_level": "CRITICAL" if is_compromised else "NOMINAL_CLEAN",
        "is_listed_on_leak_sites": is_compromised,
        "severity": "CRITICAL" if is_compromised else "NOMINAL_CLEAN",
        "disclosed_incidents": hits,
        "analyst_guidance": f"Found {len(hits)} matching extortion disclosures on active ransomware darknet shame blogs." if is_compromised else f"No active extortion listings discovered across live indexed ransomware blogs (Ransomwatch mirror HTTP {code})."
    }
