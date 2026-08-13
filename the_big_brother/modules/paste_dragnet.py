"""
PASTE DRAGNET — Hunts paste sites for a query using DuckDuckGo dorks.
Falls back gracefully if duckduckgo-search is unavailable.
"""
import asyncio
from urllib.parse import quote

import requests


PASTE_SITES = [
    "pastebin.com",
    "ghostbin.co",
    "rentry.co",
    "controlc.com",
    "paste.ee",
    "0bin.net",
    "justpaste.it",
    "hastebin.com",
    "ideone.com",
    "dpaste.org",
    "termbin.com",
    "privatebin.net",
]


def _ddg_search(query: str, max_results: int = 15):
    try:
        from duckduckgo_search import DDGS
        with DDGS(timeout=10) as ddgs:
            return list(ddgs.text(query, max_results=max_results))
    except Exception:
        return []


def _hunt_site(query: str, site: str):
    dork = f'site:{site} "{query}"'
    results = _ddg_search(dork, max_results=10)
    out = []
    for r in results:
        out.append({
            "title": r.get("title", "")[:160],
            "url": r.get("href") or r.get("url"),
            "snippet": (r.get("body") or "")[:240],
            "site": site,
        })
    return out


async def paste_dragnet(query: str) -> dict:
    query = query.strip()
    if not query:
        return {"error": "query required"}

    tasks = [asyncio.to_thread(_hunt_site, query, site) for site in PASTE_SITES]
    results_per_site = await asyncio.gather(*tasks, return_exceptions=True)

    all_hits = []
    per_site = {}
    for site, res in zip(PASTE_SITES, results_per_site):
        if isinstance(res, Exception) or not res:
            per_site[site] = 0
            continue
        per_site[site] = len(res)
        all_hits.extend(res)

    # Severity heuristic: keyword markers commonly seen in dumps
    HOT_TERMS = ["password", "passwd", "leak", "dump", "combo", "creds", "api_key", "secret", "token"]
    for hit in all_hits:
        blob = f"{hit.get('title','')} {hit.get('snippet','')}".lower()
        hit["severity"] = "CRITICAL" if any(t in blob for t in HOT_TERMS) else "LOW"

    all_hits.sort(key=lambda h: 0 if h["severity"] == "CRITICAL" else 1)

    return {
        "query": query,
        "total_hits": len(all_hits),
        "per_site": per_site,
        "results": all_hits[:120],
    }
