"""
WAYBACK SPECTRE — Wayback Machine CDX timeline + sensitive-path flagging.
Uses the free CDX server to enumerate every archived snapshot, then surfaces
historical paths that often leak data (admin/, .env, .git, backup files, etc).
"""
import asyncio
from collections import Counter
from urllib.parse import urlparse

import requests


SENSITIVE_PATTERNS = [
    r"/admin", r"/login", r"/wp-admin", r"/wp-login", r"/phpmyadmin",
    r"\.env", r"\.git", r"\.svn", r"\.htaccess", r"\.htpasswd",
    r"/config", r"/backup", r"/dump", r"/install", r"/setup",
    r"\.bak$", r"\.old$", r"\.sql$", r"\.zip$", r"\.tar\.gz$",
    r"/api/internal", r"/debug", r"/test", r"/private", r"/secret",
    r"id_rsa", r"\.pem$", r"\.key$", r"credentials", r"/dashboard",
]


def _cdx(domain: str, limit: int = 5000):
    url = "https://web.archive.org/cdx/search/cdx"
    params = {
        "url": f"{domain}/*",
        "output": "json",
        "limit": limit,
        "fl": "timestamp,original,mimetype,statuscode,digest",
        "filter": "statuscode:200",
        "collapse": "urlkey",
    }
    try:
        r = requests.get(url, params=params, timeout=15)
        if r.status_code != 200:
            return []
        rows = r.json()
        if not rows or len(rows) < 2:
            return []
        header = rows[0]
        return [dict(zip(header, row)) for row in rows[1:]]
    except Exception:
        return []


def _flag_sensitive(rows: list) -> list:
    import re
    flagged = []
    seen = set()
    for row in rows:
        url = row["original"]
        for pat in SENSITIVE_PATTERNS:
            if re.search(pat, url, re.IGNORECASE):
                key = (url, pat)
                if key in seen:
                    continue
                seen.add(key)
                ts = row["timestamp"]
                flagged.append({
                    "url": url,
                    "pattern": pat,
                    "timestamp": ts,
                    "snapshot": f"https://web.archive.org/web/{ts}/{url}",
                    "mime": row.get("mimetype", ""),
                })
                break
    return flagged[:80]


def _yearly_buckets(rows: list) -> list:
    by_year = Counter()
    for r in rows:
        ts = r["timestamp"]
        if len(ts) >= 4:
            by_year[ts[:4]] += 1
    return [{"year": y, "count": c} for y, c in sorted(by_year.items())]


def _mime_buckets(rows: list) -> list:
    c = Counter(r.get("mimetype", "unknown") for r in rows)
    return [{"mime": m, "count": n} for m, n in c.most_common(10)]


async def wayback_spectre(target: str) -> dict:
    target = target.strip()
    if target.startswith(("http://", "https://")):
        target = urlparse(target).netloc
    if not target:
        return {"error": "Invalid target"}

    rows = await asyncio.to_thread(_cdx, target)
    if not rows:
        return {
            "target": target,
            "total_snapshots": 0,
            "first_seen": None,
            "last_seen": None,
            "yearly": [],
            "mimes": [],
            "sensitive": [],
            "sample": [],
            "message": "No snapshots found in Wayback Machine.",
        }

    first = min(rows, key=lambda r: r["timestamp"])
    last = max(rows, key=lambda r: r["timestamp"])

    sensitive = _flag_sensitive(rows)
    yearly = _yearly_buckets(rows)
    mimes = _mime_buckets(rows)

    sample = []
    seen = set()
    for r in rows:
        u = r["original"]
        if u in seen:
            continue
        seen.add(u)
        sample.append({
            "url": u,
            "timestamp": r["timestamp"],
            "snapshot": f"https://web.archive.org/web/{r['timestamp']}/{u}",
        })
        if len(sample) >= 50:
            break

    return {
        "target": target,
        "total_snapshots": len(rows),
        "first_seen": first["timestamp"],
        "last_seen": last["timestamp"],
        "first_url": first["original"],
        "yearly": yearly,
        "mimes": mimes,
        "sensitive_count": len(sensitive),
        "sensitive": sensitive,
        "sample": sample,
    }
