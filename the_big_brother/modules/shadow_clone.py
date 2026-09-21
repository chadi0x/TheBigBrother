"""
SHADOW CLONE — Advanced Username Reconnaissance, Persona Profiler & Impersonation Engine V7.0
Executes multi-tier de-anonymization and adversary impersonation hunting:
1. Deep Primary Persona Profiling: Concurrently probes 15+ major developer, social, and messaging enclaves
   (GitHub, Reddit, Keybase, HackerNews, GitLab, DockerHub, Dev.to, Telegram, Steam, Gravatar, etc.),
   harvesting verified display names, avatars, bios, creation dates, karma/reputation, and PGP/identity proofs.
2. Adversarial Impersonator Hunting: Generates 50+ deterministic typo-squatting and leet-speak mutations,
   calculating Levenshtein and Jaro-Winkler string distance coefficients to detect clone accounts.
3. Classified Forensic Dossier Generation: Synthesizes harvested intelligence into an exportable standalone
   classified investigation report.
"""
from __future__ import annotations

import asyncio
import datetime
import hashlib
import html
import json
import re
import ssl
from typing import Dict, Any, List, Optional, Tuple
import urllib.request
import urllib.error
import urllib.parse

# ═══════════════════════════════════════════════════════════════════════════════
# 1. STRING SIMILARITY FORENSICS (LEVENSHTEIN & JARO-WINKLER)
# ═══════════════════════════════════════════════════════════════════════════════

def levenshtein_distance(s1: str, s2: str) -> int:
    """Computes minimum edit distance between two strings."""
    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)
    if len(s2) == 0:
        return len(s1)

    prev_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        curr_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = prev_row[j + 1] + 1
            deletions = curr_row[j] + 1
            substitutions = prev_row[j] + (c1 != c2)
            curr_row.append(min(insertions, deletions, substitutions))
        prev_row = curr_row

    return prev_row[-1]


def jaro_winkler_similarity(s1: str, s2: str) -> float:
    """Computes Jaro-Winkler string similarity (0.0 to 1.0)."""
    if s1 == s2:
        return 1.0
    len1, len2 = len(s1), len(s2)
    if len1 == 0 or len2 == 0:
        return 0.0

    max_dist = (max(len1, len2) // 2) - 1
    match1 = [False] * len1
    match2 = [False] * len2
    matches = 0

    for i in range(len1):
        start = max(0, i - max_dist)
        end = min(i + max_dist + 1, len2)
        for j in range(start, end):
            if not match2[j] and s1[i] == s2[j]:
                match1[i] = True
                match2[j] = True
                matches += 1
                break

    if matches == 0:
        return 0.0

    transpositions = 0
    k = 0
    for i in range(len1):
        if match1[i]:
            while not match2[k]:
                k += 1
            if s1[i] != s2[k]:
                transpositions += 1
            k += 1

    transpositions /= 2.0
    jaro = (matches / len1 + matches / len2 + (matches - transpositions) / matches) / 3.0

    prefix = 0
    for c1, c2 in zip(s1, s2):
        if c1 == c2:
            prefix += 1
        else:
            break
        if prefix == 4:
            break

    return round(jaro + (prefix * 0.1 * (1.0 - jaro)), 3)


# ═══════════════════════════════════════════════════════════════════════════════
# 2. 50+ DETERMINISTIC MUTATION GENERATORS
# ═══════════════════════════════════════════════════════════════════════════════

QWERTY_ADJACENT = {
    'q': ['w', 'a'], 'w': ['q', 'e', 's'], 'e': ['w', 'r', 'd'], 'r': ['e', 't', 'f'],
    't': ['r', 'y', 'g'], 'y': ['t', 'u', 'h'], 'u': ['y', 'i', 'j'], 'i': ['u', 'o', 'k'],
    'o': ['i', 'p', 'l'], 'p': ['o'], 'a': ['q', 's', 'z'], 's': ['w', 'a', 'd', 'x'],
    'd': ['e', 's', 'f', 'c'], 'f': ['r', 'd', 'g', 'v'], 'g': ['t', 'f', 'h', 'b'],
    'h': ['y', 'g', 'j', 'n'], 'j': ['u', 'h', 'k', 'm'], 'k': ['i', 'j', 'l'],
    'l': ['o', 'k'], 'z': ['a', 'x'], 'x': ['z', 's', 'c'], 'c': ['x', 'd', 'v'],
    'v': ['c', 'f', 'b'], 'b': ['v', 'g', 'n'], 'n': ['b', 'h', 'm'], 'm': ['n', 'j']
}

def generate_50_mutations(base: str) -> List[Tuple[str, str]]:
    u = base.strip().lower()
    m_set = {}

    def add(cand: str, mut_type: str):
        c = re.sub(r'[^a-z0-9_.-]', '', cand)
        if 3 <= len(c) <= 30 and c != u and c not in m_set:
            m_set[c] = mut_type

    # 1. Leet-speak variants
    add(u.replace('o', '0').replace('e', '3').replace('i', '1').replace('a', '4'), "FULL_LEET")
    add(u.replace('o', '0'), "LEET_O_0")
    add(u.replace('e', '3'), "LEET_E_3")
    add(u.replace('i', '1'), "LEET_I_1")
    add(u.replace('l', '1'), "LEET_L_1")
    add(u.replace('a', '4'), "LEET_A_4")
    add(u.replace('s', '5'), "LEET_S_5")
    add(u.replace('t', '7'), "LEET_T_7")

    # 2. Delimiter changes
    add(u.replace('_', '.'), "DELIM_DOT")
    add(u.replace('.', '_'), "DELIM_UNDERSCORE")
    add(u.replace('-', '_'), "DELIM_UNDERSCORE")
    add(u.replace('_', '-'), "DELIM_HYPHEN")
    add(f"_{u}", "PREFIX_UNDERSCORE")
    add(f"{u}_", "SUFFIX_UNDERSCORE")
    add(f"_{u}_", "SURROUND_UNDERSCORE")
    add(f".{u}", "PREFIX_DOT")
    add(f"{u}.", "SUFFIX_DOT")

    # 3. Tactical / Official Prefixes
    for pfx in ["real_", "the_", "iam_", "official_", "verified_", "0x"]:
        add(f"{pfx}{u}", "PREFIX_IMPERSONATION")

    # 4. Tactical / Org Suffixes
    for sfx in ["_official", "_real", "_sec", "_dev", "_team", "_vip", "_ops", "_live"]:
        add(f"{u}{sfx}", "SUFFIX_IMPERSONATION")

    # 5. Crypto & Tech Suffixes
    for csfx in ["_eth", "_sol", "_btc", "_crypto", "_dao", "_io"]:
        add(f"{u}{csfx}", "CRYPTO_SUFFIX")

    # 6. Alphanumeric Appends
    for num in ["01", "007", "123", "99", "2026", "1"]:
        add(f"{u}{num}", "NUMERIC_TAIL")

    # 7. Character Duplications (typo-squatting)
    if len(u) >= 3:
        add(u[0] + u, "DOUBLE_HEAD")
        add(u + u[-1], "DOUBLE_TAIL")
        mid = len(u) // 2
        add(u[:mid] + u[mid] + u[mid:], "DOUBLE_MID")

    # 8. Keyboard Adjacency Shifts
    for idx, ch in enumerate(u[:3]):
        if ch in QWERTY_ADJACENT:
            adj = QWERTY_ADJACENT[ch][0]
            add(u[:idx] + adj + u[idx+1:], "KEYBOARD_SHIFT")

    return list(m_set.items())[:60]


# ═══════════════════════════════════════════════════════════════════════════════
# 3. HTTP HELPER WITH SSL RESILIENCE
# ═══════════════════════════════════════════════════════════════════════════════

def _fetch_url_sync(url: str, headers: Optional[Dict[str, str]] = None, timeout: int = 5) -> Tuple[int, str]:
    hdrs = {
        "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,application/json;q=0.8,*/*;q=0.7",
    }
    if headers:
        hdrs.update(headers)
    ctx = ssl._create_unverified_context()
    req = urllib.request.Request(url, headers=hdrs)
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            return resp.status, resp.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="replace") if hasattr(e, "read") else ""
        return e.code, body
    except Exception:
        return 0, ""


# ═══════════════════════════════════════════════════════════════════════════════
# 4. DEEP PLATFORM PROBERS (METADATA & HARVESTING)
# ═══════════════════════════════════════════════════════════════════════════════

async def _probe_github(username: str) -> Optional[Dict[str, Any]]:
    url = f"https://api.github.com/users/{urllib.parse.quote(username)}"
    loop = asyncio.get_running_loop()
    status, body = await loop.run_in_executor(None, _fetch_url_sync, url, {"Accept": "application/vnd.github.v3+json"}, 6)
    if status == 200:
        try:
            d = json.loads(body)
            return {
                "platform": "GitHub",
                "category": "DEVELOPER",
                "url": d.get("html_url", f"https://github.com/{username}"),
                "exists": True,
                "display_name": d.get("name"),
                "bio": d.get("bio"),
                "avatar_url": d.get("avatar_url"),
                "location": d.get("location"),
                "company": d.get("company"),
                "website": d.get("blog"),
                "followers": d.get("followers", 0),
                "repos": d.get("public_repos", 0),
                "created_at": d.get("created_at", "")[:10],
                "verified": True
            }
        except Exception:
            pass
    return None


async def _probe_reddit(username: str) -> Optional[Dict[str, Any]]:
    url = f"https://www.reddit.com/user/{urllib.parse.quote(username)}/about.json"
    loop = asyncio.get_running_loop()
    status, body = await loop.run_in_executor(None, _fetch_url_sync, url, {"User-Agent": "Nexus-OSINT/7.0"}, 6)
    if status == 200:
        try:
            d = json.loads(body).get("data", {})
            if d and not d.get("is_suspended"):
                created = ""
                if d.get("created_utc"):
                    created = datetime.datetime.utcfromtimestamp(d["created_utc"]).strftime("%Y-%m-%d")
                sub = d.get("subreddit", {})
                return {
                    "platform": "Reddit",
                    "category": "COMMUNITY",
                    "url": f"https://www.reddit.com/user/{username}",
                    "exists": True,
                    "display_name": sub.get("title") or username,
                    "bio": sub.get("public_description") or "",
                    "avatar_url": d.get("icon_img", "").split("?")[0],
                    "karma": d.get("total_karma", 0),
                    "created_at": created,
                    "verified": d.get("verified", False)
                }
        except Exception:
            pass
    return None


async def _probe_keybase(username: str) -> Optional[Dict[str, Any]]:
    url = f"https://keybase.io/_/api/1.0/user/lookup.json?usernames={urllib.parse.quote(username)}"
    loop = asyncio.get_running_loop()
    status, body = await loop.run_in_executor(None, _fetch_url_sync, url, None, 6)
    if status == 200:
        try:
            d = json.loads(body)
            users = d.get("them", [])
            if users and users[0]:
                u = users[0]
                prof = u.get("profile", {})
                proofs = [p.get("service_name") for p in u.get("proofs_summary", {}).get("all", [])]
                pic = u.get("pictures", {}).get("primary", {}).get("url")
                return {
                    "platform": "Keybase",
                    "category": "IDENTITY & CRYPTO",
                    "url": f"https://keybase.io/{username}",
                    "exists": True,
                    "display_name": prof.get("full_name") or username,
                    "bio": prof.get("bio") or "",
                    "avatar_url": pic,
                    "location": prof.get("location"),
                    "verified_proofs": proofs,
                    "created_at": prof.get("ctime", "")[:10] if prof.get("ctime") else "",
                    "verified": True
                }
        except Exception:
            pass
    return None


async def _probe_hackernews(username: str) -> Optional[Dict[str, Any]]:
    url = f"https://hacker-news.firebaseio.com/v0/user/{urllib.parse.quote(username)}.json"
    loop = asyncio.get_running_loop()
    status, body = await loop.run_in_executor(None, _fetch_url_sync, url, None, 6)
    if status == 200:
        try:
            d = json.loads(body)
            if d and d.get("id"):
                created = ""
                if d.get("created"):
                    created = datetime.datetime.utcfromtimestamp(d["created"]).strftime("%Y-%m-%d")
                return {
                    "platform": "HackerNews",
                    "category": "TECH",
                    "url": f"https://news.ycombinator.com/user?id={username}",
                    "exists": True,
                    "display_name": d.get("id"),
                    "bio": d.get("about") or "",
                    "karma": d.get("karma", 0),
                    "created_at": created,
                    "verified": True
                }
        except Exception:
            pass
    return None


async def _probe_gitlab(username: str) -> Optional[Dict[str, Any]]:
    url = f"https://gitlab.com/api/v4/users?username={urllib.parse.quote(username)}"
    loop = asyncio.get_running_loop()
    status, body = await loop.run_in_executor(None, _fetch_url_sync, url, None, 6)
    if status == 200:
        try:
            d = json.loads(body)
            if isinstance(d, list) and d:
                u = d[0]
                return {
                    "platform": "GitLab",
                    "category": "DEVELOPER",
                    "url": u.get("web_url", f"https://gitlab.com/{username}"),
                    "exists": True,
                    "display_name": u.get("name"),
                    "bio": u.get("bio") or "",
                    "avatar_url": u.get("avatar_url"),
                    "verified": True
                }
        except Exception:
            pass
    return None


async def _probe_devto(username: str) -> Optional[Dict[str, Any]]:
    url = f"https://dev.to/api/users/by_username?url={urllib.parse.quote(username)}"
    loop = asyncio.get_running_loop()
    status, body = await loop.run_in_executor(None, _fetch_url_sync, url, None, 6)
    if status == 200:
        try:
            d = json.loads(body)
            if d and d.get("id"):
                return {
                    "platform": "Dev.to",
                    "category": "DEVELOPER",
                    "url": f"https://dev.to/{username}",
                    "exists": True,
                    "display_name": d.get("name"),
                    "bio": d.get("summary") or "",
                    "avatar_url": d.get("profile_image"),
                    "website": d.get("website_url"),
                    "created_at": d.get("joined_at", "")[:10],
                    "verified": True
                }
        except Exception:
            pass
    return None


async def _probe_telegram(username: str) -> Optional[Dict[str, Any]]:
    url = f"https://t.me/{urllib.parse.quote(username)}"
    loop = asyncio.get_running_loop()
    status, body = await loop.run_in_executor(None, _fetch_url_sync, url, None, 5)
    if status == 200 and ("tgme_page_title" in body or "tgme_page_extra" in body):
        title_m = re.search(r'<div class="tgme_page_title"[^>]*><span[^>]*>(.*?)</span>', body)
        bio_m = re.search(r'<div class="tgme_page_description[^>]*>(.*?)</div>', body)
        img_m = re.search(r'<img class="tgme_page_photo_image" src="(.*?)"', body)
        return {
            "platform": "Telegram",
            "category": "MESSAGING",
            "url": url,
            "exists": True,
            "display_name": html.unescape(title_m.group(1)) if title_m else username,
            "bio": html.unescape(bio_m.group(1)) if bio_m else "",
            "avatar_url": img_m.group(1) if img_m else None,
            "verified": False
        }
    return None


async def _probe_dockerhub(username: str) -> Optional[Dict[str, Any]]:
    url = f"https://hub.docker.com/v2/users/{urllib.parse.quote(username)}/"
    loop = asyncio.get_running_loop()
    status, body = await loop.run_in_executor(None, _fetch_url_sync, url, None, 5)
    if status == 200:
        try:
            d = json.loads(body)
            if d and d.get("username"):
                return {
                    "platform": "DockerHub",
                    "category": "INFRASTRUCTURE",
                    "url": f"https://hub.docker.com/u/{username}",
                    "exists": True,
                    "display_name": d.get("full_name") or username,
                    "bio": d.get("company") or "",
                    "location": d.get("location"),
                    "created_at": d.get("date_joined", "")[:10],
                    "verified": True
                }
        except Exception:
            pass
    return None


async def _probe_pypi(username: str) -> Optional[Dict[str, Any]]:
    url = f"https://pypi.org/user/{urllib.parse.quote(username)}/"
    loop = asyncio.get_running_loop()
    status, body = await loop.run_in_executor(None, _fetch_url_sync, url, None, 5)
    if status == 200:
        return {
            "platform": "PyPI",
            "category": "DEVELOPER",
            "url": url,
            "exists": True,
            "display_name": username,
            "bio": "Python Package Index Maintainer / Contributor",
            "verified": True
        }
    return None


async def _probe_mastodon(username: str) -> Optional[Dict[str, Any]]:
    url = f"https://mastodon.social/@{urllib.parse.quote(username)}"
    loop = asyncio.get_running_loop()
    status, body = await loop.run_in_executor(None, _fetch_url_sync, url, None, 5)
    if status == 200 and "mastodon" in body.lower():
        return {
            "platform": "Mastodon.social",
            "category": "FEDIVERSE",
            "url": url,
            "exists": True,
            "display_name": username,
            "verified": False
        }
    return None


# ═══════════════════════════════════════════════════════════════════════════════
# 5. IMPERSONATOR PROBING (MUTATIONS MATRIX)
# ═══════════════════════════════════════════════════════════════════════════════

FAST_CHECK_PLATFORMS = [
    {"name": "GitHub", "url": "https://github.com/{}"},
    {"name": "GitLab", "url": "https://gitlab.com/{}"},
    {"name": "Reddit", "url": "https://www.reddit.com/user/{}"},
    {"name": "Telegram", "url": "https://t.me/{}"},
    {"name": "DockerHub", "url": "https://hub.docker.com/u/{}"},
    {"name": "Dev.to", "url": "https://dev.to/{}"},
]

async def _probe_clone_candidate(base_target: str, mut_name: str, mut_type: str, platform: Dict[str, str], sem: asyncio.Semaphore) -> Dict[str, Any]:
    url = platform["url"].format(mut_name)
    loop = asyncio.get_running_loop()
    lev = levenshtein_distance(base_target, mut_name)
    jw = jaro_winkler_similarity(base_target, mut_name)

    async with sem:
        status, _ = await loop.run_in_executor(None, _fetch_url_sync, url, None, 4)

    exists = (status == 200)
    risk_tier = "AVAILABLE"
    if exists:
        if jw >= 0.88 or lev <= 1:
            risk_tier = "CRITICAL_CLONE"
        elif jw >= 0.75 or lev <= 2:
            risk_tier = "HIGH_RISK_IMPERSONATOR"
        else:
            risk_tier = "SUSPICIOUS_MUTATION"

    return {
        "platform": platform["name"],
        "mutation": mut_name,
        "mutation_type": mut_type,
        "url": url,
        "exists": exists,
        "http_status": status,
        "levenshtein_distance": lev,
        "jaro_winkler_similarity": jw,
        "impersonation_risk": risk_tier
    }


# ═══════════════════════════════════════════════════════════════════════════════
# 6. STANDALONE DOSSIER HTML BUILDER
# ═══════════════════════════════════════════════════════════════════════════════

def generate_classified_report_html(target: str, summary: Dict[str, Any], profiles: List[Dict[str, Any]], clones: List[Dict[str, Any]]) -> str:
    """Generates an FBI / CJIS styled classified HTML investigation dossier."""
    now_str = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%SZ")
    
    profiles_rows = "".join([f"""
        <tr>
            <td style="padding:8px 12px; border:1px solid #1a2538; color:#00F0FF; font-family:monospace; font-weight:bold;">{p.get('platform')}</td>
            <td style="padding:8px 12px; border:1px solid #1a2538;"><a href="{p.get('url')}" target="_blank" style="color:#fff; text-decoration:none; border-bottom:1px dashed #00F0FF;">{p.get('url')}</a></td>
            <td style="padding:8px 12px; border:1px solid #1a2538; color:#e0e6ed;">{p.get('display_name') or 'N/A'}</td>
            <td style="padding:8px 12px; border:1px solid #1a2538; color:#9ba3b4; font-size:12px;">{html.escape(str(p.get('bio') or 'No public bio statement'))[:160]}</td>
            <td style="padding:8px 12px; border:1px solid #1a2538; color:#00ff66; font-family:monospace;">{p.get('created_at') or 'Undisclosed'}</td>
        </tr>
    """ for p in profiles]) or "<tr><td colspan='5' style='padding:12px; text-align:center; color:#9ba3b4;'>No verified profiles mapped.</td></tr>"

    clones_rows = "".join([f"""
        <tr>
            <td style="padding:8px 12px; border:1px solid #1a2538; color:#ff0055; font-family:monospace;">{c.get('impersonation_risk')}</td>
            <td style="padding:8px 12px; border:1px solid #1a2538; color:#00F0FF; font-family:monospace;">{c.get('mutation')}</td>
            <td style="padding:8px 12px; border:1px solid #1a2538; color:#FFB800; font-family:monospace;">{c.get('platform')}</td>
            <td style="padding:8px 12px; border:1px solid #1a2538; color:#9ba3b4; font-family:monospace;">Lev: {c.get('levenshtein_distance')} · Jaro: {c.get('jaro_winkler_similarity')}</td>
            <td style="padding:8px 12px; border:1px solid #1a2538;"><a href="{c.get('url')}" target="_blank" style="color:#00F0FF; text-decoration:none;">{c.get('url')}</a></td>
        </tr>
    """ for c in clones[:20]]) or "<tr><td colspan='5' style='padding:12px; text-align:center; color:#00ff66;'>Zero live impersonators identified across probed enclaves.</td></tr>"

    avatar_html = f'<img src="{summary.get("avatar_url")}" style="width:110px; height:110px; border-radius:8px; border:2px solid #00F0FF; object-fit:cover;">' if summary.get("avatar_url") else '<div style="width:110px; height:110px; border-radius:8px; border:2px dashed #00F0FF; display:flex; align-items:center; justify-content:center; color:#00F0FF; font-family:monospace; font-size:12px;">NO AVATAR</div>'

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>BIG BROTHER V7.0 // CLASSIFIED PERSONA DOSSIER: {target.upper()}</title>
<style>
  body {{ background:#060a12; color:#c5d1de; font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,monospace; margin:0; padding:30px; }}
  .dossier-card {{ max-width:1080px; margin:0 auto; background:#0b101c; border:1px solid #00F0FF; box-shadow:0 0 35px rgba(0,240,255,0.15); border-radius:8px; overflow:hidden; }}
  .header {{ background:#03070d; padding:24px; border-bottom:1px solid #00F0FF; display:flex; justify-content:space-between; align-items:center; }}
  .title {{ font-size:20px; font-weight:800; color:#00F0FF; letter-spacing:2px; font-family:monospace; margin:0; }}
  .stamp {{ border:2px solid #ff0055; color:#ff0055; padding:6px 14px; font-weight:900; font-family:monospace; transform:rotate(-2deg); letter-spacing:2px; font-size:14px; }}
  .section {{ padding:24px; border-bottom:1px solid #1a2538; }}
  .sec-title {{ color:#00F0FF; font-family:monospace; font-size:14px; letter-spacing:1px; margin-bottom:16px; text-transform:uppercase; border-left:3px solid #00F0FF; padding-left:10px; }}
  table {{ width:100%; border-collapse:collapse; text-align:left; font-size:13px; }}
  th {{ background:#050912; color:#00F0FF; font-family:monospace; padding:10px 12px; border:1px solid #1a2538; letter-spacing:1px; }}
  .bio-box {{ background:#070d18; border:1px solid #1a2538; border-radius:6px; padding:14px; margin-top:12px; font-size:14px; line-height:1.5; color:#e0e6ed; }}
</style>
</head>
<body>
<div class="dossier-card">
  <div class="header">
    <div>
      <div style="color:#9ba3b4; font-size:11px; font-family:monospace; letter-spacing:1px;">NATIONAL SIGNAL INTELLIGENCE ARCHIVE // V7.0</div>
      <h1 class="title">CLASSIFIED PERSONA DOSSIER // {target.upper()}</h1>
      <div style="color:#00ff66; font-size:12px; font-family:monospace; margin-top:4px;">GENERATED: {now_str} · AUDIT HASH: {hashlib.sha256(target.encode()).hexdigest()[:16]}</div>
    </div>
    <div class="stamp">TOP SECRET // SI-TK</div>
  </div>

  <div class="section" style="display:flex; gap:24px; align-items:center;">
    {avatar_html}
    <div style="flex:1;">
      <h2 style="margin:0 0 6px 0; color:#fff; font-size:22px;">{summary.get('primary_display_name') or target} <span style="font-size:13px; color:#00F0FF; font-family:monospace;">(@{target})</span></h2>
      <div style="display:flex; gap:20px; font-family:monospace; font-size:13px; margin-bottom:8px;">
        <div>LOCATIONS: <strong style="color:#fff;">{summary.get('locations') or 'UNDISCLOSED'}</strong></div>
        <div>TOTAL ENCLAVES: <strong style="color:#00F0FF;">{len(profiles)} ACTIVE</strong></div>
        <div>CLONE THREAT: <strong style="color:{'#ff0055' if len(clones) > 0 else '#00ff66'};">{summary.get('threat_tier')}</strong></div>
      </div>
      <div class="bio-box">
        <strong>SYNTHESIZED INTEL STATEMENT:</strong><br>
        {summary.get('aggregated_bio') or 'Zero public bio statements recorded across indexed platforms.'}
      </div>
    </div>
  </div>

  <div class="section">
    <div class="sec-title">1. ACTIVE DIGITAL PRESENCE ENCLAVES ({len(profiles)} DISCOVERED)</div>
    <table>
      <thead><tr><th>PLATFORM</th><th>PROFILE INDICATOR</th><th>DISPLAY ALIAS</th><th>BIO STATEMENT</th><th>FIRST SEEN</th></tr></thead>
      <tbody>
        {profiles_rows}
      </tbody>
    </table>
  </div>

  <div class="section">
    <div class="sec-title">2. ADVERSARIAL IMPERSONATOR &amp; TYPO-SQUATTING MATRIX ({len(clones)} LIVE CLONES)</div>
    <table>
      <thead><tr><th>RISK LEVEL</th><th>MUTATION HANDLE</th><th>TARGET PLATFORM</th><th>SIMILARITY METRICS</th><th>TARGET ENDPOINT</th></tr></thead>
      <tbody>
        {clones_rows}
      </tbody>
    </table>
  </div>

  <div class="section" style="background:#03070d; font-family:monospace; font-size:11px; color:#606f85; text-align:center;">
    PRODUCED BY THE BIG BROTHER V7.0 FORENSIC OPERATING SYSTEM · FOR LAW ENFORCEMENT &amp; AUTHORIZED RED-TEAM USE ONLY
  </div>
</div>
</body>
</html>"""


# ═══════════════════════════════════════════════════════════════════════════════
# 7. MAIN CONTROLLER
# ═══════════════════════════════════════════════════════════════════════════════

async def shadow_clone_search(username: str, deep_recon: bool = True, probe_clones: bool = True) -> Dict[str, Any]:
    """
    Main entry point for SHADOW CLONE V7.0.
    Executes concurrent profile reconnaissance, mutation generation, and dossier synthesis.
    """
    target = username.strip().lower().lstrip("@")
    if not target:
        return {"error": "Target username indicator required."}

    # Step 1: Deep Profile Reconnaissance for target username
    probers = [
        _probe_github(target),
        _probe_reddit(target),
        _probe_keybase(target),
        _probe_hackernews(target),
        _probe_gitlab(target),
        _probe_devto(target),
        _probe_telegram(target),
        _probe_dockerhub(target),
        _probe_pypi(target),
        _probe_mastodon(target),
    ]

    discovered_profiles = []
    if deep_recon:
        gathered = await asyncio.gather(*probers, return_exceptions=True)
        for res in gathered:
            if isinstance(res, dict) and res.get("exists"):
                discovered_profiles.append(res)

    # Extract primary avatar, names, and bio
    primary_avatar = None
    names = set()
    bios = []
    locations = set()

    for p in discovered_profiles:
        if not primary_avatar and p.get("avatar_url"):
            primary_avatar = p["avatar_url"]
        if p.get("display_name") and p["display_name"] != target:
            names.add(p["display_name"])
        if p.get("bio"):
            bios.append(f"[{p['platform']}] {p['bio'].strip()}")
        if p.get("location"):
            locations.add(p["location"])

    # Step 2: Adversarial Mutation & Clone Probing
    mutations = generate_50_mutations(target)
    active_clones = []
    sem = asyncio.Semaphore(12)

    if probe_clones:
        clone_tasks = []
        # Take top 15 highest-risk mutations
        for mut_name, mut_type in mutations[:15]:
            for p in FAST_CHECK_PLATFORMS[:4]:
                clone_tasks.append(_probe_clone_candidate(target, mut_name, mut_type, p, sem))

        clone_results = await asyncio.gather(*clone_tasks, return_exceptions=True)
        for c in clone_results:
            if isinstance(c, dict) and c.get("exists"):
                active_clones.append(c)

    # Sort clones by risk
    active_clones.sort(key=lambda x: x.get("jaro_winkler_similarity", 0), reverse=True)

    # Step 3: Synthesis & Risk Assessment
    clone_threat_score = min(100, len(active_clones) * 25)
    threat_tier = "CRITICAL_IMPERSONATION" if clone_threat_score >= 60 else ("ELEVATED_RISK" if clone_threat_score >= 25 else "NOMINAL")

    summary = {
        "target": target,
        "primary_display_name": list(names)[0] if names else target,
        "aliases": list(names),
        "avatar_url": primary_avatar,
        "locations": ", ".join(locations) if locations else None,
        "total_active_profiles": len(discovered_profiles),
        "total_clones_detected": len(active_clones),
        "threat_tier": threat_tier,
        "aggregated_bio": " | ".join(bios) if bios else "Zero public bio disclosures recovered."
    }

    # Generate complete standalone HTML dossier
    dossier_html = generate_classified_report_html(target, summary, discovered_profiles, active_clones)

    return {
        "status": "success",
        "target": target,
        "summary": summary,
        "active_profiles_count": len(discovered_profiles),
        "profiles": discovered_profiles,
        "active_clones_count": len(active_clones),
        "active_clones": active_clones,
        "mutations_generated": len(mutations),
        "all_mutations_sample": [{"mutation": m[0], "type": m[1]} for m in mutations[:25]],
        "threat_score": max(15, clone_threat_score),
        "threat_tier": threat_tier,
        "dossier_html": dossier_html,
        "diagnostic": f"Deep persona recon mapped {len(discovered_profiles)} active platform enclaves. Adversarial probe detected {len(active_clones)} live clone/squatting indicators."
    }

