"""
CODE HUNTER — Deep Git & GitHub Harvester V7.0
Pulls full user telemetry, unmasked commit emails from events & commits,
public SSH/GPG keys, organizations, language distribution percentages, and activity heatmaps.
"""
from __future__ import annotations

import asyncio
import os
from collections import Counter
from datetime import datetime
from typing import Optional, Dict, Any, List

import json
import urllib.request
import urllib.parse
import urllib.error
try:
    import requests
except ImportError:
    requests = None

API = "https://api.github.com"


def _headers() -> dict:
    h = {
        "Accept": "application/vnd.github+json",
        "User-Agent": "TheBigBrother-Forensics/7.0 (Military-Grade OSINT)",
    }
    token = os.environ.get("GITHUB_TOKEN")
    if token:
        h["Authorization"] = f"Bearer {token}"
    return h


def _get(path: str, params: Optional[dict] = None):
    url = f"{API}{path}"
    if params:
        url += f"?{urllib.parse.urlencode(params)}"
    req = urllib.request.Request(url, headers=_headers())
    try:
        with urllib.request.urlopen(req, timeout=9) as resp:
            data = json.loads(resp.read().decode("utf-8", errors="replace"))
            return data, None
    except urllib.error.HTTPError as he:
        if he.code == 403:
            return None, "Rate-limited (60/hr unauthenticated). Add GITHUB_TOKEN to elevate limit."
        if he.code == 404:
            return None, "Target not found"
        return None, f"HTTP {he.code}"
    except Exception as e:
        return None, str(e)


def _harvest_commit_emails(login: str, repos: list, events: list) -> List[Dict[str, Any]]:
    """
    Harvests unmasked author and committer emails by cross-referencing:
    1. Public PushEvents payload.commits (primary unauthenticated leak vector)
    2. Commit patch history across top repositories
    """
    email_records: Dict[str, Dict[str, Any]] = {}

    def is_valid_email(m: Optional[str]) -> bool:
        if not m or not isinstance(m, str):
            return False
        m_lower = m.lower().strip()
        if "@" not in m_lower or "." not in m_lower:
            return False
        if any(ign in m_lower for ign in ["noreply", "users.noreply.github.com", "action@github", "web-flow@"]):
            return False
        return True

    # 1. Parse PushEvents (often contains unmasked user email in author/committer objects)
    for ev in events or []:
        if ev.get("type") == "PushEvent":
            payload = ev.get("payload") or {}
            commits = payload.get("commits") or []
            repo_name = (ev.get("repo") or {}).get("name", "public-event")
            for c in commits:
                author = c.get("author") or {}
                mail = author.get("email")
                name = author.get("name") or login
                if is_valid_email(mail):
                    norm = mail.strip().lower()
                    if norm not in email_records:
                        email_records[norm] = {
                            "email": norm,
                            "name": name,
                            "count": 0,
                            "repos": set(),
                            "source": "PUSH_EVENT_STREAM",
                            "verified_author": True
                        }
                    email_records[norm]["count"] += 1
                    email_records[norm]["repos"].add(repo_name)

    # 2. Query Commit histories for top 6 public repos
    for repo in repos[:6]:
        repo_name = repo.get("name")
        if not repo_name:
            continue
        data, _ = _get(f"/repos/{login}/{repo_name}/commits", {"author": login, "per_page": 25})
        if not data or not isinstance(data, list):
            continue
        for c in data:
            commit_obj = c.get("commit") or {}
            author = commit_obj.get("author") or {}
            committer = commit_obj.get("committer") or {}

            for person in [author, committer]:
                mail = person.get("email")
                name = person.get("name") or login
                if is_valid_email(mail):
                    norm = mail.strip().lower()
                    if norm not in email_records:
                        email_records[norm] = {
                            "email": norm,
                            "name": name,
                            "count": 0,
                            "repos": set(),
                            "source": f"GIT_COMMIT_LOG ({repo_name})",
                            "verified_author": True
                        }
                    email_records[norm]["count"] += 1
                    email_records[norm]["repos"].add(repo_name)

    # Format list with serializable sets
    results = []
    for item in sorted(email_records.values(), key=lambda x: x["count"], reverse=True):
        results.append({
            "email": item["email"],
            "name": item["name"],
            "count": item["count"],
            "repos": sorted(list(item["repos"]))[:5],
            "source": item["source"],
            "verified": item["verified_author"]
        })
    return results


def _activity_buckets(events: list) -> dict:
    by_hour = [0] * 24
    by_dow = [0] * 7
    by_type = Counter()
    for e in events or []:
        try:
            dt = datetime.fromisoformat(e["created_at"].replace("Z", "+00:00"))
            by_hour[dt.hour] += 1
            by_dow[dt.weekday()] += 1
            by_type[e["type"]] += 1
        except Exception:
            pass
    return {
        "hourly_utc": by_hour,
        "weekday": by_dow,
        "event_types": dict(by_type.most_common(10)),
        "recent_event_count": len(events or [])
    }


async def code_hunter(login: str) -> dict:
    login = login.strip().lstrip("@")
    if not login:
        return {"error": "Target GitHub login or username required"}

    # Fetch User Core Profile
    user, err = await asyncio.to_thread(_get, f"/users/{login}")
    if err:
        return {"error": err, "status": "error", "target": login}

    # Parallel Data Harvesting
    repos_task = asyncio.to_thread(_get, f"/users/{login}/repos", {"sort": "updated", "per_page": 100})
    orgs_task = asyncio.to_thread(_get, f"/users/{login}/orgs")
    events_task = asyncio.to_thread(_get, f"/users/{login}/events/public", {"per_page": 100})
    gists_task = asyncio.to_thread(_get, f"/users/{login}/gists", {"per_page": 30})
    keys_task = asyncio.to_thread(_get, f"/users/{login}/keys")
    gpg_keys_task = asyncio.to_thread(_get, f"/users/{login}/gpg_keys")

    (repos, _), (orgs, _), (events, _), (gists, _), (ssh_keys, _), (gpg_keys, _) = await asyncio.gather(
        repos_task, orgs_task, events_task, gists_task, keys_task, gpg_keys_task
    )

    repos = [r for r in repos if isinstance(r, dict)] if isinstance(repos, list) else []
    orgs = [o for o in orgs if isinstance(o, dict)] if isinstance(orgs, list) else []
    events = [e for e in events if isinstance(e, dict)] if isinstance(events, list) else []
    gists = [g for g in gists if isinstance(g, dict)] if isinstance(gists, list) else []
    ssh_keys = [k for k in ssh_keys if isinstance(k, dict)] if isinstance(ssh_keys, list) else []
    gpg_keys = [k for k in gpg_keys if isinstance(k, dict)] if isinstance(gpg_keys, list) else []

    # Process Repositories
    repo_summary = sorted(
        [
            {
                "name": r.get("name", "unnamed"),
                "stars": r.get("stargazers_count", 0),
                "forks": r.get("forks_count", 0),
                "open_issues": r.get("open_issues_count", 0),
                "language": r.get("language") or "N/A",
                "updated": r.get("updated_at"),
                "created": r.get("created_at"),
                "description": (r.get("description") or "No description provided.")[:160],
                "url": r.get("html_url"),
                "default_branch": r.get("default_branch", "main"),
                "fork": r.get("fork", False),
                "archived": r.get("archived", False)
            }
            for r in repos
        ],
        key=lambda x: (x["stars"], x["forks"]),
        reverse=True,
    )

    # Programming Language Statistics & Percentage Share
    lang_counter = Counter(r["language"] for r in repo_summary if r["language"] and r["language"] != "N/A")
    total_coded_repos = sum(lang_counter.values()) or 1
    languages = [
        {
            "name": k,
            "count": v,
            "percentage": round((v / total_coded_repos) * 100, 1)
        }
        for k, v in lang_counter.most_common(8)
    ]

    # Harvest Commit Emails
    commit_emails = await asyncio.to_thread(_harvest_commit_emails, login, repo_summary, events)

    # Activity Heatmap
    activity = _activity_buckets(events)

    total_stars = sum(r["stars"] for r in repo_summary)
    total_forks = sum(r["forks"] for r in repo_summary)
    followers = user.get("followers", 0)
    following = user.get("following", 0)
    ratio = round(followers / max(1, following), 2)

    # Account Age Computation
    created_str = user.get("created_at")
    account_age_years = 0
    if created_str:
        try:
            c_dt = datetime.fromisoformat(created_str.replace("Z", "+00:00"))
            account_age_years = round((datetime.now(c_dt.tzinfo) - c_dt).days / 365.25, 1)
        except Exception:
            pass

    # Influence and Forensic Risk Score
    influence_score = min(100, (followers // 2) + (total_stars // 4) + (len(repo_summary) // 2))

    # Public Keys Formatting
    formatted_ssh_keys = [
        {"id": k.get("id"), "key": k.get("key", "")[:35] + "...", "raw": k.get("key")}
        for k in ssh_keys if isinstance(k, dict)
    ]
    formatted_gpg_keys = [
        {
            "id": g.get("id"),
            "key_id": g.get("key_id"),
            "emails": [e.get("email") for e in g.get("emails", []) if e.get("email")],
            "can_sign": g.get("can_sign", False)
        }
        for g in gpg_keys if isinstance(g, dict)
    ]

    # Attack surface exposure threat rating
    exposure_threat = min(95, 10 + (len(commit_emails) * 15) + (len(ssh_keys) * 10) + (len(gpg_keys) * 10) + min(20, len(repos) // 2))

    # Build comprehensive profile object
    profile_data = dict(user)
    profile_data.update({
        "followers": followers,
        "following": following,
        "company": user.get("company") or "INDEPENDENT",
        "public_gists": user.get("public_gists", len(gists)),
        "public_repos": user.get("public_repos", len(repos)),
        "name": user.get("name") or login,
        "location": user.get("location") or "GLOBAL",
        "html_url": user.get("html_url") or f"https://github.com/{login}",
        "bio": user.get("bio") or "",
        "avatar_url": user.get("avatar_url") or ""
    })

    top_languages_map = {l["name"]: l["percentage"] for l in languages if "name" in l}

    return {
        "status": "success",
        "login": login,
        "id": user.get("id"),
        "node_id": user.get("node_id"),
        "name": user.get("name") or login,
        "avatar": user.get("avatar_url"),
        "bio": user.get("bio"),
        "company": user.get("company") or "INDEPENDENT",
        "location": user.get("location") or "GLOBAL",
        "blog": user.get("blog"),
        "twitter": user.get("twitter_username"),
        "email_public": user.get("email"),
        "hireable": user.get("hireable"),
        "account_type": user.get("type", "User"),
        "created_at": user.get("created_at"),
        "updated_at": user.get("updated_at"),
        "account_age_years": account_age_years,
        "public_repos": user.get("public_repos", len(repos)),
        "public_gists": user.get("public_gists", len(gists)),
        "followers": followers,
        "following": following,
        "follower_ratio": ratio,
        "html_url": user.get("html_url") or f"https://github.com/{login}",
        "influence_score": influence_score,
        "threat_score": exposure_threat,
        "threat_level": "CRITICAL" if exposure_threat >= 70 else ("ELEVATED" if exposure_threat >= 35 else "NOMINAL"),
        "total_stars": total_stars,
        "total_forks": total_forks,
        "top_repos": repo_summary[:15],
        "languages": languages,
        "top_languages": top_languages_map,
        "profile": profile_data,
        "orgs": [
            {
                "login": o.get("login"),
                "avatar_url": o.get("avatar_url"),
                "description": o.get("description", "")
            }
            for o in orgs[:20] if isinstance(o, dict)
        ],
        "commit_emails": commit_emails,
        "ssh_keys": formatted_ssh_keys,
        "gpg_keys": formatted_gpg_keys,
        "activity": activity,
        "dossier_summary": f"Target @{login} active for {account_age_years} yrs across {len(repos)} public repositories. {len(commit_emails)} unmasked commit author emails extracted."
    }
