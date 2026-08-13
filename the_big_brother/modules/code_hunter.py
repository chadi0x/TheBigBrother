"""
CODE HUNTER — GitHub OSINT via public API (no auth required, rate-limited to 60/hr/IP).
Pulls user profile, repos, top languages, public commit emails, organizations.
"""
from __future__ import annotations

import asyncio
from collections import Counter
from datetime import datetime
from typing import Optional

import requests

API = "https://api.github.com"
HEADERS = {"Accept": "application/vnd.github+json", "User-Agent": "TheBigBrother-V5"}


def _get(path: str, params: Optional[dict] = None):
    try:
        r = requests.get(f"{API}{path}", headers=HEADERS, params=params or {}, timeout=8)
        if r.status_code == 403:
            return None, "Rate-limited (60/hr unauthenticated). Add a GITHUB_TOKEN env var to lift the cap."
        if r.status_code == 404:
            return None, "Not found"
        if r.status_code != 200:
            return None, f"HTTP {r.status_code}"
        return r.json(), None
    except Exception as e:
        return None, str(e)


def _commit_emails(login: str, repos: list) -> list:
    emails = Counter()
    for repo in repos[:5]:  # Sample top 5 most-recent
        data, _ = _get(f"/repos/{login}/{repo['name']}/commits", {"author": login, "per_page": 30})
        if not data:
            continue
        for c in data:
            author = (c.get("commit") or {}).get("author") or {}
            mail = author.get("email")
            if mail and "noreply" not in mail and "users.noreply.github.com" not in mail:
                emails[mail] += 1
    return [{"email": e, "count": c} for e, c in emails.most_common(10)]


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
    }


async def code_hunter(login: str) -> dict:
    login = login.strip().lstrip("@")
    if not login:
        return {"error": "username required"}

    user, err = await asyncio.to_thread(_get, f"/users/{login}")
    if err:
        return {"error": err}

    repos_task = asyncio.to_thread(_get, f"/users/{login}/repos", {"sort": "updated", "per_page": 100})
    orgs_task = asyncio.to_thread(_get, f"/users/{login}/orgs")
    events_task = asyncio.to_thread(_get, f"/users/{login}/events/public", {"per_page": 100})
    gists_task = asyncio.to_thread(_get, f"/users/{login}/gists", {"per_page": 30})

    (repos, _), (orgs, _), (events, _), (gists, _) = await asyncio.gather(
        repos_task, orgs_task, events_task, gists_task
    )

    repos = repos or []
    orgs = orgs or []
    events = events or []
    gists = gists or []

    repo_summary = sorted(
        [
            {
                "name": r["name"],
                "stars": r.get("stargazers_count", 0),
                "forks": r.get("forks_count", 0),
                "language": r.get("language"),
                "updated": r.get("updated_at"),
                "description": (r.get("description") or "")[:140],
                "url": r.get("html_url"),
                "fork": r.get("fork", False),
            }
            for r in repos
        ],
        key=lambda x: x["stars"],
        reverse=True,
    )

    lang_count = Counter(r["language"] for r in repo_summary if r["language"])
    languages = [{"name": k, "count": v} for k, v in lang_count.most_common(10)]

    emails = await asyncio.to_thread(_commit_emails, login, repo_summary[:5])
    activity = _activity_buckets(events)

    total_stars = sum(r["stars"] for r in repo_summary)
    score = min(100, user.get("followers", 0) // 2 + total_stars // 5 + len(repo_summary) // 2)

    return {
        "login": login,
        "name": user.get("name"),
        "avatar": user.get("avatar_url"),
        "bio": user.get("bio"),
        "company": user.get("company"),
        "location": user.get("location"),
        "blog": user.get("blog"),
        "twitter": user.get("twitter_username"),
        "email_public": user.get("email"),
        "created_at": user.get("created_at"),
        "updated_at": user.get("updated_at"),
        "public_repos": user.get("public_repos"),
        "public_gists": user.get("public_gists"),
        "followers": user.get("followers"),
        "following": user.get("following"),
        "html_url": user.get("html_url"),
        "influence_score": score,
        "total_stars": total_stars,
        "top_repos": repo_summary[:12],
        "languages": languages,
        "orgs": [{"login": o["login"], "url": o.get("url")} for o in orgs[:20]],
        "commit_emails": emails,
        "gist_count": len(gists),
        "activity": activity,
    }
