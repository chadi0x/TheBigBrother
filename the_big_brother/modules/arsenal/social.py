"""
VX ARSENAL // SOCIAL & IDENTITY SURFACE ENGINES

  bluesky_intel, reddit_intel, discord_intel, telegram_intel, gravatar_intel
"""
from __future__ import annotations

import asyncio
import json
import re
import time
import urllib.parse
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from .common import (
    envelope,
    error_envelope,
    finding,
    http_json,
    http_request,
    md5,
    normalize_domain,
)

SCAM_KEYWORDS = (
    "airdrop", "giveaway", "free crypto", "double your", "guaranteed profit",
    "dm me", "investment plan", "signal group", "seed phrase",
    "connect wallet", "claim reward", "limited offer", "pump and dump",
    "presale", "whitelist spot", "mint now", "onlyfans", "only fans",
)


def _age_days(iso_ts: str) -> Optional[int]:
    if not iso_ts:
        return None
    try:
        dt = datetime.fromisoformat(str(iso_ts).replace("Z", "+00:00"))
        return int((datetime.now(timezone.utc) - dt).total_seconds() // 86400)
    except Exception:
        return None


def _scam_hits(text: str) -> List[str]:
    low = (text or "").lower()
    return [k for k in SCAM_KEYWORDS if k in low]


def _extract_tags(text: str) -> List[str]:
    return sorted(set(re.findall(r"#([A-Za-z0-9_]{2,40})", text or "")))


def _extract_links(text: str) -> List[str]:
    return sorted(set(re.findall(r"https?://[^\s<>\"')]+", text or "")))[:20]


# ===========================================================================
# 1. BLUESKY / AT PROTOCOL
# ===========================================================================

def _analyze_bluesky(target: str) -> Tuple[Dict[str, Any], List[Dict[str, Any]], int, str]:
    findings: List[Dict[str, Any]] = []
    handle = (target or "").strip().lstrip("@")
    if not handle:
        return {}, [finding("info", "No handle", "Enter a Bluesky handle or DID.")], 0, "Empty handle."

    actor = handle
    resolved = {}
    if not handle.startswith("did:"):
        r = http_json(
            f"https://public.api.bsky.app/xrpc/com.atproto.identity.resolveHandle?handle={urllib.parse.quote(handle)}",
            timeout=9,
        )
        resolved = r.get("json") or {}
        if resolved.get("did"):
            actor = resolved["did"]
        else:
            return {}, [finding("medium", "Handle did not resolve", f"Bluesky could not resolve @{handle}.")], 0, f"Unresolved handle @{handle}."

    prof_r = http_json(f"https://public.api.bsky.app/xrpc/app.bsky.actor.getProfile?actor={urllib.parse.quote(actor)}", timeout=10)
    profile = prof_r.get("json") or {}
    if not isinstance(profile, dict) or not profile.get("did"):
        return {}, [finding("medium", "Profile not available", "The actor profile endpoint returned no record.")], 0, "No Bluesky profile."

    feed_r = http_json(
        f"https://public.api.bsky.app/xrpc/app.bsky.feed.getAuthorFeed?actor={urllib.parse.quote(actor)}&limit=40&filter=posts_no_replies",
        timeout=12,
    )
    feed = (feed_r.get("json") or {}).get("feed", []) or []
    posts = []
    tags: Dict[str, int] = {}
    links: List[str] = []
    langs: Dict[str, int] = {}
    scam_text = []
    hours = [0] * 24
    total_likes = total_reposts = total_replies = 0
    for item in feed:
        post = (item or {}).get("post") or {}
        record = post.get("record") or {}
        text = record.get("text", "") or ""
        created = record.get("createdAt", "") or post.get("indexedAt", "")
        langs[str(record.get("langs", ["?"])[0] if record.get("langs") else "?")] = langs.get(str(record.get("langs", ["?"])[0] if record.get("langs") else "?"), 0) + 1
        for t in _extract_tags(text):
            tags[t] = tags.get(t, 0) + 1
        links.extend(_extract_links(text))
        scam_text.extend(_scam_hits(text))
        try:
            dt = datetime.fromisoformat(created.replace("Z", "+00:00"))
            hours[dt.hour] += 1
        except Exception:
            pass
        total_likes += int(post.get("likeCount") or 0)
        total_reposts += int(post.get("repostCount") or 0)
        total_replies += int(post.get("replyCount") or 0)
        posts.append({
            "uri": post.get("uri", ""),
            "text": text[:600],
            "created": created,
            "likes": post.get("likeCount", 0),
            "reposts": post.get("repostCount", 0),
            "replies": post.get("replyCount", 0),
            "langs": record.get("langs", []),
            "has_images": bool((post.get("embed") or {}).get("images")),
        })

    created = profile.get("createdAt", "")
    age = _age_days(created)
    followers = int(profile.get("followersCount") or 0)
    follows = int(profile.get("followsCount") or 0)
    post_count = int(profile.get("postsCount") or 0)
    ratio = round(followers / max(1, follows), 2)
    labels = [l.get("val") for l in (profile.get("labels") or []) if isinstance(l, dict)]
    description = profile.get("description", "") or ""
    if age is not None and age < 30:
        findings.append(finding("medium", "Recently created account", f"Only {age} day(s) old. New accounts are over-represented in spam and impersonation.", evidence=created))
    if post_count > 40 and followers < 15:
        findings.append(finding("medium", "High output, low audience", f"{post_count} posts but only {followers} followers — a common automated/spam profile shape.", evidence={"posts": post_count, "followers": followers}))
    if scam_text:
        findings.append(finding("high", "Scam / promotion language", "Posts contain phrases common to crypto scams or spam funnels.", evidence=sorted(set(scam_text))[:10], recommendation="Review manually before engagement; do not connect wallets or send funds."))
    if labels:
        findings.append(finding("medium", "Bluesky moderation labels", "The network applies labels to this account.", evidence=labels))
    if follows > 0 and followers / max(1, follows) < 0.1 and follows > 100:
        findings.append(finding("low", "Mass-follow pattern", f"Following {follows} while followed by {followers} suggests follow-farming.", evidence={"followers": followers, "follows": follows}))
    if links:
        findings.append(finding("info", "External links published", f"{len(set(links))} unique link(s) found in recent posts.", evidence=sorted(set(links))[:12]))

    risk = 0
    risk += 25 if scam_text else 0
    risk += 15 if age is not None and age < 30 else 0
    risk += 12 if post_count > 40 and followers < 15 else 0
    risk += 10 if labels else 0
    risk += 8 if follows > 500 and ratio < 0.1 else 0
    risk = min(100, risk)

    top_tags = sorted(tags.items(), key=lambda kv: -kv[1])[:15]
    summary = (
        f"@{profile.get('handle', handle)} ({profile.get('displayName') or 'no display name'}): "
        f"{followers:,} followers, {follows:,} following, {post_count:,} posts, "
        f"account age {age if age is not None else '?'}d; {len(posts)} recent posts analyzed; risk {risk}/100."
    )
    data = {
        "did": profile.get("did", actor),
        "handle": profile.get("handle", handle),
        "display_name": profile.get("displayName", ""),
        "description": description,
        "avatar": profile.get("avatar", ""),
        "banner": profile.get("banner", ""),
        "created_at": created,
        "account_age_days": age,
        "followers": followers,
        "follows": follows,
        "posts_count": post_count,
        "follow_ratio": ratio,
        "labels": labels,
        "indexed_at": profile.get("indexedAt", ""),
        "recent_posts": posts,
        "recent_post_count": len(posts),
        "engagement": {"likes": total_likes, "reposts": total_reposts, "replies": total_replies},
        "top_hashtags": [{"tag": t, "count": c} for t, c in top_tags],
        "languages": [{"lang": k, "count": v} for k, v in sorted(langs.items(), key=lambda kv: -kv[1])],
        "external_links": sorted(set(links))[:30],
        "posting_hours_utc": hours,
        "scam_signals": sorted(set(scam_text)),
        "resolved_did": resolved.get("did", ""),
    }
    return data, findings, risk, summary


async def run_bluesky_intel(target: str) -> Dict[str, Any]:
    started = time.perf_counter()
    data, findings, risk, summary = await asyncio.to_thread(_analyze_bluesky, target)
    if not data:
        return error_envelope("bluesky_intel", target, summary)
    return envelope(
        "bluesky_intel", "@" + str(data.get("handle", target)).lstrip("@"), risk=risk, summary=summary,
        findings=findings, data=data, iocs=[{"type": "social", "value": f"bluesky:@{data.get('handle')}"}],
        sources=["Bluesky public AT Protocol API"],
        elapsed_ms=int((time.perf_counter() - started) * 1000),
    )


# ===========================================================================
# 2. REDDIT
# ===========================================================================

def _reddit_get(path: str) -> Dict[str, Any]:
    for host in ("https://www.reddit.com", "https://old.reddit.com", "https://api.reddit.com"):
        r = http_json(
            host + path,
            timeout=10,
            headers={"User-Agent": "TheBigBrother-VX/1.0 (OSINT research)", "Accept": "application/json"},
        )
        j = r.get("json")
        if isinstance(j, dict):
            return {"ok": True, "data": j, "host": host}
        if r.get("status") == 404:
            return {"ok": False, "status": 404, "host": host}
        if r.get("status") == 403:
            continue
    return {"ok": False, "status": 0, "host": ""}


def _analyze_reddit(target: str) -> Tuple[Dict[str, Any], List[Dict[str, Any]], int, str]:
    findings: List[Dict[str, Any]] = []
    user = (target or "").strip().lstrip("@").replace("u/", "").strip("/")
    if not re.fullmatch(r"[A-Za-z0-9_-]{3,20}", user):
        return {}, [finding("info", "Invalid Reddit username", "Usernames are 3-20 characters: letters, digits, underscore, hyphen.")], 0, "Invalid username."

    about = _reddit_get(f"/user/{urllib.parse.quote(user)}/about.json")
    archive_mode = False
    if about.get("ok"):
        a = ((about.get("data") or {}).get("data") or {})
    else:
        # Reddit aggressively blocks datacenter IPs. The Arctic Shift archive is
        # a public read-only mirror of Reddit posts/comments and user stats.
        arch = http_json(
            f"https://arctic-shift.photon-reddit.com/api/users/search?author={urllib.parse.quote(user)}",
            timeout=14,
        ).get("json") or {}
        rows = arch.get("data") or [] if isinstance(arch, dict) else []
        if not rows:
            return {}, [finding("medium", "Reddit profile not reachable", "Reddit blocked the live request and no archive record was found. The account may not exist or may be suspended.")], 0, f"No Reddit profile for u/{user}."
        meta = (rows[0].get("_meta") or {})
        a = {
            "name": rows[0].get("author", user),
            "id": rows[0].get("id", ""),
            "created_utc": meta.get("earliest_post_at") or meta.get("earliest_comment_at") or 0,
            "link_karma": meta.get("post_karma", 0),
            "comment_karma": meta.get("comment_karma", 0),
            "total_karma": meta.get("total_karma", 0),
            "verified": False,
            "_archive_meta": meta,
        }
        archive_mode = True

    if archive_mode:
        pjson = http_json(
            f"https://arctic-shift.photon-reddit.com/api/posts/search?author={urllib.parse.quote(user)}&limit=50&sort=desc",
            timeout=16,
        ).get("json") or {}
        cjson = http_json(
            f"https://arctic-shift.photon-reddit.com/api/comments/search?author={urllib.parse.quote(user)}&limit=50&sort=desc",
            timeout=16,
        ).get("json") or {}
        posts = [{"kind": "t3", "data": d} for d in (pjson.get("data") or [])]
        comments = [{"kind": "t1", "data": d} for d in (cjson.get("data") or [])]
    else:
        sub_r = _reddit_get(f"/user/{urllib.parse.quote(user)}/submitted.json?limit=50&sort=new")
        com_r = _reddit_get(f"/user/{urllib.parse.quote(user)}/comments.json?limit=50&sort=new")
        posts = (((sub_r.get("data") or {}).get("data") or {}).get("children") or []) if sub_r.get("ok") else []
        comments = (((com_r.get("data") or {}).get("data") or {}).get("children") or []) if com_r.get("ok") else []

    subs: Dict[str, int] = {}
    domains: Dict[str, int] = {}
    hours = [0] * 24
    scam = []
    nsfw_posts = 0
    total_score = 0
    entries = []
    for child in (posts + comments)[:100]:
        d = child.get("data") or {}
        sub = d.get("subreddit", "") or ""
        if sub:
            subs[sub] = subs.get(sub, 0) + 1
        dom = d.get("domain", "") or ""
        if dom and dom != f"self.{sub}":
            domains[dom] = domains.get(dom, 0) + 1
        try:
            hours[datetime.fromtimestamp(float(d.get("created_utc") or 0), tz=timezone.utc).hour] += 1
        except Exception:
            pass
        if d.get("over_18"):
            nsfw_posts += 1
        scam.extend(_scam_hits((d.get("title", "") or "") + " " + (d.get("selftext", "") or "") + " " + (d.get("body", "") or "")))
        total_score += int(d.get("score") or 0)
        if len(entries) < 30:
            entries.append({
                "kind": child.get("kind"),
                "subreddit": sub,
                "title": d.get("title", ""),
                "text": (d.get("selftext") or d.get("body") or "")[:500],
                "score": d.get("score", 0),
                "comments": d.get("num_comments", 0),
                "created_utc": d.get("created_utc"),
                "permalink": "https://reddit.com" + (d.get("permalink", "") or ""),
                "over_18": d.get("over_18", False),
                "link": d.get("url_overridden_by_dest", d.get("url", "")),
            })

    created_utc = float(a.get("created_utc") or 0)
    age_days = int((time.time() - created_utc) // 86400) if created_utc else None
    karma = int(a.get("total_karma") or 0)
    link_karma = int(a.get("link_karma") or 0)
    comment_karma = int(a.get("comment_karma") or 0)
    activity = len(posts) + len(comments)
    top_subs = sorted(subs.items(), key=lambda kv: -kv[1])[:12]
    concentration = (top_subs[0][1] / activity) if top_subs and activity else 0

    if age_days is not None and age_days < 30:
        findings.append(finding("medium", "Recently created Reddit account", f"Account is {age_days} day(s) old.", evidence=a.get("created_utc")))
    if activity >= 20 and karma < 20:
        findings.append(finding("high", "High activity with near-zero karma", f"{activity} recent items but only {karma} karma — consistent with spam/bot behavior.", recommendation="Inspect content for link spam and coordinated inauthentic behavior."))
    if scam:
        findings.append(finding("high", "Scam / promotion language", "Recent content contains known scam or funnel phrases.", evidence=sorted(set(scam))[:10]))
    if concentration > 0.7 and activity >= 15:
        findings.append(finding("medium", "Extreme single-community concentration", f"{int(concentration*100)}% of recent activity is in r/{top_subs[0][0]}.", evidence=top_subs[:5]))
    if nsfw_posts:
        findings.append(finding("info", "NSFW content present", f"{nsfw_posts} of the recent items are marked over_18."))
    if a.get("is_mod"):
        findings.append(finding("info", "Moderator status", "The account moderates one or more subreddits."))
    if a.get("verified"):
        findings.append(finding("info", "Reddit verified email", "The account has a verified email on Reddit."))

    risk = 0
    risk += 25 if scam else 0
    risk += 20 if activity >= 20 and karma < 20 else 0
    risk += 12 if age_days is not None and age_days < 30 else 0
    risk += 8 if concentration > 0.7 and activity >= 15 else 0
    risk = min(100, risk)

    summary = (
        f"u/{a.get('name', user)}: {karma:,} karma ({link_karma:,} link / {comment_karma:,} comment), "
        f"account age {age_days if age_days is not None else '?'}d, {len(posts)} recent posts and "
        f"{len(comments)} comments; top community r/{top_subs[0][0] if top_subs else 'none'}; risk {risk}/100."
    )
    data = {
        "username": a.get("name", user),
        "id": a.get("id", ""),
        "created_utc": a.get("created_utc"),
        "account_age_days": age_days,
        "karma": {"total": karma, "link": link_karma, "comment": comment_karma},
        "verified_email": bool(a.get("verified")),
        "is_mod": bool(a.get("is_mod")),
        "is_gold": bool(a.get("is_gold")),
        "is_employee": bool(a.get("is_employee")),
        "profile_description": a.get("subreddit", {}).get("public_description", "") if isinstance(a.get("subreddit"), dict) else "",
        "icon_img": a.get("icon_img", ""),
        "recent_activity_count": activity,
        "recent_posts_count": len(posts),
        "recent_comments_count": len(comments),
        "top_subreddits": [{"subreddit": s, "count": c} for s, c in top_subs],
        "top_domains": [{"domain": d, "count": c} for d, c in sorted(domains.items(), key=lambda kv: -kv[1])[:15]],
        "posting_hours_utc": hours,
        "nsfw_items": nsfw_posts,
        "scam_signals": sorted(set(scam)),
        "recent_items": entries,
        "data_source": "Arctic Shift Reddit archive" if archive_mode else about.get("host", ""),
        "archive_mode": archive_mode,
    }
    if archive_mode:
        findings.append(finding("info", "Live Reddit API blocked — archive used", "Reddit returned 403 to this network; public post/comment metadata was read from the Arctic Shift archive instead."))
    return data, findings, risk, summary


async def run_reddit_intel(target: str) -> Dict[str, Any]:
    started = time.perf_counter()
    data, findings, risk, summary = await asyncio.to_thread(_analyze_reddit, target)
    if not data:
        return error_envelope("reddit_intel", target, summary)
    sources = ["Arctic Shift Reddit archive"] if data.get("archive_mode") else ["Reddit public JSON endpoints"]
    return envelope(
        "reddit_intel", "u/" + str(data.get("username", target)), risk=risk, summary=summary,
        findings=findings, data=data, iocs=[{"type": "social", "value": f"reddit:u/{data.get('username')}"}],
        sources=sources,
        elapsed_ms=int((time.perf_counter() - started) * 1000),
    )


# ===========================================================================
# 3. DISCORD INVITE
# ===========================================================================

def _snowflake_time(value: Any) -> Optional[str]:
    try:
        ms = (int(value) >> 22) + 1420070400000
        return datetime.fromtimestamp(ms / 1000, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    except Exception:
        return None


def _analyze_discord(target: str) -> Tuple[Dict[str, Any], List[Dict[str, Any]], int, str]:
    findings: List[Dict[str, Any]] = []
    raw = (target or "").strip()
    m = re.search(r"(?:discord(?:app)?\.(?:gg|com)/(?:invite/)?)([A-Za-z0-9-]{2,64})", raw)
    code = m.group(1) if m else raw.strip("/").split("/")[-1]
    if not re.fullmatch(r"[A-Za-z0-9-]{2,64}", code):
        return {}, [finding("info", "Invalid Discord invite", "Paste an invite URL or code, e.g. discord.gg/example.")], 0, "Invalid invite."
    r = http_json(
        f"https://discord.com/api/v10/invites/{urllib.parse.quote(code)}?with_counts=true&with_expiration=true&with_permissions=true",
        timeout=10,
        headers={"User-Agent": "TheBigBrother-VX/1.0"},
    )
    status = r.get("status", 0)
    j = r.get("json") or {}
    if status == 404:
        return {}, [finding("info", "Invite not found", "The invite is invalid, expired or revoked.")], 0, f"Invite {code} not found."
    if status == 429:
        return {}, [finding("low", "Discord rate limit", "Retry after the provided cooldown.")], 0, "Rate limited."
    if not isinstance(j, dict) or not j.get("code"):
        return {}, [finding("medium", "Discord API did not return an invite", f"HTTP {status}")], 0, "No invite data."

    guild = j.get("guild") or {}
    channel = j.get("channel") or {}
    inviter = j.get("inviter") or {}
    member_count = j.get("approximate_member_count") or 0
    presence = j.get("approximate_presence_count") or 0
    guild_id = guild.get("id", "")
    created = _snowflake_time(guild_id)
    features = guild.get("features", []) or []
    verification = j.get("verification_level", guild.get("verification_level", None))
    description = guild.get("description", "") or ""
    name = guild.get("name", "") or j.get("channel", {}).get("name", "")
    scam = _scam_hits(f"{name} {description}")
    if guild.get("nsfw") or j.get("nsfw"):
        findings.append(finding("medium", "NSFW server", "Discord flags this community as age-restricted."))
    if verification in (0, None):
        findings.append(finding("medium", "Low verification level", "The server has no/low membership verification, easing raid and spam accounts.", evidence=verification))
    if scam:
        findings.append(finding("high", "Scam / promotion language", "Server name or description contains known scam phrases.", evidence=scam))
    if member_count > 1000 and presence / max(1, member_count) < 0.03:
        findings.append(finding("low", "Large but inactive membership", f"{member_count:,} members but only {presence:,} online.", evidence={"members": member_count, "online": presence}))
    if created:
        age = _age_days(created.replace(" UTC", "").replace(" ", "T") + "Z") if created else None
        if age is not None and age < 14:
            findings.append(finding("medium", "Very new server", f"Created {age} day(s) ago.", evidence=created))
    if not j.get("expires_at"):
        findings.append(finding("info", "Permanent invite", "The invite does not expire, so it can circulate indefinitely."))

    risk = 0
    risk += 30 if scam else 0
    risk += 15 if guild.get("nsfw") or j.get("nsfw") else 0
    risk += 12 if verification in (0, None) else 0
    risk += 8 if member_count > 1000 and presence / max(1, member_count) < 0.03 else 0
    risk = min(100, risk)

    summary = (
        f"Invite {code} → {name or 'unknown server'} ({guild_id or 'group DM'}); "
        f"{member_count:,} members / {presence:,} online; verification {verification}; risk {risk}/100."
    )
    data = {
        "invite_code": j.get("code", code),
        "server": {
            "id": guild_id,
            "name": name,
            "description": description,
            "icon": guild.get("icon", ""),
            "banner": guild.get("banner", ""),
            "splash": guild.get("splash", ""),
            "features": features,
            "verification_level": verification,
            "premium_tier": guild.get("premium_tier"),
            "nsfw": bool(guild.get("nsfw") or j.get("nsfw")),
            "created_at": created,
            "vanity_url": guild.get("vanity_url_code", ""),
        },
        "channel": {"id": channel.get("id", ""), "name": channel.get("name", ""), "type": channel.get("type")},
        "inviter": {"id": inviter.get("id", ""), "username": inviter.get("username", ""), "discriminator": inviter.get("discriminator", ""), "avatar": inviter.get("avatar", "")},
        "approximate_member_count": member_count,
        "approximate_presence_count": presence,
        "online_ratio": round(presence / max(1, member_count), 3),
        "expires_at": j.get("expires_at"),
        "temporary": j.get("temporary", False),
        "scam_signals": scam,
    }
    return data, findings, risk, summary


async def run_discord_intel(target: str) -> Dict[str, Any]:
    started = time.perf_counter()
    data, findings, risk, summary = await asyncio.to_thread(_analyze_discord, target)
    if not data:
        return error_envelope("discord_intel", target, summary)
    return envelope(
        "discord_intel", data.get("invite_code", target), risk=risk, summary=summary, findings=findings,
        data=data, iocs=[{"type": "social", "value": f"discord:{data.get('invite_code')}"}],
        sources=["Discord public invite API v10"],
        elapsed_ms=int((time.perf_counter() - started) * 1000),
    )


# ===========================================================================
# 4. TELEGRAM
# ===========================================================================

def _tg_parse(html: str) -> Dict[str, Any]:
    def og(prop: str) -> str:
        m = re.search(r'<meta[^>]+property="og:' + re.escape(prop) + r'"[^>]+content="([^"]*)"', html, re.I)
        if not m:
            m = re.search(r'<meta[^>]+content="([^"]*)"[^>]+property="og:' + re.escape(prop) + r'"', html, re.I)
        return m.group(1) if m else ""

    extra = re.search(r'<div class="tgme_page_extra">(.*?)</div>', html, re.S)
    title = re.search(r'<div class="tgme_page_title"[^>]*>(.*?)</div>', html, re.S)
    desc = re.search(r'<div class="tgme_page_description[^"]*"[^>]*>(.*?)</div>', html, re.S)
    photo = re.search(r'<img class="tgme_page_photo_image"[^>]+src="([^"]+)"', html)
    verified = bool(re.search(r'tgme_page_title.*?verified|verified-icon|tgme_page_verified', html, re.I | re.S))
    return {
        "title": _strip_html(title.group(1)) if title else og("title"),
        "description": _strip_html(desc.group(1)) if desc else og("description"),
        "extra": _strip_html(extra.group(1)) if extra else "",
        "image": photo.group(1) if photo else og("image"),
        "verified": verified,
        "og_url": og("url"),
    }


def _strip_html(value: str) -> str:
    return re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", value or "")).strip()


def _analyze_telegram(target: str) -> Tuple[Dict[str, Any], List[Dict[str, Any]], int, str]:
    findings: List[Dict[str, Any]] = []
    raw = (target or "").strip()
    raw = re.sub(r"^https?://", "", raw, flags=re.I)
    raw = re.sub(r"^(t\.me|telegram\.me)/", "", raw, flags=re.I)
    raw = raw.split("?")[0].strip("/").lstrip("@")
    if raw.startswith("s/"):
        raw = raw[2:]
    if not re.fullmatch(r"[A-Za-z0-9_]{4,64}", raw):
        return {}, [finding("info", "Invalid Telegram username", "Telegram public names are 4-64 letters, digits or underscores.")], 0, "Invalid username."

    page = http_request(f"https://t.me/{urllib.parse.quote(raw)}", timeout=10, max_bytes=500000)
    html = page.get("text", "") or ""
    if page.get("status") == 404 or "tgme_page_wrap" not in html:
        return {}, [finding("info", "Telegram entity not found", f"t.me/{raw} did not return a public page.")], 0, f"No public Telegram entity for @{raw}."
    info = _tg_parse(html)
    extra = info.get("extra", "")
    subscribers = 0
    m = re.search(r"([\d\s,.]+)\s*(subscribers|members|subscriber|member)", extra, re.I)
    if m:
        try:
            subscribers = int(re.sub(r"[^\d]", "", m.group(1)) or 0)
        except Exception:
            subscribers = 0
    kind = "channel" if "subscriber" in extra.lower() else ("group" if "member" in extra.lower() else "profile")
    blob = f"{info.get('title','')} {info.get('description','')} {html[:60000]}"
    scam = _scam_hits(blob)

    posts = []
    latest = ""
    post_count = 0
    links: List[str] = []
    tags: Dict[str, int] = {}
    preview = http_request(f"https://t.me/s/{urllib.parse.quote(raw)}", timeout=10, max_bytes=900000)
    phtml = preview.get("text", "") or ""
    try:
        from bs4 import BeautifulSoup

        soup = BeautifulSoup(phtml, "html.parser")
        msgs = soup.select(".tgme_widget_message")
        post_count = len(msgs)
        for msg in msgs[-30:]:
            text_el = msg.select_one(".tgme_widget_message_text")
            date_el = msg.select_one(".tgme_widget_message_date time")
            views_el = msg.select_one(".tgme_widget_message_views")
            text = text_el.get_text(" ", strip=True) if text_el else ""
            date = date_el.get("datetime", "") if date_el else ""
            if not latest and date:
                latest = date
            links.extend(_extract_links(text))
            for t in _extract_tags(text):
                tags[t] = tags.get(t, 0) + 1
            posts.append({"text": text[:800], "date": date, "views": views_el.get_text(strip=True) if views_el else "", "links": _extract_links(text)})
    except Exception:
        texts = re.findall(r'<div class="tgme_widget_message_text[^"]*"[^>]*>(.*?)</div>', phtml, re.S)
        post_count = len(texts)
        for t in texts[-30:]:
            clean = _strip_html(t)
            links.extend(_extract_links(clean))
            posts.append({"text": clean[:800], "date": "", "views": "", "links": _extract_links(clean)})

    if info.get("verified"):
        findings.append(finding("info", "Verified Telegram entity", "Telegram displays a verified badge on this page."))
    if scam:
        findings.append(finding("high", "Scam / promotion language", "Public description or posts contain known scam/funnel phrases.", evidence=sorted(set(scam))[:10], recommendation="Do not send funds or credentials; report the channel if impersonating a brand."))
    if subscribers >= 10000:
        findings.append(finding("info", "Large public audience", f"Approximately {subscribers:,} subscribers/members amplifies reach.", evidence=subscribers))
    if kind == "channel":
        findings.append(finding("info", "Public broadcast channel", "Anyone can read the channel's public post history."))

    risk = 30 if scam else 0
    risk += 10 if subscribers > 100000 else 0
    risk = min(100, risk)
    summary = (
        f"@{raw} is a {kind} titled '{info.get('title') or raw}', {subscribers:,} {('subscribers' if kind == 'channel' else 'members') if subscribers else '(size hidden)'}; "
        f"{post_count} recent public post(s); risk {risk}/100."
    )
    data = {
        "username": raw,
        "url": f"https://t.me/{raw}",
        "kind": kind,
        "title": info.get("title", ""),
        "description": info.get("description", ""),
        "extra": extra,
        "subscribers": subscribers,
        "verified": info.get("verified", False),
        "image": info.get("image", ""),
        "recent_post_count": post_count,
        "latest_post_at": latest,
        "recent_posts": posts,
        "top_hashtags": [{"tag": k, "count": v} for k, v in sorted(tags.items(), key=lambda kv: -kv[1])[:12]],
        "external_links": sorted(set(links))[:25],
        "scam_signals": sorted(set(scam)),
    }
    return data, findings, risk, summary


async def run_telegram_intel(target: str) -> Dict[str, Any]:
    started = time.perf_counter()
    data, findings, risk, summary = await asyncio.to_thread(_analyze_telegram, target)
    if not data:
        return error_envelope("telegram_intel", target, summary)
    return envelope(
        "telegram_intel", "@" + str(data.get("username", target)), risk=risk, summary=summary,
        findings=findings, data=data, iocs=[{"type": "social", "value": f"telegram:@{data.get('username')}"}],
        sources=["t.me public preview", "t.me/s public channel feed"],
        elapsed_ms=int((time.perf_counter() - started) * 1000),
    )


# ===========================================================================
# 5. GRAVATAR
# ===========================================================================

def _analyze_gravatar(target: str) -> Tuple[Dict[str, Any], List[Dict[str, Any]], int, str]:
    findings: List[Dict[str, Any]] = []
    value = (target or "").strip().lower()
    if not value:
        return {}, [finding("info", "No input", "Enter an email address or Gravatar username.")], 0, "Empty input."
    if "@" in value:
        ident = md5(value)
        id_type = "email"
    else:
        ident = urllib.parse.quote(value)
        id_type = "username"

    r = http_json(f"https://www.gravatar.com/{ident}.json", timeout=10)
    j = r.get("json") or {}
    entry = (j.get("entry") or [{}])[0] if isinstance(j, dict) else {}
    if r.get("status") == 404 or not entry:
        return (
            {"identifier": value, "identifier_type": id_type, "profile_found": False, "avatar_url": f"https://www.gravatar.com/avatar/{ident}?d=404"},
            [finding("info", "No Gravatar profile", "The identifier has no public Gravatar profile (an avatar may still exist).")],
            0,
            f"No public Gravatar profile for {value}.",
        )

    accounts = entry.get("accounts", []) or []
    verified_accounts = [a for a in accounts if a.get("verified")]
    name = entry.get("name") or {}
    photos = entry.get("photos", []) or []
    emails = entry.get("emails", []) or []
    phones = entry.get("phoneNumbers", []) or []
    urls = entry.get("urls", []) or []
    location = entry.get("currentLocation", "") or ""
    about = entry.get("aboutMe", "") or ""

    if verified_accounts:
        findings.append(finding("info", "Verified linked accounts", f"{len(verified_accounts)} verified social account(s) are attached to this profile.", evidence=[f"{a.get('shortname')}: {a.get('username')}" for a in verified_accounts[:10]]))
    if location:
        findings.append(finding("medium", "Location published", f"Public Gravatar profile lists location '{location}'.", recommendation="Remove or generalize location data from public profiles."))
    if about:
        findings.append(finding("low", "Biography published", "A public biography is available and may contain personal or organizational details.", evidence=about[:280]))
    if phones:
        findings.append(finding("high", "Phone number published", f"{len(phones)} phone number(s) appear in the public profile.", recommendation="Remove phone numbers from Gravatar; they are harvested for SIM-swap and phishing."))
    if urls:
        findings.append(finding("info", "External URLs published", f"{len(urls)} website/profile URL(s).", evidence=urls[:10]))

    risk = 0
    risk += 15 if accounts else 0
    risk += 15 if location else 0
    risk += 20 if phones else 0
    risk += 10 if about else 0
    risk += 5 if emails else 0
    risk = min(100, risk)
    display = entry.get("displayName") or name.get("formatted") or entry.get("preferredUsername") or value
    summary = (
        f"Gravatar profile '{display}': {len(accounts)} linked account(s), "
        f"{len(verified_accounts)} verified, location {'present' if location else 'absent'}; risk {risk}/100."
    )
    data = {
        "identifier": value,
        "identifier_type": id_type,
        "profile_found": True,
        "hash": entry.get("hash", ""),
        "preferred_username": entry.get("preferredUsername", ""),
        "display_name": entry.get("displayName", ""),
        "name": name,
        "about": about,
        "location": location,
        "profile_url": entry.get("profileUrl", ""),
        "thumbnail": entry.get("thumbnailUrl", ""),
        "photos": photos,
        "accounts": [
            {"domain": a.get("domain"), "display": a.get("display"), "username": a.get("username"), "url": a.get("url"), "verified": a.get("verified"), "shortname": a.get("shortname")}
            for a in accounts
        ],
        "verified_accounts": len(verified_accounts),
        "emails": [{"value": e.get("value"), "primary": e.get("primary")} for e in emails],
        "phone_numbers": phones,
        "urls": urls,
        "rating": entry.get("rating", ""),
        "last_updated": entry.get("lastUpdated", ""),
        "avatar_404": f"https://www.gravatar.com/avatar/{ident}?d=404",
    }
    return data, findings, risk, summary


async def run_gravatar_intel(target: str) -> Dict[str, Any]:
    started = time.perf_counter()
    data, findings, risk, summary = await asyncio.to_thread(_analyze_gravatar, target)
    if not data:
        return error_envelope("gravatar_intel", target, summary)
    return envelope(
        "gravatar_intel", target, risk=risk, summary=summary, findings=findings, data=data,
        iocs=[{"type": "email_or_username", "value": target}],
        sources=["Gravatar public JSON profile API"],
        notes=["Gravatar profiles are public by design. Only public fields are summarized."],
        elapsed_ms=int((time.perf_counter() - started) * 1000),
    )
