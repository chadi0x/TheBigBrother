"""
SIGINT SWEEP — Social Intelligence gathering.
Fetches Reddit posts, Google News RSS, and Hacker News mentions
for a given keyword/target. Returns a ranked feed with sentiment hints.
"""

import asyncio
import aiohttp
import xml.etree.ElementTree as ET
from datetime import datetime
import re


POSITIVE_WORDS = {"great", "good", "love", "awesome", "best", "win", "launch", "growth", "success", "excellent", "top", "hire", "partner"}
NEGATIVE_WORDS = {"hack", "breach", "leak", "fail", "bad", "worst", "scam", "fraud", "attack", "lawsuit", "fine", "exposed", "stolen", "malware", "ransomware", "phish"}


def detect_sentiment(text: str) -> str:
    text_lower = text.lower()
    neg = sum(1 for w in NEGATIVE_WORDS if w in text_lower)
    pos = sum(1 for w in POSITIVE_WORDS if w in text_lower)
    if neg > pos:
        return "NEGATIVE"
    if pos > neg:
        return "POSITIVE"
    return "NEUTRAL"


def clean_html(raw: str) -> str:
    clean = re.sub(r'<[^>]+>', '', raw)
    clean = re.sub(r'&amp;', '&', clean)
    clean = re.sub(r'&lt;', '<', clean)
    clean = re.sub(r'&gt;', '>', clean)
    clean = re.sub(r'&quot;', '"', clean)
    clean = re.sub(r'\s+', ' ', clean).strip()
    return clean[:300]


async def fetch_reddit(session: aiohttp.ClientSession, query: str) -> list:
    """Fetch from Reddit's JSON API (no auth needed for public search)."""
    results = []
    headers = {"User-Agent": "TheBigBrotherV4:OSINT:1.0"}
    url = f"https://www.reddit.com/search.json?q={query}&sort=new&limit=15&type=link"
    try:
        async with session.get(url, headers=headers, timeout=aiohttp.ClientTimeout(total=10), ssl=False) as resp:
            if resp.status == 200:
                data = await resp.json()
                posts = data.get("data", {}).get("children", [])
                for post in posts:
                    p = post.get("data", {})
                    title = p.get("title", "")
                    text = p.get("selftext", "")[:200]
                    results.append({
                        "source": "Reddit",
                        "subreddit": f"r/{p.get('subreddit', '')}",
                        "title": title,
                        "snippet": text or title,
                        "url": f"https://reddit.com{p.get('permalink', '')}",
                        "score": p.get("score", 0),
                        "comments": p.get("num_comments", 0),
                        "date": datetime.utcfromtimestamp(p.get("created_utc", 0)).strftime("%Y-%m-%d"),
                        "sentiment": detect_sentiment(title + " " + text),
                    })
    except Exception as e:
        print(f"Reddit fetch error: {e}")
    return results


async def fetch_google_news(session: aiohttp.ClientSession, query: str) -> list:
    """Fetch from Google News RSS feed (no auth needed, public)."""
    results = []
    url = f"https://news.google.com/rss/search?q={query}&hl=en-US&gl=US&ceid=US:en"
    try:
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=10), ssl=False) as resp:
            if resp.status == 200:
                text = await resp.text()
                root = ET.fromstring(text)
                channel = root.find("channel")
                if channel is not None:
                    for item in channel.findall("item")[:15]:
                        title = item.findtext("title", "")
                        link = item.findtext("link", "")
                        pub_date = item.findtext("pubDate", "")
                        source_el = item.find("source")
                        source_name = source_el.text if source_el is not None else "News"
                        description = clean_html(item.findtext("description", ""))
                        results.append({
                            "source": "News",
                            "outlet": source_name,
                            "title": title,
                            "snippet": description,
                            "url": link,
                            "date": pub_date[:16] if pub_date else "",
                            "sentiment": detect_sentiment(title + " " + description),
                        })
    except Exception as e:
        print(f"Google News fetch error: {e}")
    return results


async def fetch_hackernews(session: aiohttp.ClientSession, query: str) -> list:
    """Search Hacker News via Algolia API (public, no auth)."""
    results = []
    url = f"https://hn.algolia.com/api/v1/search?query={query}&tags=story&hitsPerPage=10"
    try:
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=8), ssl=False) as resp:
            if resp.status == 200:
                data = await resp.json()
                for hit in data.get("hits", []):
                    title = hit.get("title", "")
                    ts = hit.get("created_at", "")[:10]
                    results.append({
                        "source": "HackerNews",
                        "subreddit": "HN",
                        "title": title,
                        "snippet": hit.get("story_text", "")[:200] or title,
                        "url": hit.get("url") or f"https://news.ycombinator.com/item?id={hit.get('objectID')}",
                        "score": hit.get("points", 0),
                        "comments": hit.get("num_comments", 0),
                        "date": ts,
                        "sentiment": detect_sentiment(title),
                    })
    except Exception as e:
        print(f"HackerNews fetch error: {e}")
    return results


async def fetch_twitter_nitter(session: aiohttp.ClientSession, query: str) -> list:
    """Fetch recent tweets via public Nitter RSS instances."""
    results = []
    nitter_instances = [
        "https://nitter.poast.org",
        "https://nitter.privacydev.net",
        "https://nitter.1d4.us",
    ]
    for instance in nitter_instances:
        url = f"{instance}/search/rss?q={query}&f=tweets"
        try:
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=6), ssl=False) as resp:
                if resp.status == 200:
                    text = await resp.text()
                    root = ET.fromstring(text)
                    channel = root.find("channel")
                    if channel is not None:
                        for item in channel.findall("item")[:10]:
                            title = item.findtext("title", "")
                            link = item.findtext("link", "")
                            pub_date = item.findtext("pubDate", "")
                            creator = item.findtext("{http://purl.org/dc/elements/1.1/}creator", "")
                            results.append({
                                "source": "Twitter/X",
                                "subreddit": creator,
                                "title": title,
                                "snippet": clean_html(title)[:200],
                                "url": link.replace(instance, "https://twitter.com"),
                                "score": 0,
                                "comments": 0,
                                "date": pub_date[:16] if pub_date else "",
                                "sentiment": detect_sentiment(title),
                            })
                    if results:
                        break  # Got results from this instance
        except Exception:
            continue
    return results


async def sigint_sweep(query: str):
    """
    Main SIGINT SWEEP entry point.
    Returns merged feed from Reddit, Google News, HackerNews, and Twitter/X.
    """
    connector = aiohttp.TCPConnector(ssl=False, limit=20)
    async with aiohttp.ClientSession(connector=connector) as session:
        reddit_results, news_results, hn_results, twitter_results = await asyncio.gather(
            fetch_reddit(session, query),
            fetch_google_news(session, query),
            fetch_hackernews(session, query),
            fetch_twitter_nitter(session, query),
        )

    all_results = reddit_results + news_results + hn_results + twitter_results

    # Sentiment summary
    sentiments = {"POSITIVE": 0, "NEGATIVE": 0, "NEUTRAL": 0}
    for item in all_results:
        sentiments[item.get("sentiment", "NEUTRAL")] += 1

    return {
        "query": query,
        "total": len(all_results),
        "sources": {
            "reddit": len(reddit_results),
            "news": len(news_results),
            "hackernews": len(hn_results),
            "twitter": len(twitter_results),
        },
        "sentiment_summary": sentiments,
        "feed": all_results,
    }
