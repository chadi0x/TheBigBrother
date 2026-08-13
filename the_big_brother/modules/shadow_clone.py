"""
SHADOW CLONE — Username Mutation & Impersonation Hunter V6
Generates realistic username mutations (leet-speak, keyboard shifts, country suffixes,
doubled characters, vowel swaps, prefix/suffix additions) and checks availability / exposure.
"""
import asyncio
import aiohttp
import re

MUTATION_PATTERNS = [
    # Typos & Leet
    lambda u: u.replace('o', '0').replace('e', '3').replace('a', '4').replace('i', '1').replace('l', '1'),
    lambda u: u.replace('o', '0'),
    lambda u: u.replace('i', '1').replace('l', '1'),
    lambda u: u.replace('e', '3'),
    lambda u: u.replace('a', '@'),

    # Character duplication
    lambda u: u + u[-1] if len(u) > 0 else u,
    lambda u: u[0] + u if len(u) > 0 else u,

    # Prefixes & Suffixes
    lambda u: f"real_{u}",
    lambda u: f"the_{u}",
    lambda u: f"official_{u}",
    lambda u: f"iam_{u}",
    lambda u: f"{u}_official",
    lambda u: f"{u}_real",
    lambda u: f"{u}_x",
    lambda u: f"{u}_vip",
    lambda u: f"{u}_dev",
    lambda u: f"{u}01",
    lambda u: f"{u}123",
    lambda u: f"{u}_",
    lambda u: f"_{u}_",

    # Separator changes
    lambda u: u.replace('_', '.'),
    lambda u: u.replace('.', '_'),
    lambda u: u.replace('_', '-'),
    lambda u: u.replace('-', '_'),
]

PLATFORMS_TO_CHECK = [
    {"name": "GitHub", "url": "https://github.com/{u}", "check_status": 200},
    {"name": "Twitter/X", "url": "https://x.com/{u}", "check_status": 200},
    {"name": "Instagram", "url": "https://www.instagram.com/{u}/", "check_status": 200},
    {"name": "Reddit", "url": "https://www.reddit.com/user/{u}", "check_status": 200},
    {"name": "DockerHub", "url": "https://hub.docker.com/u/{u}", "check_status": 200},
    {"name": "GitLab", "url": "https://gitlab.com/{u}", "check_status": 200},
    {"name": "Telegram", "url": "https://t.me/{u}", "check_status": 200},
    {"name": "Medium", "url": "https://medium.com/@{u}", "check_status": 200},
]

def generate_mutations(username: str) -> list[str]:
    u = username.strip().lower()
    mutations = set()
    mutations.add(u)

    for fn in MUTATION_PATTERNS:
        try:
            m = fn(u)
            if m != u and len(m) >= 3 and len(m) <= 30 and re.match(r'^[a-zA-Z0-9._\-@]+$', m):
                mutations.add(m)
        except Exception:
            pass

    return list(mutations)[:40]

async def check_single_target(session: aiohttp.ClientSession, platform: dict, mutation: str):
    url = platform["url"].format(u=mutation)
    try:
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=4), allow_redirects=True) as resp:
            if resp.status == platform["check_status"]:
                return {
                    "platform": platform["name"],
                    "username": mutation,
                    "url": url,
                    "found": True,
                    "status": resp.status
                }
    except Exception:
        pass
    return None

async def shadow_clone_search(username: str) -> dict:
    username = username.strip()
    if not username:
        return {"error": "Username cannot be empty"}

    mutations = generate_mutations(username)

    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}

    matches = []
    async with aiohttp.ClientSession(headers=headers) as session:
        tasks = []
        for m in mutations[:20]: # Cap to top 20 mutations for fast performance
            for p in PLATFORMS_TO_CHECK:
                tasks.append(check_single_target(session, p, m))

        results = await asyncio.gather(*tasks)
        for r in results:
            if r:
                matches.append(r)

    # Sort matches: exact first, then mutations
    exact_matches = [m for m in matches if m["username"].lower() == username.lower()]
    impersonators = [m for m in matches if m["username"].lower() != username.lower()]

    return {
        "target": username,
        "total_mutations_generated": len(mutations),
        "total_matches_found": len(matches),
        "exact_matches": exact_matches,
        "potential_impersonators": impersonators[:50],
        "mutations_list": mutations
    }
