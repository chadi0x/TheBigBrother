"""
HUDSON ROCK — Infostealer Intelligence Engine
Queries Hudson Rock's Cavalier OSINT API to discover compromised assets,
infostealer malware infections, leaked credentials, and affected systems.
Supports: username, email, domain, phone.
"""
import asyncio
import aiohttp
import re

BASE_URL = "https://cavalier.hudsonrock.com/api/json/v2/osint-tools"

async def hudson_rock_search(query: str, query_type: str = "auto") -> dict:
    query = query.strip()
    if not query:
        return {"error": "Query cannot be empty"}

    # Auto detect type if needed
    if query_type == "auto":
        if "@" in query and "." in query:
            query_type = "email"
        elif query.startswith("+") or (query.replace("-", "").replace(" ", "").isdigit() and len(query) >= 7):
            query_type = "phone"
        elif "." in query and not " " in query:
            query_type = "domain"
        else:
            query_type = "username"

    url = ""
    params = {}
    if query_type == "email":
        url = f"{BASE_URL}/search-by-email"
        params = {"email": query}
    elif query_type == "domain":
        url = f"{BASE_URL}/search-by-domain"
        params = {"domain": query}
    elif query_type == "phone":
        url = f"{BASE_URL}/search-by-username"
        params = {"username": query}
    else:  # username
        url = f"{BASE_URL}/search-by-username"
        params = {"username": query}

    headers = {
        "User-Agent": "TheBigBrother-OSINT/6.0 (https://thebigbrother.cloud)",
        "Accept": "application/json"
    }

    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(url, params=params, headers=headers, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    return {
                        "query": query,
                        "type": query_type,
                        "status": "success",
                        "raw": data,
                        "platform_url": "https://www.hudsonrock.com/"
                    }
                elif resp.status == 404:
                    return {
                        "query": query,
                        "type": query_type,
                        "status": "clean",
                        "message": "No infostealer compromise records found in Hudson Rock database.",
                        "platform_url": "https://www.hudsonrock.com/"
                    }
                else:
                    return {
                        "query": query,
                        "type": query_type,
                        "error": f"Hudson Rock API returned status {resp.status}",
                        "platform_url": "https://www.hudsonrock.com/"
                    }
    except Exception as e:
        return {
            "query": query,
            "type": query_type,
            "error": f"Connection failed: {str(e)}",
            "platform_url": "https://www.hudsonrock.com/"
        }
