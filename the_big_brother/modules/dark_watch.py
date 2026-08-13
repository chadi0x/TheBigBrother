import requests
from bs4 import BeautifulSoup
import asyncio

async def search_ransomware_leaks(query: str):
    """
    Searches known ransomware leak sites via Ransomwatch feed.
    """
    url = "https://raw.githubusercontent.com/joshhighet/ransomwatch/main/posts.json"
    try:
        resp = await asyncio.to_thread(requests.get, url, timeout=10)
        data = resp.json()
        
        matches = []
        query_lower = query.lower()
        
        for post in data:
            # post fields: group_name, post_title, discovered, etc.
            title = post.get("post_title", "").lower()
            group = post.get("group_name", "").lower()
            
            if query_lower in title or query_lower in group:
                matches.append({
                    "title": f"[{post.get('group_name')}] {post.get('post_title')}",
                    "link": "#", # Usually no direct link in this JSON without digging, but group name is key
                    "snippet": f"Ransomware Leak Discovered: {post.get('discovered')}",
                    "date": post.get("discovered")
                })
        return matches
    except Exception as e:
        print(f"Ransomwatch error: {e}")
        return []

async def search_dark_web(query: str):
    """
    Searches Ahmia.fi for onion links AND checks ransomware leaks.
    """
    results = []
    
    # 1. Ransomware Search
    ransom_results = await search_ransomware_leaks(query)
    results.extend(ransom_results)
    
    # 2. Onion Search (Ahmia)
    url = f"https://ahmia.fi/search/?q={query}"
    
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; rv:91.0) Gecko/20100101 Firefox/91.0"
    }
    
    try:
        resp = await asyncio.to_thread(requests.get, url, headers=headers, timeout=10)
        
        if resp.status_code == 200:
            soup = BeautifulSoup(resp.text, 'html.parser')
            
            for li in soup.find_all('li', class_='result'):
                try:
                    link = li.find('a')['href']
                    title = li.find('a').text.strip()
                    snippet = li.find('p').text.strip() if li.find('p') else "No description"
                    
                    date = li.find('span', class_='modified')
                    date_str = date.text.strip() if date else "Unknown Date"
                    
                    results.append({
                        "title": title,
                        "link": link,
                        "snippet": snippet,
                        "date": date_str
                    })
                except:
                    continue
                    
        return {"results": results, "count": len(results)}
        
    except Exception as e:
        # Return what we have if Ahmia fails
        if results:
             return {"results": results, "count": len(results)}
        return {"error": str(e)}

async def check_tor_status(onion_url: str):
    """
    Checks if an onion link is live using a tor2web proxy if local Tor isn't available,
    or just returns a specific message.
    Real Tor checking requires a SOCKS proxy (like 127.0.0.1:9050).
    We will assume Tor might not be configured in this Docker container yet, 
    so we check via a public gateway like onion.ly for basic status.
    """
    # Convert .onion to .onion.ly for public check
    gateway_url = onion_url.replace(".onion", ".onion.ly")
    if not gateway_url.startswith("http"):
        gateway_url = "http://" + gateway_url
        
    try:
        resp = await asyncio.to_thread(requests.head, gateway_url, timeout=5)
        return {"status": "Online" if resp.status_code == 200 else "Offline", "code": resp.status_code}
    except:
        return {"status": "Unreachable", "code": 0}
