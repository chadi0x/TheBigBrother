from duckduckgo_search import DDGS
from playwright.sync_api import sync_playwright
import time
import random

def fetch_images_google_playwright(query: str, limit: int = 3, headless: bool = True) -> list[str]:
    """Fallback: Fetch images using Playwright (Google Images)"""
    print(f"   [+] Attempting Google Images for {query}...")
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=headless)
            context = browser.new_context(
                user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
                viewport={"width": 1920, "height": 1080},
                locale="en-US"
            )
            page = context.new_page()
            
            # Google Images Search with SafeSearch OFF
            page.goto(f"https://www.google.com/search?tbm=isch&q={query}&safe=off", timeout=15000)
            
            # Human-like delay
            time.sleep(random.uniform(1.5, 3.0))

            # Accept cookies if needed
            try:
                page.click("button:has-text('Reject all')", timeout=2000)
            except: pass

            images = page.evaluate("""() => {
                const imgs = Array.from(document.querySelectorAll('img'));
                return imgs
                    .map(img => img.src || img.getAttribute('data-src'))
                    .filter(src => src && src.startsWith('http') && src.length > 50 && !src.includes('googleg') && !src.includes('.svg')) 
                    .slice(0, 5);
            }""")
            browser.close()
            return images[:limit]
    except Exception as e:
        print(f"   [-] Google Playwright error: {e}")
        return []

def fetch_images_bing_playwright(query: str, limit: int = 3, headless: bool = True) -> list[str]:
    """Fallback: Fetch images using Playwright (Bing Images)"""
    print(f"   [+] Attempting Bing Images for {query}...")
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=headless)
            context = browser.new_context(
                user_agent="Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.1 Safari/605.1.15",
                viewport={"width": 1920, "height": 1080}
            )
            page = context.new_page()
            
            # Bing Images with SafeSearch OFF
            page.goto(f"https://www.bing.com/images/search?q={query}&adlt=off", timeout=15000)
            time.sleep(random.uniform(1.0, 2.5))
            
            images = page.evaluate("""() => {
                const imgs = Array.from(document.querySelectorAll('.mimg'));
                return imgs
                    .map(img => img.src || img.getAttribute('data-src'))
                    .filter(src => src && src.startsWith('http'))
                    .slice(0, 5);
            }""")
            browser.close()
            return images[:limit]
    except Exception as e:
        print(f"   [-] Bing Playwright error: {e}")
        return []

def fetch_images(query: str, limit: int = 3) -> list[str]:
    """
    Robust Multi-Engine Image Fetcher.
    Strategy: DDGS (Fast) -> Bing (Medium) -> Google (Slow/Fallback).
    """
    print(f"[*] Starting Image Search for: {query}")
    
    # 1. Try DuckDuckGo (Fastest, API-like)
    try:
        print("   [+] Attempting DuckDuckGo...")
        time.sleep(random.uniform(0.5, 1.5)) # Slight delay to be nice
        with DDGS() as ddgs:
            # simple search often works better than 'images' for rate limits
            ddgs_images = list(ddgs.images(query, max_results=5))
            results = [r['image'] for r in ddgs_images if 'image' in r]
            if results:
                print(f"   [+] DDGS Success: Found {len(results)} images.")
                return results[:limit]
    except Exception as e:
        print(f"   [-] DDGS Failed ({str(e)}). Moving to next engine.")
    
    # 2. Try Bing (Playwright - generally lenient)
    results = fetch_images_bing_playwright(query, limit)
    if results:
         print(f"   [+] Bing Success: Found {len(results)} images.")
         return results
         
    # 3. Try Google (Playwright - Backup)
    results = fetch_images_google_playwright(query, limit)
    if results:
         print(f"   [+] Google Success: Found {len(results)} images.")
         return results

    print("   [!] All image fetch methods failed.")
    return []

if __name__ == "__main__":
    print(fetch_images("chadi0x"))
