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
    return fetch_images_with_diag(query, limit)[0]


def fetch_images_with_diag(query: str, limit: int = 3):
    """
    Same as fetch_images but also returns a diagnostic string describing
    which engines were tried and how each failed. Returns (results, diag).
    """
    diag_parts: list[str] = []

    # 1. DuckDuckGo (no browser needed)
    try:
        print("   [+] Attempting DuckDuckGo...")
        time.sleep(random.uniform(0.5, 1.5))
        with DDGS() as ddgs:
            ddgs_images = list(ddgs.images(query, max_results=max(limit, 8)))
            results = [r['image'] for r in ddgs_images if 'image' in r]
            if results:
                print(f"   [+] DDGS Success: Found {len(results)} images.")
                return results[:limit], "DDGS:ok"
            diag_parts.append("DDGS:empty")
    except Exception as e:
        msg = str(e).splitlines()[0][:160]
        print(f"   [-] DDGS Failed ({msg}). Moving to next engine.")
        diag_parts.append(f"DDGS:err({_short_err(msg)})")

    # 2. Bing (Playwright)
    try:
        results = fetch_images_bing_playwright(query, limit)
        if results:
            print(f"   [+] Bing Success: Found {len(results)} images.")
            return results, "Bing:ok"
        diag_parts.append("Bing:empty")
    except Exception as e:
        diag_parts.append(f"Bing:err({_short_err(str(e))})")

    # 3. Google (Playwright)
    try:
        results = fetch_images_google_playwright(query, limit)
        if results:
            print(f"   [+] Google Success: Found {len(results)} images.")
            return results, "Google:ok"
        diag_parts.append("Google:empty")
    except Exception as e:
        diag_parts.append(f"Google:err({_short_err(str(e))})")

    print("   [!] All image fetch methods failed.")
    return [], " · ".join(diag_parts)


def _short_err(msg: str) -> str:
    """Map common low-level error strings to human-readable tags."""
    s = (msg or "").lower()
    if "executable doesn't exist" in s or "chromium" in s and "install" in s:
        return "playwright-chromium-missing (run: playwright install chromium)"
    if "ratelimit" in s or "rate-limit" in s or "202 ratelimit" in s or "too many" in s:
        return "rate-limited"
    if "timeout" in s:
        return "timeout"
    if "executable" in s and "doesn't exist" in s:
        return "browser-missing"
    return (msg[:80] + "...") if len(msg) > 80 else msg

if __name__ == "__main__":
    print(fetch_images("chadi0x"))
