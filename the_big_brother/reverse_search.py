from playwright.async_api import async_playwright
import urllib.parse
import asyncio
import random

class ReverseImageSearcher:
    def __init__(self, headless=True):
        self.headless = headless

    async def _search_google(self, context, encoded_url):
        results = []
        try:
            print("   [+] Scanning Google Images... (Async)")
            page = await context.new_page()
            # Using Google Images instead of Lens, with SafeSearch OFF
            url = f"https://www.google.com/searchbyimage?image_url={encoded_url}&safe=off"
            await page.goto(url, timeout=30000)
            
            # CONSENT HANDLING
            try:
                # Try generic "Reject all" or "Accept all" buttons which cover most EU/US cases
                if await page.get_by_role("button", name="Reject all").is_visible():
                    await page.get_by_role("button", name="Reject all").click()
                elif await page.get_by_role("button", name="Accept all").is_visible():
                     await page.get_by_role("button", name="Accept all").click()
            except: pass

            await asyncio.sleep(random.uniform(2.5, 4.0))

            results = await page.evaluate("""() => {
                const imgs = Array.from(document.querySelectorAll('img'));
                return imgs
                    .map(img => img.src || img.getAttribute('data-src'))
                    .filter(src => src && src.startsWith('http') && src.length > 80 && !src.includes('gstatic') && !src.includes('google')) 
                    .slice(0, 5);
            }""")
            print(f"   [+] Google: Found {len(results)} matches.")
            await page.close()
        except Exception as e:
            print(f"   [-] Google Error: {e}")
        return results

    async def _search_bing(self, context, encoded_url):
        results = []
        try:
            print("   [+] Scanning Bing Visual... (Async)")
            page = await context.new_page()
            url = f"https://www.bing.com/images/search?view=detailv2&iss=sbi&form=SBIHMP&q=imgurl:{encoded_url}&adlt=off"
            await page.goto(url, timeout=30000)
            
             # Cookie banner check
            try:
                if await page.locator('#bnp_btn_reject').is_visible():
                    await page.click('#bnp_btn_reject')
            except: pass
            
            await asyncio.sleep(random.uniform(2.0, 3.5))

            results = await page.evaluate("""() => {
                const imgs = Array.from(document.querySelectorAll('img'));
                return imgs
                    .map(img => img.src || img.getAttribute('data-src'))
                    .filter(src => src && src.startsWith('http') && src.length > 50 && !src.includes('bing.com'))
                    .slice(0, 5);
            }""")
            print(f"   [+] Bing: Found {len(results)} matches.")
            await page.close()
        except Exception as e:
            print(f"   [-] Bing Error: {e}")
        return results

    async def _search_yandex(self, context, encoded_url):
        results = []
        try:
            print("   [+] Scanning Yandex Visual... (Async)")
            page = await context.new_page()
            url = f"https://yandex.com/images/search?rpt=imageview&url={encoded_url}"
            # Yandex needs retry logic often
            try:
                await page.goto(url, timeout=40000)
            except:
                await page.reload()
            
            await asyncio.sleep(random.uniform(3.0, 5.0))

            results = await page.evaluate("""() => {
                const imgs = Array.from(document.querySelectorAll('.serp-item__thumb, img.serp-item__img, .CbirSites-ItemThumb'));
                return imgs
                        .map(img => img.src || img.getAttribute('data-src'))
                        .filter(src => src && src.startsWith('http') && src.length > 50)
                        .slice(0, 5);
            }""")
            print(f"   [+] Yandex: Found {len(results)} matches.")
            await page.close()
        except Exception as e:
            print(f"   [-] Yandex Error: {e}")
        return results

    async def _search_tineye(self, context, encoded_url):
        results = []
        try:
            print("   [+] Scanning TinEye... (Async)")
            page = await context.new_page()
            url = f"https://tineye.com/search?url={encoded_url}"
            await page.goto(url, timeout=30000)
            
            await asyncio.sleep(random.uniform(2.0, 4.0))

            results = await page.evaluate("""() => {
                 // TinEye results are usually in .match div with .match-thumb img
                const imgs = Array.from(document.querySelectorAll('.match-thumb img, .result-match img'));
                return imgs
                    .map(img => img.src)
                    .filter(src => src && src.startsWith('http'))
                    .slice(0, 5);
            }""")
            print(f"   [+] TinEye: Found {len(results)} matches.")
            await page.close()
        except Exception as e:
            print(f"   [-] TinEye Error: {e}")
        return results

    async def search(self, image_url: str) -> dict:
        results = {"google": [], "bing": [], "yandex": [], "tineye": []}
        encoded_url = urllib.parse.quote(image_url)
        print(f"[*] Starting Async Quad-Vector Search for: {image_url}")

        async with async_playwright() as p:
            browser = await p.chromium.launch(
                headless=self.headless,
                args=['--disable-blink-features=AutomationControlled']
            )
            
            ctx_g = await browser.new_context(viewport={"width":1920,"height":1080}, user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
            ctx_b = await browser.new_context(viewport={"width":1920,"height":1080}, user_agent="Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15")
            ctx_y = await browser.new_context(viewport={"width":1920,"height":1080}, user_agent="Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
            ctx_t = await browser.new_context(viewport={"width":1920,"height":1080}, user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")

            # Run in parallel
            g_res, b_res, y_res, t_res = await asyncio.gather(
                self._search_google(ctx_g, encoded_url),
                self._search_bing(ctx_b, encoded_url),
                self._search_yandex(ctx_y, encoded_url),
                self._search_tineye(ctx_t, encoded_url)
            )
            
            results["google"] = g_res
            results["bing"] = b_res
            results["yandex"] = y_res
            results["tineye"] = t_res
            
            await browser.close()
            
        print("[*] Deep Search Complete.")
        return results
