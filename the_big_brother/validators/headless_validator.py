from dataclasses import dataclass
from typing import Optional

try:
    from playwright.sync_api import sync_playwright
except ImportError:
    sync_playwright = None

@dataclass
class LinkValidationResult:
    url: str
    is_profile: bool
    reason: Optional[str] = None
    title: Optional[str] = None
    final_url: Optional[str] = None
    visible_text: Optional[str] = None

class HeadlessValidator:
    def __init__(self, headless: bool = True):
        self.headless = headless
        self.playwright = None
        self.browser = None
        if sync_playwright is None:
            print("Warning: Playwright is not installed. Headless validation will fail.")

    def __enter__(self):
        if sync_playwright:
            self.playwright = sync_playwright().start()
            self.browser = self.playwright.chromium.launch(headless=self.headless)
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.browser:
            self.browser.close()
        if self.playwright:
            self.playwright.stop()

    def validate(self, url: str) -> LinkValidationResult:
        if not self.browser:
            if not sync_playwright:
                 return LinkValidationResult(url, False, reason="Playwright not installed")
            # If used without context manager, launch for single use (slower)
            with sync_playwright() as p:
                browser = p.chromium.launch(headless=self.headless)
                return self._validate_with_browser(browser, url)
        
        return self._validate_with_browser(self.browser, url)

    def _validate_with_browser(self, browser, url: str) -> LinkValidationResult:
        context = browser.new_context(
            user_agent="Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"
        )
        page = context.new_page()
        try:
            # Navigate
            response = page.goto(url, timeout=30000, wait_until="domcontentloaded")
            
            if not response:
                page.close()
                return LinkValidationResult(url, False, reason="No response")

            final_url = page.url
            title = page.title()
            
            # Status check
            if response.status >= 400:
                page.close()
                return LinkValidationResult(url, False, reason=f"HTTP {response.status}", title=title, final_url=final_url)

            # Heuristic 1: Title content
            error_keywords_title = ["page not found", "404", "not found", "doesn't exist", "does not exist", "user not found"]
            if any(k in title.lower() for k in error_keywords_title):
                page.close()
                return LinkValidationResult(url, False, reason="Title indicated 404", title=title, final_url=final_url)

            # Get text
            body_text = page.evaluate("document.body.innerText")
            validation_text = body_text[:1000] # First 1000 chars

            # Heuristic 2: Body content
            error_keywords_body = ["this page isn't available", "sorry, this content isn't available right now"]
            if any(k in body_text.lower() for k in error_keywords_body):
                 page.close()
                 return LinkValidationResult(url, False, reason="Body content indicated 404", title=title, final_url=final_url)
            
            page.close()
            return LinkValidationResult(url, True, title=title, final_url=final_url, visible_text=validation_text)

        except Exception as e:
            page.close()
            return LinkValidationResult(url, False, reason=f"Browsing error: {str(e)}")
