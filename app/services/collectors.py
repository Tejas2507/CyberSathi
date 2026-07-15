from abc import ABC, abstractmethod
import time
import httpx
import asyncio
import uuid
from pathlib import Path
from datetime import datetime, timezone
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
from playwright.async_api import async_playwright
from app.schemas.evidence import CollectorResult

# Shared cache for webpage retrieval results to prevent duplicate HTTP requests
WEBSITE_HTML_CACHE = {}
WEBSITE_HTML_EVENTS = {}

class BaseCollector(ABC):
    """
    Base class interface for all evidence collectors in the pipeline.
    """
    @property
    @abstractmethod
    def name(self) -> str:
        """
        Return the unique string identifier for this collector.
        """
        pass

    @abstractmethod
    async def collect(self, url: str) -> CollectorResult:
        """
        Asynchronously collect evidence for the given target URL.
        Returns a standardized CollectorResult.
        """
        pass

class WebsiteCollector(BaseCollector):
    def __init__(self, timeout_sec: float = 10.0) -> None:
        self.timeout_sec = timeout_sec

    @property
    def name(self) -> str:
        return "website"

    async def collect(self, url: str) -> CollectorResult:
        if url not in WEBSITE_HTML_EVENTS:
            WEBSITE_HTML_EVENTS[url] = asyncio.Event()
            
        errors = []
        start_time = time.perf_counter()
        
        try:
            # Configure the client to follow redirects and set timeout
            async with httpx.AsyncClient(follow_redirects=True, timeout=self.timeout_sec) as client:
                response = await client.get(url)
                response.raise_for_status()
                
            elapsed_time_ms = (time.perf_counter() - start_time) * 1000
            
            # Retrieve redirect chain urls
            redirect_chain = [str(r.url) for r in response.history]
            
            headers_dict = dict(response.headers)
            server = headers_dict.get("server") or headers_dict.get("Server")
            content_type = headers_dict.get("content-type") or headers_dict.get("Content-Type")
            
            data = {
                "original_url": url,
                "final_url": str(response.url),
                "status_code": response.status_code,
                "response_headers": headers_dict,
                "cookies": dict(response.cookies),
                "redirect_chain": redirect_chain,
                "response_html": response.text,
                "response_size": len(response.content),
                "response_encoding": response.encoding or "utf-8",
                "server": server,
                "content_type": content_type,
                "elapsed_time": elapsed_time_ms
            }
            
            # Populate shared cache for downstream HTML/Metadata collectors
            WEBSITE_HTML_CACHE[url] = data
            WEBSITE_HTML_EVENTS[url].set()
            
            return CollectorResult(
                collector_name=self.name,
                success=True,
                execution_time_ms=elapsed_time_ms,
                data=data,
                errors=[],
                timestamp=datetime.now(timezone.utc)
            )
            
        except httpx.TimeoutException as e:
            elapsed_time_ms = (time.perf_counter() - start_time) * 1000
            errors.append(f"TimeoutError: Request timed out after {self.timeout_sec}s: {str(e)}")
        except httpx.ConnectError as e:
            elapsed_time_ms = (time.perf_counter() - start_time) * 1000
            err_msg = str(e)
            if "ssl" in err_msg.lower() or "cert" in err_msg.lower():
                errors.append(f"SSLError: SSL verification failed: {err_msg}")
            else:
                errors.append(f"DNSOrConnectionError: Failed to connect (DNS failure or connection refused): {err_msg}")
        except httpx.TooManyRedirects as e:
            elapsed_time_ms = (time.perf_counter() - start_time) * 1000
            errors.append(f"RedirectLoopError: Too many redirects: {str(e)}")
        except httpx.HTTPStatusError as e:
            elapsed_time_ms = (time.perf_counter() - start_time) * 1000
            errors.append(f"HTTPStatusError: Non-successful HTTP response: {str(e)}")
        except httpx.RequestError as e:
            elapsed_time_ms = (time.perf_counter() - start_time) * 1000
            errors.append(f"RequestError: HTTP request failure: {str(e)}")
        except Exception as e:
            elapsed_time_ms = (time.perf_counter() - start_time) * 1000
            errors.append(f"UnexpectedError: {type(e).__name__}: {str(e)}")
            
        # Ensure event settles even on failure so dependent collectors don't block forever
        if url in WEBSITE_HTML_EVENTS:
            WEBSITE_HTML_EVENTS[url].set()
            
        return CollectorResult(
            collector_name=self.name,
            success=False,
            execution_time_ms=elapsed_time_ms,
            data=None,
            errors=errors,
            timestamp=datetime.now(timezone.utc)
        )

class SSLCollector(BaseCollector):
    @property
    def name(self) -> str:
        return "ssl"

    async def collect(self, url: str) -> CollectorResult:
        raise NotImplementedError("SSLCollector not implemented.")

class WHOISCollector(BaseCollector):
    @property
    def name(self) -> str:
        return "whois"

    async def collect(self, url: str) -> CollectorResult:
        raise NotImplementedError("WHOISCollector not implemented.")

class DNSCollector(BaseCollector):
    @property
    def name(self) -> str:
        return "dns"

    async def collect(self, url: str) -> CollectorResult:
        raise NotImplementedError("DNSCollector not implemented.")

class HTMLCollector(BaseCollector):
    @property
    def name(self) -> str:
        return "html"

    async def collect(self, url: str) -> CollectorResult:
        start_time = time.perf_counter()
        
        # Initialize event if not present to avoid race conditions
        if url not in WEBSITE_HTML_EVENTS:
            WEBSITE_HTML_EVENTS[url] = asyncio.Event()
            
        # Wait for WebsiteCollector to finish fetching HTML
        try:
            await asyncio.wait_for(WEBSITE_HTML_EVENTS[url].wait(), timeout=15.0)
        except asyncio.TimeoutError:
            duration_ms = (time.perf_counter() - start_time) * 1000
            return CollectorResult(
                collector_name=self.name,
                success=False,
                execution_time_ms=round(duration_ms, 2),
                data=None,
                errors=["TimeoutError: Waiting for WebsiteCollector timed out."],
                timestamp=datetime.now(timezone.utc)
            )

        # Retrieve crawled response HTML from shared cache
        web_data = WEBSITE_HTML_CACHE.get(url)
        if not web_data or not web_data.get("response_html"):
            duration_ms = (time.perf_counter() - start_time) * 1000
            return CollectorResult(
                collector_name=self.name,
                success=False,
                execution_time_ms=round(duration_ms, 2),
                data=None,
                errors=["DependencyError: WebsiteCollector failed or returned no HTML data."],
                timestamp=datetime.now(timezone.utc)
            )
            
        html_content = web_data["response_html"]
        
        try:
            # Parse HTML content gracefully using bs4
            soup = BeautifulSoup(html_content, "html.parser")
            
            page_title = soup.title.get_text().strip() if soup.title else None
            
            desc_tag = soup.find("meta", attrs={"name": "description"}) or soup.find("meta", attrs={"property": "og:description"})
            meta_description = desc_tag.get("content", "").strip() if desc_tag and desc_tag.get("content") else None
            
            keywords_tag = soup.find("meta", attrs={"name": "keywords"})
            meta_keywords = [k.strip() for k in keywords_tag.get("content", "").split(",") if k.strip()] if keywords_tag and keywords_tag.get("content") else []
            
            canonical_tag = soup.find("link", rel="canonical")
            canonical_url = canonical_tag.get("href", "").strip() if canonical_tag and canonical_tag.get("href") else None
            if canonical_url:
                canonical_url = urljoin(url, canonical_url)
                
            forms = soup.find_all("form")
            forms_count = len(forms)
            form_actions = [urljoin(url, f.get("action", "").strip()) for f in forms if f.get("action")]
            
            password_input_count = len(soup.find_all("input", type="password"))
            email_input_count = len(soup.find_all("input", type="email"))
            telephone_input_count = len(soup.find_all("input", type="tel"))
            hidden_input_count = len(soup.find_all("input", type="hidden"))
            
            button_count = len(soup.find_all("button")) + len(soup.find_all("input", type=["submit", "button"]))
            anchor_count = len(soup.find_all("a"))
            iframe_count = len(soup.find_all("iframe"))
            image_count = len(soup.find_all("img"))
            
            external_script_count = len([s for s in soup.find_all("script") if s.get("src")])
            inline_script_count = len([s for s in soup.find_all("script") if not s.get("src")])
            
            # Simple form intent detection logic
            detected_login_form = False
            detected_signup_form = False
            detected_payment_form = False
            detected_otp_form = False
            
            for form in forms:
                form_html = str(form).lower()
                has_password = form.find("input", type="password") is not None
                
                if has_password and any(k in form_html for k in ["login", "signin", "log-in", "sign-in"]):
                    detected_login_form = True
                
                if any(k in form_html for k in ["signup", "register", "create account", "join", "sign-up"]):
                    if has_password or "confirm" in form_html:
                        detected_signup_form = True
                        
                if any(k in form_html for k in ["cardnumber", "cvv", "payment", "checkout", "billing", "credit card"]):
                    detected_payment_form = True
                    
                if any(k in form_html for k in ["otp", "one-time", "passcode", "verification code", "2fa"]):
                    detected_otp_form = True
            
            # Clean text extraction
            text_soup = BeautifulSoup(html_content, "html.parser")
            for element in text_soup(["script", "style", "noscript", "svg"]):
                element.decompose()
            raw_text = text_soup.get_text(separator=" ")
            visible_text = " ".join(raw_text.split())
            
            # Favicon extraction
            favicon_tag = soup.find("link", rel=lambda x: x and "icon" in x.lower())
            favicon_url = favicon_tag.get("href", "").strip() if favicon_tag and favicon_tag.get("href") else None
            if favicon_url:
                favicon_url = urljoin(url, favicon_url)
                
            # Links extraction
            hyperlinks = []
            external_links = []
            internal_links = []
            parsed_base = urlparse(url)
            for a in soup.find_all("a", href=True):
                href = a.get("href", "").strip()
                if href:
                    abs_url = urljoin(url, href)
                    hyperlinks.append(abs_url)
                    
                    parsed_link = urlparse(abs_url)
                    if parsed_link.netloc and parsed_link.netloc != parsed_base.netloc:
                        external_links.append(abs_url)
                    else:
                        internal_links.append(abs_url)
                        
            # Suspicious JS indicators extraction
            suspicious_js_indicators = []
            indicators = ["eval(", "document.write(", "window.location", "atob(", "btoa(", "base64"]
            for script in soup.find_all("script"):
                script_content = script.get_text() or ""
                script_src = script.get("src", "")
                for ind in indicators:
                    if ind in script_content or ind in script_src:
                        if ind not in suspicious_js_indicators:
                            suspicious_js_indicators.append(ind)
                            
            # Legacy/compatibility fields
            script_tags_count = len(soup.find_all("script"))
            iframe_urls = [urljoin(url, iframe.get("src", "").strip()) for iframe in soup.find_all("iframe") if iframe.get("src")]

            data = {
                "page_title": page_title,
                "meta_description": meta_description,
                "meta_keywords": meta_keywords,
                "canonical_url": canonical_url,
                "forms_count": forms_count,
                "form_actions": form_actions,
                "password_input_count": password_input_count,
                "email_input_count": email_input_count,
                "telephone_input_count": telephone_input_count,
                "hidden_input_count": hidden_input_count,
                "button_count": button_count,
                "anchor_count": anchor_count,
                "iframe_count": iframe_count,
                "image_count": image_count,
                "external_script_count": external_script_count,
                "inline_script_count": inline_script_count,
                "detected_login_form": detected_login_form,
                "detected_signup_form": detected_signup_form,
                "detected_payment_form": detected_payment_form,
                "detected_otp_form": detected_otp_form,
                "visible_text": visible_text,
                "favicon_url": favicon_url,
                "hyperlinks": hyperlinks,
                "suspicious_js_indicators": suspicious_js_indicators,
                "external_links": external_links,
                "internal_links": internal_links,
                "script_tags_count": script_tags_count,
                "iframe_urls": iframe_urls
            }
            
            elapsed_time_ms = (time.perf_counter() - start_time) * 1000
            return CollectorResult(
                collector_name=self.name,
                success=True,
                execution_time_ms=round(elapsed_time_ms, 2),
                data=data,
                errors=[],
                timestamp=datetime.now(timezone.utc)
            )
            
        except Exception as e:
            elapsed_time_ms = (time.perf_counter() - start_time) * 1000
            return CollectorResult(
                collector_name=self.name,
                success=False,
                execution_time_ms=round(elapsed_time_ms, 2),
                data=None,
                errors=[f"ParsingError: HTML parsing failed: {type(e).__name__}: {str(e)}"],
                timestamp=datetime.now(timezone.utc)
            )

class PlaywrightCollector(BaseCollector):
    def __init__(self, timeout_sec: float = 30.0) -> None:
        self.timeout_sec = timeout_sec

    @property
    def name(self) -> str:
        return "playwright"

    async def collect(self, url: str) -> CollectorResult:
        start_time = time.perf_counter()
        errors = []
        
        browser = None
        context = None
        
        screenshot_path = None
        full_page_screenshot_path = None
        rendered_html = ""
        final_url = url
        page_title = ""
        visible_text = ""
        meta_description = None
        viewport_size = {"width": 1280, "height": 800}
        page_dimensions = {"width": 1280, "height": 800}
        cookies = []
        local_storage = {}
        session_storage = {}
        console_errors = []
        failed_requests = []
        total_request_count = 0
        js_redirects_detected = False
        
        try:
            async with async_playwright() as p:
                try:
                    browser = await p.chromium.launch(headless=True)
                except Exception as e:
                    raise RuntimeError(f"Browser launch failure: {str(e)}")
                    
                try:
                    context = await browser.new_context(viewport={"width": 1280, "height": 800})
                    page = await context.new_page()
                except Exception as e:
                    raise RuntimeError(f"Page/Context initialization failure: {str(e)}")
                
                # Attach listeners
                page.on("console", lambda msg: console_errors.append(msg.text) if msg.type == "error" else None)
                
                def on_request(req):
                    nonlocal total_request_count
                    total_request_count += 1
                page.on("request", on_request)
                
                def on_request_failed(req):
                    failed_requests.append({
                        "url": req.url,
                        "error_text": req.failure.error_text if req.failure else "Unknown request failure"
                    })
                page.on("requestfailed", on_request_failed)
                
                # Navigate to URL
                try:
                    await page.goto(url, wait_until="networkidle", timeout=self.timeout_sec * 1000)
                except Exception as e:
                    raise RuntimeError(f"Navigation failure: {str(e)}")
                
                load_time_ms = (time.perf_counter() - start_time) * 1000
                
                final_url = page.url
                js_redirects_detected = (final_url != url)
                
                page_title = await page.title()
                rendered_html = await page.content()
                
                try:
                    meta_desc_element = await page.query_selector('meta[name="description"]')
                    meta_description = await meta_desc_element.get_attribute("content") if meta_desc_element else None
                except Exception:
                    meta_description = None
                    
                try:
                    visible_text = await page.evaluate("() => document.body.innerText")
                except Exception:
                    visible_text = ""
                    
                try:
                    viewport_size = page.viewport_size
                    page_dimensions = await page.evaluate("() => { return { width: document.documentElement.scrollWidth, height: document.documentElement.scrollHeight }; }")
                except Exception:
                    pass
                    
                try:
                    cookies = await context.cookies()
                except Exception:
                    cookies = []
                    
                try:
                    local_storage = await page.evaluate("() => { return { ...localStorage }; }")
                    session_storage = await page.evaluate("() => { return { ...sessionStorage }; }")
                except Exception:
                    pass
                
                # Screenshots storage using UUID
                screenshot_dir = Path("artifacts/screenshots")
                screenshot_dir.mkdir(parents=True, exist_ok=True)
                
                shot_uuid = uuid.uuid4()
                screenshot_file = screenshot_dir / f"{shot_uuid}.png"
                full_page_screenshot_file = screenshot_dir / f"{shot_uuid}_full.png"
                
                try:
                    await page.screenshot(path=str(screenshot_file), full_page=False)
                    screenshot_path = str(screenshot_file.resolve())
                except Exception as e:
                    errors.append(f"ScreenshotCaptureError: Failed standard screenshot: {str(e)}")
                    
                try:
                    await page.screenshot(path=str(full_page_screenshot_file), full_page=True)
                    full_page_screenshot_path = str(full_page_screenshot_file.resolve())
                except Exception as e:
                    errors.append(f"ScreenshotCaptureError: Failed full page screenshot: {str(e)}")
                
                await context.close()
                await browser.close()
                
            elapsed_time_ms = (time.perf_counter() - start_time) * 1000
            
            data = {
                "screenshot_path": screenshot_path,
                "full_page_screenshot_path": full_page_screenshot_path,
                "rendered_html": rendered_html,
                "final_url": final_url,
                "page_title": page_title,
                "visible_text": visible_text,
                "meta_description": meta_description,
                "viewport_size": viewport_size,
                "page_dimensions": page_dimensions,
                "cookies": cookies,
                "local_storage": local_storage,
                "session_storage": session_storage,
                "console_errors": console_errors,
                "failed_requests": failed_requests,
                "total_request_count": total_request_count,
                "js_redirects_detected": js_redirects_detected,
                "load_time_ms": load_time_ms
            }
            
            return CollectorResult(
                collector_name=self.name,
                success=True,
                execution_time_ms=round(elapsed_time_ms, 2),
                data=data,
                errors=errors,
                timestamp=datetime.now(timezone.utc)
            )
            
        except Exception as e:
            elapsed_time_ms = (time.perf_counter() - start_time) * 1000
            errors.append(f"PlaywrightException: {type(e).__name__}: {str(e)}")
            return CollectorResult(
                collector_name=self.name,
                success=False,
                execution_time_ms=round(elapsed_time_ms, 2),
                data=None,
                errors=errors,
                timestamp=datetime.now(timezone.utc)
            )

class ScreenshotCollector(BaseCollector):
    @property
    def name(self) -> str:
        return "screenshot"

    async def collect(self, url: str) -> CollectorResult:
        raise NotImplementedError("ScreenshotCollector is deprecated. Use PlaywrightCollector instead.")

class OCRCollector(BaseCollector):
    @property
    def name(self) -> str:
        return "ocr"

    async def collect(self, url: str) -> CollectorResult:
        raise NotImplementedError("OCRCollector not implemented.")

class RedirectCollector(BaseCollector):
    @property
    def name(self) -> str:
        return "redirects"

    async def collect(self, url: str) -> CollectorResult:
        raise NotImplementedError("RedirectCollector not implemented.")

class HeaderCollector(BaseCollector):
    @property
    def name(self) -> str:
        return "headers"

    async def collect(self, url: str) -> CollectorResult:
        raise NotImplementedError("HeaderCollector not implemented.")

class MetadataCollector(BaseCollector):
    @property
    def name(self) -> str:
        return "metadata"

    async def collect(self, url: str) -> CollectorResult:
        raise NotImplementedError("MetadataCollector not implemented.")
