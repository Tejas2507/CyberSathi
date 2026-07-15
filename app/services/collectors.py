from abc import ABC, abstractmethod
import time
import httpx
from datetime import datetime, timezone
from app.schemas.evidence import CollectorResult

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
        raise NotImplementedError("HTMLCollector not implemented.")

class ScreenshotCollector(BaseCollector):
    @property
    def name(self) -> str:
        return "screenshot"

    async def collect(self, url: str) -> CollectorResult:
        raise NotImplementedError("ScreenshotCollector not implemented.")

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
