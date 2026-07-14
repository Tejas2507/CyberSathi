from abc import ABC, abstractmethod
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
    @property
    def name(self) -> str:
        return "website"

    async def collect(self, url: str) -> CollectorResult:
        raise NotImplementedError("WebsiteCollector not implemented.")

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
