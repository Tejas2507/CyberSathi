import pytest
import httpx
from unittest.mock import AsyncMock, MagicMock, patch
from app.services.collectors import WebsiteCollector

@pytest.mark.anyio
async def test_website_collector_success():
    # Setup mock response
    mock_response = MagicMock(spec=httpx.Response)
    mock_response.status_code = 200
    mock_response.url = httpx.URL("https://example.com/final")
    
    # Mock redirect history responses
    r1 = MagicMock(spec=httpx.Response)
    r1.url = httpx.URL("https://example.com/r1")
    r2 = MagicMock(spec=httpx.Response)
    r2.url = httpx.URL("https://example.com/r2")
    mock_response.history = [r1, r2]
    
    mock_response.headers = httpx.Headers({
        "server": "nginx/1.25",
        "content-type": "text/html; charset=utf-8"
    })
    mock_response.cookies = httpx.Cookies({"auth": "test-cookie"})
    mock_response.text = "<html>Success HTML</html>"
    mock_response.content = b"<html>Success HTML</html>"
    mock_response.encoding = "utf-8"
    mock_response.raise_for_status = MagicMock()  # success path

    # Patch AsyncClient.get
    with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
        mock_get.return_value = mock_response
        
        collector = WebsiteCollector(timeout_sec=3.0)
        result = await collector.collect("https://example.com/start")
        
        assert result.success is True
        assert result.collector_name == "website"
        assert result.data["original_url"] == "https://example.com/start"
        assert result.data["final_url"] == "https://example.com/final"
        assert result.data["status_code"] == 200
        assert result.data["response_encoding"] == "utf-8"
        assert result.data["server"] == "nginx/1.25"
        assert result.data["content_type"] == "text/html; charset=utf-8"
        assert result.data["cookies"] == {"auth": "test-cookie"}
        assert result.data["redirect_chain"] == [
            "https://example.com/r1",
            "https://example.com/r2"
        ]
        assert result.data["response_html"] == "<html>Success HTML</html>"
        assert result.data["response_size"] == len(b"<html>Success HTML</html>")
        assert len(result.errors) == 0

@pytest.mark.anyio
async def test_website_collector_timeout():
    with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
        # Mock TimeoutException
        mock_get.side_effect = httpx.TimeoutException("Read timeout", request=MagicMock())
        
        collector = WebsiteCollector(timeout_sec=1.5)
        result = await collector.collect("https://example.com")
        
        assert result.success is False
        assert result.data is None
        assert len(result.errors) == 1
        assert "TimeoutError" in result.errors[0]

@pytest.mark.anyio
async def test_website_collector_dns_connection_refused():
    with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
        # Mock ConnectError
        mock_get.side_effect = httpx.ConnectError("Failed to resolve DNS", request=MagicMock())
        
        collector = WebsiteCollector()
        result = await collector.collect("https://example.com")
        
        assert result.success is False
        assert result.data is None
        assert len(result.errors) == 1
        assert "DNSOrConnectionError" in result.errors[0]

@pytest.mark.anyio
async def test_website_collector_ssl_error():
    with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
        # Mock SSL error via ConnectError containing SSL details
        mock_get.side_effect = httpx.ConnectError("[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed", request=MagicMock())
        
        collector = WebsiteCollector()
        result = await collector.collect("https://example.com")
        
        assert result.success is False
        assert result.data is None
        assert len(result.errors) == 1
        assert "SSLError" in result.errors[0]

@pytest.mark.anyio
async def test_website_collector_redirect_loop():
    with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
        # Mock TooManyRedirects
        mock_get.side_effect = httpx.TooManyRedirects("Redirect loop detected", request=MagicMock())
        
        collector = WebsiteCollector()
        result = await collector.collect("https://example.com")
        
        assert result.success is False
        assert result.data is None
        assert len(result.errors) == 1
        assert "RedirectLoopError" in result.errors[0]

@pytest.mark.anyio
async def test_website_collector_http_status_error():
    with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
        # Mock HTTPStatusError (e.g. 500 Server Error)
        mock_response = MagicMock(spec=httpx.Response)
        mock_response.status_code = 500
        mock_response.raise_for_status.side_effect = httpx.HTTPStatusError(
            "Internal Server Error", request=MagicMock(), response=mock_response
        )
        mock_get.return_value = mock_response
        
        collector = WebsiteCollector()
        result = await collector.collect("https://example.com")
        
        assert result.success is False
        assert result.data is None
        assert len(result.errors) == 1
        assert "HTTPStatusError" in result.errors[0]
