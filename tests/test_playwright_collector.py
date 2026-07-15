import pytest
import asyncio
from unittest.mock import AsyncMock, MagicMock, patch
from app.services.collectors import PlaywrightCollector

@pytest.mark.anyio
async def test_playwright_collector_success():
    # Setup mock playwright page
    mock_page = AsyncMock()
    mock_page.url = "https://example.com/redirected"
    mock_page.title.return_value = "Rendered Title"
    mock_page.content.return_value = "<html>Rendered HTML</html>"
    mock_page.viewport_size = {"width": 1280, "height": 800}
    
    # Define side effect values for evaluating page content:
    # 1. visible text innerText
    # 2. page dimensions (scrollWidth, scrollHeight)
    # 3. localStorage dict
    # 4. sessionStorage dict
    mock_page.evaluate.side_effect = [
        "Rendered visible page text",
        {"width": 1920, "height": 1500},
        {"user_id": "12345"},
        {"session_token": "abcde"}
    ]
    
    # Meta description element mock
    mock_meta = AsyncMock()
    mock_meta.get_attribute.return_value = "Mocked Meta Description"
    mock_page.query_selector.return_value = mock_meta
    
    # Setup mock context
    mock_context = AsyncMock()
    mock_context.new_page.return_value = mock_page
    mock_context.cookies.return_value = [{"name": "auth_cookie", "value": "xyz"}]
    
    # Setup mock browser
    mock_browser = AsyncMock()
    mock_browser.new_context.return_value = mock_context
    
    # Patch async_playwright context manager
    mock_p_instance = MagicMock()
    mock_p_instance.chromium.launch = AsyncMock(return_value=mock_browser)
    
    mock_p_ctx = MagicMock()
    mock_p_ctx.__aenter__ = AsyncMock(return_value=mock_p_instance)
    mock_p_ctx.__aexit__ = AsyncMock(return_value=None)
    
    with patch("app.services.collectors.async_playwright", return_value=mock_p_ctx):
        collector = PlaywrightCollector(timeout_sec=5.0)
        result = await collector.collect("https://example.com/start")
        
        assert result.success is True
        assert result.collector_name == "playwright"
        
        data = result.data
        assert data["final_url"] == "https://example.com/redirected"
        assert data["page_title"] == "Rendered Title"
        assert data["meta_description"] == "Mocked Meta Description"
        assert data["visible_text"] == "Rendered visible page text"
        assert data["viewport_size"] == {"width": 1280, "height": 800}
        assert data["page_dimensions"] == {"width": 1920, "height": 1500}
        assert data["cookies"] == [{"name": "auth_cookie", "value": "xyz"}]
        assert data["local_storage"] == {"user_id": "12345"}
        assert data["session_storage"] == {"session_token": "abcde"}
        assert data["js_redirects_detected"] is True
        assert data["screenshot_path"] is not None
        assert data["full_page_screenshot_path"] is not None
        assert len(result.errors) == 0

@pytest.mark.anyio
async def test_playwright_collector_launch_failure():
    mock_p_instance = MagicMock()
    # Emulate crash when launching browser
    mock_p_instance.chromium.launch = AsyncMock(side_effect=Exception("Failed to launch chromium binary"))
    
    mock_p_ctx = MagicMock()
    mock_p_ctx.__aenter__ = AsyncMock(return_value=mock_p_instance)
    mock_p_ctx.__aexit__ = AsyncMock(return_value=None)
    
    with patch("app.services.collectors.async_playwright", return_value=mock_p_ctx):
        collector = PlaywrightCollector()
        result = await collector.collect("https://example.com")
        
        assert result.success is False
        assert result.data is None
        assert len(result.errors) == 1
        assert "Browser launch failure" in result.errors[0]

@pytest.mark.anyio
async def test_playwright_collector_navigation_failure():
    mock_page = AsyncMock()
    # Emulate network timeout or resolution error on goto
    mock_page.goto.side_effect = RuntimeError("Navigation timed out after 30000ms")
    
    mock_context = AsyncMock()
    mock_context.new_page.return_value = mock_page
    
    mock_browser = AsyncMock()
    mock_browser.new_context.return_value = mock_context
    
    mock_p_instance = MagicMock()
    mock_p_instance.chromium.launch = AsyncMock(return_value=mock_browser)
    
    mock_p_ctx = MagicMock()
    mock_p_ctx.__aenter__ = AsyncMock(return_value=mock_p_instance)
    mock_p_ctx.__aexit__ = AsyncMock(return_value=None)
    
    with patch("app.services.collectors.async_playwright", return_value=mock_p_ctx):
        collector = PlaywrightCollector()
        result = await collector.collect("https://example.com")
        
        assert result.success is False
        assert result.data is None
        assert len(result.errors) == 1
        assert "Navigation failure" in result.errors[0]
