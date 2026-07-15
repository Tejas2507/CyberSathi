import pytest
import asyncio
from datetime import datetime, timezone
from bs4 import BeautifulSoup
from app.services.collectors import (
    HTMLCollector,
    WEBSITE_HTML_CACHE,
    WEBSITE_HTML_EVENTS
)
from app.schemas.evidence import CollectorResult

# Clean up cache and events helper
def setup_web_cache(url: str, html_content: str = None, success: bool = True):
    if success:
        WEBSITE_HTML_CACHE[url] = {
            "response_html": html_content,
            "status_code": 200
        }
    else:
        WEBSITE_HTML_CACHE[url] = None
    
    event = asyncio.Event()
    WEBSITE_HTML_EVENTS[url] = event
    event.set()

@pytest.fixture(autouse=True)
def cleanup_cache():
    yield
    WEBSITE_HTML_CACHE.clear()
    WEBSITE_HTML_EVENTS.clear()

@pytest.mark.anyio
async def test_html_collector_success():
    url = "https://example.com/login"
    html_content = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>   Secure Sign-In Area   </title>
        <meta name="description" content="Access your Cybersathi profile safely.">
        <meta name="keywords" content="safety, cyber, assistant, security">
        <link rel="canonical" href="https://example.com/canonical-login">
        <link rel="shortcut icon" href="/assets/favicon.ico">
    </head>
    <body>
        <h1>Login to CyberSathi</h1>
        
        <!-- Login Form -->
        <form action="/auth/login" method="POST">
            <input type="text" name="username" placeholder="Username or Email">
            <input type="password" name="pwd">
            <input type="hidden" name="csrf_token" value="abc123xyz">
            <button type="submit">Sign In</button>
        </form>

        <!-- Newsletter Sign-Up Form -->
        <form action="https://external-service.com/subscribe">
            <input type="email" name="user_email">
            <input type="tel" name="phone">
            <button type="button">Subscribe</button>
        </form>

        <a href="/about-us">About</a>
        <a href="https://google.com">Google</a>
        <iframe src="/embedded-map"></iframe>
        <img src="logo.png">

        <script>
            console.log("Inline safe script");
            eval("console.log('inline eval call')");
        </script>
        <script src="https://example.com/external.js"></script>
        <style>
            body { color: #333; }
        </style>
        <noscript>Please enable JS.</noscript>
    </body>
    </html>
    """
    
    setup_web_cache(url, html_content)
    
    collector = HTMLCollector()
    result = await collector.collect(url)
    
    assert result.success is True
    assert result.collector_name == "html"
    
    data = result.data
    assert data["page_title"] == "Secure Sign-In Area"
    assert data["meta_description"] == "Access your Cybersathi profile safely."
    assert data["meta_keywords"] == ["safety", "cyber", "assistant", "security"]
    assert data["canonical_url"] == "https://example.com/canonical-login"
    assert data["favicon_url"] == "https://example.com/assets/favicon.ico"
    
    # Counts
    assert data["forms_count"] == 2
    assert "/auth/login" in data["form_actions"][0]
    assert "https://external-service.com/subscribe" in data["form_actions"][1]
    
    assert data["password_input_count"] == 1
    assert data["email_input_count"] == 1
    assert data["telephone_input_count"] == 1
    assert data["hidden_input_count"] == 1
    assert data["button_count"] == 2
    assert data["anchor_count"] == 2
    assert data["iframe_count"] == 1
    assert data["image_count"] == 1
    assert data["external_script_count"] == 1
    assert data["inline_script_count"] == 1
    
    # Intents
    assert data["detected_login_form"] is True
    assert data["detected_signup_form"] is False
    assert data["detected_payment_form"] is False
    assert data["detected_otp_form"] is False
    
    # Clean visible text (should not include script, style or noscript)
    visible_text = data["visible_text"]
    assert "Login to CyberSathi" in visible_text
    assert "Subscribe" in visible_text
    assert "console.log" not in visible_text
    assert "Please enable JS" not in visible_text
    assert "color: #333" not in visible_text
    
    # Links
    assert "https://example.com/about-us" in data["hyperlinks"]
    assert "https://google.com" in data["hyperlinks"]
    assert "https://example.com/about-us" in data["internal_links"]
    assert "https://google.com" in data["external_links"]
    
    # Suspicious JS
    assert "eval(" in data["suspicious_js_indicators"]

@pytest.mark.anyio
async def test_html_collector_malformed_html():
    url = "https://example.com/malformed"
    # Unclosed tags, mixed quotes, and completely broken layout
    html_content = "<title>Malformed</title><p>Broken text <i>unclosed italic <b>unclosed bold"
    
    setup_web_cache(url, html_content)
    
    collector = HTMLCollector()
    result = await collector.collect(url)
    
    assert result.success is True
    assert result.data["page_title"] == "Malformed"
    assert "unclosed italic unclosed bold" in result.data["visible_text"]

@pytest.mark.anyio
async def test_html_collector_dependency_failed():
    url = "https://example.com/failed-site"
    # Setup cache as failed
    setup_web_cache(url, success=False)
    
    collector = HTMLCollector()
    result = await collector.collect(url)
    
    assert result.success is False
    assert result.data is None
    assert len(result.errors) == 1
    assert "DependencyError" in result.errors[0]

@pytest.mark.anyio
async def test_html_collector_waiting_timeout():
    url = "https://example.com/slow-site"
    # We do NOT call setup_web_cache, so the event never fires
    # Set the event as a slow one that will timeout (we can mock wait_for timeout)
    # To test without waiting 15 seconds, we can patch wait_for to raise TimeoutError immediately
    with patch("asyncio.wait_for", side_effect=asyncio.TimeoutError()):
        collector = HTMLCollector()
        result = await collector.collect(url)
        
        assert result.success is False
        assert result.data is None
        assert "TimeoutError" in result.errors[0]
from unittest.mock import patch
