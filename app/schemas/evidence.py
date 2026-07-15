from pydantic import BaseModel, Field
from typing import Dict, Any, List, Optional
from datetime import datetime, timezone
from app.schemas.safety import ClassifierResult

class CollectorResult(BaseModel):
    """
    Standard schema for the output of any single evidence collector execution.
    """
    collector_name: str = Field(..., description="Name of the collector")
    success: bool = Field(..., description="Whether the collection succeeded without uncaught errors")
    execution_time_ms: float = Field(..., description="Collector execution time in milliseconds")
    data: Optional[Dict[str, Any]] = Field(default=None, description="Data collected (if successful)")
    errors: List[str] = Field(default_factory=list, description="Any error strings captured during run")
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc), description="Time of collection")

# --- Nested Evidence Models ---

class WebsiteEvidence(BaseModel):
    title: Optional[str] = None
    original_url: Optional[str] = None
    final_url: Optional[str] = None
    status_code: Optional[int] = None
    response_headers: Dict[str, str] = Field(default_factory=dict)
    cookies: Dict[str, str] = Field(default_factory=dict)
    redirect_chain: List[str] = Field(default_factory=list)
    response_html: Optional[str] = None
    response_size: Optional[int] = None
    response_encoding: Optional[str] = None
    server: Optional[str] = None
    content_type: Optional[str] = None
    elapsed_time: Optional[float] = None
    response_time_ms: Optional[float] = None

class SSLEvidence(BaseModel):
    ssl_valid: bool = False
    ssl_issuer: Optional[str] = None
    ssl_expiry: Optional[str] = None
    ssl_subject: Optional[str] = None

class WHOISEvidence(BaseModel):
    registrar: Optional[str] = None
    creation_date: Optional[str] = None
    expiration_date: Optional[str] = None
    age_days: Optional[int] = None
    registrant_country: Optional[str] = None

class DNSEvidence(BaseModel):
    a_records: List[str] = Field(default_factory=list)
    mx_records: List[str] = Field(default_factory=list)
    ns_records: List[str] = Field(default_factory=list)
    txt_records: List[str] = Field(default_factory=list)

class HTMLEvidence(BaseModel):
    page_title: Optional[str] = None
    meta_description: Optional[str] = None
    meta_keywords: List[str] = Field(default_factory=list)
    canonical_url: Optional[str] = None
    forms_count: int = 0
    form_actions: List[str] = Field(default_factory=list)
    password_input_count: int = 0
    email_input_count: int = 0
    telephone_input_count: int = 0
    hidden_input_count: int = 0
    button_count: int = 0
    anchor_count: int = 0
    iframe_count: int = 0
    image_count: int = 0
    external_script_count: int = 0
    inline_script_count: int = 0
    detected_login_form: bool = False
    detected_signup_form: bool = False
    detected_payment_form: bool = False
    detected_otp_form: bool = False
    visible_text: Optional[str] = None
    favicon_url: Optional[str] = None
    hyperlinks: List[str] = Field(default_factory=list)
    suspicious_js_indicators: List[str] = Field(default_factory=list)
    # Legacy/compatibility fields
    external_links: List[str] = Field(default_factory=list)
    internal_links: List[str] = Field(default_factory=list)
    script_tags_count: int = 0
    iframe_urls: List[str] = Field(default_factory=list)

class MetadataEvidence(BaseModel):
    meta_tags: Dict[str, str] = Field(default_factory=dict)
    og_properties: Dict[str, str] = Field(default_factory=dict)

class HeadersEvidence(BaseModel):
    server: Optional[str] = None
    content_security_policy: Optional[str] = None
    security_headers: Dict[str, str] = Field(default_factory=dict)
    raw_headers: Dict[str, str] = Field(default_factory=dict)

class RedirectsEvidence(BaseModel):
    redirect_history: List[str] = Field(default_factory=list)
    final_url: Optional[str] = None
    redirect_count: int = 0

class PlaywrightEvidence(BaseModel):
    screenshot_path: Optional[str] = None
    full_page_screenshot_path: Optional[str] = None
    rendered_html: Optional[str] = None
    final_url: Optional[str] = None
    page_title: Optional[str] = None
    visible_text: Optional[str] = None
    meta_description: Optional[str] = None
    viewport_size: Optional[Dict[str, int]] = None
    page_dimensions: Optional[Dict[str, int]] = None
    cookies: List[Dict[str, Any]] = Field(default_factory=list)
    local_storage: Dict[str, str] = Field(default_factory=dict)
    session_storage: Dict[str, str] = Field(default_factory=dict)
    console_errors: List[str] = Field(default_factory=list)
    failed_requests: List[Dict[str, Any]] = Field(default_factory=list)
    total_request_count: int = 0
    js_redirects_detected: bool = False
    load_time_ms: float = 0.0

class ScreenshotEvidence(BaseModel):
    screenshot_path: Optional[str] = None
    screenshot_size_bytes: Optional[int] = None

class OCREvidence(BaseModel):
    extracted_text: Optional[str] = None
    ocr_confidence: Optional[float] = None
    detected_phrases: List[str] = Field(default_factory=list)

class CollectionSummary(BaseModel):
    success_count: int = 0
    failure_count: int = 0
    total_time_ms: float = 0.0
    collector_metrics: Dict[str, float] = Field(default_factory=dict)
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

# --- Master Evidence Model ---

class Evidence(BaseModel):
    """
    Consolidated master object holding all stages of gathered website evidence.
    """
    url: str = Field(..., description="The target URL inspected")
    prediction_result: Optional[ClassifierResult] = Field(default=None, description="URL ML Classifier verdict")
    website: Optional[WebsiteEvidence] = Field(default=None, description="General website loading telemetry")
    ssl: Optional[SSLEvidence] = Field(default=None, description="SSL Certificate properties")
    whois: Optional[WHOISEvidence] = Field(default=None, description="WHOIS domain registration properties")
    dns: Optional[DNSEvidence] = Field(default=None, description="Domain DNS queries details")
    html: Optional[HTMLEvidence] = Field(default=None, description="Parsed HTML details")
    metadata: Optional[MetadataEvidence] = Field(default=None, description="Extracted HTML meta-tags details")
    headers: Optional[HeadersEvidence] = Field(default=None, description="Response headers telemetry")
    redirects: Optional[RedirectsEvidence] = Field(default=None, description="Redirect trace logs details")
    screenshot: Optional[ScreenshotEvidence] = Field(default=None, description="Headless browser screenshot details")
    playwright: Optional[PlaywrightEvidence] = Field(default=None, description="Playwright browser rendering details")
    ocr: Optional[OCREvidence] = Field(default=None, description="OCR text extracted from screenshot details")
    
    # Authoritative HTML & Rendering fields for LLM Consumption
    raw_html: Optional[str] = Field(default=None, description="Raw HTML response from WebsiteCollector")
    rendered_html: Optional[str] = Field(default=None, description="Fully rendered DOM HTML from PlaywrightCollector")
    primary_html: Optional[str] = Field(default=None, description="Authoritative HTML (rendered DOM if available, else raw)")
    raw_visible_text: Optional[str] = Field(default=None, description="Visible text from raw HTML")
    rendered_visible_text: Optional[str] = Field(default=None, description="Visible text from rendered DOM")
    viewport_screenshot_path: Optional[str] = Field(default=None, description="Path to standard viewport screenshot")
    fullpage_screenshot_path: Optional[str] = Field(default=None, description="Path to full page screenshot")
    
    collection_summary: Optional[CollectionSummary] = Field(default=None, description="Consolidated metrics about the run")
