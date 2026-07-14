from pydantic import BaseModel, HttpUrl, Field
from typing import Dict, Any, List, Optional
from datetime import datetime

class UrlInspectionRequest(BaseModel):
    url: HttpUrl = Field(..., description="The fully qualified URL to inspect (must start with http:// or https://)")
    bypass_cache: bool = Field(default=False, description="Bypass internal safety cache databases if True")

class ClassifierResult(BaseModel):
    is_suspicious: bool = Field(..., description="Fast ML classifier verdict")
    risk_score: float = Field(..., description="Classifier probability score between 0.0 and 1.0")
    model_version: str = Field(..., description="Identifier of the model version used")

class WhoisData(BaseModel):
    registrar: Optional[str] = None
    creation_date: Optional[str] = None
    expiration_date: Optional[str] = None
    updated_date: Optional[str] = None
    age_days: Optional[int] = None

class DnsRecordData(BaseModel):
    record_type: str
    values: List[str]

class ScraperData(BaseModel):
    title: Optional[str] = None
    ssl_valid: bool
    ssl_issuer: Optional[str] = None
    external_links_count: int
    has_input_fields: bool
    screenshot_captured: bool

class DeepInspectionDetails(BaseModel):
    whois: Optional[WhoisData] = None
    dns: List[DnsRecordData] = Field(default_factory=list)
    scraper: Optional[ScraperData] = None

class LlmAdvisory(BaseModel):
    verdict: str = Field(..., description="Safe, Suspicious, or Dangerous")
    threats_detected: List[str] = Field(default_factory=list)
    confidence: str = Field(..., description="Low, Medium, or High")
    summary: str = Field(..., description="Detailed safety advisory in markdown")
    remediation_steps: List[str] = Field(default_factory=list)

class UrlInspectionResponse(BaseModel):
    url: str
    overall_status: str = Field(..., description="Overall risk status (e.g. SAFE, SUSPICIOUS, DANGEROUS)")
    overall_score: float = Field(..., description="Consolidated threat score from 0.0 to 1.0")
    classifier_result: ClassifierResult
    deep_inspection: DeepInspectionDetails
    llm_advisory: Optional[LlmAdvisory] = None
    timestamp: datetime = Field(default_factory=datetime.utcnow)
