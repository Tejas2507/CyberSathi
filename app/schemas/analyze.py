"""
API-level request/response schemas for the /analyze endpoint.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, HttpUrl, Field


class AnalyzeRequest(BaseModel):
    url: HttpUrl = Field(
        ...,
        description="The fully-qualified URL to inspect (must start with http:// or https://)",
    )
    bypass_cache: bool = Field(
        default=False,
        description="If True, skip the local confirmed_phishing DB cache and re-run full analysis",
    )


class ReportingAuthority(BaseModel):
    name: str
    url: str
    reason: str


class GuidanceResult(BaseModel):
    official_website: Optional[str] = None
    reporting_authorities: List[ReportingAuthority] = Field(default_factory=list)
    immediate_actions: List[str] = Field(default_factory=list)
    preventive_measures: List[str] = Field(default_factory=list)
    additional_advice: List[str] = Field(default_factory=list)


class PipelineTimings(BaseModel):
    fast_evidence_latency_ms: Optional[float] = None
    prompt1_latency_ms: Optional[float] = None
    playwright_latency_ms: Optional[float] = None
    total_pipeline_latency_ms: float


class AnalyzeResponse(BaseModel):
    url: str = Field(..., description="The inspected URL")
    verdict: str = Field(..., description="phishing | legitimate | uncertain")
    confidence: float = Field(..., description="LLM confidence score [0.0 – 1.0]")
    severity: Optional[str] = Field(
        default=None, description="low | medium | high | critical"
    )
    cached: bool = Field(
        default=False,
        description="True if this result was served from local DB cache",
    )
    impersonated_entity: Optional[str] = Field(
        default=None, description="Brand / entity being impersonated (if any)"
    )
    scam_category: Optional[str] = Field(
        default=None, description="Category of scam detected"
    )
    targeted_information: List[str] = Field(
        default_factory=list, description="Types of personal information being targeted"
    )
    key_evidence: List[str] = Field(
        default_factory=list, description="Key evidence bullets supporting the verdict"
    )
    summary: str = Field(default="", description="Human-readable analysis summary")
    guidance: Optional[Dict[str, Any]] = Field(
        default=None, description="Citizen safety guidance (only for phishing/uncertain)"
    )
    timings: Optional[Dict[str, Any]] = Field(
        default=None, description="Pipeline latency breakdown in milliseconds"
    )
