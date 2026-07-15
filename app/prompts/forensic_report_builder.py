from typing import Dict, Any, Tuple, Optional, List
import json
from pathlib import Path
from pydantic import BaseModel, Field
from app.schemas.evidence import Evidence

class PromptBundle(BaseModel):
    text_prompt: str = Field(..., description="The structured text forensic report prompt")
    image_paths: List[Path] = Field(default_factory=list, description="List of local paths to screenshots for multimodal consumption")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Metadata associated with the prompt run")
    estimated_tokens: int = Field(..., description="Estimated token count of the text prompt")
    image_count: int = Field(0, description="Number of attached images")

def estimate_tokens(text: str) -> int:
    """Simple token estimator based on ~4 characters per token."""
    return len(text) // 4

def build_security_prompt(evidence: Evidence) -> PromptBundle:
    """
    Builds the forensic report (Prompt 1) for LLM consumption.
    The LLM acts as an adaptive verifier. If evidence is sufficient,
    it returns requires_more_evidence=false. Else it requests the screenshot.
    """
    website = evidence.website
    whois = evidence.whois
    ssl = evidence.ssl
    html = evidence.html
    playwright = evidence.playwright
    
    # Compute redirect count
    redirect_count = 0
    if website and website.redirect_chain:
        redirect_count = max(0, len(website.redirect_chain) - 1)
        
    # Viewport screenshot setup
    image_paths = []
    has_screenshot = False
    if evidence.viewport_screenshot_path:
        image_paths.append(Path(evidence.viewport_screenshot_path))
        has_screenshot = True
        
    # Build report body
    lines = [
        "You are an experienced cybersecurity analyst.",
        "You have received an initial machine-learning assessment and a collection of website evidence.",
        "The machine learning classifier is only an initial signal.",
        "Do NOT assume it is correct.",
        "Your task is to determine whether the currently available evidence is sufficient to confidently classify the website.",
        "If it is sufficient, return a verdict.",
        "If it is NOT sufficient, request only the additional evidence that is actually required.",
        "Never request unnecessary evidence.",
        "Return STRICT JSON only.",
        "Do not return markdown.",
        "Do not reveal chain-of-thought.",
        "",
        "==================================================",
        "FORENSIC EVIDENCE REPORT",
        "==================================================",
        "",
        "--- 1. Viewport Screenshot ---",
        "A rendered screenshot of the webpage has been attached." if has_screenshot else "A rendered screenshot of the webpage is NOT attached yet.",
        "",
        "--- 2. Rendered Visible Text ---",
        f"{playwright.visible_text[:2000] if playwright and playwright.visible_text else 'None'}",
        "",
        "--- 3. Machine Learning Assessment ---",
        f"Classifier: {evidence.classifier_name or 'Unknown'}",
        f"Probability: {evidence.classifier_probability if evidence.classifier_probability is not None else 'N/A'}",
        f"Confidence: {evidence.classifier_confidence if evidence.classifier_confidence is not None else 'N/A'}",
        "",
        "--- 4. WHOIS ---",
        f"Organization: {whois.organization or 'N/A' if whois else 'N/A'}",
        f"Registrar: {whois.registrar or 'N/A' if whois else 'N/A'}",
        f"Domain Age: {whois.domain_age if whois and whois.domain_age is not None else 'N/A'} days",
        f"Creation Date: {whois.creation_date or 'N/A' if whois else 'N/A'}",
        f"Expiry: {whois.expiry or 'N/A' if whois else 'N/A'}",
        "",
        "--- 5. SSL ---",
        f"Organization: {ssl.organization or 'N/A' if ssl else 'N/A'}",
        f"Issuer: {ssl.issuer or 'N/A' if ssl else 'N/A'}",
        f"Expiry: {ssl.expiry or 'N/A' if ssl else 'N/A'}",
        "",
        "--- 6. Website Summary / HTML Metadata ---",
        f"Final URL: {evidence.final_url or evidence.url}",
        f"HTTP Status: {website.status_code if website else 'N/A'}",
        f"Redirect Count: {redirect_count}",
        f"Title: {html.page_title or 'N/A' if html else 'N/A'}",
        f"Meta Description: {html.meta_description or 'N/A' if html else 'N/A'}",
        f"Forms: {html.forms_count if html else 0}",
        f"Password Fields: {html.password_input_count if html else 0}",
        f"Hidden Inputs: {html.hidden_input_count if html else 0}",
        f"External Scripts: {html.external_script_count if html else 0}",
        f"Suspicious Javascript: {', '.join(html.suspicious_js_indicators) if html and html.suspicious_js_indicators else 'None'}",
        "",
        "--- 7. Browser Summary ---",
        f"Rendered Page Title: {playwright.page_title or 'N/A' if playwright else 'N/A'}",
        f"Javascript Redirect: {playwright.js_redirects_detected if playwright else False}",
        f"Console Errors: {len(playwright.console_errors) if playwright and playwright.console_errors else 0}",
        f"Failed Requests: {len(playwright.failed_requests) if playwright and playwright.failed_requests else 0}",
        f"Page Load Time: {playwright.load_time_ms if playwright and playwright.load_time_ms is not None else 'N/A'} ms",
        "",
        "A rendered screenshot of the webpage is attached." if has_screenshot else "A rendered screenshot of the webpage is NOT attached.",
        "",
        "==================================================",
        "JSON SCHEMA SPECIFICATION",
        "==================================================",
        "Your JSON output must match the following schema exactly:",
        "{",
        '  "verdict": "phishing|legitimate|uncertain",',
        '  "confidence": 0.0,',
        '  "severity": "low|medium|high|critical",',
        '  "impersonated_entity": "string",',
        '  "scam_category": "string",',
        '  "targeted_information": ["string"],',
        '  "key_evidence": [',
        '    "concise evidence bullet 1",',
        '    "concise evidence bullet 2"',
        '  ],',
        '  "summary": "string",',
        '  "requires_more_evidence": bool,',
        '  "required_evidence": ["viewport_screenshot"],',
        '  "requires_guidance": bool',
        "}",
        "Rules:",
        "- If confidence is high, requires_more_evidence must be false.",
        "- If confidence is low, requires_more_evidence must be true.",
        "- required_evidence may contain 'viewport_screenshot' only."
    ]
    
    text_prompt = "\n".join(lines)
    tokens = estimate_tokens(text_prompt)
    
    return PromptBundle(
        text_prompt=text_prompt,
        image_paths=image_paths,
        metadata={
            "original_url": evidence.original_url,
            "final_url": evidence.final_url,
            "classifier_verdict": evidence.classifier_label
        },
        estimated_tokens=tokens,
        image_count=len(image_paths)
    )

def build_guidance_prompt(security_verdict_json: Dict[str, Any]) -> PromptBundle:
    """
    Builds the safety advisory report (Prompt 2) for LLM consumption.
    Assumes phishing has already been confirmed.
    Requests structured mitigation JSON, instructing the LLM to search for live details.
    """
    lines = [
        "A phishing attack has been confirmed. Your task is to generate structured citizen guidance mitigation.",
        "Do NOT repeat the security analysis or explain why the site is phishing.",
        "You must use web search (if available) to retrieve the current official reporting portals and URLs for the impersonated entity.",
        "",
        "Confirmed Threat Summary:",
        f" - Impersonated Entity: {security_verdict_json.get('impersonated_entity', 'Unknown')}",
        f" - Scam Category: {security_verdict_json.get('scam_category', 'Phishing')}",
        f" - Targeted Information: {', '.join(security_verdict_json.get('targeted_information', []))}",
        "",
        "Return STRICT JSON only matching this schema:",
        "{",
        '  "official_website": "string (the real official website of the impersonated brand)",',
        '  "reporting_authorities": [',
        '    {',
        '       "name": "string (name of the cyber crime or anti-phishing authority)",',
        '       "url": "string (url of reporting portal)",',
        '       "reason": "string (why report here)"',
        '    }',
        '  ],',
        '  "immediate_actions": [',
        '     "urgent action bullet 1",',
        '     "urgent action bullet 2"',
        '  ],',
        '  "preventive_measures": [',
        '     "future safety tip 1",',
        '     "future safety tip 2"',
        '  ],',
        '  "additional_advice": [',
        '     "helpful social engineering check 1",',
        '     "helpful social engineering check 2"',
        '  ]',
        "}",
        "",
        "Do NOT return markdown. Do NOT return code blocks. Do NOT reveal chain of thought."
    ]
    
    text_prompt = "\n".join(lines)
    tokens = estimate_tokens(text_prompt)
    
    return PromptBundle(
        text_prompt=text_prompt,
        image_paths=[],
        metadata={"scam_category": security_verdict_json.get("scam_category")},
        estimated_tokens=tokens,
        image_count=0
    )
