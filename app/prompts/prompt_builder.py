from typing import Dict, Any, Tuple, Optional
import json
from app.schemas.evidence import Evidence

def estimate_tokens(text: str) -> int:
    """Simple token estimator based on ~4 characters per token."""
    return len(text) // 4

def build_security_prompt(evidence: Evidence) -> Tuple[str, Dict[str, Any], Optional[str]]:
    """
    Builds the forensic investigation report prompt (Template 1) for the LLM.
    Returns:
        - prompt_text: The complete prompt string.
        - structured_evidence: Dictionary of structured evidence extracted.
        - screenshot_path: Path to the viewport screenshot for multimodal inputs.
    """
    # Extract sub-components safely
    website = evidence.website
    whois = evidence.whois
    ssl = evidence.ssl
    html = evidence.html
    playwright = evidence.playwright
    
    # 1. Structured evidence dict
    structured_evidence = {
        "url_information": {
            "original_url": evidence.original_url or evidence.url,
            "final_url": evidence.final_url or (website.final_url if website else evidence.url)
        },
        "url_classifier": {
            "classifier_name": evidence.classifier_name,
            "classifier_probability": evidence.classifier_probability,
            "classifier_confidence": evidence.classifier_confidence,
            "classifier_label": evidence.classifier_label
        },
        "website": {
            "status_code": website.status_code if website else None,
            "response_headers": website.response_headers if website else {},
            "response_size": website.response_size if website else None,
            "redirect_chain": website.redirect_chain if website else []
        },
        "whois": {
            "domain_age": whois.domain_age if whois else None,
            "creation_date": whois.creation_date if whois else None,
            "expiry": whois.expiry if whois else None,
            "registrar": whois.registrar if whois else None,
            "organization": whois.organization if whois else None
        },
        "ssl": {
            "issuer": ssl.issuer if ssl else None,
            "subject": ssl.subject if ssl else None,
            "organization": ssl.organization if ssl else None,
            "valid_from": ssl.valid_from if ssl else None,
            "valid_to": ssl.valid_to if ssl else None,
            "san": ssl.san if ssl else [],
            "tls_version": ssl.tls_version if ssl else None
        },
        "html": {
            "title": html.page_title if html else None,
            "meta_description": html.meta_description if html else None,
            "forms_count": html.forms_count if html else 0,
            "password_input_count": html.password_input_count if html else 0,
            "email_input_count": html.email_input_count if html else 0,
            "hidden_input_count": html.hidden_input_count if html else 0,
            "iframe_count": html.iframe_count if html else 0,
            "external_script_count": html.external_script_count if html else 0,
            "suspicious_javascript_indicators": html.suspicious_js_indicators if html else [],
            "favicon_url": html.favicon_url if html else None,
            "canonical_url": html.canonical_url if html else None
        },
        "playwright": {
            "rendered_visible_text": playwright.visible_text if playwright else None,
            "viewport_screenshot_path": evidence.viewport_screenshot_path,
            "fullpage_screenshot_path": evidence.fullpage_screenshot_path,
            "rendered_page_title": playwright.page_title if playwright else None,
            "javascript_redirect_detected": playwright.js_redirects_detected if playwright else False,
            "failed_request_count": len(playwright.failed_requests) if playwright and playwright.failed_requests else 0,
            "console_error_count": len(playwright.console_errors) if playwright and playwright.console_errors else 0,
            "page_load_time_ms": playwright.load_time_ms if playwright else None
        }
    }
    
    # 2. Format Prompt Text
    lines = [
        "CyberSathi Phishing Investigation Report",
        "=========================================",
        "",
        "Machine Learning Assessment",
        "---------------------------",
        f"Classifier Name: {evidence.classifier_name or 'Unknown'}",
        f"Probability Score: {evidence.classifier_probability if evidence.classifier_probability is not None else 'N/A'}",
        f"Confidence Score: {evidence.classifier_confidence if evidence.classifier_confidence is not None else 'N/A'}",
        f"Label Verdict: {evidence.classifier_label or 'N/A'}",
        "",
        "IMPORTANT: The classifier prediction is only an initial assessment. Do NOT assume it is correct. Review the evidence independently.",
        "",
        "Website Summary",
        "---------------",
        f"HTTP Status Code: {structured_evidence['website']['status_code'] or 'N/A'}",
        f"Final URL: {structured_evidence['url_information']['final_url']}",
        f"Redirect Chain: {' -> '.join(structured_evidence['website']['redirect_chain']) if structured_evidence['website']['redirect_chain'] else 'None'}",
        "",
        "WHOIS Details",
        "-------------",
        f"Domain Age: {structured_evidence['whois']['domain_age'] if structured_evidence['whois']['domain_age'] is not None else 'N/A'} days",
        f"Creation Date: {structured_evidence['whois']['creation_date'] or 'N/A'}",
        f"Expiry Date: {structured_evidence['whois']['expiry'] or 'N/A'}",
        f"Registrar: {structured_evidence['whois']['registrar'] or 'N/A'}",
        f"Registrant Organization: {structured_evidence['whois']['organization'] or 'N/A'}",
        "",
        "SSL TLS Properties",
        "------------------",
        f"Issuer: {structured_evidence['ssl']['issuer'] or 'N/A'}",
        f"Subject: {structured_evidence['ssl']['subject'] or 'N/A'}",
        f"Organization: {structured_evidence['ssl']['organization'] or 'N/A'}",
        f"Validity Range: {structured_evidence['ssl']['valid_from'] or 'N/A'} to {structured_evidence['ssl']['valid_to'] or 'N/A'}",
        f"Subject Alternative Names (SAN): {', '.join(structured_evidence['ssl']['san']) if structured_evidence['ssl']['san'] else 'None'}",
        f"TLS Version: {structured_evidence['ssl']['tls_version'] or 'N/A'}",
        "",
        "HTML Document Summary (Static Parse)",
        "------------------------------------",
        f"Page Title: {structured_evidence['html']['title'] or 'N/A'}",
        f"Meta Description: {structured_evidence['html']['meta_description'] or 'N/A'}",
        f"Forms Count: {structured_evidence['html']['forms_count']}",
        f"Password Inputs: {structured_evidence['html']['password_input_count']}",
        f"Hidden Inputs: {structured_evidence['html']['hidden_input_count']}",
        f"Scripts Count: {structured_evidence['html']['external_script_count']} external",
        f"Suspicious JS Keywords Found: {', '.join(structured_evidence['html']['suspicious_javascript_indicators']) if structured_evidence['html']['suspicious_javascript_indicators'] else 'None'}",
        "",
        "Browser Settle Summary (Dynamic Render)",
        "--------------------------------------",
        f"Rendered Page Title: {structured_evidence['playwright']['rendered_page_title'] or 'N/A'}",
        f"JS Redirect Detected: {structured_evidence['playwright']['javascript_redirect_detected']}",
        f"Failed Network Requests: {structured_evidence['playwright']['failed_request_count']}",
        f"Console Errors: {structured_evidence['playwright']['console_error_count']}",
        f"Page Load Time: {structured_evidence['playwright']['page_load_time_ms'] if structured_evidence['playwright']['page_load_time_ms'] is not None else 'N/A'} ms",
        f"Rendered Text Size: {len(structured_evidence['playwright']['rendered_visible_text'] or '')} characters",
        "",
        "Rendered Visible Text Preview (First 1500 Chars):",
        f"{structured_evidence['playwright']['rendered_visible_text'][:1500] if structured_evidence['playwright']['rendered_visible_text'] else 'None'}",
        "",
        "Screenshot Info",
        "---------------",
        f"Viewport Screenshot: Attached. Exposes local filepath: {evidence.viewport_screenshot_path or 'N/A'}",
        "",
        "========================================",
        "LLM FORENSIC ANALYSIS COMMANDS",
        "========================================",
        "Perform a cybersecurity forensic review on the website evidence above.",
        "Your task is to:",
        "1. Determine whether the website is phishing.",
        "2. Explain the forensic reasoning step by step.",
        "3. Estimate your evaluation confidence (0.0 to 1.0).",
        "4. Identify the brand or organization impersonated (if any).",
        "5. Identify the scam category (e.g., Banking, Social Media, Credential Harvesting, Support, Govt, E-commerce, None).",
        "6. Identify targeted credentials/information (e.g. Passwords, OTPs, Card details, Personal info).",
        "7. Flag whether the target requires guidance advisory.",
        "",
        "You must return STRICT JSON only. No markdown formatting blocks (e.g. do NOT use ```json).",
        "No conversational introduction, explanations, or chain of thought text.",
        "Your output must be a single parsable JSON object matching this schema:",
        "{",
        '  "is_phishing": bool,',
        '  "confidence": float,',
        '  "reasoning": [string],',
        '  "impersonated_entity": string,',
        '  "scam_category": string,',
        '  "targeted_information": [string],',
        '  "summary": string,',
        '  "requires_guidance": bool',
        "}"
    ]
    
    prompt_text = "\n".join(lines)
    return prompt_text, structured_evidence, evidence.viewport_screenshot_path

def build_guidance_prompt(security_verdict_json: Dict[str, Any]) -> str:
    """
    Builds the guidance and citizen safety prompt (Template 2) for the LLM.
    Args:
        - security_verdict_json: Dict corresponding to output structure of Prompt 1.
    """
    reasoning = ", ".join(security_verdict_json.get("reasoning", [])) or "N/A"
    impersonated = security_verdict_json.get("impersonated_entity") or "Unknown Entity"
    category = security_verdict_json.get("scam_category") or "Phishing"
    targeted = ", ".join(security_verdict_json.get("targeted_information", [])) or "Credentials"
    summary = security_verdict_json.get("summary") or "Suspicious phishing website copy."
    
    lines = [
        "CyberSathi Phishing Mitigation and Guidance Request",
        "===================================================",
        "",
        "The following security analysis has confirmed a phishing threat:",
        f" - Impersonated Entity: {impersonated}",
        f" - Scam Category: {category}",
        f" - Targeted Credentials / Info: {targeted}",
        f" - Summary: {summary}",
        f" - Forensic Reasoning: {reasoning}",
        "",
        "INSTRUCTIONS FOR THE LLM:",
        "Assuming this phishing threat has been confirmed, generate a citizen guidance response for the victim.",
        "Your response must cover the following sections clearly:",
        "",
        "1. IMMEDIATE ACTIONS",
        "   - Crucial urgent actions the user should take right now (e.g. block credit cards, change credentials, freeze bank accounts).",
        "",
        "2. PREVENTIVE MEASURES",
        "   - How to protect their accounts/systems from future threats (e.g. enable 2FA, secure hardware keys, DNS filtering).",
        "",
        "3. REPORTING AUTHORITIES",
        "   - Official law enforcement portals or corporate platforms where this incident should be reported (e.g., National Cyber Crime Reporting Portal in India [cybercrime.gov.in], or the specific official phishing report channel of the impersonated brand).",
        "",
        "4. OFFICIAL WEBSITE",
        "   - Provide the legitimate corporate/government domain address of the impersonated organization to guide the user safely.",
        "",
        "5. ADDITIONAL ADVICE",
        "   - Helpful hints for spotting fake links or social engineering indicators.",
        "",
        "Provide direct, supportive, and reassuring advice written for a distressed citizen. Keep paragraphs structured and easy to digest."
    ]
    return "\n".join(lines)
