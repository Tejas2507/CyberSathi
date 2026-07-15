from typing import List, Optional
from datetime import datetime, timezone
from app.schemas.evidence import (
    Evidence,
    CollectorResult,
    WebsiteEvidence,
    SSLEvidence,
    WHOISEvidence,
    DNSEvidence,
    HTMLEvidence,
    MetadataEvidence,
    HeadersEvidence,
    RedirectsEvidence,
    ScreenshotEvidence,
    PlaywrightEvidence,
    OCREvidence,
    CollectionSummary,
)
from app.schemas.safety import ClassifierResult

class EvidenceBuilder:
    """
    Builder responsible for compiling the list of collector results and
    converting them into validated nested Pydantic models.
    """
    @staticmethod
    def build(
        url: str,
        results: List[CollectorResult],
        prediction_result: Optional[ClassifierResult] = None
    ) -> Evidence:
        # Initialize evidence placeholders
        website = None
        ssl = None
        whois = None
        dns = None
        html = None
        metadata = None
        headers = None
        redirects = None
        screenshot = None
        playwright = None
        ocr = None
        
        success_count = 0
        failure_count = 0
        total_time_ms = 0.0
        collector_metrics = {}
        
        for res in results:
            total_time_ms += res.execution_time_ms
            collector_metrics[res.collector_name] = res.execution_time_ms
            
            if res.success:
                success_count += 1
                data = res.data or {}
                
                # Map raw data dictionaries to specific validated Pydantic schemas
                try:
                    if res.collector_name == "website":
                        website = WebsiteEvidence(**data)
                    elif res.collector_name == "ssl":
                        ssl = SSLEvidence(**data)
                    elif res.collector_name == "whois":
                        whois = WHOISEvidence(**data)
                    elif res.collector_name == "dns":
                        dns = DNSEvidence(**data)
                    elif res.collector_name == "html":
                        html = HTMLEvidence(**data)
                    elif res.collector_name == "metadata":
                        metadata = MetadataEvidence(**data)
                    elif res.collector_name == "headers":
                        headers = HeadersEvidence(**data)
                    elif res.collector_name == "redirects":
                        redirects = RedirectsEvidence(**data)
                    elif res.collector_name == "screenshot":
                        screenshot = ScreenshotEvidence(**data)
                    elif res.collector_name == "playwright":
                        playwright = PlaywrightEvidence(**data)
                    elif res.collector_name == "ocr":
                        ocr = OCREvidence(**data)
                except Exception as e:
                    # In case validation fails for one field, log it, treat it as a failure
                    # or allow it to fall back to None.
                    # We will log the validation error and proceed so the master object still builds.
                    success_count -= 1
                    failure_count += 1
            else:
                failure_count += 1
                
        summary = CollectionSummary(
            success_count=success_count,
            failure_count=failure_count,
            total_time_ms=round(total_time_ms, 2),
            collector_metrics=collector_metrics,
            timestamp=datetime.now(timezone.utc)
        )
        
        # Resolve URL and Classifier Master Fields
        original_url = url
        final_url = playwright.final_url if playwright and playwright.final_url else (website.final_url if website and website.final_url else url)
        
        classifier_name = None
        classifier_probability = None
        classifier_confidence = None
        classifier_label = None
        
        if prediction_result:
            classifier_name = prediction_result.model_version
            classifier_probability = prediction_result.risk_score
            classifier_confidence = prediction_result.confidence
            classifier_label = "phishing" if prediction_result.is_suspicious else "legitimate"
            
        raw_visible_text = html.visible_text if html else None
        rendered_visible_text = playwright.visible_text if playwright else None
        
        viewport_screenshot_path = playwright.screenshot_path if playwright else None
        fullpage_screenshot_path = playwright.full_page_screenshot_path if playwright else None
        
        # Strip large raw and rendered HTML strings from submodels in final Evidence object
        if website:
            website.response_html = None
        if playwright:
            playwright.rendered_html = None
            
        return Evidence(
            url=url,
            prediction_result=prediction_result,
            website=website,
            ssl=ssl,
            whois=whois,
            dns=dns,
            html=html,
            metadata=metadata,
            headers=headers,
            redirects=redirects,
            screenshot=screenshot,
            playwright=playwright,
            ocr=ocr,
            original_url=original_url,
            final_url=final_url,
            classifier_name=classifier_name,
            classifier_probability=classifier_probability,
            classifier_confidence=classifier_confidence,
            classifier_label=classifier_label,
            raw_visible_text=raw_visible_text,
            rendered_visible_text=rendered_visible_text,
            viewport_screenshot_path=viewport_screenshot_path,
            fullpage_screenshot_path=fullpage_screenshot_path,
            collection_summary=summary
        )
