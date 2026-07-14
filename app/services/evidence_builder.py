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
            ocr=ocr,
            collection_summary=summary
        )
