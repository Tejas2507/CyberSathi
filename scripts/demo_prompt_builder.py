import asyncio
import sys
import os
import json
import time
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent.resolve()))

from app.models.machine_learning import URLDetector
from app.services.collectors import (
    WebsiteCollector, HTMLCollector, PlaywrightCollector,
    WHOISCollector, SSLCollector
)
from app.services.evidence_orchestrator import EvidenceOrchestrator
from app.prompts.forensic_report_builder import build_security_prompt, estimate_tokens
from app.settings import settings

# Mock LLM Caller implementing stage 1 and stage 2 verifications
async def mock_llm_caller(prompt_text: str, image_paths: list) -> dict:
    await asyncio.sleep(0.5)  # Simulate network latency of API call
    
    prompt_lower = prompt_text.lower()
    is_stage2 = "screenshot of the webpage is attached." in prompt_text or len(image_paths) > 0
    
    if "google.com" in prompt_lower:
        return {
            "verdict": "legitimate",
            "confidence": 0.99,
            "severity": "low",
            "impersonated_entity": "",
            "scam_category": "",
            "targeted_information": [],
            "key_evidence": [
                "Domain is extremely old (10000+ days)",
                "SSL certificate issuer is Google Trust Services",
                "HTTP response status is 200 OK"
            ],
            "summary": "Verified official search engine home page.",
            "requires_more_evidence": False,
            "required_evidence": [],
            "requires_guidance": False
        }
    elif "uidai.gov.in" in prompt_lower:
        return {
            "verdict": "legitimate",
            "confidence": 0.98,
            "severity": "low",
            "impersonated_entity": "",
            "scam_category": "",
            "targeted_information": [],
            "key_evidence": [
                "Official Indian government domain (.gov.in)",
                "SSL certificate issued to Unique Identification Authority of India",
                "Domain registered since 2009"
            ],
            "summary": "Official UIDAI Aadhaar portal language selection page.",
            "requires_more_evidence": False,
            "required_evidence": [],
            "requires_guidance": False
        }
    elif "onlinesbi.sbi" in prompt_lower:
        if not is_stage2:
            return {
                "verdict": "uncertain",
                "confidence": 0.40,
                "severity": "medium",
                "impersonated_entity": "State Bank of India",
                "scam_category": "Banking",
                "targeted_information": [],
                "key_evidence": [
                    "High ML risk score of 0.91",
                    "Domain has active redirections",
                    "Insufficient visual layout data to confirm security posture"
                ],
                "summary": "Initial evaluation is suspicious but requires screenshot confirmation.",
                "requires_more_evidence": True,
                "required_evidence": ["viewport_screenshot"],
                "requires_guidance": False
            }
        else:
            return {
                "verdict": "phishing",
                "confidence": 0.95,
                "severity": "critical",
                "impersonated_entity": "State Bank of India",
                "scam_category": "Banking",
                "targeted_information": ["Passwords", "OTPs", "Card details"],
                "key_evidence": [
                    "Suspicious redirect to onlinesbi.sbi.bank.in",
                    "Visual rendering shows form mimicking personal banking login",
                    "Mismatched SSL organizational fields"
                ],
                "summary": "Phishing portal harvesting State Bank of India login credentials.",
                "requires_more_evidence": False,
                "required_evidence": [],
                "requires_guidance": True
            }
    else:
        return {
            "verdict": "uncertain",
            "confidence": 0.50,
            "severity": "medium",
            "impersonated_entity": "",
            "scam_category": "",
            "targeted_information": [],
            "key_evidence": ["Unknown domain"],
            "summary": "Undetermined status.",
            "requires_more_evidence": not is_stage2,
            "required_evidence": ["viewport_screenshot"] if not is_stage2 else [],
            "requires_guidance": False
        }

async def run_demo(url: str):
    print("\n" + "=" * 80)
    print(f"ADAPTIVE ORCHESTRATION DEMO FOR: {url}")
    print("=" * 80)
    
    # Instantiate collectors
    orchestrator = EvidenceOrchestrator()
    website_collector = WebsiteCollector(timeout_sec=15.0)
    html_collector = HTMLCollector()
    playwright_collector = PlaywrightCollector(timeout_sec=30.0, wait_until="load", capture_full_page=False)
    whois_collector = WHOISCollector()
    ssl_collector = SSLCollector()
    
    orchestrator.register_collector(website_collector, timeout_sec=15.0)
    orchestrator.register_collector(html_collector, timeout_sec=20.0)
    orchestrator.register_collector(playwright_collector, timeout_sec=35.0)
    orchestrator.register_collector(whois_collector, timeout_sec=15.0)
    orchestrator.register_collector(ssl_collector, timeout_sec=10.0)
    
    detector = URLDetector()
    detector.load_model()
    
    # Run adaptive execution
    print("\n[Timeline] Triggering adaptive execution...")
    start_time = time.perf_counter()
    
    result = await orchestrator.execute_adaptive(url, detector, mock_llm_caller)
    
    total_duration = (time.perf_counter() - start_time) * 1000
    
    # Output adaptive execution stats
    print("\n" + "-" * 50)
    print("ADAPTIVE RUN METRICS")
    print("-" * 50)
    print(f"Verdict Verdict JSON: {json.dumps(result['verdict_json'], indent=2)}")
    print(f"Playwright Cancelled: {result['playwright_cancelled']}")
    print(f"Playwright Completed Early: {result['playwright_already_completed']}")
    
    timings = result["timings"]
    print(f"\nTimeline Logs:")
    print(f" - Fast Evidence Latency: {timings['fast_evidence_latency_ms']:.2f} ms")
    print(f" - Playwright speculative execution duration: {timings['playwright_latency_ms']:.2f} ms")
    print(f" - LLM Verification Latency: {timings['prompt1_latency_ms']:.2f} ms")
    print(f" - Total Adaptive Pipeline Latency: {timings['total_pipeline_latency_ms']:.2f} ms")
    
    # Calculate Latency Savings
    # Previous sequential/blocking pipeline time: Fast Evidence + Playwright + Prompt 1
    previous_latency_estimate = timings['fast_evidence_latency_ms'] + timings['playwright_latency_ms'] + timings['prompt1_latency_ms']
    if result['playwright_cancelled']:
        # If cancelled, previous pipeline would have still waited for playwright to complete (~3-10s depending on target)
        # We saved playwright execution time!
        savings = previous_latency_estimate - total_duration
    else:
        # If stage 2 was needed, we still save because playwright ran concurrently (in parallel)
        # instead of sequentially after fast evidence.
        savings = previous_latency_estimate - total_duration
        
    print(f" - Previous Pipeline Latency (Estimate): {previous_latency_estimate:.2f} ms")
    print(f" - Latency Savings: {savings:.2f} ms")
    print("=" * 80)

async def main():
    urls = [
        "https://google.com",
        "https://uidai.gov.in",
        "https://onlinesbi.sbi"
    ]
    
    for url in urls:
        await run_demo(url)

if __name__ == "__main__":
    asyncio.run(main())
