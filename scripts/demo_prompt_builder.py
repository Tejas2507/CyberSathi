import asyncio
import sys
import os
import json
from datetime import datetime
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent.resolve()))

from app.models.machine_learning import URLDetector
from app.services.collectors import (
    WebsiteCollector, HTMLCollector, PlaywrightCollector,
    WHOISCollector, SSLCollector
)
from app.services.evidence_orchestrator import EvidenceOrchestrator
from app.services.evidence_builder import EvidenceBuilder
from app.prompts.forensic_report_builder import build_security_prompt, estimate_tokens, PromptBundle
from app.schemas.safety import ClassifierResult
from app.settings import settings

async def main():
    if len(sys.argv) < 2:
        print("Usage: uv run python scripts/demo_prompt_builder.py <url>")
        sys.exit(1)
        
    url = sys.argv[1]
    
    print("=" * 80)
    print(f"RUNNING PROMPT BUILDER DEMO FOR: {url}")
    print("=" * 80)
    
    # 1. Run URL Classifier
    print("\n[Step 1] Running URL Classifier...")
    detector = URLDetector()
    detector.load_model()
    raw_clf = detector.predict(url)
    
    classifier_result = ClassifierResult(
        is_suspicious=(raw_clf["label"] == "phishing"),
        risk_score=raw_clf["probability"],
        confidence=raw_clf.get("confidence", 0.0),
        model_version=settings.CLASSIFIER_MODEL_NAME
    )
    print(f"ML Classifier verdict: {classifier_result.is_suspicious} (Prob: {classifier_result.risk_score:.4f}, Confidence: {classifier_result.confidence})")
    
    # 2. Setup Orchestrator & Register Active collectors (Part 1 Freeze list)
    print("\n[Step 2] Setting up Evidence Orchestrator...")
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
    
    # 3. Execute
    print("\n[Step 3] Executing active collectors...")
    start_time = asyncio.get_event_loop().time()
    results = await orchestrator.execute(url)
    pipeline_duration_ms = (asyncio.get_event_loop().time() - start_time) * 1000
    
    # 4. Build consolidated Evidence object
    print("\n[Step 4] Building Evidence object...")
    evidence = EvidenceBuilder.build(url, results, classifier_result)
    
    # Dump final Evidence object schema
    evidence_json = evidence.model_dump_json(indent=2)
    # Print individual collector metrics
    print("\n[Step 5] Timing Metrics:")
    for name, dur in evidence.collection_summary.collector_metrics.items():
        print(f" - {name}: {dur:.2f} ms")
    print(f" - Total Pipeline execution: {pipeline_duration_ms:.2f} ms")
    
    # 5. Generate Prompt 1 (PromptBundle)
    print("\n[Step 6] Generating Forensic Assessment Prompt Bundle (Prompt 1)...")
    bundle = build_security_prompt(evidence)
    
    print("\n" + "=" * 50)
    print("PROMPT STATISTICS (PROMPT BUNDLE)")
    print("=" * 50)
    print(f"Character Count: {len(bundle.text_prompt)}")
    print(f"Estimated Tokens: {bundle.estimated_tokens}")
    print(f"Image Count: {bundle.image_count}")
    print(f"Image Attachments (Paths): {bundle.image_paths}")
    
    print("\n" + "=" * 50)
    print("PROMPT PREVIEW (First 2000 Chars)")
    print("=" * 50)
    print(bundle.text_prompt[:2000])
    if len(bundle.text_prompt) > 2000:
        print("\n... [truncated] ...")
    print("=" * 80)
    
    # Print out full final Evidence object to assist walkthrough drafting
    print("\n### FULL FINAL EVIDENCE OBJECT JSON ###")
    print(evidence_json)
    print("=" * 80)

if __name__ == "__main__":
    asyncio.run(main())
