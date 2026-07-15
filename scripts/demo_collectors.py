import asyncio
import sys
import os
import json
import shutil
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse

# Ensure the root of the project is in python path
sys.path.insert(0, str(Path(__file__).parent.parent.resolve()))

from app.models.machine_learning import URLDetector
from app.services.collectors import WebsiteCollector, HTMLCollector, PlaywrightCollector
from app.services.evidence_orchestrator import EvidenceOrchestrator
from app.services.evidence_builder import EvidenceBuilder

async def main():
    if len(sys.argv) < 2:
        print("Usage: uv run python scripts/demo_collectors.py <url>")
        sys.exit(1)
        
    url = sys.argv[1]
    
    # 1. Parse domain and format timestamp for folder name
    parsed_url = urlparse(url)
    domain = parsed_url.netloc or parsed_url.path
    # Clean domain name for safety
    domain = "".join(c for c in domain if c.isalnum() or c in ".-_").strip()
    if not domain:
        domain = "unknown_domain"
        
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_dir = Path("artifacts/demo") / f"{timestamp}_{domain}"
    output_dir.mkdir(parents=True, exist_ok=True)
    
    print("=" * 80)
    print(f"DEMO PIPELINE FOR: {url}")
    print(f"Output directory: {output_dir}")
    print("=" * 80)
    
    # 2. Run URL classifier
    print("\n[Step 1] Running URL Classifier...")
    detector = URLDetector()
    detector.load_model()
    raw_classifier_result = detector.predict(url)
    print(f"Classifier Verdict: {raw_classifier_result['label']} (Prob: {raw_classifier_result['probability']:.4f})")
    
    from app.schemas.safety import ClassifierResult
    from app.settings import settings
    
    classifier_result = ClassifierResult(
        is_suspicious=(raw_classifier_result["label"] == "phishing"),
        risk_score=raw_classifier_result["probability"],
        model_version=settings.CLASSIFIER_MODEL_NAME
    )
    
    # 3. Setup Evidence Orchestrator
    print("\n[Step 2] Setting up Evidence Orchestrator...")
    orchestrator = EvidenceOrchestrator()
    
    # Register our collectors
    website_collector = WebsiteCollector(timeout_sec=15.0)
    html_collector = HTMLCollector()
    playwright_collector = PlaywrightCollector(timeout_sec=30.0)
    
    orchestrator.register_collector(website_collector, timeout_sec=15.0)
    orchestrator.register_collector(html_collector, timeout_sec=20.0)
    orchestrator.register_collector(playwright_collector, timeout_sec=35.0)
    
    # 4. Execute pipeline concurrently
    print("\n[Step 3] Executing collectors in parallel...")
    results = await orchestrator.execute(url)
    
    # 5. Build consolidated Evidence object
    print("\n[Step 4] Building Evidence object...")
    evidence = EvidenceBuilder.build(url, results, classifier_result)
    
    # 6. Save outputs under artifacts/demo/
    print("\n[Step 5] Writing outputs to disk...")
    
    # Write website_raw.html
    raw_html = evidence.raw_html or ""
    with open(output_dir / "website_raw.html", "w", encoding="utf-8") as f:
        f.write(raw_html)
    print(f" - Saved website_raw.html ({len(raw_html)} characters)")
    
    # Write website_rendered.html
    rendered_html = evidence.rendered_html or ""
    with open(output_dir / "website_rendered.html", "w", encoding="utf-8") as f:
        f.write(rendered_html)
    print(f" - Saved website_rendered.html ({len(rendered_html)} characters)")
    
    # Handle screenshots from Playwright
    # Find playwright result
    playwright_res = next((r for r in results if r.collector_name == "playwright"), None)
    if playwright_res and playwright_res.success and playwright_res.data:
        p_data = playwright_res.data
        v_path = p_data.get("screenshot_path")
        f_path = p_data.get("full_page_screenshot_path")
        
        if v_path and os.path.exists(v_path):
            shutil.copy(v_path, output_dir / "viewport.png")
            print(" - Copied viewport.png")
        else:
            print(" - Viewport screenshot not found or failed")
            
        if f_path and os.path.exists(f_path):
            shutil.copy(f_path, output_dir / "fullpage.png")
            print(" - Copied fullpage.png")
        else:
            print(" - Full-page screenshot not found or failed")
    else:
        print(" - Playwright execution failed, skipping screenshots.")
        
    # Write website.json (consolidated Evidence)
    # Convert timestamp to string before serializing
    evidence_dict = json.loads(evidence.model_dump_json())
    with open(output_dir / "website.json", "w", encoding="utf-8") as f:
        json.dump(evidence_dict, f, indent=2)
    print(" - Saved website.json")
    
    # Write collector_output.json (raw results list)
    serialized_results = []
    for r in results:
        res_dict = r.model_dump()
        # Convert datetime to ISO string
        if isinstance(res_dict.get("timestamp"), datetime):
            res_dict["timestamp"] = res_dict["timestamp"].isoformat()
        serialized_results.append(res_dict)
        
    with open(output_dir / "collector_output.json", "w", encoding="utf-8") as f:
        json.dump(serialized_results, f, indent=2)
    print(" - Saved collector_output.json")
    
    print("\n" + "=" * 80)
    print(" PIPELINE EXECUTION COMPLETED SUCCESSFULLY!")
    print(f" Results directory: {output_dir.resolve()}")
    print("=" * 80)

if __name__ == "__main__":
    asyncio.run(main())
