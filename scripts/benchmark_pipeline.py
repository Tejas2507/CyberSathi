import asyncio
import sys
import time
import os
import json
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent.resolve()))

from app.models.machine_learning import URLDetector
from app.services.collectors import (
    WebsiteCollector, HTMLCollector, PlaywrightCollector,
    WHOISCollector, SSLCollector, DNSCollector
)
from app.services.evidence_orchestrator import EvidenceOrchestrator
from app.services.evidence_builder import EvidenceBuilder
from app.schemas.safety import ClassifierResult
from app.settings import settings

async def run_single_pipeline(url: str, wait_until: str = "networkidle", capture_full_page: bool = True):
    """Runs the complete pipeline for a single URL and returns detailed metrics."""
    # 1. Run ML Classifier
    detector = URLDetector()
    detector.load_model()
    start_clf = time.perf_counter()
    raw_clf = detector.predict(url)
    clf_time = (time.perf_counter() - start_clf) * 1000
    
    classifier_result = ClassifierResult(
        is_suspicious=(raw_clf["label"] == "phishing"),
        risk_score=raw_clf["probability"],
        model_version=settings.CLASSIFIER_MODEL_NAME
    )
    
    # 2. Setup Orchestrator
    orchestrator = EvidenceOrchestrator()
    website_collector = WebsiteCollector(timeout_sec=15.0)
    html_collector = HTMLCollector()
    playwright_collector = PlaywrightCollector(timeout_sec=30.0, wait_until=wait_until, capture_full_page=capture_full_page)
    whois_collector = WHOISCollector()
    ssl_collector = SSLCollector()
    
    orchestrator.register_collector(website_collector, timeout_sec=15.0)
    orchestrator.register_collector(html_collector, timeout_sec=20.0)
    orchestrator.register_collector(playwright_collector, timeout_sec=35.0)
    orchestrator.register_collector(whois_collector, timeout_sec=15.0)
    orchestrator.register_collector(ssl_collector, timeout_sec=10.0)
    
    # 3. Execute
    start_pipeline = time.perf_counter()
    results = await orchestrator.execute(url)
    pipeline_time = (time.perf_counter() - start_pipeline) * 1000
    
    # 4. Build Evidence Object
    evidence = EvidenceBuilder.build(url, results, classifier_result)
    
    return {
        "url": url,
        "classifier_verdict": raw_clf["label"],
        "classifier_prob": raw_clf["probability"],
        "classifier_time_ms": clf_time,
        "pipeline_time_ms": pipeline_time,
        "results": results,
        "evidence": evidence
    }

async def benchmark_experiments():
    """Runs all the experiments for Parts 1, 2, 3, 5, 6, 7."""
    targets = ["https://google.com", "https://uidai.gov.in", "https://onlinesbi.sbi"]
    extra_whois_targets = ["https://github.com", "https://icloud.com"]
    all_targets = targets + extra_whois_targets
    
    print("\n" + "=" * 80)
    print("RUNNING ALL BENCHMARK EXPERIMENTS")
    print("=" * 80)
    
    # --- Part 1: Playwright Navigation Strategies ---
    print("\n--- Part 1: Playwright Navigation Strategies ---")
    strategies = ["load", "domcontentloaded", "networkidle"]
    strategy_results = []
    
    for url in targets:
        for strat in strategies:
            print(f"Benchmarking {url} with strategy '{strat}'...")
            try:
                collector = PlaywrightCollector(timeout_sec=20.0, wait_until=strat, capture_full_page=False)
                start = time.perf_counter()
                res = await collector.collect(url)
                latency = (time.perf_counter() - start) * 1000
                
                html_size = len(res.data.get("rendered_html") or "") if res.success and res.data else 0
                text_len = len(res.data.get("visible_text") or "") if res.success and res.data else 0
                failed_reqs = len(res.data.get("failed_requests") or []) if res.success and res.data else 0
                console_errs = len(res.data.get("console_errors") or []) if res.success and res.data else 0
                
                strategy_results.append({
                    "url": url,
                    "strategy": strat,
                    "latency_ms": latency,
                    "success": res.success,
                    "html_size": html_size,
                    "text_len": text_len,
                    "failed_reqs": failed_reqs,
                    "console_errs": console_errs
                })
            except Exception as e:
                print(f"Error benchmarking {url} with {strat}: {e}")
                
    # --- Part 2: Screenshot Cost ---
    print("\n--- Part 2: Screenshot Cost ---")
    screenshot_results = []
    for url in targets:
        for capture_full in [False, True]:
            desc = "Viewport only" if not capture_full else "Viewport + Fullpage"
            print(f"Benchmarking screenshot cost on {url} ({desc})...")
            try:
                collector = PlaywrightCollector(timeout_sec=20.0, wait_until="load", capture_full_page=capture_full)
                start = time.perf_counter()
                res = await collector.collect(url)
                latency = (time.perf_counter() - start) * 1000
                
                v_size = 0
                f_size = 0
                if res.success and res.data:
                    v_path = res.data.get("screenshot_path")
                    f_path = res.data.get("full_page_screenshot_path")
                    if v_path and os.path.exists(v_path):
                        v_size = os.path.getsize(v_path)
                    if f_path and os.path.exists(f_path):
                        f_size = os.path.getsize(f_path)
                        
                screenshot_results.append({
                    "url": url,
                    "description": desc,
                    "latency_ms": latency,
                    "viewport_size_bytes": v_size,
                    "fullpage_size_bytes": f_size
                })
            except Exception as e:
                print(f"Error benchmarking screenshot on {url}: {e}")
                
    # --- Part 5: WHOIS Experiment ---
    print("\n--- Part 5: WHOIS Experiment ---")
    whois_results = []
    whois_collector = WHOISCollector()
    for url in all_targets:
        print(f"Benchmarking WHOIS on {url}...")
        start = time.perf_counter()
        res = await whois_collector.collect(url)
        latency = (time.perf_counter() - start) * 1000
        
        domain_age = res.data.get("domain_age") if res.success and res.data else None
        registrar = res.data.get("registrar") if res.success and res.data else None
        
        whois_results.append({
            "url": url,
            "success": res.success,
            "latency_ms": latency,
            "domain_age": domain_age,
            "registrar": registrar,
            "errors": res.errors
        })
        
    # --- Part 6: SSL Experiment ---
    print("\n--- Part 6: SSL Experiment ---")
    ssl_results = []
    ssl_collector = SSLCollector()
    for url in all_targets:
        print(f"Benchmarking SSL on {url}...")
        start = time.perf_counter()
        res = await ssl_collector.collect(url)
        latency = (time.perf_counter() - start) * 1000
        
        issuer = res.data.get("issuer") if res.success and res.data else None
        tls_version = res.data.get("tls_version") if res.success and res.data else None
        
        ssl_results.append({
            "url": url,
            "success": res.success,
            "latency_ms": latency,
            "issuer": issuer,
            "tls_version": tls_version,
            "errors": res.errors
        })
        
    # --- Part 7: DNS Experiment ---
    print("\n--- Part 7: DNS Experiment ---")
    dns_results = []
    dns_collector = DNSCollector()
    for url in all_targets:
        print(f"Benchmarking DNS on {url}...")
        start = time.perf_counter()
        res = await dns_collector.collect(url)
        latency = (time.perf_counter() - start) * 1000
        
        a_records = len(res.data.get("A") or []) if res.success and res.data else 0
        mx_records = len(res.data.get("MX") or []) if res.success and res.data else 0
        
        dns_results.append({
            "url": url,
            "success": res.success,
            "latency_ms": latency,
            "a_records_count": a_records,
            "mx_records_count": mx_records,
            "errors": res.errors
        })
        
    # --- OUTPUT MARKDOWN TABLES FOR WALKTHROUGH ---
    print("\n" + "=" * 80)
    print("BENCHMARK EXPERIMENTS RESULTS SUMMARY")
    print("=" * 80)
    
    # Strategy Table
    print("\n### Playwright Navigation Strategy Benchmark")
    print("| Target URL | Strategy | Latency (ms) | Success | HTML Size (Chars) | Text Length | Failed Reqs | Console Errs |")
    print("| --- | --- | --- | --- | --- | --- | --- | --- |")
    for r in strategy_results:
        print(f"| {r['url']} | {r['strategy']} | {r['latency_ms']:.2f} | {r['success']} | {r['html_size']} | {r['text_len']} | {r['failed_reqs']} | {r['console_errs']} |")
        
    # Screenshot Cost Table
    print("\n### Screenshot Cost Benchmark")
    print("| Target URL | Mode | Latency (ms) | Viewport Size (KB) | Full Page Size (KB) |")
    print("| --- | --- | --- | --- | --- |")
    for r in screenshot_results:
        print(f"| {r['url']} | {r['description']} | {r['latency_ms']:.2f} | {r['viewport_size_bytes']/1024:.2f} | {r['fullpage_size_bytes']/1024:.2f} |")
        
    # WHOIS Table
    print("\n### WHOIS Benchmark")
    print("| Target URL | Success | Latency (ms) | Domain Age (Days) | Registrar | Errors |")
    print("| --- | --- | --- | --- | --- | --- |")
    for r in whois_results:
        print(f"| {r['url']} | {r['success']} | {r['latency_ms']:.2f} | {r['domain_age']} | {r['registrar']} | {r['errors']} |")
        
    # SSL Table
    print("\n### SSL Benchmark")
    print("| Target URL | Success | Latency (ms) | TLS Version | Issuer | Errors |")
    print("| --- | --- | --- | --- | --- | --- |")
    for r in ssl_results:
        print(f"| {r['url']} | {r['success']} | {r['latency_ms']:.2f} | {r['tls_version']} | {r['issuer']} | {r['errors']} |")
        
    # DNS Table
    print("\n### DNS Benchmark")
    print("| Target URL | Success | Latency (ms) | A Records Count | MX Records Count | Errors |")
    print("| --- | --- | --- | --- | --- | --- |")
    for r in dns_results:
        print(f"| {r['url']} | {r['success']} | {r['latency_ms']:.2f} | {r['a_records_count']} | {r['mx_records_count']} | {r['errors']} |")

async def run_single_url_benchmark(url: str):
    print("=" * 80)
    print(f"BENCHMARKING PIPELINE FOR: {url}")
    print("=" * 80)
    
    start_total = time.perf_counter()
    metrics = await run_single_pipeline(url)
    total_total = (time.perf_counter() - start_total) * 1000
    
    evidence = metrics["evidence"]
    summary = evidence.collection_summary
    
    print("\n### Pipeline Timing Summary")
    print(f" - Classifier verdict time: {metrics['classifier_time_ms']:.2f} ms")
    print(f" - Pipeline execution time: {metrics['pipeline_time_ms']:.2f} ms")
    print(f" - Total run time: {total_total:.2f} ms")
    
    print("\n### Individual Collector Latencies")
    for name, lat in summary.collector_metrics.items():
        print(f" - {name}: {lat:.2f} ms")
        
    print("\n### Evidence Sizes")
    raw_html_len = len(evidence.raw_html or "")
    rendered_html_len = len(evidence.rendered_html or "")
    raw_text_len = len(evidence.raw_visible_text or "")
    rendered_text_len = len(evidence.rendered_visible_text or "")
    
    print(f" - Raw HTML character count: {raw_html_len}")
    print(f" - Rendered HTML character count: {rendered_html_len}")
    print(f" - Raw visible text length: {raw_text_len}")
    print(f" - Rendered visible text length: {rendered_text_len}")
    
    print("\n### Screenshot Sizes")
    v_path = evidence.viewport_screenshot_path
    f_path = evidence.fullpage_screenshot_path
    
    if v_path and os.path.exists(v_path):
        print(f" - Viewport screenshot size: {os.path.getsize(v_path)/1024:.2f} KB ({v_path})")
    else:
        print(" - Viewport screenshot: None")
        
    if f_path and os.path.exists(f_path):
        print(f" - Full page screenshot size: {os.path.getsize(f_path)/1024:.2f} KB ({f_path})")
    else:
        print(" - Full page screenshot: None")

if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--run-all-experiments":
        asyncio.run(benchmark_experiments())
    elif len(sys.argv) > 1:
        asyncio.run(run_single_url_benchmark(sys.argv[1]))
    else:
        print("Usage:")
        print("  uv run python scripts/benchmark_pipeline.py <url>")
        print("  uv run python scripts/benchmark_pipeline.py --run-all-experiments")
        sys.exit(1)
