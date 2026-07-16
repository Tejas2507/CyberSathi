#!/usr/bin/env python3
"""
scripts/demo_analyze.py
=======================
End-to-end demonstration of the CyberSathi adaptive phishing detection pipeline.

Usage:
    uv run python scripts/demo_analyze.py [URL] [--bypass-cache]

If no URL is provided, a set of test URLs is run in sequence.

Environment:
    GEMINI_API_KEY must be set in .env or shell environment.
"""

from __future__ import annotations

import asyncio
import json
import sys
import time
from pathlib import Path
from typing import List

# Ensure project root is on the path when run directly
sys.path.insert(0, str(Path(__file__).parent.parent))

from dotenv import load_dotenv  # type: ignore[import]
load_dotenv()

from app.services.analysis_service import AnalysisService


# ---------------------------------------------------------------------------
# Demo URLs
# ---------------------------------------------------------------------------
DEFAULT_TEST_URLS: List[str] = [
    "https://google.com",           # Legitimate baseline
    "https://uidai.gov.in",         # Government — legitimate
    "http://paypa1-secure.com",     # Suspicious — typosquat (may 404)
]


def _pretty_print(result: dict) -> None:
    verdict = result.get("verdict", "?").upper()
    confidence = result.get("confidence", 0.0)
    cached = result.get("cached", False)
    timings = result.get("timings", {})
    total_ms = timings.get("total_pipeline_latency_ms", 0)

    sep = "=" * 60

    verdict_icon = {
        "PHISHING":   "🚨",
        "LEGITIMATE": "✅",
        "UNCERTAIN":  "⚠️",
    }.get(verdict, "❓")

    print(f"\n{sep}")
    print(f"  URL       : {result.get('url')}")
    print(f"  Verdict   : {verdict_icon}  {verdict}  (confidence: {confidence:.2%})")
    if cached:
        print(f"  Source    : 📦 Local DB Cache")
    if result.get("severity"):
        print(f"  Severity  : {result.get('severity', '').upper()}")
    if result.get("impersonated_entity"):
        print(f"  Impersonated : {result.get('impersonated_entity')}")
    if result.get("scam_category"):
        print(f"  Scam Type : {result.get('scam_category')}")
    print(f"  Latency   : {total_ms:.0f} ms total")

    fast_ms = timings.get("fast_evidence_latency_ms")
    if fast_ms:
        print(f"    ├─ Fast evidence  : {fast_ms:.0f} ms")
    p1_ms = timings.get("prompt1_latency_ms")
    if p1_ms:
        print(f"    ├─ LLM Stage 1    : {p1_ms:.0f} ms")
    pw_ms = timings.get("playwright_latency_ms")
    if pw_ms and pw_ms > 0:
        print(f"    └─ Playwright     : {pw_ms:.0f} ms")

    key_evidence = result.get("key_evidence", [])
    if key_evidence:
        print("\n  Key Evidence:")
        for bullet in key_evidence[:5]:
            print(f"    • {bullet}")

    summary = result.get("summary", "")
    if summary:
        print(f"\n  Summary:\n    {summary[:300]}")

    guidance = result.get("guidance")
    if guidance:
        print("\n  🛡️  Safety Guidance:")
        official = guidance.get("official_website")
        if official:
            print(f"    Official website  : {official}")
        actions = guidance.get("immediate_actions", [])
        if actions:
            print("    Immediate actions :")
            for a in actions[:3]:
                print(f"      ⚡ {a}")

    print(sep)


async def main() -> None:
    urls: List[str] = []
    bypass_cache = "--bypass-cache" in sys.argv

    # Collect URLs from CLI args (skip flags)
    cli_urls = [a for a in sys.argv[1:] if not a.startswith("--")]
    if cli_urls:
        urls = cli_urls
    else:
        urls = DEFAULT_TEST_URLS

    from app.settings import settings
    print("\n🔍 CyberSathi — Phishing Detection Demo")
    print(f"   Model    : {settings.GEMINI_MODEL} (adaptive pipeline)")
    print(f"   URLs     : {len(urls)}")
    print(f"   Cache bypass: {bypass_cache}\n")

    service = AnalysisService()

    for url in urls:
        print(f"\n▶  Analyzing: {url}")
        t0 = time.perf_counter()
        try:
            async for event in service.analyze_stream(url=url, bypass_cache=bypass_cache):
                ev_type = event.get("event")
                elapsed_ms = (time.perf_counter() - t0) * 1000
                
                if ev_type == "initial_assessment":
                    status_lbl = event.get("status", "").upper()
                    icon = "✅ SAFE" if status_lbl == "SAFE" else "🚨 PHISHING SUSPECTED"
                    print(f"   ├─ [Initial Assessment] {icon} (obtained in {elapsed_ms:.0f} ms)")
                
                elif ev_type == "collecting_evidence":
                    print(f"   ├─ [Deep Scan] {event.get('message')} (elapsed: {elapsed_ms:.0f} ms)")
                
                elif ev_type == "final_result":
                    _pretty_print(event)
                    
        except Exception as exc:
            print(f"  ❌ Error: {type(exc).__name__}: {exc}")
        elapsed = (time.perf_counter() - t0) * 1000
        print(f"   (wall time: {elapsed:.0f} ms)\n")

    print("\n✅  Demo complete.")


if __name__ == "__main__":
    asyncio.run(main())
