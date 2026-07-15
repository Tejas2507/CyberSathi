#!/usr/bin/env python3
"""
scripts/benchmark_e2e.py
========================
End-to-end benchmark: runs the full adaptive pipeline on 5 real URLs
(2 legitimate + 3 phishing from OpenPhish live feed) and produces
a machine-readable JSON result + human-readable table.

URLs sourced from OpenPhish live feed on 2025-07-15.

Usage:
    uv run python scripts/benchmark_e2e.py
"""

from __future__ import annotations

import asyncio
import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from dotenv import load_dotenv
load_dotenv()

from app.services.analysis_service import AnalysisService

URLS = [
    # Legitimate
    ("https://uidai.gov.in",                                         "legitimate"),
    ("https://onlinesbi.sbi",                                        "legitimate"),
    # Phishing — sourced from OpenPhish live feed (2025-07-15)
    ("http://shopee-performance-dashboard.pages.dev/",               "phishing"),
    ("https://web-login-trezors-en-us.typedream.app/",               "phishing"),
    ("https://secure--sso-netcoins-com-cdn--oauth.webflow.io/",      "phishing"),
]

# Per-URL timeout: kill any URL that takes longer than this
URL_TIMEOUT_SEC = 180


async def analyze_one(service: AnalysisService, url: str, expected: str) -> dict:
    """Runs analysis for a single URL with a hard wall-clock timeout."""
    t0 = time.perf_counter()
    try:
        r = await asyncio.wait_for(
            service.analyze(url=url, bypass_cache=True),
            timeout=URL_TIMEOUT_SEC,
        )
        elapsed = (time.perf_counter() - t0) * 1000
        timings = r.get("timings", {})
        return {
            "url": url,
            "expected": expected,
            "verdict": r.get("verdict"),
            "confidence": r.get("confidence"),
            "severity": r.get("severity"),
            "cached": r.get("cached"),
            "impersonated_entity": r.get("impersonated_entity"),
            "timings": timings,
            "fast_evidence_ms": timings.get("fast_evidence_latency_ms", 0) or 0,
            "llm_stage1_ms": timings.get("prompt1_latency_ms", 0) or 0,
            "playwright_ms": timings.get("playwright_latency_ms", 0) or 0,
            "total_ms": elapsed,
            "playwright_cancelled": (timings.get("playwright_latency_ms") or 0) == 0,
            "stage2_invoked": (timings.get("playwright_latency_ms") or 0) > 0,
            "guidance_generated": r.get("guidance") is not None,
            "key_evidence": r.get("key_evidence", [])[:3],
            "summary": (r.get("summary") or "")[:150],
            "error": None,
        }
    except asyncio.TimeoutError:
        elapsed = (time.perf_counter() - t0) * 1000
        return {
            "url": url,
            "expected": expected,
            "verdict": "timeout",
            "confidence": 0.0,
            "fast_evidence_ms": 0,
            "llm_stage1_ms": 0,
            "playwright_ms": 0,
            "total_ms": elapsed,
            "playwright_cancelled": False,
            "stage2_invoked": False,
            "guidance_generated": False,
            "key_evidence": [],
            "summary": "",
            "error": f"Analysis exceeded {URL_TIMEOUT_SEC}s wall-clock limit",
        }
    except Exception as exc:
        elapsed = (time.perf_counter() - t0) * 1000
        return {
            "url": url,
            "expected": expected,
            "verdict": "error",
            "confidence": 0.0,
            "fast_evidence_ms": 0,
            "llm_stage1_ms": 0,
            "playwright_ms": 0,
            "total_ms": elapsed,
            "playwright_cancelled": False,
            "stage2_invoked": False,
            "guidance_generated": False,
            "key_evidence": [],
            "summary": "",
            "error": str(exc),
        }


async def run_all():
    service = AnalysisService()
    results = []

    for url, expected in URLS:
        print(f"\n▶  Analyzing: {url}")
        result = await analyze_one(service, url, expected)
        results.append(result)

        if result["error"]:
            print(f"   ❌ {result['verdict'].upper()}: {result['error'][:80]}")
        else:
            print(f"   ✅ verdict={result['verdict']}  conf={result.get('confidence', 0):.2f}  total={result['total_ms']:.0f}ms")

    # Save JSON
    out_path = Path("scripts/benchmark_results.json")
    out_path.write_text(json.dumps(results, indent=2, default=str))
    print(f"\n✅  Results saved to {out_path}")

    # Print detailed per-URL results
    print("\n" + "─" * 90)
    for r in results:
        verdict_icon = {
            "legitimate": "✅", "phishing": "🚨", "uncertain": "⚠️",
            "error": "❌", "timeout": "⏱️"
        }.get(r["verdict"], "❓")
        print(f"\n  {verdict_icon}  {r['url']}")
        print(f"     Expected      : {r['expected']}")
        print(f"     Verdict       : {r['verdict']}  (confidence: {r.get('confidence', 0):.0%})")
        if r.get("impersonated_entity"):
            print(f"     Impersonated  : {r['impersonated_entity']}")
        print(f"     Fast evidence : {r['fast_evidence_ms']:.0f} ms")
        print(f"     LLM Stage 1   : {r['llm_stage1_ms']:.0f} ms")
        if r["stage2_invoked"]:
            print(f"     Playwright/S2 : {r['playwright_ms']:.0f} ms  ← Stage 2 invoked")
        else:
            print(f"     Playwright    : Cancelled — fast evidence was sufficient")
        print(f"     Guidance      : {'Yes' if r['guidance_generated'] else 'No'}")
        print(f"     Total latency : {r['total_ms']:.0f} ms")
        if r.get("key_evidence"):
            for b in r["key_evidence"]:
                print(f"       • {b}")
        if r.get("error"):
            print(f"     ERROR         : {r['error']}")

    # Print summary table
    print("\n\n" + "=" * 112)
    print(f"{'URL':<55} {'Expected':<12} {'Verdict':<12} {'Conf':>5} {'Fast':>7} {'LLM1':>7} {'Total':>8} {'S2':>4} {'Guid':>5}")
    print("-" * 112)
    for r in results:
        url_d = r["url"][:53]
        conf = r.get("confidence") or 0.0
        s2 = "Yes" if r["stage2_invoked"] else "No"
        guid = "Yes" if r["guidance_generated"] else "No"
        print(
            f"{url_d:<55} {r['expected']:<12} {r.get('verdict','err'):<12} "
            f"{conf:>5.2f} {r['fast_evidence_ms']:>7.0f} {r['llm_stage1_ms']:>7.0f} "
            f"{r['total_ms']:>8.0f} {s2:>4} {guid:>5}"
        )
    print("=" * 112)

    correct = sum(
        1 for r in results
        if r.get("verdict") == r["expected"]
    )
    total = len(results)
    successful = sum(1 for r in results if r.get("error") is None)
    print(f"\n  Pipeline completed: {successful}/{total} URLs")
    print(f"  Correct verdicts : {correct}/{successful} (of completed analyses)\n")

    return results


if __name__ == "__main__":
    asyncio.run(run_all())
