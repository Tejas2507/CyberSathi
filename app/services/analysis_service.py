"""
AnalysisService
===============
End-to-end phishing analysis orchestrator.
Wires together:
  - Local confirmed_phishing DB cache lookup
  - ML classifier
  - Evidence orchestrator (adaptive two-stage pipeline)
  - Gemini LLM adapter (Stage 1 + optional Stage 2)
  - Artifact cleanup
  - DB cache insertion

Public entry point:  AnalysisService.analyze(url, bypass_cache=False)
"""

from __future__ import annotations

import asyncio
import shutil
import time
from pathlib import Path
from typing import Any, Dict, Optional, AsyncGenerator

from app.logging import logger
from app.models.machine_learning import phishing_model
from app.prompts.forensic_report_builder import build_guidance_prompt
from app.services.llm_adapter import GeminiLLMAdapter, LLMConfigurationError
from app.services.phishing_database import phishing_db
from app.settings import settings


# ---------------------------------------------------------------------------
# Artifact cleanup helper
# ---------------------------------------------------------------------------

_ARTIFACT_DIRS = [
    Path("artifacts/screenshots"),
    Path("artifacts/rendered_html"),
    Path("artifacts/html"),
]


def _cleanup_artifacts() -> None:
    """Removes all transient screenshot/rendered HTML artifacts after analysis."""
    for d in _ARTIFACT_DIRS:
        if d.exists():
            try:
                shutil.rmtree(d)
                d.mkdir(parents=True, exist_ok=True)  # Recreate empty dir
                logger.debug(f"[Cleanup] Cleared artifacts in '{d}'")
            except Exception as exc:
                logger.warning(f"[Cleanup] Failed to clear '{d}': {exc}")


# ---------------------------------------------------------------------------
# AnalysisService
# ---------------------------------------------------------------------------

class AnalysisService:
    """
    Stateless analysis service.  Instantiate once at app startup and reuse.
    """

    def __init__(self) -> None:
        # Lazy import to defer orchestrator / collector setup until first call
        from app.services.collectors import (
            HTMLCollector,
            PlaywrightCollector,
            SSLCollector,
            WebsiteCollector,
            WHOISCollector,
        )
        from app.services.evidence_orchestrator import EvidenceOrchestrator

        self._orchestrator = EvidenceOrchestrator(default_timeout_sec=15.0)
        self._orchestrator.register_collector(WebsiteCollector(), timeout_sec=12.0)
        self._orchestrator.register_collector(HTMLCollector(), timeout_sec=12.0)
        self._orchestrator.register_collector(WHOISCollector(), timeout_sec=12.0)
        self._orchestrator.register_collector(SSLCollector(), timeout_sec=12.0)
        self._orchestrator.register_collector(PlaywrightCollector(), timeout_sec=25.0)

        # Initialise LLM adapter (may raise LLMConfigurationError)
        self._llm: Optional[GeminiLLMAdapter] = None
        self._llm_error: Optional[str] = None
        try:
            self._llm = GeminiLLMAdapter()
        except LLMConfigurationError as exc:
            self._llm_error = str(exc)
            logger.error(f"[AnalysisService] LLM disabled: {exc}")

        logger.info("[AnalysisService] Initialized.")

    # ------------------------------------------------------------------
    # LLM caller shim passed to the orchestrator
    # ------------------------------------------------------------------

    async def _llm_caller(
        self,
        text_prompt: str,
        image_paths: list,
    ) -> Dict[str, Any]:
        if self._llm is None:
            raise LLMConfigurationError(
                self._llm_error or "GEMINI_API_KEY is not set."
            )
        return await self._llm.analyze_security(text_prompt, image_paths)

    # ------------------------------------------------------------------
    # Main entry point
    # ------------------------------------------------------------------

    async def analyze(
        self,
        url: str,
        bypass_cache: bool = False,
    ) -> Dict[str, Any]:
        """
        Runs the full adaptive phishing detection pipeline.

        Returns a structured result dict:
        {
            "url": str,
            "verdict": str,            # "phishing" | "legitimate" | "uncertain"
            "confidence": float,
            "severity": str,
            "cached": bool,            # True = result from local DB
            "impersonated_entity": str,
            "scam_category": str,
            "targeted_information": [...],
            "key_evidence": [...],
            "summary": str,
            "guidance": {...} | None,
            "timings": {...},
        }
        """
        start = time.perf_counter()
        logger.info(f"[AnalysisService] BEGIN analysis for '{url}'")

        # ----------------------------------------------------------------
        # 1. Local DB cache lookup
        # ----------------------------------------------------------------
        if not bypass_cache:
            cached_record = phishing_db.lookup(url)
            if cached_record:
                logger.info(f"[AnalysisService] Cache HIT — returning stored verdict.")
                return {
                    "url": url,
                    "verdict": "phishing",
                    "confidence": cached_record["confidence"],
                    "severity": cached_record.get("severity"),
                    "cached": True,
                    "impersonated_entity": cached_record.get("impersonated"),
                    "scam_category": cached_record.get("scam_category"),
                    "targeted_information": [],
                    "key_evidence": [],
                    "summary": cached_record.get("summary", ""),
                    "guidance": None,
                    "timings": {
                        "total_pipeline_latency_ms": round(
                            (time.perf_counter() - start) * 1000, 2
                        )
                    },
                }

        # ----------------------------------------------------------------
        # 2. Ensure ML model is loaded
        # ----------------------------------------------------------------
        if not phishing_model.is_loaded:
            logger.info("[AnalysisService] Loading ML model...")
            await asyncio.to_thread(phishing_model.load_model)

        # ----------------------------------------------------------------
        # 3. Adaptive evidence + LLM pipeline
        # ----------------------------------------------------------------
        pipeline_result = await self._orchestrator.execute_adaptive(
            url=url,
            detector=phishing_model,
            llm_caller=self._llm_caller,
        )

        verdict_json: Dict[str, Any] = pipeline_result["verdict_json"]
        guidance_bundle = pipeline_result.get("guidance_bundle")
        timings: Dict[str, Any] = pipeline_result.get("timings", {})

        verdict = verdict_json.get("verdict", "uncertain")
        confidence = float(verdict_json.get("confidence", 0.0))

        # ----------------------------------------------------------------
        # 4. Guidance prompt (Stage 2b) — if verdict requires guidance
        # ----------------------------------------------------------------
        guidance_result: Optional[Dict[str, Any]] = None

        requires_guidance = verdict_json.get("requires_guidance", False)

        if requires_guidance and self._llm is not None:
            g_bundle = guidance_bundle or build_guidance_prompt(verdict_json)
            logger.info("[AnalysisService] Running guidance prompt...")
            try:
                guidance_result = await self._llm.generate_guidance(g_bundle.text_prompt)
            except Exception as exc:
                logger.error(f"[AnalysisService] Guidance generation failed: {exc}")
                guidance_result = None

        # ----------------------------------------------------------------
        # 5. Store to DB if high-confidence phishing
        # ----------------------------------------------------------------
        phishing_db.insert(url, verdict_json)

        # ----------------------------------------------------------------
        # 6. Artifact cleanup
        # ----------------------------------------------------------------
        _cleanup_artifacts()

        total_ms = round((time.perf_counter() - start) * 1000, 2)
        timings["total_pipeline_latency_ms"] = total_ms

        logger.info(
            f"[AnalysisService] DONE — verdict={verdict}, "
            f"confidence={confidence}, latency={total_ms}ms"
        )

        return {
            "url": url,
            "verdict": verdict,
            "confidence": confidence,
            "severity": verdict_json.get("severity"),
            "cached": False,
            "impersonated_entity": verdict_json.get("impersonated_entity"),
            "scam_category": verdict_json.get("scam_category"),
            "targeted_information": verdict_json.get("targeted_information", []),
            "key_evidence": verdict_json.get("key_evidence", []),
            "summary": verdict_json.get("summary", ""),
            "guidance": guidance_result,
            "timings": timings,
        }

    async def analyze_stream(
        self,
        url: str,
        bypass_cache: bool = False,
    ) -> AsyncGenerator[Dict[str, Any], None]:
        """
        Streams progress and results for the phishing analysis.
        Yields structured dictionaries for JSON-stream consumption.
        """
        start = time.perf_counter()
        logger.info(f"[AnalysisService] BEGIN streaming analysis for '{url}'")

        # 1. Local DB cache lookup
        if not bypass_cache:
            cached_record = phishing_db.lookup(url)
            if cached_record:
                logger.info(f"[AnalysisService] Cache HIT — returning stored verdict via stream.")
                yield {
                    "event": "initial_assessment",
                    "status": "threat_suspected",
                    "risk_score": cached_record["confidence"],
                    "cached": True,
                }
                yield {
                    "event": "final_result",
                    "url": url,
                    "verdict": "phishing",
                    "confidence": cached_record["confidence"],
                    "severity": cached_record.get("severity"),
                    "cached": True,
                    "impersonated_entity": cached_record.get("impersonated"),
                    "scam_category": cached_record.get("scam_category"),
                    "targeted_information": [],
                    "key_evidence": [],
                    "summary": cached_record.get("summary", ""),
                    "guidance": None,
                    "timings": {
                        "total_pipeline_latency_ms": round(
                            (time.perf_counter() - start) * 1000, 2
                        )
                    },
                }
                return

        # 2. Ensure ML model is loaded
        if not phishing_model.is_loaded:
            logger.info("[AnalysisService] Loading ML model...")
            await asyncio.to_thread(phishing_model.load_model)

        # 3. Fast URL Classifier Prediction
        clf_start = time.perf_counter()
        raw_clf = await asyncio.to_thread(phishing_model.predict, url)
        clf_latency = (time.perf_counter() - clf_start) * 1000
        logger.info(f"[AnalysisService] Classifier result obtained in {clf_latency:.2f}ms")

        from app.schemas.safety import ClassifierResult
        prediction_result = ClassifierResult(
            is_suspicious=(raw_clf["label"] == "phishing"),
            risk_score=raw_clf["probability"],
            confidence=raw_clf.get("confidence", 0.0),
            model_version=settings.CLASSIFIER_MODEL_NAME
        )

        status_str = "threat_suspected" if prediction_result.is_suspicious else "safe"
        yield {
            "event": "initial_assessment",
            "status": status_str,
            "risk_score": prediction_result.risk_score,
            "cached": False
        }

        # 4. Fast Legitimate Bypassing (no LLM, no Deep Scans)
        if not prediction_result.is_suspicious:
            logger.info("[AnalysisService] Bypassing deep scans for SAFE url.")
            final_verdict_json = {
                "verdict": "legitimate",
                "confidence": prediction_result.confidence,
                "severity": "low",
                "impersonated_entity": "none",
                "scam_category": "none",
                "targeted_information": [],
                "key_evidence": [
                    f"URL classifier classified domain as legitimate with confidence {prediction_result.confidence:.2%}"
                ],
                "summary": "The initial machine learning classifier detected no signs of phishing or malicious patterns on this domain.",
                "requires_more_evidence": False,
                "requires_guidance": False
            }
            total_ms = round((time.perf_counter() - start) * 1000, 2)
            yield {
                "event": "final_result",
                "url": url,
                "verdict": "legitimate",
                "confidence": prediction_result.confidence,
                "severity": "low",
                "cached": False,
                "impersonated_entity": "none",
                "scam_category": "none",
                "targeted_information": [],
                "key_evidence": final_verdict_json["key_evidence"],
                "summary": final_verdict_json["summary"],
                "guidance": None,
                "timings": {
                    "fast_evidence_latency_ms": clf_latency,
                    "prompt1_latency_ms": 0.0,
                    "playwright_latency_ms": 0.0,
                    "total_pipeline_latency_ms": total_ms
                }
            }
            return

        # 5. Deep Scan (Threat Suspected)
        yield {
            "event": "collecting_evidence",
            "message": "Threat suspected. Gathering deep forensic evidence and invoking LLM..."
        }

        pipeline_result = await self._orchestrator.execute_adaptive(
            url=url,
            detector=phishing_model,
            llm_caller=self._llm_caller,
            prediction_result=prediction_result
        )

        verdict_json: Dict[str, Any] = pipeline_result["verdict_json"]
        guidance_bundle = pipeline_result.get("guidance_bundle")
        timings: Dict[str, Any] = pipeline_result.get("timings", {})

        verdict = verdict_json.get("verdict", "uncertain")
        confidence = float(verdict_json.get("confidence", 0.0))

        # Guidance
        guidance_result = None
        requires_guidance = verdict_json.get("requires_guidance", False)

        if requires_guidance and self._llm is not None:
            g_bundle = guidance_bundle or build_guidance_prompt(verdict_json)
            logger.info("[AnalysisService] Running guidance prompt...")
            try:
                guidance_result = await self._llm.generate_guidance(g_bundle.text_prompt)
            except Exception as exc:
                logger.error(f"[AnalysisService] Guidance generation failed: {exc}")
                guidance_result = None

        # Store to DB
        phishing_db.insert(url, verdict_json)

        # Cleanup
        _cleanup_artifacts()

        total_ms = round((time.perf_counter() - start) * 1000, 2)
        timings["total_pipeline_latency_ms"] = total_ms

        logger.info(
            f"[AnalysisService] DONE — verdict={verdict}, "
            f"confidence={confidence}, latency={total_ms}ms"
        )

        yield {
            "event": "final_result",
            "url": url,
            "verdict": verdict,
            "confidence": confidence,
            "severity": verdict_json.get("severity"),
            "cached": False,
            "impersonated_entity": verdict_json.get("impersonated_entity"),
            "scam_category": verdict_json.get("scam_category"),
            "targeted_information": verdict_json.get("targeted_information", []),
            "key_evidence": verdict_json.get("key_evidence", []),
            "summary": verdict_json.get("summary", ""),
            "guidance": guidance_result,
            "timings": timings,
        }
