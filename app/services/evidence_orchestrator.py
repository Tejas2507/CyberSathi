import asyncio
import time
from datetime import datetime, timezone
from typing import Dict, List, Optional, Any, Callable
from app.services.collectors import BaseCollector
from app.schemas.evidence import CollectorResult, Evidence
from app.schemas.safety import ClassifierResult
from app.services.evidence_builder import EvidenceBuilder
from app.prompts.forensic_report_builder import build_security_prompt, build_guidance_prompt
from app.logging import logger
from app.settings import settings

class EvidenceOrchestrator:
    """
    Orchestrates parallel execution of registered BaseCollectors for a target URL.
    Implements timeouts, error safety boundaries, and logs telemetry.
    """
    def __init__(self, default_timeout_sec: float = 10.0) -> None:
        self.collectors: Dict[str, BaseCollector] = {}
        self.timeouts: Dict[str, float] = {}
        self.default_timeout_sec = default_timeout_sec

    def register_collector(self, collector: BaseCollector, timeout_sec: Optional[float] = None) -> None:
        """
        Registers a new collector with a custom or default timeout.
        """
        name = collector.name
        self.collectors[name] = collector
        self.timeouts[name] = timeout_sec if timeout_sec is not None else self.default_timeout_sec
        logger.info(f"Registered collector '{name}' with timeout: {self.timeouts[name]}s")

    async def execute_collector(self, collector_name: str, url: str) -> CollectorResult:
        """
        Wraps single collector execution with timing, error safety, logging and timeout bounds.
        """
        collector = self.collectors[collector_name]
        timeout = self.timeouts[collector_name]
        
        logger.info(f"Collector '{collector_name}' started for URL: {url}")
        start_time = time.perf_counter()
        
        try:
            # Execute with timeout boundary
            result = await asyncio.wait_for(collector.collect(url), timeout=timeout)
            duration_ms = (time.perf_counter() - start_time) * 1000
            
            logger.info(f"Collector '{collector_name}' completed successfully in {duration_ms:.2f}ms")
            
            # Ensure the returned result contains correct duration metrics
            result.execution_time_ms = round(duration_ms, 2)
            return result
            
        except asyncio.TimeoutError:
            duration_ms = (time.perf_counter() - start_time) * 1000
            error_msg = f"TimeoutError: Collector execution exceeded {timeout}s limit"
            logger.error(f"Collector '{collector_name}' failed: {error_msg}")
            
            return CollectorResult(
                collector_name=collector_name,
                success=False,
                execution_time_ms=round(duration_ms, 2),
                errors=[error_msg],
                timestamp=datetime.now(timezone.utc),
            )
            
        except Exception as e:
            duration_ms = (time.perf_counter() - start_time) * 1000
            error_msg = f"CollectorException: {type(e).__name__}: {str(e)}"
            logger.error(f"Collector '{collector_name}' failed: {error_msg}")
            
            return CollectorResult(
                collector_name=collector_name,
                success=False,
                execution_time_ms=round(duration_ms, 2),
                errors=[error_msg],
                timestamp=datetime.now(timezone.utc),
            )

    async def execute(self, url: str) -> List[CollectorResult]:
        """
        Triggers all registered collectors concurrently.
        """
        if not self.collectors:
            logger.warning("No collectors registered in orchestrator. Returning empty results.")
            return []
            
        logger.info(f"Initiating evidence collection pipeline for URL: {url} across {len(self.collectors)} collectors")
        
        tasks = [
            self.execute_collector(name, url)
            for name in self.collectors
        ]
        
        # Execute concurrently and wait for all tasks to settle
        results = await asyncio.gather(*tasks)
        
        logger.info("All evidence collectors settled.")
        return list(results)

    async def execute_adaptive(
        self,
        url: str,
        detector: Any,
        llm_caller: Callable[[str, Optional[List[Any]]], Any],
        prediction_result: Optional[ClassifierResult] = None
    ) -> Dict[str, Any]:
        """
        Executes the latency-aware adaptive evidence acquisition pipeline.
        Concurrently executes all collectors, running Playwright speculatively.
        Blocks only on Fast Evidence (Website, HTML, WHOIS, SSL + ML Classifier).
        Runs Stage 1 LLM. If needed, awaits Playwright to rerun Stage 2 LLM.
        """
        logger.info(f"[Adaptive Orchestrator] Starting adaptive pipeline for {url}")
        
        start_pipeline = time.perf_counter()
        
        # 1. Start ML Classifier asynchronously in thread pool (or use pre-computed result)
        classifier_start = time.perf_counter()
        if prediction_result is not None:
            raw_clf = {
                "label": "phishing" if prediction_result.is_suspicious else "legitimate",
                "probability": prediction_result.risk_score,
                "confidence": prediction_result.confidence or 0.0
            }
            classifier_task = asyncio.Future()
            classifier_task.set_result(raw_clf)
        else:
            classifier_task = asyncio.create_task(asyncio.to_thread(detector.predict, url))
        
        # 2. Start Playwright speculatively in background
        playwright_start = time.perf_counter()
        playwright_task = asyncio.create_task(self.execute_collector("playwright", url))
        
        # 3. Start Fast Collectors in parallel
        fast_tasks = {
            "website": asyncio.create_task(self.execute_collector("website", url)),
            "html": asyncio.create_task(self.execute_collector("html", url)),
            "whois": asyncio.create_task(self.execute_collector("whois", url)),
            "ssl": asyncio.create_task(self.execute_collector("ssl", url))
        }
        
        # Wait for Fast Collectors + ML Classifier to finish
        fast_results = await asyncio.gather(
            fast_tasks["website"],
            fast_tasks["html"],
            fast_tasks["whois"],
            fast_tasks["ssl"],
            classifier_task,
            return_exceptions=True
        )
        
        fast_evidence_latency = (time.perf_counter() - start_pipeline) * 1000
        logger.info(f"[Adaptive Orchestrator] Fast evidence collected in {fast_evidence_latency:.2f}ms")
        
        # Unpack results safely
        website_res = fast_results[0]
        html_res = fast_results[1]
        whois_res = fast_results[2]
        ssl_res = fast_results[3]
        raw_clf = fast_results[4]
        
        # Map classifier result
        if isinstance(raw_clf, Exception):
            logger.error(f"Classifier failed: {raw_clf}")
            prediction_result = ClassifierResult(
                is_suspicious=False,
                risk_score=0.0,
                confidence=0.0,
                model_version=settings.CLASSIFIER_MODEL_NAME
            )
        else:
            prediction_result = ClassifierResult(
                is_suspicious=(raw_clf["label"] == "phishing"),
                risk_score=raw_clf["probability"],
                confidence=raw_clf.get("confidence", 0.0),
                model_version=settings.CLASSIFIER_MODEL_NAME
            )
            
        # Build first stage evidence
        collector_results = []
        for res in [website_res, html_res, whois_res, ssl_res]:
            if not isinstance(res, Exception):
                collector_results.append(res)
                
        evidence_stage1 = EvidenceBuilder.build(url, collector_results, prediction_result)
        
        playwright_cancelled = False
        playwright_already_completed = False
        playwright_latency = 0.0

        if not prediction_result.is_suspicious:
            logger.info("[Adaptive Orchestrator] Fast Legitimate path activated (Classifier verdict is legitimate). Skipping LLM.")
            if not playwright_task.done():
                playwright_task.cancel()
                playwright_cancelled = True
            else:
                playwright_already_completed = True
                try:
                    pw_res = await playwright_task
                    playwright_latency = pw_res.execution_time_ms if pw_res else 0.0
                except Exception:
                    pass
            
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
            
            total_pipeline_latency = (time.perf_counter() - start_pipeline) * 1000
            
            return {
                "verdict_json": final_verdict_json,
                "guidance_bundle": None,
                "playwright_cancelled": playwright_cancelled,
                "playwright_already_completed": playwright_already_completed,
                "timings": {
                    "fast_evidence_latency_ms": fast_evidence_latency,
                    "prompt1_latency_ms": 0.0,
                    "playwright_latency_ms": playwright_latency,
                    "total_pipeline_latency_ms": total_pipeline_latency
                }
            }

        # Generate stage 1 prompt
        prompt_bundle1 = build_security_prompt(evidence_stage1)
        
        # Call Stage 1 LLM
        prompt1_start = time.perf_counter()
        logger.info("[Adaptive Orchestrator] Invoking LLM Stage 1 verification...")
        llm_response1 = await llm_caller(prompt_bundle1.text_prompt, [])
        prompt1_latency = (time.perf_counter() - prompt1_start) * 1000
        logger.info(f"[Adaptive Orchestrator] LLM Stage 1 settled in {prompt1_latency:.2f}ms")
        
        requires_more = llm_response1.get("requires_more_evidence", False)
        verdict = llm_response1.get("verdict", "uncertain")
        requires_guidance = llm_response1.get("requires_guidance", False)
        
        final_verdict_json = llm_response1
        prompt2_bundle = None
        
        # Case A: Sufficient fast evidence
        if not requires_more:
            # Attempt Playwright cancellation
            if not playwright_task.done():
                playwright_task.cancel()
                playwright_cancelled = True
                logger.info("[Adaptive Orchestrator] Playwright Cancelled")
            else:
                playwright_already_completed = True
                logger.info("[Adaptive Orchestrator] Playwright Already Completed")
                try:
                    pw_res = await playwright_task
                    playwright_latency = pw_res.execution_time_ms if pw_res else 0.0
                except Exception:
                    pass
                    
            # Check for guidance
            if (verdict == "phishing" or verdict == "uncertain") and requires_guidance:
                logger.info("[Adaptive Orchestrator] Launching Prompt 2 guidance prompt...")
                prompt2_bundle = build_guidance_prompt(llm_response1)
                
        # Case B: Requires more evidence
        else:
            logger.info("[Adaptive Orchestrator] Stage 1 requested more evidence. Awaiting Playwright...")
            
            # Wait for Playwright speculative task to complete
            pw_start_wait = time.perf_counter()
            try:
                playwright_res = await playwright_task
            except Exception as e:
                logger.error(f"Playwright speculative task failed: {e}")
                playwright_res = None
                
            playwright_latency = (time.perf_counter() - playwright_start) * 1000
            
            # Build Stage 2 Evidence (includes Playwright results)
            collector_results_stage2 = collector_results.copy()
            if playwright_res and not isinstance(playwright_res, Exception):
                collector_results_stage2.append(playwright_res)
                
            evidence_stage2 = EvidenceBuilder.build(url, collector_results_stage2, prediction_result)
            
            # Generate stage 2 prompt with screenshot attached
            prompt_bundle2 = build_security_prompt(evidence_stage2)
            
            # Call Stage 2 LLM
            prompt2_start = time.perf_counter()
            logger.info("[Adaptive Orchestrator] Invoking LLM Stage 2 verification (with screenshot)...")
            images = prompt_bundle2.image_paths
            llm_response2 = await llm_caller(prompt_bundle2.text_prompt, images)
            prompt2_latency_ms = (time.perf_counter() - prompt2_start) * 1000
            prompt1_latency += prompt2_latency_ms # Accumulate total verification latency
            
            final_verdict_json = llm_response2
            verdict = llm_response2.get("verdict", "uncertain")
            requires_guidance = llm_response2.get("requires_guidance", False)
            
            # Check for guidance
            if (verdict == "phishing" or verdict == "uncertain") and requires_guidance:
                logger.info("[Adaptive Orchestrator] Launching Prompt 2 guidance prompt...")
                prompt2_bundle = build_guidance_prompt(llm_response2)
                
        total_pipeline_latency = (time.perf_counter() - start_pipeline) * 1000
        
        return {
            "verdict_json": final_verdict_json,
            "guidance_bundle": prompt2_bundle,
            "playwright_cancelled": playwright_cancelled,
            "playwright_already_completed": playwright_already_completed,
            "timings": {
                "fast_evidence_latency_ms": fast_evidence_latency,
                "prompt1_latency_ms": prompt1_latency,
                "playwright_latency_ms": playwright_latency,
                "total_pipeline_latency_ms": total_pipeline_latency
            }
        }
