import asyncio
import time
from datetime import datetime, timezone
from typing import Dict, List, Optional
from app.services.collectors import BaseCollector
from app.schemas.evidence import CollectorResult
from app.logging import logger

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
