import pytest
import asyncio
from datetime import datetime, timezone
from app.services.collectors import BaseCollector
from app.schemas.evidence import CollectorResult, Evidence
from app.services.evidence_orchestrator import EvidenceOrchestrator
from app.services.evidence_builder import EvidenceBuilder
from app.schemas.safety import ClassifierResult

# --- Mock Collector Implementations for Testing ---

class MockSuccessCollector(BaseCollector):
    def __init__(self, name: str, sleep_time: float = 0.05, return_data: dict = None) -> None:
        self._name = name
        self.sleep_time = sleep_time
        self.return_data = return_data or {"message": "Success"}

    @property
    def name(self) -> str:
        return self._name

    async def collect(self, url: str) -> CollectorResult:
        if self.sleep_time > 0:
            await asyncio.sleep(self.sleep_time)
        return CollectorResult(
            collector_name=self.name,
            success=True,
            execution_time_ms=0.0,  # Orchestrator overrides this
            data=self.return_data,
            errors=[],
            timestamp=datetime.now(timezone.utc),
        )

class MockFailureCollector(BaseCollector):
    @property
    def name(self) -> str:
        return "faulty_collector"

    async def collect(self, url: str) -> CollectorResult:
        raise ValueError("Critical collector failure occurred!")

class MockTimeoutCollector(BaseCollector):
    @property
    def name(self) -> str:
        return "slow_collector"

    async def collect(self, url: str) -> CollectorResult:
        await asyncio.sleep(2.0)
        return CollectorResult(
            collector_name=self.name,
            success=True,
            execution_time_ms=0.0,
            data={"status": "completed_late"},
            errors=[],
            timestamp=datetime.now(timezone.utc),
        )

# --- Unit Tests ---

def test_collector_registration():
    orchestrator = EvidenceOrchestrator()
    collector = MockSuccessCollector("test_collector")
    
    orchestrator.register_collector(collector, timeout_sec=5.0)
    
    assert "test_collector" in orchestrator.collectors
    assert orchestrator.collectors["test_collector"] is collector
    assert orchestrator.timeouts["test_collector"] == 5.0

@pytest.mark.anyio
async def test_parallel_execution():
    orchestrator = EvidenceOrchestrator()
    # Register three collectors that each sleep for 0.1 seconds
    c1 = MockSuccessCollector("c1", sleep_time=0.1)
    c2 = MockSuccessCollector("c2", sleep_time=0.1)
    c3 = MockSuccessCollector("c3", sleep_time=0.1)
    
    orchestrator.register_collector(c1)
    orchestrator.register_collector(c2)
    orchestrator.register_collector(c3)
    
    start_time = asyncio.get_event_loop().time()
    results = await orchestrator.execute("https://example.com")
    duration = asyncio.get_event_loop().time() - start_time
    
    assert len(results) == 3
    # If executed sequentially, total time would be >= 0.3s.
    # Parallel execution should be close to 0.1s (definitely under 0.25s).
    assert duration < 0.25
    assert all(r.success for r in results)

@pytest.mark.anyio
async def test_failure_handling():
    orchestrator = EvidenceOrchestrator()
    # Register one success and one faulty collector
    success = MockSuccessCollector("website", return_data={"title": "Test Title"})
    faulty = MockFailureCollector()
    
    orchestrator.register_collector(success)
    orchestrator.register_collector(faulty)
    
    results = await orchestrator.execute("https://example.com")
    
    assert len(results) == 2
    
    res_dict = {r.collector_name: r for r in results}
    
    # Faulty collector fails, but returns structured CollectorResult
    assert res_dict["website"].success is True
    assert res_dict["website"].data == {"title": "Test Title"}
    
    assert res_dict["faulty_collector"].success is False
    assert len(res_dict["faulty_collector"].errors) == 1
    assert "ValueError" in res_dict["faulty_collector"].errors[0]

@pytest.mark.anyio
async def test_timeout_handling():
    orchestrator = EvidenceOrchestrator()
    slow = MockTimeoutCollector()
    # Register with a short 0.2s timeout
    orchestrator.register_collector(slow, timeout_sec=0.2)
    
    results = await orchestrator.execute("https://example.com")
    
    assert len(results) == 1
    res = results[0]
    assert res.success is False
    assert len(res.errors) == 1
    assert "TimeoutError" in res.errors[0]

def test_evidence_builder():
    results = [
        CollectorResult(
            collector_name="website",
            success=True,
            execution_time_ms=10.0,
            data={"title": "Test Safe Web", "status_code": 200, "server": "nginx"},
            errors=[],
            timestamp=datetime.now(timezone.utc)
        ),
        CollectorResult(
            collector_name="ssl",
            success=True,
            execution_time_ms=12.0,
            data={"ssl_valid": True, "ssl_issuer": "Let's Encrypt"},
            errors=[],
            timestamp=datetime.now(timezone.utc)
        ),
        CollectorResult(
            collector_name="whois",
            success=False,
            execution_time_ms=8.0,
            data=None,
            errors=["Connection Timeout"],
            timestamp=datetime.now(timezone.utc)
        )
    ]
    
    classifier_res = ClassifierResult(
        is_suspicious=False,
        risk_score=0.15,
        model_version="mock-model"
    )
    
    evidence = EvidenceBuilder.build(
        url="https://example.com",
        results=results,
        prediction_result=classifier_res
    )
    
    assert isinstance(evidence, Evidence)
    assert evidence.url == "https://example.com"
    assert evidence.prediction_result is classifier_res
    
    # Submodels parsed successfully
    assert evidence.website is not None
    assert evidence.website.title == "Test Safe Web"
    assert evidence.website.status_code == 200
    
    assert evidence.ssl is not None
    assert evidence.ssl.ssl_valid is True
    assert evidence.ssl.ssl_issuer == "Let's Encrypt"
    
    # Failed collector remains None
    assert evidence.whois is None
    
    # Summary compiled correctly
    assert evidence.collection_summary is not None
    assert evidence.collection_summary.success_count == 2
    assert evidence.collection_summary.failure_count == 1
    assert evidence.collection_summary.total_time_ms == 30.0
    assert evidence.collection_summary.collector_metrics == {"website": 10.0, "ssl": 12.0, "whois": 8.0}
