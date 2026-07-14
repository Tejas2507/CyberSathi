import pytest
import threading
from app.models.machine_learning import URLDetector, phishing_model

def test_singleton():
    detector1 = URLDetector()
    detector2 = URLDetector()
    assert detector1 is detector2
    assert detector1 is phishing_model

def test_invalid_urls():
    detector = URLDetector()
    # Ensure model is initialized to test validation path
    detector.load_model()
    
    invalid_cases = [
        "",
        "google.com",          # Missing scheme
        "ftp://google.com",    # Unsupported scheme
        "http://",             # Missing netloc
        "https://google",      # Invalid domain structure (no dot)
    ]
    for url in invalid_cases:
        with pytest.raises(ValueError):
            detector.predict(url)

def test_prediction():
    detector = URLDetector()
    detector.load_model()
    
    res = detector.predict("https://example.com")
    assert "label" in res
    assert "probability" in res
    assert "confidence" in res
    assert "raw_logits" in res
    assert "latency_ms" in res
    
    assert isinstance(res["label"], str)
    assert 0.0 <= res["probability"] <= 1.0
    assert 0.0 <= res["confidence"] <= 1.0
    assert len(res["raw_logits"]) == 2
    assert res["latency_ms"] >= 0.0
    assert res["label"] in ["legitimate", "phishing"]

def test_thread_safety():
    detector = URLDetector()
    detector.load_model()
    
    results = []
    errors = []
    
    def worker():
        try:
            res = detector.predict("https://example.com")
            results.append(res)
        except Exception as e:
            errors.append(e)
            
    threads = [threading.Thread(target=worker) for _ in range(10)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
        
    assert len(errors) == 0, f"Errors occurred during threaded execution: {errors}"
    assert len(results) == 10
