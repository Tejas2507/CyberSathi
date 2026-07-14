import time
import torch
import logging
import threading
from urllib.parse import urlparse
from transformers import AutoTokenizer, AutoModelForSequenceClassification
from app.config import MODEL_CACHE_DIR
from app.settings import settings

logger = logging.getLogger("cybersathi")

class URLDetector:
    """
    Thread-safe Singleton URL safety detector using HuggingFace.
    Loads the tokenizer and model exactly once during initialization.
    """
    _instance = None
    _lock = threading.Lock()

    def __new__(cls, *args, **kwargs):
        with cls._lock:
            if cls._instance is None:
                cls._instance = super(URLDetector, cls).__new__(cls, *args, **kwargs)
                cls._instance._initialized = False
            return cls._instance

    def __init__(self) -> None:
        if self._initialized:
            return
        self.tokenizer = None
        self.model = None
        self.device = None
        self.is_loaded = False
        self._inference_lock = threading.Lock()
        self._initialized = True

    def _detect_device(self) -> torch.device:
        # Device priority: 1. Apple MPS, 2. CUDA, 3. CPU
        try:
            if torch.backends.mps.is_available():
                return torch.device("mps")
        except AttributeError:
            pass
        if torch.cuda.is_available():
            return torch.device("cuda")
        return torch.device("cpu")

    def load_model(self) -> None:
        """
        Loads the HuggingFace tokenizer and sequence classification model.
        Guarantees thread-safe, single-time loading.
        """
        with self._lock:
            if self.is_loaded:
                return
            model_name = settings.CLASSIFIER_MODEL_NAME
            logger.info(f"Loading URLDetector tokenizer and model '{model_name}'...")
            try:
                self.device = self._detect_device()
                logger.info(f"URLDetector device: {self.device}")
                
                # Fetch/load using HuggingFace cache directory
                self.tokenizer = AutoTokenizer.from_pretrained(model_name, cache_dir=MODEL_CACHE_DIR)
                self.model = AutoModelForSequenceClassification.from_pretrained(model_name, cache_dir=MODEL_CACHE_DIR)
                
                self.model.to(self.device)
                self.model.eval()
                self.is_loaded = True
                logger.info("URLDetector model loaded successfully.")
            except Exception as e:
                logger.error(f"Failed to load URLDetector model: {e}")
                self.is_loaded = False
                raise e

    def predict(self, url: str) -> dict:
        """
        Performs sequence classification to predict if the given URL is legitimate or phishing.
        """
        if not self.is_loaded:
            raise RuntimeError("URLDetector model is not loaded. Call load_model() first.")
            
        # Reject invalid URLs
        if not self._is_valid_url(url):
            raise ValueError(f"Invalid URL: {url}")
            
        start_time = time.perf_counter()
        
        # Guard inference with thread lock for safety (especially for MPS multi-threading)
        with self._inference_lock:
            inputs = self.tokenizer(
                url, 
                return_tensors="pt", 
                truncation=True, 
                max_length=512, 
                padding=True
            )
            inputs = {k: v.to(self.device) for k, v in inputs.items()}
            
            with torch.inference_mode():
                outputs = self.model(**inputs)
                logits = outputs.logits
                logits_cpu = logits.squeeze().cpu()
                probs = torch.softmax(logits_cpu, dim=-1)
                
        latency_ms = (time.perf_counter() - start_time) * 1000
        
        probs_list = probs.tolist()
        logits_list = logits_cpu.tolist()
        
        # Label mapping setup
        id2label = {0: "legitimate", 1: "phishing"}
        if hasattr(self.model.config, "id2label") and self.model.config.id2label:
            for k, v in self.model.config.id2label.items():
                if v == "LABEL_0":
                    id2label[k] = "legitimate"
                elif v == "LABEL_1":
                    id2label[k] = "phishing"
                else:
                    id2label[k] = v
                    
        max_idx = int(torch.argmax(probs).item())
        label = id2label.get(max_idx, str(max_idx))
        probability = probs_list[max_idx]
        
        return {
            "label": label,
            "probability": probability,
            "confidence": probability,  # Using the class probability as standard confidence
            "raw_logits": logits_list,
            "latency_ms": round(latency_ms, 2)
        }

    def _is_valid_url(self, url: str) -> bool:
        if not url:
            return False
        try:
            parsed = urlparse(url)
            if not parsed.scheme or not parsed.netloc:
                return False
            if parsed.scheme.lower() not in ["http", "https"]:
                return False
            domain = parsed.netloc.split(":")[0]
            if not domain or "." not in domain:
                return False
            return True
        except Exception:
            return False

# Export the singleton instance
phishing_model = URLDetector()
