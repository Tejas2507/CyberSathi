import os
from app.settings import settings

API_V1_STR = settings.API_V1_STR
PROJECT_NAME = settings.PROJECT_NAME

MODEL_CACHE_DIR = os.path.join(os.getcwd(), ".cache", "huggingface")

DEFAULT_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/125.0.0.0 Safari/537.36"
)
MAX_PAGE_SCROLLS = 3
SCAN_TIMEOUT_SEC = 20

DNS_RESOLVERS = ["8.8.8.8", "1.1.1.1"]
