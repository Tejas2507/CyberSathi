import logging
import sys
from app.settings import settings

log_level = getattr(logging, settings.LOG_LEVEL.upper(), logging.INFO)

def setup_logging() -> None:
    logging.basicConfig(
        level=log_level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        handlers=[
            logging.StreamHandler(sys.stdout)
        ],
        force=True
    )

logger = logging.getLogger("cybersathi")
logger.setLevel(log_level)
