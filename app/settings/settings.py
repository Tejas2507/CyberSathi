from pydantic_settings import BaseSettings, SettingsConfigDict
from typing import List, Union
from pydantic import field_validator

class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env", env_file_encoding="utf-8", case_sensitive=True, extra="ignore"
    )

    APP_NAME: str = "CyberSathi Backend"
    APP_ENV: str = "local"
    DEBUG: bool = True
    API_V1_STR: str = "/api/v1"
    PROJECT_NAME: str = "CyberSathi"

    HOST: str = "0.0.0.0"
    PORT: int = 8000

    LOG_LEVEL: str = "INFO"

    CLASSIFIER_MODEL_NAME: str = "CrabInHoney/urlbert-tiny-v4-phishing-classifier"
    CLASSIFIER_THRESHOLD: float = 0.75

    PLAYWRIGHT_TIMEOUT_MS: int = 15000
    PLAYWRIGHT_HEADLESS: bool = True
    HTTP_REQUEST_TIMEOUT_SEC: int = 10
    MAX_DNS_LOOKUP_RETRY: int = 3

    LLM_PROVIDER: str = "gemini"
    LLM_API_KEY: str = ""
    LLM_MODEL: str = "gpt-4o"
    LLM_TEMPERATURE: float = 0.0

    GEMINI_API_KEY: str = ""
    GEMINI_MODEL: str = "gemini-3.5-flash"

    PHISHING_DB_PATH: str = "confirmed_phishing.db"
    PHISHING_CONFIDENCE_THRESHOLD: float = 0.95

    BACKEND_CORS_ORIGINS: Union[str, List[str]] = ["http://localhost:3000", "http://localhost:8000"]

    @field_validator("BACKEND_CORS_ORIGINS", mode="before")
    @classmethod
    def assemble_cors_origins(cls, v: Union[str, List[str]]) -> Union[List[str], str]:
        if isinstance(v, str) and not v.startswith("["):
            return [i.strip() for i in v.split(",")]
        elif isinstance(v, (list, str)):
            return v
        raise ValueError(v)

settings = Settings()
