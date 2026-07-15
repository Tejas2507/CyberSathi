"""
GeminiLLMAdapter
================
Provider-isolated Gemini LLM integration for CyberSathi.

Uses the current google-genai SDK (google.genai).
Reads GEMINI_API_KEY from environment / settings.
Raises LLMConfigurationError if the key is absent.
"""

from __future__ import annotations

import asyncio
import json
import re
from pathlib import Path
from typing import Any, Dict, List, Optional

from app.logging import logger
from app.settings import settings


class LLMConfigurationError(Exception):
    """Raised when the Gemini API key is absent or invalid."""


def _parse_json_response(raw_text: str) -> Dict[str, Any]:
    """
    Extracts the first JSON object from an LLM response.
    Handles markdown code-fences and stray leading text.
    """
    # Strip markdown fences
    stripped = re.sub(r"```(?:json)?", "", raw_text).strip().strip("`").strip()

    # Try direct parse
    try:
        return json.loads(stripped)
    except json.JSONDecodeError:
        pass

    # Extract first {...} block
    match = re.search(r"\{.*\}", stripped, re.DOTALL)
    if match:
        try:
            return json.loads(match.group(0))
        except json.JSONDecodeError:
            pass

    logger.warning(f"[GeminiAdapter] Failed to parse JSON from response: {raw_text[:300]}")
    return {"raw_response": raw_text}


class GeminiLLMAdapter:
    """
    Stateless Gemini LLM adapter using the google.genai SDK.
    All methods are async via run_in_executor.
    """

    def __init__(self) -> None:
        api_key = settings.GEMINI_API_KEY
        if not api_key:
            raise LLMConfigurationError(
                "GEMINI_API_KEY is not set. "
                "Please add it to your .env file or environment variables."
            )

        from google import genai  # type: ignore[import]
        from google.genai import types  # type: ignore[import]

        self._genai = genai
        self._types = types
        self._client = genai.Client(
            api_key=api_key,
            http_options=types.HttpOptions(timeout=60000)
        )
        self.model_name = settings.GEMINI_MODEL
        logger.info(f"[GeminiAdapter] Initialized with model: {self.model_name}")

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _call_sync(
        self,
        text_prompt: str,
        image_paths: Optional[List[Path]] = None,
        _retries: int = 3,
    ) -> str:
        """Synchronous call — will be wrapped in executor. Retries on 503."""
        import time as _time

        contents: list = []

        # Attach images first (multimodal order: images → text)
        if image_paths:
            from PIL import Image  # type: ignore[import]

            for img_path in image_paths:
                p = Path(img_path)
                if p.exists():
                    try:
                        img = Image.open(str(p))
                        contents.append(img)
                        logger.debug(f"[GeminiAdapter] Attached image: {p.name}")
                    except Exception as exc:
                        logger.warning(f"[GeminiAdapter] Could not load image {p}: {exc}")
                else:
                    logger.warning(f"[GeminiAdapter] Image not found, skipping: {p}")

        contents.append(text_prompt)

        last_exc: Exception = RuntimeError("No attempts made")
        for attempt in range(1, _retries + 1):
            try:
                response = self._client.models.generate_content(
                    model=self.model_name,
                    contents=contents,
                    config=self._types.GenerateContentConfig(
                        temperature=settings.LLM_TEMPERATURE,
                        candidate_count=1,
                    ),
                )
                return response.text or ""
            except Exception as exc:
                last_exc = exc
                err_str = str(exc)
                # Retry on transient 503 / 429 / overload / rate limit
                is_transient = (
                    "503" in err_str or "UNAVAILABLE" in err_str or "overloaded" in err_str.lower() or
                    "429" in err_str or "RESOURCE_EXHAUSTED" in err_str or "quota" in err_str.lower() or
                    "timeout" in err_str.lower() or "timed out" in err_str.lower() or "deadline" in err_str.lower() or
                    "504" in err_str
                )
                if is_transient:
                    wait = 3 ** attempt
                    logger.warning(
                        f"[GeminiAdapter] Transient API Error (attempt {attempt}/{_retries}): {err_str[:120]}. "
                        f"Retrying in {wait}s..."
                    )
                    _time.sleep(wait)
                    continue
                raise  # Non-retryable error

        raise last_exc


    # ------------------------------------------------------------------
    # Public async API
    # ------------------------------------------------------------------

    async def analyze_security(
        self,
        text_prompt: str,
        image_paths: Optional[List[Path]] = None,
    ) -> Dict[str, Any]:
        """
        Stage 1 / Stage 2 forensic security analysis.
        Returns parsed JSON dict conforming to ForensicReportBuilder schema.
        """
        logger.info(
            f"[GeminiAdapter] analyze_security → model={self.model_name} "
            f"images={len(image_paths) if image_paths else 0}"
        )

        loop = asyncio.get_event_loop()
        raw_text: str = await loop.run_in_executor(
            None, self._call_sync, text_prompt, image_paths or []
        )

        parsed = _parse_json_response(raw_text)
        logger.debug(f"[GeminiAdapter] analyze_security result keys: {list(parsed.keys())}")
        return parsed

    async def generate_guidance(
        self,
        text_prompt: str,
    ) -> Dict[str, Any]:
        """
        Stage 2b citizen safety guidance.
        Returns parsed JSON dict conforming to ForensicReportBuilder guidance schema.
        """
        logger.info(f"[GeminiAdapter] generate_guidance → model={self.model_name}")

        loop = asyncio.get_event_loop()
        raw_text: str = await loop.run_in_executor(
            None, self._call_sync, text_prompt, []
        )

        parsed = _parse_json_response(raw_text)
        logger.debug(f"[GeminiAdapter] generate_guidance result keys: {list(parsed.keys())}")
        return parsed
