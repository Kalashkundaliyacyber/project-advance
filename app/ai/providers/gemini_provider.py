"""
ScanWise AI — Gemini Provider (EMERGENCY CLOUD FALLBACK ONLY)
Used ONLY when both Qwen and Llama are unavailable.
Never used as primary provider.
"""
import json
import logging
import os
import time
import urllib.request
import urllib.error

logger = logging.getLogger("scanwise.ai.gemini")

GEMINI_API_KEY  = os.environ.get("GEMINI_API_KEY", "")
GEMINI_MODEL    = os.environ.get("GEMINI_MODEL", "gemini-2.0-flash-lite")
GEMINI_BASE_URL = "https://generativelanguage.googleapis.com/v1beta/models"
MAX_RETRIES     = 2
RETRY_DELAY     = 2.0

SAFETY_SETTINGS = [
    {"category": "HARM_CATEGORY_HARASSMENT",        "threshold": "BLOCK_NONE"},
    {"category": "HARM_CATEGORY_HATE_SPEECH",       "threshold": "BLOCK_NONE"},
    {"category": "HARM_CATEGORY_SEXUALLY_EXPLICIT", "threshold": "BLOCK_NONE"},
    {"category": "HARM_CATEGORY_DANGEROUS_CONTENT", "threshold": "BLOCK_ONLY_HIGH"},
]

GENERATION_CONFIG = {
    "temperature":     0.1,
    "topP":            0.8,
    "topK":            20,
    "maxOutputTokens": 4096,
    "responseMimeType": "application/json",
}


class GeminiSafetyBlock(Exception):
    pass

class GeminiQuotaError(Exception):
    pass


class GeminiProvider:
    """Emergency cloud fallback. Only used when all local models fail."""

    def __init__(self):
        self.api_key = GEMINI_API_KEY
        self.model   = GEMINI_MODEL

    def is_available(self) -> bool:
        return bool(self.api_key and self.api_key not in ("", "your_key_here"))

    def generate(self, prompt: str, system: str = "",
                 expect_json: bool = True, max_tokens: int = 2048) -> str:
        if not self.is_available():
            raise ValueError("GEMINI_API_KEY not configured")

        config = {**GENERATION_CONFIG, "maxOutputTokens": max_tokens}
        contents = [{"role": "user", "parts": [{"text": prompt}]}]
        payload = {
            "contents":          contents,
            "generationConfig":  config,
            "safetySettings":    SAFETY_SETTINGS,
        }
        if system:
            payload["system_instruction"] = {"parts": [{"text": system}]}

        last_err = None
        for attempt in range(MAX_RETRIES + 1):
            try:
                return self._post(payload)
            except GeminiQuotaError:
                raise
            except GeminiSafetyBlock:
                raise
            except Exception as e:
                last_err = e
                if attempt < MAX_RETRIES:
                    time.sleep(RETRY_DELAY * (attempt + 1))

        raise RuntimeError(f"Gemini failed after {MAX_RETRIES + 1} attempts: {last_err}")

    def chat(self, messages: list, system: str = "", max_tokens: int = 2048) -> str:
        if not self.is_available():
            raise ValueError("GEMINI_API_KEY not configured")

        config = {**GENERATION_CONFIG, "maxOutputTokens": max_tokens,
                  "responseMimeType": "text/plain"}
        contents = []
        for m in messages:
            role = "user" if m["role"] == "user" else "model"
            contents.append({"role": role, "parts": [{"text": m["content"]}]})

        payload = {"contents": contents, "generationConfig": config,
                   "safetySettings": SAFETY_SETTINGS}
        if system:
            payload["system_instruction"] = {"parts": [{"text": system}]}

        return self._post(payload, expect_json=False)

    # ── Internal ──────────────────────────────────────────────────────────────

    def _post(self, payload: dict, expect_json: bool = True) -> str:
        url  = f"{GEMINI_BASE_URL}/{self.model}:generateContent?key={self.api_key}"
        data = json.dumps(payload).encode()
        req  = urllib.request.Request(
            url, data=data, headers={"Content-Type": "application/json"}, method="POST"
        )
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                body = json.loads(resp.read().decode())
        except urllib.error.HTTPError as e:
            code = e.code
            msg  = e.read().decode()[:200]
            if code == 429:
                raise GeminiQuotaError(f"Quota exceeded: {msg}")
            raise RuntimeError(f"Gemini HTTP {code}: {msg}")

        candidates = body.get("candidates", [])
        if not candidates:
            reason = body.get("promptFeedback", {}).get("blockReason", "unknown")
            raise GeminiSafetyBlock(f"Blocked: {reason}")

        parts = candidates[0].get("content", {}).get("parts", [])
        text  = "".join(p.get("text", "") for p in parts).strip()

        if not text:
            raise ValueError("Gemini returned empty response")
        return text


# Singleton
gemini_provider = GeminiProvider()
