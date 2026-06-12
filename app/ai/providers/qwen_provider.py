"""
ThreatWeave AI — Qwen 2.5 7B Instruct Provider (PRIMARY)
Use Case: Chatbot + general reasoning
Best balance of speed and intelligence for network security Q&A.
Runs via Ollama on localhost.
"""
import json
import logging
import os
import urllib.request
import urllib.error

logger = logging.getLogger("threatweave.ai.qwen")

OLLAMA_BASE  = os.environ.get("OLLAMA_URL", "http://localhost:11434")
QWEN_MODEL   = os.environ.get("QWEN_MODEL", "qwen2.5:7b")
TIMEOUT_SECS = int(os.environ.get("QWEN_TIMEOUT", "20"))


class QwenProvider:
    """Primary AI engine — Qwen 2.5 7B Instruct via Ollama."""

    def __init__(self):
        self.model = QWEN_MODEL
        self._available: bool | None = None

    def is_available(self) -> bool:
        if self._available is not None:
            return self._available
        self._available = self._check_model()
        return self._available

    def invalidate_cache(self):
        self._available = None

    def generate(self, prompt: str, system: str = "",
                 expect_json: bool = True, max_tokens: int = 2048) -> str:
        payload = json.dumps({
            "model":  self.model,
            "prompt": prompt,
            "system": system or "",
            "stream": False,
            "options": {
                "num_predict": max_tokens,
                "temperature": 0.1,
                "top_p": 0.9,
                "num_ctx": 2048,   # Reduced to lower RAM usage
            },
        }).encode()
        req = urllib.request.Request(
            f"{OLLAMA_BASE}/api/generate",
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=TIMEOUT_SECS) as resp:
                body = json.loads(resp.read().decode())
        except urllib.error.HTTPError as e:
            if e.code == 404:
                logger.warning("Qwen model '%s' not found. Run: ollama pull %s", self.model, self.model)
                self._available = False
            raise
        except TimeoutError:
            logger.warning("Qwen generate timed out — model may not be loaded.")
            self._available = False
            raise RuntimeError("timed out")
        return body.get("response", "").strip()

    def chat(self, messages: list, system: str = "", max_tokens: int = 2048) -> str:
        full_messages = (
            [{"role": "system", "content": system}] if system else []
        ) + messages
        payload = json.dumps({
            "model":    self.model,
            "stream":   False,
            "messages": full_messages,
            "options":  {"num_predict": max_tokens, "temperature": 0.15, "top_p": 0.9},
        }).encode()
        req = urllib.request.Request(
            f"{OLLAMA_BASE}/api/chat",
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=TIMEOUT_SECS) as resp:
                body = json.loads(resp.read().decode())
        except urllib.error.HTTPError as e:
            if e.code == 404:
                self._available = False
            raise
        except TimeoutError:
            logger.warning("Qwen chat timed out.")
            self._available = False
            raise RuntimeError("timed out")
        return body.get("message", {}).get("content", "").strip()

    def _check_model(self) -> bool:
        try:
            req = urllib.request.Request(f"{OLLAMA_BASE}/api/tags", method="GET")
            with urllib.request.urlopen(req, timeout=5) as resp:
                body = json.loads(resp.read().decode())
            models = [m["name"] for m in body.get("models", [])]
            model_base = self.model.split(":")[0]
            if any(model_base in m for m in models):
                return True
            # Graceful fallback: try 3b if 7b not installed
            fallback = model_base.replace("7b", "3b")
            if fallback != model_base and any(fallback in m for m in models):
                logger.info("Qwen: %s not found, using %s", self.model, fallback)
                self.model = fallback
                return True
            logger.warning("Qwen model '%s' not found. Run: ollama pull %s", self.model, self.model)
            return False
        except Exception as e:
            logger.debug("Qwen availability check failed: %s", e)
            return False


# Singleton
qwen_provider = QwenProvider()
