"""
ScanWise AI — Llama 3.2 1B Provider (CHAT ONLY)
Handles: conversational responses, quick summaries.
NOT used for structured JSON / patch reasoning — that is Qwen's job.
Runs via Ollama on localhost.

Architecture note:
  Llama 3.2 3B removed — redundant, wastes RAM, adds fallback latency.
  Only Llama 3.2 1B is kept here as the lightweight chat model.

FIX 3: Timeout 120s, exponential-backoff retry, model auto-detection,
        OLLAMA_KEEP_ALIVE=0 to release VRAM after use.
"""
import json
import logging
import os
import time
import urllib.request
import urllib.error

logger = logging.getLogger("scanwise.ai.llama")

OLLAMA_BASE   = os.environ.get("OLLAMA_URL", "http://localhost:11434")
LLAMA_MODEL   = os.environ.get("LLAMA_MODEL", "")   # auto-detected if blank
TIMEOUT_SECS  = int(os.environ.get("LLAMA_TIMEOUT", "120"))
MAX_RETRIES   = int(os.environ.get("LLAMA_RETRIES", "2"))

# 1B models only — 3B is intentionally excluded (removed from architecture)
_LLAMA_CANDIDATES = [
    "llama3.2:1b",
    "llama3.2:1b-instruct-q4_K_M",
    "llama3.2:1b-instruct-q8_0",
    "llama3.2",       # smallest available tag
    "llama3.1:8b",    # only if 1B not available
    "llama3.1",
    "llama3:8b",
    "llama3",
]


class LlamaProvider:
    """Lightweight chat-only provider — Llama 3.2 1B via Ollama."""

    def __init__(self):
        self._model: str | None = LLAMA_MODEL or None
        self._available: bool | None = None

    @property
    def model(self) -> str:
        return self._model or LLAMA_MODEL or "llama3.2:1b"

    def is_available(self) -> bool:
        if self._available is not None:
            return self._available
        self._available = self._check_and_resolve_model()
        return self._available

    def invalidate_cache(self):
        self._available = None
        self._model = LLAMA_MODEL or None

    def generate(self, prompt: str, system: str = "",
                 expect_json: bool = False, max_tokens: int = 512) -> str:
        """
        Single-turn generation with retry on transient errors.
        max_tokens = 512 default — 1B model, keep responses short.
        OLLAMA_KEEP_ALIVE=0 releases model from VRAM after response.
        """
        model = self.model
        logger.debug("llama.generate endpoint=%s/api/generate model=%s", OLLAMA_BASE, model)

        payload = json.dumps({
            "model":      model,
            "prompt":     prompt,
            "system":     system or "",
            "stream":     False,
            "keep_alive": 0,    # release from VRAM immediately after generation
            "options": {
                "num_predict": max_tokens,
                "temperature": 0.2,
                "top_p":       0.9,
                "num_ctx":     2048,
            },
        }).encode()

        last_exc = None
        for attempt in range(1, MAX_RETRIES + 1):
            try:
                req = urllib.request.Request(
                    f"{OLLAMA_BASE}/api/generate",
                    data=payload,
                    headers={"Content-Type": "application/json"},
                    method="POST",
                )
                t0 = time.time()
                with urllib.request.urlopen(req, timeout=TIMEOUT_SECS) as resp:
                    body = json.loads(resp.read().decode())
                latency = int((time.time() - t0) * 1000)
                result  = body.get("response", "").strip()
                logger.debug("llama.generate ok attempt=%d latency=%dms", attempt, latency)
                return result
            except urllib.error.URLError as e:
                last_exc = e
                logger.warning("llama.generate attempt=%d failed: %s", attempt, e)
                if attempt < MAX_RETRIES:
                    wait = 2 ** attempt
                    logger.info("llama retrying in %ds…", wait)
                    time.sleep(wait)
            except Exception as e:
                last_exc = e
                logger.warning("llama.generate attempt=%d error: %s", attempt, e)
                break

        raise last_exc or RuntimeError("llama generate failed after retries")

    def chat(self, messages: list, system: str = "", max_tokens: int = 512) -> str:
        """Multi-turn chat with retry. keep_alive=0 to free VRAM."""
        model = self.model
        logger.debug("llama.chat endpoint=%s/api/chat model=%s", OLLAMA_BASE, model)

        full_messages = (
            [{"role": "system", "content": system}] if system else []
        ) + messages

        payload = json.dumps({
            "model":      model,
            "stream":     False,
            "keep_alive": 0,
            "messages":   full_messages,
            "options":    {"num_predict": max_tokens, "temperature": 0.2, "num_ctx": 2048},
        }).encode()

        last_exc = None
        for attempt in range(1, MAX_RETRIES + 1):
            try:
                req = urllib.request.Request(
                    f"{OLLAMA_BASE}/api/chat",
                    data=payload,
                    headers={"Content-Type": "application/json"},
                    method="POST",
                )
                with urllib.request.urlopen(req, timeout=TIMEOUT_SECS) as resp:
                    body = json.loads(resp.read().decode())
                return body.get("message", {}).get("content", "").strip()
            except urllib.error.URLError as e:
                last_exc = e
                logger.warning("llama.chat attempt=%d failed: %s", attempt, e)
                if attempt < MAX_RETRIES:
                    time.sleep(2 ** attempt)
            except Exception as e:
                last_exc = e
                break

        raise last_exc or RuntimeError("llama chat failed after retries")

    def _check_and_resolve_model(self) -> bool:
        """Query /api/tags, find best available 1B llama model, cache selection."""
        try:
            req = urllib.request.Request(f"{OLLAMA_BASE}/api/tags", method="GET")
            with urllib.request.urlopen(req, timeout=5) as resp:
                body = json.loads(resp.read().decode())
        except Exception as e:
            logger.warning("llama: Ollama not reachable at %s — %s", OLLAMA_BASE, e)
            return False

        available = [m["name"] for m in body.get("models", [])]
        logger.info("llama: Ollama available models: %s", available)

        if LLAMA_MODEL:
            base = LLAMA_MODEL.split(":")[0]
            if any(base in m for m in available):
                self._model = LLAMA_MODEL
                logger.info("llama: using env-specified model=%s", self._model)
                return True
            else:
                logger.warning("llama: LLAMA_MODEL=%s not found. Available: %s",
                               LLAMA_MODEL, available)

        for candidate in _LLAMA_CANDIDATES:
            cand_base = candidate.split(":")[0]
            cand_tag  = candidate.split(":")[1] if ":" in candidate else None
            for m in available:
                m_base = m.split(":")[0]
                if cand_base == m_base:
                    if cand_tag is None or m == candidate or m.startswith(candidate):
                        self._model = m
                        logger.info("llama: auto-selected model=%s", self._model)
                        return True

        logger.warning(
            "llama: no llama model found. Available: %s. "
            "Run: ollama pull llama3.2:1b", available
        )
        return False


# Singleton
llama_provider = LlamaProvider()
