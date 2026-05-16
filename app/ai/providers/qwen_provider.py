"""
ScanWise AI — Qwen2.5-Coder Provider (PRIMARY)
Handles ALL: patch guidance, remediation, CVE analysis, structured JSON generation,
             executive summaries, hardening suggestions, advanced chat.
Runs via Ollama on localhost.

FIX 2: Auto-detects the best available qwen model — no hardcoded tag.
        Logs endpoint, model, response status clearly.
        keep_alive=0 releases VRAM after each generation.

ROOT CAUSE OF 404:
  The previous code hardcoded "qwen2.5-coder:3b" but the model installed
  locally may have a different tag (e.g. "qwen2.5-coder:latest" or just
  "qwen2.5-coder"). Ollama returns 404 when the model name doesn't exactly
  match what's installed. Fixed by querying /api/tags and auto-selecting.
"""
import json
import logging
import os
import urllib.request
import urllib.error

logger = logging.getLogger("scanwise.ai.qwen")

OLLAMA_BASE   = os.environ.get("OLLAMA_URL", "http://localhost:11434")
QWEN_MODEL    = os.environ.get("QWEN_MODEL", "")   # blank = auto-detect
TIMEOUT_SECS  = int(os.environ.get("QWEN_TIMEOUT", "120"))

# Priority order — most capable first, then smaller variants
# Architecture: 3b is PRIMARY — fast, low-RAM, good enough for patch JSON.
# 7b only selected if explicitly env-overridden via QWEN_MODEL.
_QWEN_CANDIDATES = [
    "qwen2.5-coder:3b",    # PRIMARY
    "qwen2.5-coder:latest",
    "qwen2.5-coder",
    "qwen2.5-coder:1.5b",
    "qwen2.5:3b",
    "qwen2.5",
    "qwen:7b",
    "qwen",
]


class QwenProvider:
    """Primary AI engine — Qwen2.5-Coder via Ollama."""

    def __init__(self):
        self._model: str | None = QWEN_MODEL or None
        self._available: bool | None = None

    @property
    def model(self) -> str:
        return self._model or QWEN_MODEL or "qwen2.5-coder:3b"

    def is_available(self) -> bool:
        """Check Ollama is running and a qwen model is present. Cached per-process."""
        if self._available is not None:
            return self._available
        self._available = self._check_and_resolve_model()
        return self._available

    def invalidate_cache(self):
        self._available = None
        self._model = QWEN_MODEL or None

    def generate(self, prompt: str, system: str = "",
                 expect_json: bool = True, max_tokens: int = 800) -> str:
        """
        Single-turn generation.
        max_tokens = 800 default — enough for structured patch JSON, avoids truncation.
        keep_alive=0 releases model from VRAM after generation.
        """
        model = self.model
        logger.debug(
            "qwen.generate endpoint=%s/api/generate model=%s max_tokens=%d",
            OLLAMA_BASE, model, max_tokens
        )

        json_instruction = (
            " Respond with ONLY a valid JSON object. No markdown, no prose." 
            if expect_json else ""
        )

        payload = json.dumps({
            "model":      model,
            "prompt":     prompt + json_instruction,
            "system":     system or "",
            "stream":     False,
            "keep_alive": 0,   # release VRAM after each call
            "options": {
                "num_predict": max_tokens,
                "temperature": 0.1,
                "top_p":       0.9,
                "num_ctx":     4096,
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
            result = body.get("response", "").strip()
            logger.debug("qwen.generate ok model=%s len=%d", model, len(result))
            return result
        except urllib.error.HTTPError as e:
            logger.error(
                "qwen.generate HTTP %s %s  endpoint=%s/api/generate  model=%s",
                e.code, e.reason, OLLAMA_BASE, model
            )
            raise
        except urllib.error.URLError as e:
            logger.error("qwen.generate URLError: %s  endpoint=%s", e.reason, OLLAMA_BASE)
            raise

    def chat(self, messages: list, system: str = "", max_tokens: int = 800) -> str:
        """Multi-turn chat. keep_alive=0 to free VRAM."""
        model = self.model
        logger.debug("qwen.chat endpoint=%s/api/chat model=%s", OLLAMA_BASE, model)

        full_messages = (
            [{"role": "system", "content": system}] if system else []
        ) + messages

        payload = json.dumps({
            "model":      model,
            "stream":     False,
            "keep_alive": 0,
            "messages":   full_messages,
            "options":    {"num_predict": max_tokens, "temperature": 0.15, "top_p": 0.9},
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
            return body.get("message", {}).get("content", "").strip()
        except urllib.error.HTTPError as e:
            logger.error(
                "qwen.chat HTTP %s %s  endpoint=%s/api/chat  model=%s",
                e.code, e.reason, OLLAMA_BASE, model
            )
            raise

    # ── Internal ──────────────────────────────────────────────────────────────

    def _check_and_resolve_model(self) -> bool:
        """
        Query /api/tags, find best available qwen model, cache it.
        Root-cause fix: the 404 was caused by requesting a model name that
        doesn't match the exact string returned by `ollama list`.
        This method resolves to the actual installed name.
        """
        try:
            req = urllib.request.Request(f"{OLLAMA_BASE}/api/tags", method="GET")
            with urllib.request.urlopen(req, timeout=5) as resp:
                body = json.loads(resp.read().decode())
        except Exception as e:
            logger.warning("qwen: Ollama not reachable at %s — %s", OLLAMA_BASE, e)
            return False

        available = [m["name"] for m in body.get("models", [])]
        logger.info("qwen: Ollama available models: %s", available)

        # If user explicitly set QWEN_MODEL, verify it's actually installed
        if QWEN_MODEL:
            base = QWEN_MODEL.split(":")[0]
            exact_match = next((m for m in available if m == QWEN_MODEL), None)
            prefix_match = next((m for m in available if m.split(":")[0] == base), None)
            chosen = exact_match or prefix_match
            if chosen:
                self._model = chosen
                logger.info("qwen: using env-specified model=%s (resolved=%s)",
                            QWEN_MODEL, chosen)
                return True
            else:
                logger.warning(
                    "qwen: QWEN_MODEL=%s not found in Ollama. "
                    "Will try auto-detection. Available: %s", QWEN_MODEL, available
                )

        # Auto-detect: walk priority list, pick first installed match
        for candidate in _QWEN_CANDIDATES:
            cand_base = candidate.split(":")[0]
            cand_tag  = candidate.split(":")[1] if ":" in candidate else None
            for m in available:
                m_base = m.split(":")[0]
                if cand_base == m_base:
                    if cand_tag is None or m == candidate or m.startswith(candidate):
                        self._model = m
                        logger.info("qwen: auto-selected model=%s", self._model)
                        return True

        logger.warning(
            "qwen: no qwen model found in Ollama. Available: %s. "
            "To fix: ollama pull qwen2.5-coder:3b", available
        )
        return False


# Singleton
qwen_provider = QwenProvider()
