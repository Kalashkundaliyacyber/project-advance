"""
ThreatWeave AI — Llama Provider (FAST LOCAL CHATBOT + GENERAL PURPOSE)

Supports two models via env config:
  LLAMA_CHAT_MODEL  = llama3.2:3b   (Fast local chatbot)
  LLAMA_GEN_MODEL   = llama3.1:8b   (General purpose analysis)

Both run via Ollama on localhost.
"""
import json
import logging
import os
import urllib.request
import urllib.error

logger = logging.getLogger("threatweave.ai.llama")

OLLAMA_BASE      = os.environ.get("OLLAMA_URL", "http://localhost:11434")
LLAMA_CHAT_MODEL = os.environ.get("LLAMA_CHAT_MODEL", "llama3.2:3b")
LLAMA_GEN_MODEL  = os.environ.get("LLAMA_GEN_MODEL",  "llama3.1:8b")
TIMEOUT_SECS     = int(os.environ.get("LLAMA_TIMEOUT", "20"))


class LlamaProvider:
    """
    Dual-model Llama provider.
    - chat mode: uses llama3.2:3b (fast, low memory)
    - generate mode: uses llama3.1:8b (general purpose)
    Falls back between the two if one is missing.
    """

    def __init__(self):
        self.chat_model  = LLAMA_CHAT_MODEL
        self.gen_model   = LLAMA_GEN_MODEL
        self.model       = self.chat_model   # for status display
        self._chat_ok: bool | None = None
        self._gen_ok:  bool | None = None

    def is_available(self) -> bool:
        self._chat_ok = self._check(self.chat_model)
        self._gen_ok  = self._check(self.gen_model)
        return self._chat_ok or self._gen_ok

    def invalidate_cache(self):
        self._chat_ok = None
        self._gen_ok  = None

    def generate(self, prompt: str, system: str = "",
                 expect_json: bool = False, max_tokens: int = 1024) -> str:
        model = self.gen_model if self._gen_ok else self.chat_model
        payload = json.dumps({
            "model":  model,
            "prompt": prompt,
            "system": system or "",
            "stream": False,
            "options": {"num_predict": max_tokens, "temperature": 0.2, "top_p": 0.9},
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
                logger.warning("Llama generate model %s not found — marking unavailable", model)
                if model == self.gen_model:
                    self._gen_ok = False
                else:
                    self._chat_ok = False
            raise
        except TimeoutError:
            logger.warning("Llama generate timed out.")
            raise RuntimeError("timed out")
        return body.get("response", "").strip()

    def chat(self, messages: list, system: str = "", max_tokens: int = 1024) -> str:
        model = self.chat_model if self._chat_ok else self.gen_model
        self.model = model  # update display
        full_messages = (
            [{"role": "system", "content": system}] if system else []
        ) + messages
        payload = json.dumps({
            "model":    model,
            "stream":   False,
            "messages": full_messages,
            "options":  {"num_predict": max_tokens, "temperature": 0.1, "num_ctx": 2048},
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
                logger.warning("Llama chat model %s not found", model)
                if model == self.chat_model:
                    self._chat_ok = False
                else:
                    self._gen_ok = False
            raise
        except TimeoutError:
            logger.warning("Llama chat timed out.")
            raise RuntimeError("timed out")
        return body.get("message", {}).get("content", "").strip()

    def _check(self, model: str) -> bool:
        try:
            req = urllib.request.Request(f"{OLLAMA_BASE}/api/tags", method="GET")
            with urllib.request.urlopen(req, timeout=5) as resp:
                body = json.loads(resp.read().decode())
            models = [m["name"] for m in body.get("models", [])]
            model_base = model.split(":")[0]
            return any(model_base in m for m in models)
        except Exception as e:
            logger.debug("Llama check failed for %s: %s", model, e)
            return False


# Singleton
llama_provider = LlamaProvider()
