"""
ScanWise AI — AI Provider Manager v4.0
Architecture: Qwen2.5-Coder 3B (primary) → Gemini (cloud backup) → Rule engine
              Llama 3.2 1B (chat) → Qwen (advanced chat) → Gemini

NEW in v4.0:
  - Circuit breaker per provider (CLOSED/OPEN/HALF_OPEN states)
  - Provider cooldown after consecutive failures
  - Provider health scoring (success rate + latency)
  - Retry limits enforced at orchestrator level
  - Manual circuit-breaker reset via reset_circuit_breaker()

Llama 3.2 3B REMOVED — redundant, wastes RAM, adds fallback latency.
Qwen2.5-Coder 3B is PRIMARY for all structured reasoning.
Llama 3.2 1B is CHATBOT only.
"""
import logging
import os
import time
from enum import Enum
from typing import Optional

from app.ai.providers.qwen_provider   import qwen_provider
from app.ai.providers.llama_provider  import llama_provider   # 1B chatbot only
from app.ai.providers.gemini_provider import (
    gemini_provider, GeminiQuotaError, GeminiSafetyBlock
)
from app.ai.utils.logging_utils import log_provider_call, get_stats

logger = logging.getLogger("scanwise.ai.manager")

_FAILURE_THRESHOLD = int(os.environ.get("CB_FAILURE_THRESHOLD", "3"))
_COOLDOWN_SECS     = int(os.environ.get("CB_COOLDOWN_SECS",     "60"))
_HALF_OPEN_LIMIT   = int(os.environ.get("CB_HALF_OPEN_LIMIT",   "1"))

_ADVANCED_CHAT_KEYWORDS = {
    "remediat", "patch", "exploit", "cve", "vulnerab",
    "hardening", "configure", "iptables", "firewall",
    "docker", "kubernetes", "nginx", "apache", "openssh",
    "debug", "fix", "how to", "command", "upgrade",
}


class CircuitState(Enum):
    CLOSED    = "closed"
    OPEN      = "open"
    HALF_OPEN = "half_open"


class ProviderCircuitBreaker:
    """Per-provider circuit breaker with health scoring."""

    def __init__(self, name: str):
        self.name               = name
        self.state              = CircuitState.CLOSED
        self._failure_count     = 0
        self._last_failure_ts   = 0.0
        self._half_open_probes  = 0
        self._total_calls       = 0
        self._total_successes   = 0
        self._total_latency_ms  = 0

    def allow_request(self) -> bool:
        if self.state == CircuitState.CLOSED:
            return True
        if self.state == CircuitState.OPEN:
            if time.time() - self._last_failure_ts >= _COOLDOWN_SECS:
                logger.info("CB[%s]: OPEN → HALF_OPEN", self.name)
                self.state = CircuitState.HALF_OPEN
                self._half_open_probes = 0
                return True
            return False
        if self._half_open_probes < _HALF_OPEN_LIMIT:
            self._half_open_probes += 1
            return True
        return False

    def record_success(self, latency_ms: int):
        self._total_calls      += 1
        self._total_successes  += 1
        self._total_latency_ms += latency_ms
        self._failure_count     = 0
        if self.state == CircuitState.HALF_OPEN:
            logger.info("CB[%s]: HALF_OPEN → CLOSED (probe ok)", self.name)
        self.state = CircuitState.CLOSED

    def record_failure(self, reason: str = ""):
        self._total_calls    += 1
        self._failure_count  += 1
        self._last_failure_ts = time.time()
        if self.state == CircuitState.HALF_OPEN:
            logger.warning("CB[%s]: HALF_OPEN → OPEN (probe failed: %s)", self.name, reason)
            self.state = CircuitState.OPEN
        elif self._failure_count >= _FAILURE_THRESHOLD:
            logger.warning("CB[%s]: CLOSED → OPEN (%d failures)", self.name, self._failure_count)
            self.state = CircuitState.OPEN

    def reset(self):
        self.state            = CircuitState.CLOSED
        self._failure_count   = 0
        self._half_open_probes = 0

    @property
    def health_score(self) -> float:
        if self._total_calls == 0:
            return 1.0
        success_rate  = self._total_successes / self._total_calls
        avg_latency   = self._total_latency_ms / self._total_calls
        latency_score = max(0.0, 1.0 - avg_latency / 30_000)
        return round(0.7 * success_rate + 0.3 * latency_score, 3)

    def status_dict(self) -> dict:
        return {
            "state":              self.state.value,
            "failure_count":      self._failure_count,
            "health_score":       self.health_score,
            "total_calls":        self._total_calls,
            "success_rate":       (
                f"{self._total_successes}/{self._total_calls}"
                if self._total_calls else "—"
            ),
            "cooldown_remaining": max(0, int(
                _COOLDOWN_SECS - (time.time() - self._last_failure_ts)
            )) if self.state == CircuitState.OPEN else 0,
        }


class AIProviderManager:
    """
    Unified AI provider manager with per-provider circuit breakers.
    generate(): Qwen → Gemini → raises RuntimeError
    chat():     Llama 1B → Qwen (advanced) → Gemini
    """

    def __init__(self):
        self._active_provider     = "unknown"
        self._fallback_reason     = ""
        self._last_status_refresh = 0.0
        self._status_cache: dict  = {}
        self._cb: dict[str, ProviderCircuitBreaker] = {
            "qwen":   ProviderCircuitBreaker("qwen"),
            "llama":  ProviderCircuitBreaker("llama"),
            "gemini": ProviderCircuitBreaker("gemini"),
        }

    def generate(self, prompt: str, system: str = "",
                 expect_json: bool = True, max_tokens: int = 1024) -> tuple:
        """Structured generation. Returns (text, provider_name)."""
        if qwen_provider.is_available() and self._cb["qwen"].allow_request():
            result = self._try_generate("qwen", qwen_provider, prompt, system, max_tokens)
            if result:
                return result, "qwen"

        if gemini_provider.is_available() and self._cb["gemini"].allow_request():
            result = self._try_gemini_generate(prompt, system, max_tokens)
            if result:
                return result, "gemini"

        self._active_provider = "rule-based"
        raise RuntimeError(
            f"All AI providers unavailable or circuit-open. {self._fallback_reason}. "
            "Rule-based fallback will be used by the caller."
        )

    def chat(self, messages: list, system: str = "",
             max_tokens: int = 512) -> tuple:
        """Multi-turn chat. Returns (text, provider_name)."""
        last_msg       = messages[-1].get("content", "") if messages else ""
        needs_advanced = self._needs_advanced_reasoning(last_msg)

        if needs_advanced and qwen_provider.is_available() and self._cb["qwen"].allow_request():
            result = self._try_chat("qwen", qwen_provider, messages, system, max_tokens)
            if result:
                return result, "qwen"

        if llama_provider.is_available() and self._cb["llama"].allow_request():
            result = self._try_chat("llama", llama_provider, messages, system, max_tokens)
            if result:
                return result, "llama"

        if not needs_advanced and qwen_provider.is_available() and self._cb["qwen"].allow_request():
            result = self._try_chat("qwen", qwen_provider, messages, system, max_tokens)
            if result:
                return result, "qwen"

        if gemini_provider.is_available() and self._cb["gemini"].allow_request():
            result = self._try_gemini_chat(messages, system, max_tokens)
            if result:
                return result, "gemini"

        raise RuntimeError(f"All chat providers unavailable or circuit-open. {self._fallback_reason}")

    def status(self) -> dict:
        now = time.time()
        if now - self._last_status_refresh < 30.0 and self._status_cache:
            return self._status_cache

        qwen_ok   = qwen_provider.is_available()
        llama_ok  = llama_provider.is_available()
        gemini_ok = gemini_provider.is_available()
        ollama_ok = qwen_ok or llama_ok

        active = (
            "qwen"       if qwen_ok   else
            "llama"      if llama_ok  else
            "gemini"     if gemini_ok else
            "rule-based"
        )
        self._active_provider = active
        stats = get_stats()

        self._status_cache = {
            "active_provider":    active,
            "qwen_available":     qwen_ok,
            "llama_available":    llama_ok,
            "gemini_available":   gemini_ok,
            "ollama_available":   ollama_ok,
            "qwen_model":         qwen_provider.model,
            "llama_model":        llama_provider.model,
            "gemini_model":       gemini_provider.model,
            "ollama_model":       qwen_provider.model,
            "fallback_reason":    self._fallback_reason,
            "display_name":       self._display_name(active),
            "display_provider":   self._display_provider(active),
            "last_latency_ms":    stats.get("last_latency_ms", 0),
            "total_calls":        stats.get("total_calls", 0),
            "qwen_success_rate":  stats.get("qwen_success_rate", "—"),
            "llama_success_rate": stats.get("llama_success_rate", "—"),
            "gemini_success_rate": stats.get("gemini_success_rate", "—"),
            "cache_hit_rate":     stats.get("cache_hit_rate", "—"),
            "circuit_breakers":   {n: cb.status_dict() for n, cb in self._cb.items()},
        }
        self._last_status_refresh = now
        return self._status_cache

    def invalidate_provider_cache(self):
        qwen_provider.invalidate_cache()
        llama_provider.invalidate_cache()
        self._status_cache        = {}
        self._last_status_refresh = 0.0

    def reset_circuit_breaker(self, provider: str):
        """Force-reset a circuit breaker to CLOSED (manual recovery)."""
        if provider in self._cb:
            self._cb[provider].reset()
            logger.info("CB[%s]: manually reset to CLOSED", provider)
            self._status_cache = {}

    def run_startup_health_check(self) -> dict:
        logger.info("=" * 54)
        logger.info("AI Provider Health Check")
        logger.info("=" * 54)
        health = {}

        qwen_ok = qwen_provider.is_available()
        health["qwen"] = {"available": qwen_ok, "model": qwen_provider.model if qwen_ok else "N/A"}
        if qwen_ok:
            logger.info("✅ Qwen  READY  model=%s", qwen_provider.model)
        else:
            logger.warning("⚠️  Qwen  NOT READY — run: ollama pull qwen2.5-coder:3b")

        llama_ok = llama_provider.is_available()
        health["llama"] = {"available": llama_ok, "model": llama_provider.model if llama_ok else "N/A"}
        if llama_ok:
            logger.info("✅ Llama READY  model=%s", llama_provider.model)
        else:
            logger.warning("⚠️  Llama NOT READY — run: ollama pull llama3.2:1b")

        gemini_ok = gemini_provider.is_available()
        health["gemini"] = {"available": gemini_ok}
        if gemini_ok:
            logger.info("✅ Gemini READY  model=%s", gemini_provider.model)
        else:
            logger.info("ℹ️  Gemini not configured (GEMINI_API_KEY not set)")

        if not qwen_ok and not llama_ok and not gemini_ok:
            logger.warning("⚠️  All AI providers unavailable — rule engine fallback only.")
        elif qwen_ok:
            logger.info("Active provider: Qwen2.5-Coder 3B (primary)")
        elif llama_ok:
            logger.info("Active provider: Llama 1B (chat fallback)")

        logger.info("=" * 54)
        return health

    # ── Internal helpers ───────────────────────────────────────────────────────

    def _try_generate(self, name: str, provider, prompt: str,
                      system: str, max_tokens: int) -> Optional[str]:
        t0 = time.time()
        try:
            text    = provider.generate(prompt, system=system,
                                        expect_json=True, max_tokens=max_tokens)
            latency = int((time.time() - t0) * 1000)
            self._cb[name].record_success(latency)
            log_provider_call(name, True, latency)
            self._active_provider = name
            self._fallback_reason = ""
            return text
        except Exception as e:
            latency = int((time.time() - t0) * 1000)
            reason  = str(e)[:80]
            self._cb[name].record_failure(reason)
            log_provider_call(name, False, latency, reason=reason)
            self._fallback_reason = f"{name}: {reason}"
            logger.warning("Provider %s generate failed (CB=%s): %s",
                           name, self._cb[name].state.value, e)
            return None

    def _try_chat(self, name: str, provider, messages: list,
                  system: str, max_tokens: int) -> Optional[str]:
        t0 = time.time()
        try:
            text    = provider.chat(messages, system=system, max_tokens=max_tokens)
            latency = int((time.time() - t0) * 1000)
            self._cb[name].record_success(latency)
            log_provider_call(name, True, latency)
            self._active_provider = name
            self._fallback_reason = ""
            return text
        except Exception as e:
            latency = int((time.time() - t0) * 1000)
            reason  = str(e)[:80]
            self._cb[name].record_failure(reason)
            log_provider_call(name, False, latency, reason=reason)
            self._fallback_reason = f"{name}: {reason}"
            logger.warning("Provider %s chat failed (CB=%s): %s",
                           name, self._cb[name].state.value, e)
            return None

    def _try_gemini_generate(self, prompt: str, system: str,
                             max_tokens: int) -> Optional[str]:
        t0 = time.time()
        try:
            text    = gemini_provider.generate(prompt, system=system,
                                               expect_json=True, max_tokens=max_tokens)
            latency = int((time.time() - t0) * 1000)
            self._cb["gemini"].record_success(latency)
            log_provider_call("gemini", True, latency)
            self._active_provider = "gemini"
            return text
        except GeminiQuotaError as e:
            latency = int((time.time() - t0) * 1000)
            self._cb["gemini"].record_failure("quota_exceeded")
            log_provider_call("gemini", False, latency, reason="quota_exceeded")
            self._fallback_reason = f"Gemini quota: {e}"
            return None
        except GeminiSafetyBlock as e:
            self._cb["gemini"].record_failure("safety_block")
            log_provider_call("gemini", False, 0, reason="safety_block")
            self._fallback_reason = f"Gemini safety: {e}"
            return None
        except Exception as e:
            latency = int((time.time() - t0) * 1000)
            reason  = str(e)[:80]
            self._cb["gemini"].record_failure(reason)
            log_provider_call("gemini", False, latency, reason=reason)
            self._fallback_reason = f"Gemini: {e}"
            return None

    def _try_gemini_chat(self, messages: list, system: str,
                         max_tokens: int) -> Optional[str]:
        t0 = time.time()
        try:
            text    = gemini_provider.chat(messages, system=system, max_tokens=max_tokens)
            latency = int((time.time() - t0) * 1000)
            self._cb["gemini"].record_success(latency)
            log_provider_call("gemini", True, latency)
            return text
        except (GeminiQuotaError, GeminiSafetyBlock) as e:
            self._cb["gemini"].record_failure(str(e)[:40])
            log_provider_call("gemini", False, 0, reason=str(e)[:60])
            return None
        except Exception as e:
            latency = int((time.time() - t0) * 1000)
            reason  = str(e)[:80]
            self._cb["gemini"].record_failure(reason)
            log_provider_call("gemini", False, latency, reason=reason)
            return None

    def _needs_advanced_reasoning(self, message: str) -> bool:
        return any(kw in message.lower() for kw in _ADVANCED_CHAT_KEYWORDS)

    @staticmethod
    def _display_name(active: str) -> str:
        return {
            "qwen":       "Qwen2.5-Coder 3B",
            "llama":      "Llama 3.2 1B",
            "gemini":     "Gemini (Cloud)",
            "rule-based": "Rule Engine",
            "unknown":    "Detecting…",
        }.get(active, active)

    @staticmethod
    def _display_provider(active: str) -> str:
        return {
            "qwen":       "Ollama · Primary",
            "llama":      "Ollama · Chat",
            "gemini":     "Google AI · Cloud Backup",
            "rule-based": "No AI · Rules only",
            "unknown":    "Starting…",
        }.get(active, active)


# Singleton (backwards compatible name)
ai_router = AIProviderManager()
