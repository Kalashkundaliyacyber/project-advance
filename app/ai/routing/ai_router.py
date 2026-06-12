"""
ThreatWeave — AI Provider Manager v4.0

Model Stack:
  PRIMARY   Qwen 2.5 7B Instruct   → Chatbot + reasoning
  FAST      Llama 3.2 3B           → Fast local chatbot
  GENERAL   Llama 3.1 8B           → General purpose analysis
  SECURITY  DeepSeek R1 8B Distill → Deep CVE/security analysis
  EMERGENCY Rule Engine            → No AI needed (offline fallback)

Routing Strategy:
  GENERATE/ANALYSIS:
    Security tasks  → DeepSeek R1 → Qwen → Llama 3.1 8B → Rule engine
    General tasks   → Qwen        → Llama 3.1 8B → DeepSeek R1 → Rule engine

  CHAT:
    Advanced topics → Qwen → DeepSeek R1 → Llama 3.2 3B → keyword fallback
    Normal chat     → Llama 3.2 3B → Qwen → Llama 3.1 8B → keyword fallback
"""
import logging
import time
from typing import Optional

from app.ai.providers.qwen_provider     import qwen_provider
from app.ai.providers.llama_provider    import llama_provider
from app.ai.providers.deepseek_provider import deepseek_provider
from app.ai.utils.logging_utils         import log_provider_call, get_stats

logger = logging.getLogger("ThreatWeave.ai.manager")

# Keywords that warrant deep security analysis (DeepSeek R1 first)
_SECURITY_KEYWORDS = {
    "cve", "exploit", "vulnerab", "0day", "zero-day", "rce",
    "remote code", "privilege escalation", "sql injection", "buffer overflow",
    "attack chain", "threat actor", "malware", "ransomware", "backdoor",
    "metasploit", "shodan", "nuclei", "nmap script",
    "cvss", "epss", "kev", "known exploited",
}

# Keywords that warrant advanced reasoning (Qwen first)
_ADVANCED_CHAT_KEYWORDS = {
    "remediat", "patch", "hardening", "configure", "iptables", "firewall",
    "docker", "kubernetes", "nginx", "apache", "openssh",
    "debug", "fix", "how to", "command", "upgrade", "mitigation",
}


class AIProviderManager:
    """
    Unified AI provider manager — clean 4-model stack.
    Backwards compatible: exposes .generate() and .chat()
    """

    def __init__(self):
        self._active_provider = "unknown"
        self._fallback_reason = ""
        self._last_status_refresh = 0.0
        self._status_cache: dict = {}

    # ── Public interface ───────────────────────────────────────────────────────

    def generate(self, prompt: str, system: str = "",
                 expect_json: bool = True, max_tokens: int = 2048,
                 task_type: str = "general") -> tuple:
        """
        Generate a response. Returns (text, provider_name).

        task_type hints:
          "security"  → DeepSeek R1 first
          "general"   → Qwen first
          "fast"      → Llama 3.2 3B first
        """
        is_security = (task_type == "security") or self._is_security_task(prompt)

        if is_security:
            stack = [
                ("deepseek", deepseek_provider),
                ("qwen",     qwen_provider),
                ("llama",    llama_provider),
            ]
        else:
            stack = [
                ("qwen",     qwen_provider),
                ("llama",    llama_provider),
                ("deepseek", deepseek_provider),
            ]

        for name, provider in stack:
            if provider.is_available():
                result = self._try_generate(name, provider, prompt, system, max_tokens, expect_json=expect_json)
                if result:
                    return result, name

        self._active_provider = "rule-based"
        raise RuntimeError(
            f"All AI providers failed. {self._fallback_reason}. "
            "Rule-based fallback will be used by the caller."
        )

    def chat(self, messages: list, system: str = "",
             max_tokens: int = 1024) -> tuple:
        """
        Multi-turn chat. Returns (text, provider_name).
        Routes advanced security questions to Qwen/DeepSeek,
        normal chat to Llama 3.2 3B (fast).
        """
        last_msg = messages[-1].get("content", "") if messages else ""
        is_security = self._is_security_task(last_msg)
        is_advanced = self._is_advanced_task(last_msg)

        if is_security:
            # CVE/exploit questions → Qwen then DeepSeek then Llama
            chat_stack = [
                ("qwen",     qwen_provider),
                ("deepseek", deepseek_provider),
                ("llama",    llama_provider),
            ]
        elif is_advanced:
            # Remediation/hardening → Qwen then Llama
            chat_stack = [
                ("qwen",  qwen_provider),
                ("llama", llama_provider),
            ]
        else:
            # Normal chat → Llama 3.2 3B (fastest) then Qwen
            chat_stack = [
                ("llama", llama_provider),
                ("qwen",  qwen_provider),
            ]

        for name, provider in chat_stack:
            if provider.is_available():
                result = self._try_chat(name, provider, messages, system, max_tokens)
                if result:
                    return result, name

        raise RuntimeError(f"All chat providers failed. {self._fallback_reason}")

    def analyze_cve(self, cve_data: dict, context: str = "") -> tuple:
        """
        Deep CVE analysis — uses DeepSeek R1 first, falls back to Qwen.
        Returns (analysis_text, provider_name).
        """
        if deepseek_provider.is_available():
            try:
                t0 = time.time()
                result = deepseek_provider.analyze_security(cve_data, context)
                log_provider_call("deepseek", True, int((time.time()-t0)*1000))
                return result, "deepseek"
            except Exception as e:
                logger.warning("DeepSeek CVE analysis failed: %s", e)

        # Fallback to Qwen
        prompt = f"""Analyze this CVE for network security impact.
CVE Data: {cve_data}
{f'Context: {context}' if context else ''}
Return JSON with: severity_assessment, exploit_likelihood, attack_vectors, immediate_actions, long_term_fix, confidence_score"""
        try:
            result, name = self.generate(prompt, task_type="security")
            return result, name
        except Exception:
            raise RuntimeError("CVE analysis failed — all providers unavailable")

    def status(self) -> dict:
        """Return current provider status for /api/ai/status endpoint."""
        now = time.time()
        if now - self._last_status_refresh < 30.0 and self._status_cache:
            return self._status_cache

        qwen_ok     = qwen_provider.is_available()
        llama_ok    = llama_provider.is_available()
        deepseek_ok = deepseek_provider.is_available()
        any_ok      = qwen_ok or llama_ok or deepseek_ok

        if qwen_ok:         active = "qwen"
        elif llama_ok:      active = "llama"
        elif deepseek_ok:   active = "deepseek"
        else:               active = "rule-based"

        self._active_provider = active
        stats = get_stats()

        self._status_cache = {
            # Core status
            "active_provider":      active,
            "any_available":        any_ok,
            "ollama_available":     any_ok,
            "openrouter_available": False,   # Removed in Phase 3

            # Per-model availability
            "qwen_available":       qwen_ok,
            "llama_available":      llama_ok,
            "deepseek_available":   deepseek_ok,

            # Model names
            "qwen_model":           qwen_provider.model,
            "llama_model":          f"{llama_provider.chat_model} / {llama_provider.gen_model}",
            "llama_chat_model":     llama_provider.chat_model,
            "llama_gen_model":      llama_provider.gen_model,
            "deepseek_model":       deepseek_provider.model,
            "ollama_model":         qwen_provider.model,

            # Backward-compat aliases (some frontend may reference these)
            "nemotron_available":   False,
            "gpt_oss_available":    False,
            "llama33_available":    llama_ok,
            "gemma4_available":     False,
            "nemotron_model":       "",
            "gpt_oss_model":        "",
            "llama33_model":        llama_provider.chat_model,
            "gemma4_model":         "",
            "deepseek_flash_model": deepseek_provider.model,

            # Display
            "fallback_reason":      self._fallback_reason,
            "display_name":         self._display_name(active),
            "display_provider":     self._display_provider(active),

            # Stats
            "last_latency_ms":      stats.get("last_latency_ms", 0),
            "total_calls":          stats.get("total_calls", 0),
            "qwen_success_rate":    stats.get("qwen_success_rate", "—"),
            "llama_success_rate":   stats.get("llama_success_rate", "—"),
            "deepseek_success_rate": stats.get("deepseek_success_rate", "—"),
            "cache_hit_rate":       stats.get("cache_hit_rate", "—"),

            # Model stack description
            "model_stack": {
                "primary":   {"name": "Qwen 2.5 7B Instruct",   "use": "Chatbot + reasoning",     "available": qwen_ok},
                "fast":      {"name": "Llama 3.2 3B",            "use": "Fast local chatbot",       "available": llama_ok},
                "general":   {"name": "Llama 3.1 8B",            "use": "General purpose",          "available": llama_ok},
                "security":  {"name": "DeepSeek R1 8B Distill",  "use": "Security analysis",        "available": deepseek_ok},
                "emergency": {"name": "Rule Engine",             "use": "No AI offline fallback",   "available": True},
            },
        }
        self._last_status_refresh = now
        return self._status_cache

    def invalidate_provider_cache(self):
        qwen_provider.invalidate_cache()
        llama_provider.invalidate_cache()
        deepseek_provider.invalidate_cache()
        self._status_cache = {}
        self._last_status_refresh = 0.0

    # ── Internal helpers ───────────────────────────────────────────────────────

    def _try_generate(self, name: str, provider, prompt: str,
                      system: str, max_tokens: int,
                      expect_json: bool = True) -> Optional[str]:
        t0 = time.time()
        try:
            text = provider.generate(prompt, system=system,
                                     expect_json=expect_json, max_tokens=max_tokens)
            latency = int((time.time() - t0) * 1000)
            log_provider_call(name, True, latency)
            self._active_provider = name
            self._fallback_reason = ""
            return text
        except Exception as e:
            latency = int((time.time() - t0) * 1000)
            reason  = str(e)[:80]
            log_provider_call(name, False, latency, reason=reason)
            self._fallback_reason = f"{name}: {reason}"
            logger.warning("Provider %s generate failed: %s", name, e)
            return None

    def _try_chat(self, name: str, provider, messages: list,
                  system: str, max_tokens: int) -> Optional[str]:
        t0 = time.time()
        try:
            text = provider.chat(messages, system=system, max_tokens=max_tokens)
            latency = int((time.time() - t0) * 1000)
            log_provider_call(name, True, latency)
            self._active_provider = name
            self._fallback_reason = ""
            return text
        except Exception as e:
            latency = int((time.time() - t0) * 1000)
            reason  = str(e)[:80]
            log_provider_call(name, False, latency, reason=reason)
            self._fallback_reason = f"{name}: {reason}"
            logger.warning("Provider %s chat failed: %s", name, e)
            return None

    def _is_security_task(self, text: str) -> bool:
        text_lower = text.lower()
        return any(kw in text_lower for kw in _SECURITY_KEYWORDS)

    def _is_advanced_task(self, text: str) -> bool:
        text_lower = text.lower()
        return any(kw in text_lower for kw in _ADVANCED_CHAT_KEYWORDS)

    @staticmethod
    def _display_name(active: str) -> str:
        return {
            "qwen":       "Qwen 2.5 7B Instruct",
            "llama":      "Llama 3.2 3B / 3.1 8B",
            "deepseek":   "DeepSeek R1 8B Distill",
            "rule-based": "Rule Engine",
            "unknown":    "Detecting…",
        }.get(active, active)

    @staticmethod
    def _display_provider(active: str) -> str:
        return {
            "qwen":       "Ollama · Primary Chatbot",
            "llama":      "Ollama · Fast / General",
            "deepseek":   "Ollama · Security Analysis",
            "rule-based": "No AI · Rules only",
            "unknown":    "Starting…",
        }.get(active, active)


# ── Singleton ─────────────────────────────────────────────────────────────────
ai_router = AIProviderManager()
