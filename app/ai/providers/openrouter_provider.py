"""
ThreatWeave — OpenRouter Provider (DISABLED — Phase 3)
=======================================================
OpenRouter cloud providers removed in Phase 3.
Replaced by local 4-model stack:
  Qwen 2.5 7B Instruct | Llama 3.2 3B | Llama 3.1 8B | DeepSeek R1 8B

This file is kept as a backward-compatibility shim so any existing
import statements don't cause ImportError.

All provider objects are no-ops that report is_available() = False.
"""
import logging

logger = logging.getLogger("ThreatWeave.ai.openrouter")
logger.debug("OpenRouter disabled — using local 4-model stack")


class OpenRouterQuotaError(Exception):
    pass


class _NoOpProvider:
    """No-op provider that always reports unavailable."""
    model = "openrouter-disabled"

    def is_available(self) -> bool:
        return False

    def generate(self, *args, **kwargs) -> str:
        raise RuntimeError("OpenRouter has been removed. Use local models via Ollama.")

    def chat(self, *args, **kwargs) -> str:
        raise RuntimeError("OpenRouter has been removed. Use local models via Ollama.")

    def invalidate_cache(self) -> None:
        pass


# Backward-compatible singleton aliases
# These are referenced by old imports in ai_router.py (legacy)
nemotron_provider       = _NoOpProvider()
gpt_oss_provider        = _NoOpProvider()
deepseek_flash_provider = _NoOpProvider()
llama33_provider        = _NoOpProvider()
gemma4_provider         = _NoOpProvider()
deepseek_provider       = _NoOpProvider()

MODELS: dict = {}

__all__ = [
    "OpenRouterQuotaError",
    "nemotron_provider", "gpt_oss_provider", "deepseek_flash_provider",
    "llama33_provider", "gemma4_provider", "deepseek_provider",
    "MODELS",
]
