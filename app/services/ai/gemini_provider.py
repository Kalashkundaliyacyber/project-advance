"""
Legacy shim — gemini_provider has been replaced by openrouter_provider.
Kept so any old import doesn't crash with ImportError.
"""
from app.ai.providers.openrouter_provider import (
    OpenRouterProvider, OpenRouterQuotaError,
    nemotron_provider, deepseek_flash_provider,
)

# Map old names to OpenRouter equivalents
GeminiSafetyBlock = OpenRouterQuotaError
GeminiQuotaError  = OpenRouterQuotaError
gemini_provider   = nemotron_provider      # best structural replacement

__all__ = [
    "GeminiSafetyBlock", "GeminiQuotaError", "gemini_provider",
    "OpenRouterProvider", "OpenRouterQuotaError",
]
