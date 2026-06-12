"""
Legacy shim — Gemini replaced by 4-model local stack.
Kept to avoid ImportError in any old code paths.
"""
from app.ai.providers.qwen_provider import qwen_provider

class GeminiSafetyBlock(Exception): pass
class GeminiQuotaError(Exception): pass

# Map old names to Qwen (best local equivalent)
gemini_provider   = qwen_provider
nemotron_provider = qwen_provider

# OpenRouter shims — no-ops so imports don't crash
class _NoOp:
    model = "unavailable"
    def is_available(self): return False
    def generate(self, *a, **kw): raise RuntimeError("OpenRouter removed — use local models")
    def chat(self, *a, **kw): raise RuntimeError("OpenRouter removed — use local models")
    def invalidate_cache(self): pass

class OpenRouterQuotaError(Exception): pass

gpt_oss_provider        = _NoOp()
deepseek_flash_provider = _NoOp()
llama33_provider        = _NoOp()
gemma4_provider         = _NoOp()

__all__ = [
    "GeminiSafetyBlock", "GeminiQuotaError", "gemini_provider",
    "nemotron_provider", "gpt_oss_provider", "deepseek_flash_provider",
    "llama33_provider", "gemma4_provider", "OpenRouterQuotaError",
]
