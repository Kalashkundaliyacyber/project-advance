"""
ThreatWeave services — active model stack.
Cloud AI handled by OpenRouter (5 free models, no local GPU needed).
"""
from app.ai.routing.ai_router             import ai_router, AIProviderManager
from app.ai.providers.qwen_provider       import qwen_provider
from app.ai.providers.llama_provider      import llama_provider as ollama_fallback
from app.ai.providers.openrouter_provider import (
    nemotron_provider    as nemotron,
    gpt_oss_provider     as gpt_oss,
    llama33_provider     as llama33,
    gemma4_provider      as gemma4,
    deepseek_flash_provider as deepseek_flash,
    OpenRouterQuotaError,
)
from app.services.ai.prompt_templates import (
    SYSTEM_INSTRUCTION,
    SCAN_ANALYSIS_PROMPT,
    CHAT_SYSTEM_TEMPLATE,
    CVE_EXPLAIN_PROMPT,
    PATCH_GUIDANCE_PROMPT,
)

__all__ = [
    "ai_router",
    "AIProviderManager",
    "qwen_provider",
    "ollama_fallback",
    "nemotron",
    "gpt_oss",
    "llama33",
    "gemma4",
    "deepseek_flash",
    "OpenRouterQuotaError",
    "SYSTEM_INSTRUCTION",
    "SCAN_ANALYSIS_PROMPT",
    "CHAT_SYSTEM_TEMPLATE",
    "CVE_EXPLAIN_PROMPT",
    "PATCH_GUIDANCE_PROMPT",
]
