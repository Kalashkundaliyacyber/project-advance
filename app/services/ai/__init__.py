"""
ScanWise AI — AI Services Package v5.0
All AI logic has moved to app/ai/. This package re-exports for backwards compatibility.
"""
from app.services.ai.ai_router               import ai_router
from app.ai.providers.gemini_provider        import gemini_provider as gemini, GeminiSafetyBlock, GeminiQuotaError
from app.ai.providers.qwen_provider          import qwen_provider
from app.ai.providers.llama_provider         import llama_provider as ollama_fallback
from app.services.ai.prompt_templates        import (
    SYSTEM_INSTRUCTION,
    SCAN_ANALYSIS_PROMPT,
    CHAT_SYSTEM_TEMPLATE,
    CVE_EXPLAIN_PROMPT,
    PATCH_GUIDANCE_PROMPT,
)

__all__ = [
    "ai_router",
    "gemini",
    "GeminiSafetyBlock",
    "GeminiQuotaError",
    "qwen_provider",
    "ollama_fallback",
    "SYSTEM_INSTRUCTION",
    "SCAN_ANALYSIS_PROMPT",
    "CHAT_SYSTEM_TEMPLATE",
    "CVE_EXPLAIN_PROMPT",
    "PATCH_GUIDANCE_PROMPT",
]
