"""
ScanWise AI — Legacy Gemini provider shim (v5.0)
Logic has moved to app/ai/providers/gemini_provider.py.
Kept for backwards compatibility with any existing imports.
"""
from app.ai.providers.gemini_provider import (
    GeminiProvider, GeminiSafetyBlock, GeminiQuotaError, gemini_provider
)

__all__ = [
    "GeminiProvider",
    "GeminiSafetyBlock",
    "GeminiQuotaError",
    "gemini_provider",
]
