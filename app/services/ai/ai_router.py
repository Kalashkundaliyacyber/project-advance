"""
ScanWise AI — Legacy AI Router shim (v5.0)
This file is kept for backwards compatibility.
All logic has been moved to app/ai/routing/ai_router.py.
"""
from app.ai.routing.ai_router import ai_router, AIProviderManager

__all__ = ["ai_router", "AIProviderManager"]
