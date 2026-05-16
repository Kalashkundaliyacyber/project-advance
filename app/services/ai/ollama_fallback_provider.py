"""
ScanWise AI — Legacy Ollama provider shim (v5.0)
Logic has moved to app/ai/providers/qwen_provider.py and llama_provider.py.
Kept for backwards compatibility.
"""
from app.ai.providers.qwen_provider  import QwenProvider,  qwen_provider
from app.ai.providers.llama_provider import LlamaProvider, llama_provider

__all__ = [
    "QwenProvider",  "qwen_provider",
    "LlamaProvider", "llama_provider",
]
