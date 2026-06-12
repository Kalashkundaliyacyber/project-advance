"""
ThreatWeave — AI Logging Utility
Structured logging for provider calls: latency, retries, fallbacks, cache hits.
"""
import logging
import time
from collections import deque
from typing import Optional

logger = logging.getLogger("ThreatWeave.ai.logging")

# Rolling window of last N calls for stats
_CALL_HISTORY: deque = deque(maxlen=200)


def log_provider_call(
    provider: str,
    success: bool,
    latency_ms: int,
    reason: str = "",
    cache_hit: bool = False,
    queue_size: int = 0,
    retry_count: int = 0,
):
    """Record a structured provider call event."""
    entry = {
        "ts":         time.time(),
        "provider":   provider,
        "success":    success,
        "latency_ms": latency_ms,
        "reason":     reason,
        "cache_hit":  cache_hit,
        "queue_size": queue_size,
        "retry_count": retry_count,
    }
    _CALL_HISTORY.append(entry)

    level = logging.INFO if success else logging.WARNING
    cache_tag = " [CACHE HIT]" if cache_hit else ""
    retry_tag = f" [retry={retry_count}]" if retry_count else ""
    reason_tag = f" reason={reason}" if reason else ""
    logger.log(
        level,
        "AI provider=%s success=%s latency=%dms queue=%d%s%s%s",
        provider, success, latency_ms, queue_size,
        cache_tag, retry_tag, reason_tag,
    )


def get_stats() -> dict:
    """Return aggregated stats from the rolling call history."""
    if not _CALL_HISTORY:
        return {
            "total_calls": 0,
            "last_latency_ms": 0,
            "qwen_success_rate": "—",
            "llama_success_rate": "—",
            "openrouter_success_rate": "—",
            "cache_hit_rate": "—",
            "fallback_count": 0,
        }

    calls = list(_CALL_HISTORY)
    total = len(calls)

    def _rate(provider: str) -> str:
        prov_calls = [c for c in calls if c["provider"] == provider]
        if not prov_calls:
            return "—"
        ok = sum(1 for c in prov_calls if c["success"])
        return f"{ok}/{len(prov_calls)} ({100*ok//len(prov_calls)}%)"

    last_latency = calls[-1]["latency_ms"] if calls else 0
    cache_hits   = sum(1 for c in calls if c["cache_hit"])
    fallbacks    = sum(1 for c in calls if not c["success"])

    return {
        "total_calls":        total,
        "last_latency_ms":    last_latency,
        "qwen_success_rate":  _rate("qwen"),
        "llama_success_rate": _rate("llama"),
        "openrouter_success_rate": _rate("nemotron"),
        "cache_hit_rate":     f"{cache_hits}/{total}" if total else "—",
        "fallback_count":     fallbacks,
    }
