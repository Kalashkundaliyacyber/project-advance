"""
ScanWise AI — AI Logging Utility v2.0
Structured logging for provider calls: latency, retries, fallbacks, cache hits.

v2.0: Also forwards events to TelemetryCollector for /api/telemetry observability.
The telemetry import is lazy (try/except) so logging_utils remains importable
without the full telemetry module during early bootstrap.
"""
import logging
import time
from collections import deque

logger = logging.getLogger("scanwise.ai.logging")

# Rolling window of last 200 calls for get_stats()
_CALL_HISTORY: deque = deque(maxlen=200)


def log_provider_call(
    provider: str,
    success: bool,
    latency_ms: int,
    reason: str     = "",
    cache_hit: bool = False,
    queue_size: int = 0,
    retry_count: int = 0,
    correlation_id: str = "",
    event_type: str = "generate",
):
    """Record a structured provider call event and forward to telemetry."""
    entry = {
        "ts":             time.time(),
        "provider":       provider,
        "success":        success,
        "latency_ms":     latency_ms,
        "reason":         reason,
        "cache_hit":      cache_hit,
        "queue_size":     queue_size,
        "retry_count":    retry_count,
        "correlation_id": correlation_id,
        "event_type":     event_type,
    }
    _CALL_HISTORY.append(entry)

    level     = logging.INFO if success else logging.WARNING
    cache_tag = " [CACHE HIT]"        if cache_hit   else ""
    retry_tag = f" [retry={retry_count}]" if retry_count else ""
    reason_tag = f" reason={reason}"  if reason       else ""
    cid_tag   = f" cid={correlation_id}" if correlation_id else ""

    logger.log(
        level,
        "AI provider=%s success=%s latency=%dms queue=%d%s%s%s%s",
        provider, success, latency_ms, queue_size,
        cache_tag, retry_tag, reason_tag, cid_tag,
    )

    # Forward to structured telemetry collector (non-blocking, best-effort)
    try:
        from app.ai.utils.telemetry import telemetry
        if event_type == "timeout":
            telemetry.record_timeout(provider, latency_ms / 1000, correlation_id)
        elif event_type == "json_error":
            telemetry.record_json_error(provider, reason, correlation_id)
        elif not cache_hit:
            telemetry.record_provider(
                provider, success, latency_ms,
                reason=reason, correlation_id=correlation_id,
                event_type=event_type,
            )
    except Exception:
        pass  # never let telemetry break the hot path


def get_stats() -> dict:
    """Return aggregated stats from the rolling call history."""
    if not _CALL_HISTORY:
        return {
            "total_calls":        0,
            "last_latency_ms":    0,
            "qwen_success_rate":  "—",
            "llama_success_rate": "—",
            "gemini_success_rate":"—",
            "cache_hit_rate":     "—",
            "fallback_count":     0,
        }

    calls = list(_CALL_HISTORY)
    total = len(calls)

    def _rate(provider: str) -> str:
        prov = [c for c in calls if c["provider"] == provider]
        if not prov:
            return "—"
        ok = sum(1 for c in prov if c["success"])
        return f"{ok}/{len(prov)} ({100*ok//len(prov)}%)"

    last_latency = calls[-1]["latency_ms"] if calls else 0
    cache_hits   = sum(1 for c in calls if c["cache_hit"])
    fallbacks    = sum(1 for c in calls if not c["success"])

    return {
        "total_calls":        total,
        "last_latency_ms":    last_latency,
        "qwen_success_rate":  _rate("qwen"),
        "llama_success_rate": _rate("llama"),
        "gemini_success_rate":_rate("gemini"),
        "cache_hit_rate":     f"{cache_hits}/{total}" if total else "—",
        "fallback_count":     fallbacks,
    }
