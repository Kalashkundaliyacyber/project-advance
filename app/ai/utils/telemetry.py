"""
ScanWise AI — Structured Telemetry & Observability
Tracks: provider latency, timeouts, JSON failures, retries, memory,
        queue metrics, scan duration, circuit breaker events.

Why this matters:
  Without structured observability, production debugging is guesswork.
  Structured logs with correlation IDs allow:
    - tracing a single request end-to-end
    - identifying provider latency spikes
    - detecting retry storms before they cascade
    - research benchmarking across provider configurations

Usage:
    from app.ai.utils.telemetry import telemetry
    telemetry.record_scan(session_id, duration_ms, host_count, vuln_count)
    telemetry.record_provider(provider, success, latency_ms, correlation_id)
    snapshot = telemetry.snapshot()
"""
from __future__ import annotations
import logging
import os
import time
import uuid
from collections import deque
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger("scanwise.telemetry")

_HISTORY_SIZE = int(os.environ.get("TELEMETRY_HISTORY", "500"))


@dataclass
class ProviderEvent:
    ts:             float
    provider:       str
    success:        bool
    latency_ms:     int
    reason:         str     = ""
    correlation_id: str     = ""
    event_type:     str     = "generate"   # generate | chat | cache | timeout | json_error


@dataclass
class ScanEvent:
    ts:           float
    session_id:   str
    duration_ms:  int
    host_count:   int
    vuln_count:   int
    scan_type:    str = ""
    error:        str = ""


@dataclass
class QueueEvent:
    ts:          float
    job_id:      str
    event:       str    # enqueue | start | done | timeout | cancel
    wait_ms:     int = 0
    run_ms:      int = 0


class TelemetryCollector:
    """
    In-memory ring-buffer telemetry collector.
    Provides a /api/telemetry snapshot endpoint via .snapshot().
    Thread-safe for single asyncio event loop use.
    """

    def __init__(self):
        self._provider_events: deque[ProviderEvent] = deque(maxlen=_HISTORY_SIZE)
        self._scan_events:     deque[ScanEvent]     = deque(maxlen=200)
        self._queue_events:    deque[QueueEvent]    = deque(maxlen=_HISTORY_SIZE)
        self._start_time       = time.time()

    # ── Recording API ─────────────────────────────────────────────────────────

    def record_provider(
        self,
        provider:       str,
        success:        bool,
        latency_ms:     int,
        reason:         str  = "",
        correlation_id: str  = "",
        event_type:     str  = "generate",
    ) -> None:
        self._provider_events.append(ProviderEvent(
            ts=time.time(), provider=provider, success=success,
            latency_ms=latency_ms, reason=reason,
            correlation_id=correlation_id, event_type=event_type,
        ))

    def record_timeout(self, provider: str, timeout_secs: float,
                       correlation_id: str = "") -> None:
        self.record_provider(
            provider, False, int(timeout_secs * 1000),
            reason="timeout", correlation_id=correlation_id,
            event_type="timeout",
        )
        logger.warning("TIMEOUT provider=%s timeout=%.1fs cid=%s",
                       provider, timeout_secs, correlation_id)

    def record_json_error(self, provider: str, raw_text: str,
                          correlation_id: str = "") -> None:
        self.record_provider(
            provider, False, 0,
            reason=f"json_error:{raw_text[:50]}",
            correlation_id=correlation_id,
            event_type="json_error",
        )
        logger.warning("JSON_ERROR provider=%s cid=%s sample=%s",
                       provider, correlation_id, raw_text[:80])

    def record_scan(
        self,
        session_id:  str,
        duration_ms: int,
        host_count:  int,
        vuln_count:  int,
        scan_type:   str = "",
        error:       str = "",
    ) -> None:
        self._scan_events.append(ScanEvent(
            ts=time.time(), session_id=session_id, duration_ms=duration_ms,
            host_count=host_count, vuln_count=vuln_count,
            scan_type=scan_type, error=error,
        ))

    def record_queue_event(self, job_id: str, event: str,
                           wait_ms: int = 0, run_ms: int = 0) -> None:
        self._queue_events.append(QueueEvent(
            ts=time.time(), job_id=job_id, event=event,
            wait_ms=wait_ms, run_ms=run_ms,
        ))

    # ── Snapshot ──────────────────────────────────────────────────────────────

    def snapshot(self) -> dict:
        """Return a structured telemetry snapshot for the /api/telemetry endpoint."""
        now   = time.time()
        plist = list(self._provider_events)
        slist = list(self._scan_events)
        qlist = list(self._queue_events)

        # Provider stats
        def _provider_stats(name: str) -> dict:
            events = [e for e in plist if e.provider == name]
            if not events:
                return {"calls": 0}
            successes  = [e for e in events if e.success]
            failures   = [e for e in events if not e.success]
            timeouts   = [e for e in failures if e.event_type == "timeout"]
            json_errs  = [e for e in failures if e.event_type == "json_error"]
            latencies  = [e.latency_ms for e in successes]
            return {
                "calls":         len(events),
                "successes":     len(successes),
                "failures":      len(failures),
                "timeouts":      len(timeouts),
                "json_errors":   len(json_errs),
                "success_rate":  f"{len(successes)}/{len(events)}",
                "avg_latency_ms": int(sum(latencies) / len(latencies)) if latencies else 0,
                "p95_latency_ms": int(sorted(latencies)[int(len(latencies) * 0.95)]) if len(latencies) >= 20 else None,
            }

        # Queue stats
        queue_waits = [e.wait_ms for e in qlist if e.event == "done" and e.wait_ms > 0]
        queue_runs  = [e.run_ms  for e in qlist if e.event == "done" and e.run_ms  > 0]

        # Scan stats
        scan_durations = [s.duration_ms for s in slist if s.duration_ms > 0]
        recent_scans   = slist[-5:]

        # Memory (optional, non-blocking)
        mem_mb = _get_memory_mb()

        return {
            "uptime_seconds": int(now - self._start_time),
            "providers": {
                "qwen":   _provider_stats("qwen"),
                "llama":  _provider_stats("llama"),
                "gemini": _provider_stats("gemini"),
                "cache":  _provider_stats("cache"),
            },
            "queue": {
                "total_jobs":      len(qlist),
                "avg_wait_ms":     int(sum(queue_waits) / len(queue_waits)) if queue_waits else 0,
                "avg_run_ms":      int(sum(queue_runs)  / len(queue_runs))  if queue_runs  else 0,
                "timeouts":        sum(1 for e in qlist if e.event == "timeout"),
                "cancellations":   sum(1 for e in qlist if e.event == "cancel"),
            },
            "scans": {
                "total":           len(slist),
                "avg_duration_ms": int(sum(scan_durations) / len(scan_durations)) if scan_durations else 0,
                "errors":          sum(1 for s in slist if s.error),
                "recent":          [
                    {"session_id": s.session_id[:8], "scan_type": s.scan_type,
                     "duration_ms": s.duration_ms, "vulns": s.vuln_count}
                    for s in recent_scans
                ],
            },
            "memory_mb": mem_mb,
            "total_events_recorded": len(plist) + len(slist) + len(qlist),
        }

    def new_correlation_id(self) -> str:
        """Generate a short correlation ID for request tracing."""
        return str(uuid.uuid4())[:8]


def _get_memory_mb() -> Optional[float]:
    """Non-blocking RSS memory check. Returns None on failure."""
    try:
        import resource
        kb = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        # Linux returns kB, macOS returns bytes
        if os.uname().sysname == "Linux":
            return round(kb / 1024, 1)
        return round(kb / 1024 / 1024, 1)
    except Exception:
        return None


# Module-level singleton
telemetry = TelemetryCollector()
