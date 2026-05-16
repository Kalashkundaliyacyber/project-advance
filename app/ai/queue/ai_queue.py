"""
ScanWise AI — AI Request Queue v2.0
Sequential semaphore queue with:
  - Correlation IDs for per-job tracking
  - Per-job cancellation support
  - Persistent progress state (in-memory, polled by frontend)
  - Retry-safe execution (idempotent job keys)
  - Queue depth telemetry

MAX_CONCURRENT = 1 prevents VRAM spikes when Qwen 3B is the sole primary model.
Increase via AI_MAX_CONCURRENT env var only if hardware allows.
"""
import asyncio
import logging
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, Optional

logger = logging.getLogger("scanwise.ai.queue")

MAX_CONCURRENT = int(__import__("os").environ.get("AI_MAX_CONCURRENT", "1"))

# ── Job State ─────────────────────────────────────────────────────────────────

class JobStatus(Enum):
    PENDING   = "pending"
    RUNNING   = "running"
    DONE      = "done"
    FAILED    = "failed"
    CANCELLED = "cancelled"


@dataclass
class JobRecord:
    job_id:     str
    key:        str            # idempotency key (e.g. "qwen:patch:ssh:22")
    status:     JobStatus      = JobStatus.PENDING
    created_at: float          = field(default_factory=time.time)
    started_at: Optional[float] = None
    done_at:    Optional[float] = None
    result:     Any            = None
    error:      str            = ""
    cancel_event: asyncio.Event = field(default_factory=asyncio.Event)

    def as_dict(self) -> dict:
        return {
            "job_id":     self.job_id,
            "key":        self.key,
            "status":     self.status.value,
            "created_at": self.created_at,
            "started_at": self.started_at,
            "done_at":    self.done_at,
            "wait_ms":    int((self.started_at or time.time()) - self.created_at) * 1000,
            "run_ms":     int((self.done_at or time.time()) - (self.started_at or time.time())) * 1000 if self.started_at else 0,
            "error":      self.error,
        }


# ── Global state ──────────────────────────────────────────────────────────────

_semaphore: Optional[asyncio.Semaphore] = None
_jobs: Dict[str, JobRecord]             = {}   # job_id → JobRecord
_key_to_job: Dict[str, str]             = {}   # idempotency key → latest job_id
_MAX_HISTORY                            = 200  # keep last N completed jobs


def _get_semaphore() -> asyncio.Semaphore:
    global _semaphore
    if _semaphore is None:
        _semaphore = asyncio.Semaphore(MAX_CONCURRENT)
    return _semaphore


# ── Public API ────────────────────────────────────────────────────────────────

async def run_with_queue(
    fn: Callable,
    *args,
    timeout: float = 120.0,
    job_key: str   = "",
    **kwargs,
) -> Any:
    """
    Run an AI call through the semaphore queue.

    Args:
        fn:       Synchronous callable to execute in thread pool.
        *args:    Positional args passed to fn.
        timeout:  Total timeout (queue wait + execution).
        job_key:  Optional idempotency key. If given, tracks job state.
        **kwargs: Keyword args passed to fn.

    Returns:
        fn(*args, **kwargs) result.

    Raises:
        asyncio.TimeoutError: if queue wait + execution exceeds timeout.
        asyncio.CancelledError: if the job was cancelled before completion.
    """
    job_id = str(uuid.uuid4())[:8]
    key    = job_key or f"job:{job_id}"
    job    = JobRecord(job_id=job_id, key=key)
    _jobs[job_id]   = job
    _key_to_job[key] = job_id
    _prune_history()

    sem = _get_semaphore()
    pending = _count_pending()
    logger.debug("AI queue: enqueue job=%s key=%s pending=%d", job_id, key, pending)

    try:
        async with asyncio.timeout(timeout):
            async with sem:
                if job.cancel_event.is_set():
                    job.status = JobStatus.CANCELLED
                    raise asyncio.CancelledError(f"Job {job_id} was cancelled before execution")

                job.status     = JobStatus.RUNNING
                job.started_at = time.time()
                logger.debug("AI queue: start job=%s key=%s", job_id, key)

                loop   = asyncio.get_event_loop()
                result = await loop.run_in_executor(None, lambda: fn(*args, **kwargs))

                job.status  = JobStatus.DONE
                job.done_at = time.time()
                job.result  = result
                run_ms  = int((job.done_at - job.started_at) * 1000)
                wait_ms = int((job.started_at - job.created_at) * 1000)
                logger.debug("AI queue: done job=%s run_ms=%d", job_id, run_ms)
                try:
                    from app.ai.utils.telemetry import telemetry as _tel
                    _tel.record_queue_event(job_id, "done", wait_ms=wait_ms, run_ms=run_ms)
                except Exception:
                    pass
                return result

    except asyncio.TimeoutError:
        job.status = JobStatus.FAILED
        job.error  = f"timeout after {timeout}s"
        job.done_at = time.time()
        logger.warning("AI queue: timeout job=%s key=%s", job_id, key)
        raise
    except asyncio.CancelledError:
        job.status  = JobStatus.CANCELLED
        job.done_at = time.time()
        logger.info("AI queue: cancelled job=%s key=%s", job_id, key)
        raise
    except Exception as e:
        job.status  = JobStatus.FAILED
        job.error   = str(e)[:200]
        job.done_at = time.time()
        logger.warning("AI queue: failed job=%s: %s", job_id, e)
        raise


def cancel_job(job_key: str) -> bool:
    """
    Cancel a pending or running job by its idempotency key.
    Returns True if the job was found and cancellation was signalled.
    """
    job_id = _key_to_job.get(job_key)
    if not job_id:
        return False
    job = _jobs.get(job_id)
    if not job:
        return False
    if job.status in (JobStatus.PENDING, JobStatus.RUNNING):
        job.cancel_event.set()
        logger.info("AI queue: cancel signalled for job=%s key=%s", job_id, job_key)
        return True
    return False


def get_job_status(job_key: str) -> Optional[dict]:
    """Return current status dict for a job key, or None if not found."""
    job_id = _key_to_job.get(job_key)
    if not job_id:
        return None
    job = _jobs.get(job_id)
    return job.as_dict() if job else None


def get_queue_depth() -> int:
    """Number of jobs currently PENDING (waiting for semaphore slot)."""
    return sum(1 for j in _jobs.values() if j.status == JobStatus.PENDING)


def get_queue_stats() -> dict:
    """Queue telemetry snapshot."""
    jobs = list(_jobs.values())
    return {
        "pending":   sum(1 for j in jobs if j.status == JobStatus.PENDING),
        "running":   sum(1 for j in jobs if j.status == JobStatus.RUNNING),
        "done":      sum(1 for j in jobs if j.status == JobStatus.DONE),
        "failed":    sum(1 for j in jobs if j.status == JobStatus.FAILED),
        "cancelled": sum(1 for j in jobs if j.status == JobStatus.CANCELLED),
        "total":     len(jobs),
        "max_concurrent": MAX_CONCURRENT,
    }


# ── Internal helpers ──────────────────────────────────────────────────────────

def _count_pending() -> int:
    return sum(1 for j in _jobs.values() if j.status == JobStatus.PENDING)


def _prune_history():
    """Keep _jobs dict from growing unbounded; remove oldest completed entries."""
    completed = [
        j for j in _jobs.values()
        if j.status in (JobStatus.DONE, JobStatus.FAILED, JobStatus.CANCELLED)
    ]
    if len(completed) > _MAX_HISTORY:
        oldest = sorted(completed, key=lambda j: j.created_at)
        for j in oldest[: len(completed) - _MAX_HISTORY]:
            _jobs.pop(j.job_id, None)
            _key_to_job.pop(j.key, None)
